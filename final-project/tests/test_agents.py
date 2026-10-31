"""The detection core, unit level: protocol parsing, tools + ledger, the analyst ReAct
loop, the planner, the model client's wire format, and the orchestrator state machine.

Everything is offline: the model is :class:`agentfakes.ScriptedModel` (or an
``httpx.MockTransport`` for the wire tests) and the jail is :class:`agentfakes.LocalSandbox`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from agentfakes import FakeExecutor, LocalSandbox, ScriptedModel, action, confirm_args, native
from ono.agents.analyst import MAX_CALLS_PER_TURN, run_analyst
from ono.agents.definitions import ANALYST, PLANNER
from ono.agents.model import (
    BudgetExhaustedError,
    CallBudget,
    ModelClient,
    ModelError,
    ModelReply,
    ToolCall,
)
from ono.agents.planner import default_plan, run_planner
from ono.agents.protocol import ParseFailure, extract_json_object, parse_reply
from ono.agents.tools import MAX_LINES_PER_READ, ToolBox
from ono.agents.trajectory import Trajectory
from ono.config import Settings
from ono.errors import PipelineError
from ono.executor.client import ExecutorUnavailableError
from ono.orchestrator import DetectionOrchestrator
from ono.sast import Candidate

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"

SQLI = Candidate(
    file="app/views.py",
    line=16,
    cwe_hint="CWE-89",
    rule="sql-string-built-from-input",
    excerpt='    cur.execute(f"SELECT * FROM users WHERE id = {uid}")',
)
PICKLE = Candidate(
    file="app/util.py", line=5, cwe_hint="CWE-502", rule="unsafe-deserialization", excerpt=""
)


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "model_backend": "service",
        "model_service_url": "http://model.test/v1",
        "model_name": "qwen2.5-coder:7b",
        "executor_token": SecretStr("unit-test-token-0123456789"),
    }
    return Settings(_env_file=None, **{**base, **overrides})


@pytest.fixture
def sandbox() -> LocalSandbox:
    return LocalSandbox(FIXTURE_REPO)


@pytest.fixture
def toolbox(sandbox: LocalSandbox) -> ToolBox:
    return ToolBox(sandbox, max_output_chars=6000)


def _text(content: str) -> ModelReply:
    return ModelReply(text=content, protocol="text")


# ===========================================================================
# 1. Protocol: model replies -> tool calls
# ===========================================================================


def test_native_tool_calls_win_over_text() -> None:
    reply = native("grep", {"pattern": "x"})
    reply.text = '{"tool": "tree", "args": {}}'
    calls = parse_reply(reply)
    assert not isinstance(calls, ParseFailure)
    assert [c.name for c in calls] == ["grep"] and calls[0].call_id == "call_1"


@pytest.mark.parametrize(
    ("text", "name", "args"),
    [
        ('{"tool": "grep", "args": {"pattern": "exec"}}', "grep", {"pattern": "exec"}),
        ('Sure!\n```json\n{"tool": "tree", "args": {}}\n```\nDone.', "tree", {}),
        (
            '{"name": "read_lines", '
            '"arguments": "{\\"path\\": \\"a.py\\", \\"start\\": 1, \\"end\\": 5}"}',
            "read_lines",
            {"path": "a.py", "start": 1, "end": 5},
        ),
        ('{"tool": "grep", "pattern": "request"}', "grep", {"pattern": "request"}),
        (
            '{"function": {"name": "read_file", "arguments": {"path": "x.py"}}}',
            "read_file",
            {"path": "x.py"},
        ),
        ('{"action": "functions.grep", "params": {"pattern": "a"}}', "grep", {"pattern": "a"}),
        ('{"tool": "read", "args": {"path": "x.py"}}', "read_file", {"path": "x.py"}),
        ('{"tool_calls": [{"function": {"name": "tree", "arguments": "{}"}}]}', "tree", {}),
        ('{"tool": "grep", "args": {"pattern": "a",}}', "grep", {"pattern": "a"}),  # trailing comma
        ('Let me look {"tool": "tree", "args": {"path": "app"}} at it', "tree", {"path": "app"}),
    ],
)
def test_text_protocol_shapes(text: str, name: str, args: dict[str, Any]) -> None:
    calls = parse_reply(_text(text))
    assert not isinstance(calls, ParseFailure), calls
    assert (calls[0].name, calls[0].args) == (name, args)


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ('{"vulnerable": false, "description": "input is validated"}', "dismiss"),
        ('{"vulnerable": true, "cwe": "CWE-89", "file": "a.py", "line_start": 3}', "confirm"),
        ('{"dismiss": true, "reason": "constant input"}', "dismiss"),
        ('{"dismiss": {"reason": "unreachable"}}', "dismiss"),
        ('{"finding": {"cwe": "CWE-78", "file": "a.py"}}', "confirm"),
        ('{"cwe": "CWE-78", "file": "a.py", "name": "shell injection"}', "confirm"),  # not a tool
    ],
)
def test_verdict_shapes(text: str, name: str) -> None:
    calls = parse_reply(_text(text))
    assert not isinstance(calls, ParseFailure)
    assert calls[0].name == name


def test_dismiss_reason_is_carried() -> None:
    calls = parse_reply(_text('{"vulnerable": false, "description": "input is validated"}'))
    assert not isinstance(calls, ParseFailure)
    assert calls[0].args == {"reason": "input is validated"}


@pytest.mark.parametrize("text", ["", "   ", "I think line 16 is bad {oops", "[1, 2, 3]", "{}"])
def test_garbage_is_a_parse_failure_with_a_hint(text: str) -> None:
    result = parse_reply(_text(text))
    assert isinstance(result, ParseFailure)
    assert '{"tool": "<name>", "args": {...}}' in result.hint


def test_extract_json_object_finds_the_first_object() -> None:
    assert extract_json_object('prose {"a": 1} more {"b": 2}') == {"a": 1}
    assert extract_json_object("nothing here") is None


# ===========================================================================
# 2. Tools, truncation, and the read ledger
# ===========================================================================


def test_read_lines_renders_numbered_lines_and_records_the_ledger(
    toolbox: ToolBox, sandbox: LocalSandbox
) -> None:
    result = toolbox.dispatch(
        ToolCall("read_lines", {"path": "app/views.py", "start": 12, "end": 17})
    )
    assert result.ok and not result.truncated
    assert "   16 | " in result.text and 'cur.execute(f"SELECT' in result.text
    assert toolbox.ledger.has_range("app/views.py", 12, 17)
    assert not toolbox.ledger.has_line("app/views.py", 18)
    assert sandbox.calls == [("read_lines", "app/views.py", "12", "17")]


def test_read_lines_caps_the_range_per_call(toolbox: ToolBox, sandbox: LocalSandbox) -> None:
    toolbox.dispatch(ToolCall("read_lines", {"path": "app/views.py", "start": 1, "end": 10_000}))
    assert sandbox.calls[-1] == ("read_lines", "app/views.py", "1", str(MAX_LINES_PER_READ))


def test_read_file_uses_a_bounded_line_read(toolbox: ToolBox, sandbox: LocalSandbox) -> None:
    result = toolbox.dispatch(ToolCall("read_file", {"path": "app/util.py"}))
    assert result.ok and "pickle.loads(blob)" in result.text
    assert sandbox.calls[-1] == ("read_lines", "app/util.py", "1", str(MAX_LINES_PER_READ))
    assert toolbox.ledger.has_line("app/util.py", 5)


def test_long_output_is_truncated_on_whole_lines_and_the_ledger_matches(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_text("".join(f"x{i} = {i}  # {'#' * 30}\n" for i in range(150)))
    tb = ToolBox(LocalSandbox(tmp_path), max_output_chars=700)
    result = tb.dispatch(ToolCall("read_file", {"path": "big.py"}))
    assert result.truncated and "[truncated:" in result.text
    shown = [ln for ln in result.text.splitlines() if " | " in ln]
    assert 1 < len(shown) < 150
    assert len(result.text) <= 700 + 120  # the cap plus the truncation notice
    assert tb.ledger.has_range("big.py", 1, len(shown))
    assert not tb.ledger.has_line("big.py", len(shown) + 1)


def test_grep_records_matches_in_the_ledger(toolbox: ToolBox) -> None:
    result = toolbox.dispatch(ToolCall("grep", {"pattern": r"request\.args", "path": "app"}))
    assert result.ok
    assert "app/views.py:13:" in result.text and "app/views.py:22:" in result.text
    assert toolbox.ledger.has_line("app/views.py", 13)
    assert not toolbox.ledger.has_line("app/views.py", 14)
    none = toolbox.dispatch(ToolCall("grep", {"pattern": "no_such_symbol_anywhere"}))
    assert none.ok and none.text.startswith("no matches")


def test_tree_lists_the_workspace(toolbox: ToolBox) -> None:
    result = toolbox.dispatch(ToolCall("tree", {}))
    assert result.ok and "app/" in result.text and "app/views.py" in result.text


@pytest.mark.parametrize(
    ("call", "needle"),
    [
        (ToolCall("run", {"cmd": "id"}), "unknown tool 'run'"),
        (ToolCall("confirm", {}), "unknown tool 'confirm'"),  # verdicts are not dispatchable
        (ToolCall("read_file", {}), "'path' is required"),
        (ToolCall("read_lines", {"path": "a.py", "start": "x"}), "must be an integer"),
        (ToolCall("grep", {"pattern": ""}), "non-empty 'pattern'"),
        (ToolCall("read_file", {"path": "../../etc/passwd"}), "sandbox error"),
        (ToolCall("read_file", {"path": "/etc/passwd"}), "sandbox error"),
        (ToolCall("read_file", {"path": "app/nope.py"}), "sandbox error"),
        (ToolCall("grep", {"__malformed__": "{bad"}), "not valid JSON"),
    ],
)
def test_bad_tool_calls_become_error_text_not_exceptions(
    toolbox: ToolBox, call: ToolCall, needle: str
) -> None:
    result = toolbox.dispatch(call)
    assert result.ok is False and result.text.startswith("ERROR:") and needle in result.text
    assert toolbox.ledger.files == []


# ===========================================================================
# 3. The analyst ReAct loop
# ===========================================================================


def _run(
    model: ScriptedModel,
    sandbox: LocalSandbox,
    *,
    candidate: Candidate = SQLI,
    max_steps: int = 8,
    deadline: float | None = None,
    budget: CallBudget | None = None,
    plan_text: str = "",
) -> Any:
    toolbox = ToolBox(sandbox, max_output_chars=6000)
    window = toolbox.dispatch(
        ToolCall("read_lines", {"path": candidate.file, "start": 11, "end": 24})
    )
    plan = default_plan(candidate)
    if plan_text:
        plan.steps = [plan_text]
    return run_analyst(
        model,
        ANALYST.with_budget(max_steps=max_steps),
        scan_id="scn_t",
        target_id="fixture",
        candidate=candidate,
        plan=plan,
        window_text=window.text,
        toolbox=toolbox,
        budget=budget or CallBudget(limit=100),
        deadline=deadline if deadline is not None else time.monotonic() + 60,
        trajectory=Trajectory(scan_id="scn_t", role="analyst", candidate="t"),
    )


def test_happy_path_dispatches_tools_in_order_and_confirms(sandbox: LocalSandbox) -> None:
    model = ScriptedModel(
        [
            action("read_lines", path="app/views.py", start=1, end=30),
            action("grep", pattern="request\\.args", path="app"),
            action("confirm", **confirm_args()),
        ]
    )
    out = _run(model, sandbox)

    assert out.verdict == "confirm" and out.finding is not None
    assert sandbox.calls[1:] == [
        ("read_lines", "app/views.py", "1", "30"),
        ("grep", "request\\.args", "app"),
    ]
    assert model.n_calls == 3
    f = out.finding
    assert (f.file, f.line_range, f.cwe, f.severity) == ("app/views.py", (16, 16), "CWE-89", "high")
    assert [(t.file, t.line) for t in f.trace] == [("app/views.py", 13), ("app/views.py", 16)]
    assert f.rung == 2 and f.verified is False and f.patch_diff == ""
    assert f.finding_id.startswith("fnd_")
    # the model saw each tool result before its next move
    second_call = model.calls[1]["messages"]
    assert (
        second_call[-1]["role"] == "user" and "RESULT of read_lines" in second_call[-1]["content"]
    )
    assert "    1 | " in second_call[-1]["content"]
    kinds = [s.kind for s in out.trajectory.steps]
    assert kinds == ["model", "tool", "model", "tool", "model", "verdict"]
    assert out.trajectory.outcome == "confirm" and out.trajectory.model_calls == 3


def test_garbage_replies_are_retried_within_budget(sandbox: LocalSandbox) -> None:
    model = ScriptedModel(
        ["Hmm, let me think about this.", "{broken json", action("confirm", **confirm_args())]
    )
    out = _run(model, sandbox)
    assert out.verdict == "confirm" and model.n_calls == 3
    hints = [m["content"] for m in model.calls[2]["messages"] if m["role"] == "user"]
    assert any("could not find a JSON action" in h for h in hints)
    assert [s.kind for s in out.trajectory.steps].count("parse_error") == 2


def test_step_budget_is_a_hard_cap(sandbox: LocalSandbox) -> None:
    model = ScriptedModel(default=action("read_lines", path="app/views.py", start=1, end=5))
    out = _run(model, sandbox, max_steps=3)
    assert out.verdict == "exhausted" and out.finding is None
    assert model.n_calls == 3
    last_prompt = model.calls[-1]["messages"][-1]["content"]
    assert "LAST step" in last_prompt


def test_garbage_forever_cannot_loop(sandbox: LocalSandbox) -> None:
    model = ScriptedModel(default="no json here")
    out = _run(model, sandbox, max_steps=4)
    assert out.verdict == "exhausted" and model.n_calls == 4


def test_dismiss_yields_no_finding(sandbox: LocalSandbox) -> None:
    model = ScriptedModel([action("dismiss", reason="uid is cast to int before use")])
    out = _run(model, sandbox)
    assert out.verdict == "dismiss" and out.finding is None
    assert out.reason == "uid is cast to int before use"
    assert out.trajectory.steps[-1].kind == "verdict"


def test_unread_locations_are_snapped_to_the_sast_sink(sandbox: LocalSandbox) -> None:
    claimed = confirm_args(
        file="app/util.py",  # never read in this session
        line_start=5,
        line_end=5,
        trace=[
            {"file": "app/util.py", "line": 5, "symbol": "pickle.loads", "note": "invented"},
            {"file": "app/views.py", "line": 13, "symbol": "request.args.get", "note": "read"},
        ],
    )
    out = _run(ScriptedModel([action("confirm", **claimed)]), sandbox)
    f = out.finding
    assert f is not None
    assert (f.file, f.line_range) == ("app/views.py", (16, 16))
    assert "anchored to the SAST sink" in f.description
    assert [(t.file, t.line) for t in f.trace] == [("app/views.py", 13)]


def test_lines_inside_a_read_range_are_honoured_partially_read_ranges_are_clamped(
    sandbox: LocalSandbox,
) -> None:
    out = _run(
        ScriptedModel([action("confirm", **confirm_args(line_start=14, line_end=16))]), sandbox
    )
    assert out.finding is not None and out.finding.line_range == (14, 16)
    out = _run(
        ScriptedModel([action("confirm", **confirm_args(line_start=22, line_end=40))]), sandbox
    )
    assert out.finding is not None and out.finding.line_range == (22, 22)


def test_trace_with_no_read_hop_falls_back_to_the_sast_hop(sandbox: LocalSandbox) -> None:
    out = _run(ScriptedModel([action("confirm", **confirm_args(trace="nope"))]), sandbox)
    f = out.finding
    assert f is not None and len(f.trace) == 1
    assert f.trace[0].line == 16 and "sql-string-built-from-input" in f.trace[0].note
    assert f.rung == 1  # a single hop is not an evidence-backed source->sink trace


def test_confirm_without_a_cwe_is_rejected_and_retried(sandbox: LocalSandbox) -> None:
    model = ScriptedModel(
        [
            action("confirm", **confirm_args(cwe="unknown")),
            action("confirm", **confirm_args(cwe="89")),
        ]
    )
    out = _run(model, sandbox)
    assert out.verdict == "confirm" and out.finding is not None and out.finding.cwe == "CWE-89"
    assert model.n_calls == 2
    assert "confirm rejected" in model.calls[1]["messages"][-1]["content"]


def test_unknown_and_disallowed_tools_are_reported_back(sandbox: LocalSandbox) -> None:
    model = ScriptedModel(
        [
            action("run", cmd="rm -rf /"),
            action("apply_patch", diff="x"),
            action("dismiss", reason="ok"),
        ]
    )
    out = _run(model, sandbox)
    assert out.verdict == "dismiss"
    assert sandbox.calls == [("read_lines", "app/views.py", "11", "24")]  # nothing else ran
    feedback = model.calls[1]["messages"][-1]["content"]
    assert "not available" in feedback or "unknown tool" in feedback


def test_native_protocol_echoes_tool_calls_and_answers_with_tool_messages(
    sandbox: LocalSandbox,
) -> None:
    model = ScriptedModel(
        [
            native("read_lines", {"path": "app/views.py", "start": 1, "end": 10}, "call_a"),
            native("confirm", confirm_args(), "call_b"),
        ],
        protocol="native",
    )
    out = _run(model, sandbox)
    assert out.verdict == "confirm"
    msgs = model.calls[1]["messages"]
    assert msgs[-2]["role"] == "assistant" and msgs[-2]["tool_calls"][0]["id"] == "call_a"
    assert msgs[-1] == {
        "role": "tool",
        "tool_call_id": "call_a",
        "name": "read_lines",
        "content": msgs[-1]["content"],
    }
    assert "    1 | " in msgs[-1]["content"]


def test_at_most_three_tool_calls_per_turn(sandbox: LocalSandbox) -> None:
    reply = native("tree", {}, "c1")
    for i in range(2, 7):
        extra = native("grep", {"pattern": f"p{i}"}, f"c{i}")
        reply.tool_calls.extend(extra.tool_calls)
        reply.raw_message["tool_calls"].extend(extra.raw_message["tool_calls"])
    model = ScriptedModel([reply, action("dismiss", reason="x")], protocol="native")
    _run(model, sandbox)
    assert len(sandbox.calls) == 1 + MAX_CALLS_PER_TURN
    assert any("only the first 3" in m["content"] for m in model.calls[1]["messages"])


def test_scan_budget_stops_the_loop_before_a_request(sandbox: LocalSandbox) -> None:
    model = ScriptedModel(default=action("tree"))
    with pytest.raises(BudgetExhaustedError):
        _run(model, sandbox, budget=CallBudget(limit=2))
    assert model.n_calls == 2


def test_candidate_deadline_is_checked_between_steps(sandbox: LocalSandbox) -> None:
    model = ScriptedModel(default=action("tree"))
    out = _run(model, sandbox, deadline=time.monotonic() - 1)
    assert out.verdict == "timeout" and model.n_calls == 0


def test_plan_and_window_feed_the_analyst_prompt(sandbox: LocalSandbox) -> None:
    model = ScriptedModel([action("dismiss", reason="x")])
    _run(model, sandbox, plan_text="grep for 'request.args' then read the handler")
    prompt = model.calls[0]["messages"][1]["content"]
    assert model.calls[0]["messages"][0]["content"] == ANALYST.system_prompt
    assert "grep for 'request.args' then read the handler" in prompt
    assert "   16 | " in prompt and "suspected CWE: CWE-89" in prompt
    assert "at most 8 steps" in prompt
    assert model.calls[0]["tools"] is not None and len(model.calls[0]["tools"]) == 6


# ===========================================================================
# 4. The planner
# ===========================================================================


def test_planner_parses_a_plan_and_caps_the_lists() -> None:
    plan_json = {
        "hypothesis": "uid reaches the SQL string unescaped",
        "source": "request.args.get('id') at line 13",
        "sink": "cur.execute(f...) at line 16",
        "greps": [f"g{i}" for i in range(10)],
        "reads": ["app/views.py:1-30"],
        "steps": [f"step {i}" for i in range(10)],
        "decision_rule": "confirm if uid is not cast",
    }
    model = ScriptedModel([json.dumps(plan_json)])
    traj = Trajectory(scan_id="s", role="planner", candidate="c")
    plan = run_planner(
        model,
        PLANNER,
        candidate=SQLI,
        window_text="   16 | x",
        budget=CallBudget(5),
        trajectory=traj,
    )
    assert plan.origin == "planner" and len(plan.greps) == 4 and len(plan.steps) == 6
    rendered = plan.render()
    assert "Hypothesis: uid reaches" in rendered and "  1. step 0" in rendered
    assert model.calls[0]["messages"][0]["content"] == PLANNER.system_prompt
    assert "   16 | x" in model.calls[0]["messages"][1]["content"]
    assert model.calls[0]["tools"] is None  # the planner has no tools
    assert traj.outcome == "plan"


def test_planner_garbage_degrades_to_the_default_plan() -> None:
    model = ScriptedModel(["I would start by reading the file."])
    traj = Trajectory(scan_id="s", role="planner", candidate="c")
    plan = run_planner(
        model, PLANNER, candidate=SQLI, window_text="", budget=CallBudget(5), trajectory=traj
    )
    assert plan.origin == "default" and plan.steps == default_plan(SQLI).steps
    assert traj.outcome == "default-plan"


# ===========================================================================
# 5. ModelClient wire format (httpx.MockTransport)
# ===========================================================================


def _client(settings: Settings, handler: Any) -> ModelClient:
    return ModelClient(settings, transport=httpx.MockTransport(handler))


def _completion(message: dict[str, Any], status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json={
            "choices": [{"message": message}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2},
        },
    )


def test_native_request_and_tool_call_parsing() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _completion(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "grep", "arguments": '{"pattern": "x"}'},
                    },
                    {
                        "id": "c2",
                        "type": "function",
                        "function": {"name": "tree", "arguments": {"path": "app"}},
                    },
                ],
            }
        )

    client = _client(
        _settings(agent_tool_protocol="native", model_service_api_key=SecretStr("sk-1")), handler
    )
    reply = client.chat(
        [{"role": "user", "content": "hi"}], tools=[{"type": "function"}], temperature=0.0
    )
    body = json.loads(seen[0].content)
    assert str(seen[0].url) == "http://model.test/v1/chat/completions"
    assert seen[0].headers["Authorization"] == "Bearer sk-1"
    assert body["model"] == "qwen2.5-coder:7b" and body["tools"] == [{"type": "function"}]
    assert body["temperature"] == 0.0 and body["stream"] is False
    assert reply.protocol == "native" and reply.prompt_tokens == 10
    assert [(c.name, c.args, c.call_id) for c in reply.tool_calls] == [
        ("grep", {"pattern": "x"}, "c1"),
        ("tree", {"path": "app"}, "c2"),
    ]
    assert reply.raw_message["tool_calls"][0]["id"] == "c1"


def test_auto_protocol_falls_back_to_text_when_tools_are_rejected() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies.append(body)
        if "tools" in body:
            return httpx.Response(400, json={"error": "model does not support tools"})
        return _completion({"role": "assistant", "content": '{"tool": "tree", "args": {}}'})

    client = _client(_settings(agent_tool_protocol="auto"), handler)
    protocols = [client.protocol]
    reply = client.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function"}])
    assert reply.protocol == "text" and reply.text.startswith('{"tool"')
    protocols.append(client.protocol)
    assert protocols == ["auto", "text"]
    client.chat([{"role": "user", "content": "again"}], tools=[{"type": "function"}])
    assert [("tools" in b) for b in bodies] == [True, False, False]  # sticky fallback


def test_auto_protocol_locks_to_native_when_tools_are_accepted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _completion({"role": "assistant", "content": "ok"})

    client = _client(_settings(agent_tool_protocol="auto"), handler)
    client.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function"}])
    assert client.protocol == "native"


def test_text_protocol_never_sends_tools_and_no_key_means_no_header() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _completion({"role": "assistant", "content": "x"})

    client = _client(_settings(agent_tool_protocol="text"), handler)
    client.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function"}])
    assert "tools" not in json.loads(seen[0].content)
    assert "authorization" not in seen[0].headers


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(503, text="loading"),
        httpx.Response(200, json={"nope": 1}),
        httpx.Response(200, json={"choices": [{"message": "str"}]}),
    ],
)
def test_transport_and_body_failures_are_model_errors(response: httpx.Response) -> None:
    client = _client(_settings(), lambda request: response)
    with pytest.raises(ModelError):
        client.chat([{"role": "user", "content": "hi"}])


def test_unreachable_endpoint_is_a_model_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(ModelError, match="unreachable"):
        _client(_settings(), handler).chat([{"role": "user", "content": "hi"}])


def test_budget_is_taken_before_any_request() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _completion({"role": "assistant", "content": "x"})

    client = _client(_settings(), handler)
    budget = CallBudget(limit=1)
    client.chat([{"role": "user", "content": "hi"}], budget=budget)
    with pytest.raises(BudgetExhaustedError):
        client.chat([{"role": "user", "content": "hi"}], budget=budget)
    assert len(seen) == 1 and budget.used == 1


# ===========================================================================
# 6. The orchestrator state machine (fake executor, scripted model)
# ===========================================================================

CANDIDATES = [PICKLE, SQLI, Candidate("app/views.py", 23, "CWE-78", "shell-command-from-string")]

PLAN_REPLY = json.dumps({"hypothesis": "h", "source": "s", "sink": "k", "steps": ["read"]})


def _per_candidate_script(verdicts: dict[str, str]) -> Any:
    """Planner -> plan JSON; analyst -> one grep, then the verdict for that candidate."""

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == PLANNER.system_prompt:
            return PLAN_REPLY
        task = messages[1]["content"]
        key = next(
            k for k in verdicts if f"file: {k.split(':')[0]}\n  line: {k.split(':')[1]}\n" in task
        )
        if not any(m["role"] == "user" and m["content"].startswith("RESULT of") for m in messages):
            return action("grep", pattern="request", path="app")
        return verdicts[key]

    return script


def _confirm_for(file: str, line: int, cwe: str) -> str:
    return action(
        "confirm", **confirm_args(cwe=cwe, file=file, line_start=line, line_end=line, trace=[])
    )


def test_detect_runs_planner_then_analyst_per_candidate_in_one_sandbox(tmp_path: Path) -> None:
    settings = _settings(agent_trajectory_dir=tmp_path / "traj", context_lines=5)
    executor = FakeExecutor()
    model = ScriptedModel(
        script=_per_candidate_script(
            {
                "app/util.py:5": _confirm_for("app/util.py", 5, "CWE-502"),
                "app/views.py:16": _confirm_for("app/views.py", 16, "CWE-89"),
                "app/views.py:23": action("dismiss", reason="host is validated"),
            }
        )
    )
    orch = DetectionOrchestrator(settings, model=model, executor=executor)

    report = orch.detect("scn_o", "fixture", FIXTURE_REPO, CANDIDATES)

    assert executor.events == ["create scn_o", "destroy scn_o"]
    assert report.sandbox_id == "sbx_scn_o"
    assert [o.state for o in report.outcomes] == ["confirmed", "confirmed", "dismissed"]
    assert [(f.file, f.line_range, f.cwe) for f in report.findings] == [
        ("app/util.py", (5, 5), "CWE-502"),
        ("app/views.py", (16, 16), "CWE-89"),
    ]
    assert report.budget_limit == 3 * (settings.analyst_max_steps + 1)
    assert report.model_calls == model.n_calls == 3 * (1 + 2)  # planner + grep + verdict
    assert report.stopped_early == ""
    assert "2 raw finding(s) from 3 candidate(s)" in report.summary
    # every candidate: window read through the jail first, then the analyst's grep
    sbx = executor.sandboxes[0]
    assert sbx.calls[0] == ("read_lines", "app/util.py", "1", "10")
    assert ("grep", "request", "app") in sbx.calls
    # the planner's plan reached the analyst, and the window was marked
    analyst_prompt = model.calls[1]["messages"][1]["content"]
    assert "Investigation plan (planner):" in analyst_prompt and "Hypothesis: h" in analyst_prompt
    flagged = next(ln for ln in analyst_prompt.splitlines() if ln.startswith("    5 | "))
    assert flagged.endswith("<-- FLAGGED") and "pickle.loads(blob)" in flagged
    assert all(o.plan is not None and o.plan.origin == "planner" for o in report.outcomes)
    # trajectories persisted: one planner + one analyst record per candidate
    lines = (tmp_path / "traj" / "scn_o.jsonl").read_text().splitlines()
    records = [json.loads(ln) for ln in lines]
    assert [r["role"] for r in records] == ["planner", "analyst"] * 3
    assert records[1]["outcome"] == "confirm" and records[1]["steps"][1]["tool"] == "grep"


def test_planner_disabled_makes_no_planner_call() -> None:
    settings = _settings(planner_enabled=False)
    model = ScriptedModel(default=action("dismiss", reason="no"))
    orch = DetectionOrchestrator(settings, model=model, executor=FakeExecutor())
    report = orch.detect("s", "t", FIXTURE_REPO, CANDIDATES)
    assert model.n_calls == 3 and report.budget_limit == 3 * settings.analyst_max_steps
    assert all(o.plan is not None and o.plan.origin == "default" for o in report.outcomes)
    assert all(c["messages"][0]["content"] == ANALYST.system_prompt for c in model.calls)


def test_no_candidates_opens_no_sandbox_and_makes_no_call() -> None:
    executor, model = FakeExecutor(), ScriptedModel()
    report = DetectionOrchestrator(_settings(), model=model, executor=executor).detect(
        "s", "t", FIXTURE_REPO, []
    )
    assert report.findings == [] and executor.events == [] and model.n_calls == 0


def test_max_candidates_bounds_the_queue_and_the_budget() -> None:
    settings = _settings(max_candidates=1, planner_enabled=False, analyst_max_steps=2)
    model = ScriptedModel(default=action("dismiss", reason="no"))
    report = DetectionOrchestrator(settings, model=model, executor=FakeExecutor()).detect(
        "s", "t", FIXTURE_REPO, CANDIDATES
    )
    assert len(report.outcomes) == 1 and report.budget_limit == 2 and model.n_calls == 1


def test_unreadable_candidate_is_skipped_without_a_model_call() -> None:
    bogus = Candidate("app/missing.py", 3, "CWE-78", "r")
    model = ScriptedModel(default=action("dismiss", reason="no"))
    report = DetectionOrchestrator(_settings(), model=model, executor=FakeExecutor()).detect(
        "s", "t", FIXTURE_REPO, [bogus, SQLI]
    )
    assert [o.state for o in report.outcomes] == ["skipped", "dismissed"]
    assert "cannot read the flagged line" in report.outcomes[0].reason
    assert model.n_calls == 2  # planner + analyst for SQLI only


def test_budget_exhaustion_stops_the_queue_and_tears_down() -> None:
    class Stingy(ScriptedModel):
        def chat(
            self, messages: Any, *, tools: Any = None, temperature: float = 0.0, budget: Any = None
        ) -> ModelReply:
            if self.n_calls >= 3:
                raise BudgetExhaustedError("model-call budget exhausted (3/3)")
            return super().chat(messages, tools=tools, temperature=temperature, budget=budget)

    executor = FakeExecutor()
    model = Stingy(default=action("dismiss", reason="no"))
    report = DetectionOrchestrator(_settings(), model=model, executor=executor).detect(
        "s", "t", FIXTURE_REPO, CANDIDATES
    )
    assert len(report.outcomes) == 1 and "budget exhausted" in report.stopped_early
    assert executor.events == ["create s", "destroy s"]


def test_executor_failures_become_pipeline_errors_and_still_tear_down() -> None:
    model = ScriptedModel(default=action("dismiss", reason="no"))
    with pytest.raises(PipelineError, match="rejected EXECUTOR_TOKEN"):
        DetectionOrchestrator(
            _settings(), model=model, executor=FakeExecutor(auth_fail=True)
        ).detect("s", "t", FIXTURE_REPO, CANDIDATES)

    executor = FakeExecutor()

    def break_after_first_read(sbx: LocalSandbox) -> None:
        sbx.fail_with = ExecutorUnavailableError("executor timed out on POST read")

    executor.on_create = break_after_first_read
    with pytest.raises(PipelineError, match="unreachable mid-scan"):
        DetectionOrchestrator(_settings(), model=model, executor=executor).detect(
            "s", "t", FIXTURE_REPO, CANDIDATES
        )
    assert executor.events == ["create s", "destroy s"]


def test_preflight_reports_an_actionable_reason() -> None:
    model = ScriptedModel()
    with pytest.raises(PipelineError, match=r"executor unreachable at http://127\.0\.0\.1:8081"):
        DetectionOrchestrator(
            _settings(), model=model, executor=FakeExecutor(unreachable=True)
        ).preflight()
    with pytest.raises(PipelineError, match="Docker daemon is unavailable"):
        DetectionOrchestrator(
            _settings(), model=model, executor=FakeExecutor(docker=False)
        ).preflight()
    health = DetectionOrchestrator(_settings(), model=model, executor=FakeExecutor()).preflight()
    assert health.docker is True


def test_model_transport_errors_propagate_out_of_detect() -> None:
    class Dead(ScriptedModel):
        def chat(
            self, messages: Any, *, tools: Any = None, temperature: float = 0.0, budget: Any = None
        ) -> ModelReply:
            raise ModelError("model endpoint unreachable")

    executor = FakeExecutor()
    with pytest.raises(ModelError):
        DetectionOrchestrator(_settings(), model=Dead(), executor=executor).detect(
            "s", "t", FIXTURE_REPO, CANDIDATES
        )
    assert executor.events == ["create s", "destroy s"]
