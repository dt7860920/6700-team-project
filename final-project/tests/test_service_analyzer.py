"""Service backend end to end, offline: real ingest + regex SAST, the orchestrated
planner/analyst flow on a scripted model, and a fake Executor standing in for the jail.

Repo targets point at ``tests/fixtures/vuln_repo`` (a local directory, copied not
cloned). The real-jail variant of this flow is ``tests/test_orchestrator_docker.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from agentfakes import FakeExecutor, ScriptedModel, action, confirm_args
from ono import sast
from ono.agents.definitions import PLANNER
from ono.agents.model import ModelClient, ModelError
from ono.analyzer import ServiceAnalyzer, build_analyzer
from ono.config import Settings
from ono.errors import PipelineError
from ono.executor.client import ExecutorClient
from ono.models import ScanOptions, ScanRequest
from ono.service import ScanService
from ono.store import InMemoryScanStore
from ono.targets import Target, TargetRegistry, get_registry

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"
SNIPPET = 'import os\nos.system("ping " + host)\n'
TOKEN = SecretStr("unit-test-token-0123456789")


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never run the Semgrep binary in the suite: the regex fallback is deterministic."""

    def unavailable(root: Path, rulesets: Any) -> dict[str, object]:
        raise sast.SemgrepUnavailableError("semgrep disabled in tests")

    monkeypatch.setattr(sast, "run_semgrep", unavailable)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return tmp_path / "ws"


def _settings(workspace: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "model_backend": "service",
        "model_service_url": "http://localhost:11434/v1/",  # trailing slash on purpose
        "model_name": "qwen2.5-coder:7b",
        "executor_token": TOKEN,
        "workspace_dir": workspace,
        "context_lines": 5,
    }
    return Settings(_env_file=None, **{**base, **overrides})


def _script(verdict_for: dict[str, str], *, grep_first: bool = True) -> Any:
    """Planner -> a plan; analyst -> (optionally one grep, then) the verdict for the sink."""

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        if messages[0]["content"] == PLANNER.system_prompt:
            return json.dumps({"hypothesis": "h", "source": "s", "sink": "k"})
        task = messages[1]["content"]
        key = next(
            k
            for k in verdict_for
            if f"file: {k.rsplit(':', 1)[0]}\n  line: {k.rsplit(':', 1)[1]}\n" in task
        )
        seen_result = any(
            m["role"] == "user" and m["content"].startswith("RESULT") for m in messages
        )
        if grep_first and not seen_result:
            return action("grep", pattern="request|host", path=".")
        return verdict_for[key]

    return script


def _confirm(file: str, line: int, cwe: str, **extra: Any) -> str:
    fields: dict[str, Any] = {
        "cwe": cwe,
        "file": file,
        "line_start": line,
        "line_end": line,
        "trace": [],
        **extra,
    }
    return action("confirm", **confirm_args(**fields))


@pytest.fixture
def registry() -> TargetRegistry:
    return get_registry()


@pytest.fixture
def snippet(registry: TargetRegistry) -> Target:
    return registry["snippet"]


@pytest.fixture
def repo() -> Target:
    """A ``repo`` target whose source is the local fixture directory (no network)."""
    return Target(
        target_id="fixture-repo",
        name="fixture",
        kind="repo",
        languages=["python"],
        source=str(FIXTURE_REPO),
        snapshot="fixture",
    )


def _analyzer(
    settings: Settings, model: ScriptedModel, executor: FakeExecutor | None = None
) -> ServiceAnalyzer:
    return ServiceAnalyzer(settings, model=model, executor=executor or FakeExecutor())


# -- Construction --------------------------------------------------------------


def test_build_analyzer_selects_service_with_real_clients(workspace: Path) -> None:
    analyzer = build_analyzer(_settings(workspace))
    assert isinstance(analyzer, ServiceAnalyzer)
    assert analyzer.backend == "service"
    assert analyzer.base_url == "http://localhost:11434/v1"
    assert isinstance(analyzer.model, ModelClient)
    assert isinstance(analyzer.executor, ExecutorClient)
    assert analyzer.executor.base_url == "http://127.0.0.1:8081"


def test_service_backend_requires_the_executor_token(workspace: Path) -> None:
    with pytest.raises(ValidationError, match="executor_token is required"):
        Settings(
            _env_file=None,
            model_backend="service",
            model_service_url="http://localhost:11434/v1",
            workspace_dir=workspace,
        )


def test_local_backend_still_unimplemented() -> None:
    with pytest.raises(NotImplementedError, match="MODEL_BACKEND=service"):
        build_analyzer(Settings(_env_file=None, model_backend="local"))


# -- Repo target: ingest -> SAST -> one sandbox -> planner + analyst per candidate ----


def test_repo_scan_end_to_end(repo: Target, workspace: Path) -> None:
    executor = FakeExecutor()
    model = ScriptedModel(
        script=_script(
            {
                "app/util.py:5": _confirm("app/util.py", 5, "CWE-502"),
                "app/views.py:16": _confirm(
                    "app/views.py",
                    16,
                    "CWE-89",
                    trace=[
                        {
                            "file": "app/views.py",
                            "line": 13,
                            "symbol": "request.args.get",
                            "note": "source",
                        },
                        {
                            "file": "app/views.py",
                            "line": 16,
                            "symbol": "cur.execute",
                            "note": "sink",
                        },
                    ],
                ),
                "app/views.py:23": action("dismiss", reason="host is validated upstream"),
            }
        )
    )
    analyzer = _analyzer(_settings(workspace), model, executor)

    result = analyzer.run("scn_repo", repo, ScanOptions())

    assert [s.stage for s in result.stages] == ["ingest", "sast", "plan", "analyze", "verify"]
    assert all(s.status == "ok" for s in result.stages), result.stages
    assert result.stages[0].summary == f"snapshot {workspace / 'scn_repo'}"
    assert result.stages[1].summary == "3 candidate(s)"
    assert result.stages[2].summary.startswith("planner+analyst app/util.py:5 (CWE-502)")
    assert result.stages[3].summary == "2 raw finding(s)"
    assert result.stages[4].summary == "2 passed the verifier"
    # one jail for the whole scan, opened after SAST with the ingested workspace, torn down after
    assert executor.events == ["create scn_repo", "destroy scn_repo"]
    assert executor.sandboxes[0].root == workspace / "scn_repo"
    assert not (workspace / "scn_repo").exists()  # workspace cleaned up after the run
    # all code reads went through the jail: window per candidate + the analyst's greps
    reads = [c for c in executor.sandboxes[0].calls if c[0] == "read_lines"]
    assert [c[1] for c in reads] == ["app/util.py", "app/views.py", "app/views.py"]
    assert sum(1 for c in executor.sandboxes[0].calls if c[0] == "grep") == 3
    # findings: anchored, unverified, rung 1-2, stable ids
    assert [(f.file, f.line_range, f.cwe, f.rung) for f in result.findings] == [
        ("app/util.py", (5, 5), "CWE-502", 1),
        ("app/views.py", (16, 16), "CWE-89", 2),
    ]
    assert all(
        f.verified is False and f.scan_id == "scn_repo" and f.patch_diff == ""
        for f in result.findings
    )
    assert [t.line for t in result.findings[1].trace] == [13, 16]
    assert model.n_calls == 3 * 3  # planner + grep + verdict per candidate
    report = analyzer.last_report
    assert report is not None and [o.state for o in report.outcomes] == [
        "confirmed",
        "confirmed",
        "dismissed",
    ]


def test_dismissed_candidates_produce_no_finding(repo: Target, workspace: Path) -> None:
    model = ScriptedModel(default=action("dismiss", reason="not reachable"))
    analyzer = _analyzer(_settings(workspace, planner_enabled=False), model)
    result = analyzer.run("s", repo, ScanOptions())
    assert result.findings == [] and model.n_calls == 3
    assert result.stages[3].summary == "0 raw finding(s)"


def test_max_candidates_bounds_model_calls(repo: Target, workspace: Path) -> None:
    model = ScriptedModel(default=action("dismiss", reason="no"))
    analyzer = _analyzer(_settings(workspace, max_candidates=2, planner_enabled=False), model)
    analyzer.run("s", repo, ScanOptions())
    assert model.n_calls == 2
    assert analyzer.last_report is not None and analyzer.last_report.budget_limit == 2 * 8


def test_semgrep_results_feed_the_orchestrator_when_available(
    repo: Target, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canned = json.loads((FIXTURE_REPO.parent / "semgrep_output.json").read_text())
    monkeypatch.setattr(sast, "run_semgrep", lambda root, rulesets: canned)
    model = ScriptedModel(default=action("dismiss", reason="no"))
    analyzer = _analyzer(_settings(workspace, planner_enabled=False), model)
    analyzer.run("s", repo, ScanOptions())
    assert model.n_calls == 4  # 5 Semgrep results -> 4 unique sinks (one no-CWE rule dropped)
    assert (
        "python.flask.security.injection.tainted-sql-string"
        in model.calls[0]["messages"][1]["content"]
    )


# -- Snippet target goes through the jail too -----------------------------------------


def test_snippet_is_written_then_read_through_the_sandbox(snippet: Target, workspace: Path) -> None:
    executor = FakeExecutor()
    model = ScriptedModel(
        [
            json.dumps({"hypothesis": "shell injection"}),
            _confirm("snippet.py", 2, "CWE-78", severity="high"),
        ]
    )
    result = _analyzer(_settings(workspace), model, executor).run(
        "scn_svc", snippet, ScanOptions(snippet=SNIPPET)
    )
    assert len(result.findings) == 1
    f = result.findings[0]
    assert (f.target_id, f.cwe, f.file, f.line_range, f.verified) == (
        "snippet",
        "CWE-78",
        "snippet.py",
        (2, 2),
        False,
    )
    assert executor.sandboxes[0].calls[0] == ("read_lines", "snippet.py", "1", "7")
    assert "RESULT" not in model.calls[1]["messages"][-1]["content"]  # confirmed straight away
    assert not (workspace / "scn_svc").exists()


def test_clean_snippet_makes_no_model_call_and_opens_no_sandbox(
    snippet: Target, workspace: Path
) -> None:
    executor, model = FakeExecutor(), ScriptedModel()
    result = _analyzer(_settings(workspace), model, executor).run(
        "s", snippet, ScanOptions(snippet="print('hello')\n")
    )
    assert result.findings == [] and model.n_calls == 0 and executor.events == []
    assert result.stages[2].summary.startswith("REPORT none")


# -- Failure modes: clear, never silent ------------------------------------------------


def test_unreachable_executor_fails_the_scan_before_ingest(repo: Target, workspace: Path) -> None:
    model = ScriptedModel()
    analyzer = _analyzer(_settings(workspace), model, FakeExecutor(unreachable=True))
    with pytest.raises(PipelineError, match=r"executor unreachable at http://127\.0\.0\.1:8081"):
        analyzer.run("scn_x", repo, ScanOptions())
    assert model.n_calls == 0 and not (workspace / "scn_x").exists()


def test_scan_service_reports_the_executor_failure_in_the_scan_message(
    repo: Target, workspace: Path
) -> None:
    settings = _settings(workspace)
    analyzer = _analyzer(settings, ScriptedModel(), FakeExecutor(unreachable=True))
    registry = TargetRegistry({"fixture-repo": repo})
    service = ScanService(settings, registry, analyzer, InMemoryScanStore())
    response = service.run_scan(ScanRequest(target_id="fixture-repo"))
    assert response.status == "failed" and response.findings == []
    assert "executor unreachable at http://127.0.0.1:8081" in response.message
    assert "make executor" in response.message
    assert response.progress == "" and response.completed_at is not None
    # the same failure is visible on the live record the API and UI poll
    live = service.get_scan(response.scan_id)
    assert live is not None and live.status == "failed" and live.message == response.message
    service.close()


def test_service_backend_reports_candidate_progress_live(repo: Target, workspace: Path) -> None:
    """The orchestrator's per-candidate loop shows up in the scan record's progress log."""
    model = ScriptedModel(default=action("dismiss", reason="not reachable"))
    settings = _settings(workspace, planner_enabled=False)
    analyzer = _analyzer(settings, model)
    service = ScanService(
        settings, TargetRegistry({"fixture-repo": repo}), analyzer, store := InMemoryScanStore()
    )
    response = service.run_scan(ScanRequest(target_id="fixture-repo"))
    assert response.status == "done"
    messages = [e.message for e in response.events]
    assert "Checking the sandbox Executor and the model endpoint" in messages
    assert any(m.startswith("Analyzing candidate 1 of 3 - app/util.py:5") for m in messages)
    assert any(
        m.startswith("Candidate 3 of 3 dismissed:") and "not reachable" in m for m in messages
    )
    assert [s.stage for s in response.pipeline] == ["ingest", "sast", "plan", "analyze", "verify"]
    assert store.get_findings(response.scan_id) == []
    service.close()


def test_model_endpoint_failure_fails_the_scan_and_cleans_up(repo: Target, workspace: Path) -> None:
    settings = _settings(workspace)
    model = ModelClient(
        settings, transport=httpx.MockTransport(lambda r: httpx.Response(503, text="loading"))
    )
    executor = FakeExecutor()
    analyzer = ServiceAnalyzer(settings, model=model, executor=executor)
    with pytest.raises(ModelError, match="503"):
        analyzer.run("scn_fail", repo, ScanOptions())
    assert executor.events == ["create scn_fail", "destroy scn_fail"]  # jail torn down on error
    assert not (workspace / "scn_fail").exists()


def test_ingest_failure_fails_the_scan_cleanly(workspace: Path) -> None:
    model = ScriptedModel()
    analyzer = _analyzer(_settings(workspace), model)
    missing = Target(
        target_id="gone", name="gone", kind="repo", source="/no/such/dir", snapshot="n/a"
    )
    with pytest.raises(Exception, match="unsupported target source"):
        analyzer.run("scn_gone", missing, ScanOptions())
    assert model.n_calls == 0 and not (workspace / "scn_gone").exists()


def test_stages_outside_run_fail_loudly(repo: Target, workspace: Path) -> None:
    analyzer = _analyzer(_settings(workspace), ScriptedModel())
    with pytest.raises(RuntimeError, match="must run via run"):
        analyzer.sast_shortlist(repo, ScanOptions())
