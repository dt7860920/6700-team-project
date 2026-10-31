"""The analyst agent: a bounded ReAct loop over read-only sandbox tools.

    reason -> call a tool -> see the result -> ... -> confirm(finding) | dismiss(reason)

Hard guarantees, independent of what the model does:

* at most ``definition.max_steps`` model calls per candidate (every call counts, including
  retries after a malformed reply); the last step is announced as such and may only end
  with a verdict - a non-verdict there is ``exhausted`` (no finding);
* at most :data:`MAX_CALLS_PER_TURN` tool executions per model turn, each result truncated
  to the configured character cap before it goes back to the model;
* a malformed reply, an unknown tool, bad arguments or a sandbox error are fed back as
  text and the loop continues - nothing raises except a dead model endpoint;
* the final :class:`~ono.models.Finding` is **anchored**: its file and lines, and every
  hop of its trace, must be lines the analyst read through the sandbox (the
  :class:`~ono.agents.tools.ReadLedger`); otherwise it falls back to the SAST sink.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Literal

from ono.agents.definitions import AgentDefinition
from ono.agents.model import CallBudget, ChatModel, ModelReply, ToolCall
from ono.agents.planner import InvestigationPlan
from ono.agents.protocol import ParseFailure, parse_reply, render_action_format
from ono.agents.tools import ReadLedger, ToolBox, ToolResult, openai_tool_schemas
from ono.agents.trajectory import Trajectory
from ono.models import Finding, Severity, TraceStep, finding_id_for
from ono.sast import Candidate

__all__ = ["MAX_CALLS_PER_TURN", "AnalystOutcome", "finding_from_verdict", "run_analyst"]

log = logging.getLogger(__name__)

MAX_CALLS_PER_TURN = 3
MAX_TRACE_HOPS = 12

Verdict = Literal["confirm", "dismiss", "exhausted", "timeout"]

_CWE_NUMBER = re.compile(r"(\d+)")
_SEVERITY_ALIASES: dict[str, Severity] = {
    "low": "low",
    "info": "low",
    "informational": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}


@dataclass(slots=True)
class AnalystOutcome:
    verdict: Verdict
    reason: str
    finding: Finding | None
    trajectory: Trajectory
    ledger: ReadLedger


def run_analyst(
    model: ChatModel,
    definition: AgentDefinition,
    *,
    scan_id: str,
    target_id: str,
    candidate: Candidate,
    plan: InvestigationPlan,
    window_text: str,
    toolbox: ToolBox,
    budget: CallBudget,
    deadline: float,
    trajectory: Trajectory,
) -> AnalystOutcome:
    """Run the loop for one candidate. Only model transport / budget errors propagate."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": definition.system_prompt},
        {
            "role": "user",
            "content": _task_prompt(candidate, plan, window_text, definition.max_steps),
        },
    ]
    schemas = openai_tool_schemas(definition.tools)
    allowed = set(definition.tool_names)

    def done(verdict: Verdict, reason: str, finding: Finding | None = None) -> AnalystOutcome:
        trajectory.finish(verdict)
        return AnalystOutcome(verdict, reason, finding, trajectory, toolbox.ledger)

    for step in range(1, definition.max_steps + 1):
        if time.monotonic() > deadline:
            trajectory.record("note", "candidate time budget exhausted", ok=False)
            return done("timeout", "per-candidate time budget exhausted before a verdict")
        last = step == definition.max_steps
        if last:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "This is your LAST step. You must answer now with confirm(...) or "
                        "dismiss(...) based on what you have read. If unsure, dismiss."
                    ),
                }
            )
        t0 = time.perf_counter()
        reply = model.chat(
            messages, tools=schemas, temperature=definition.temperature, budget=budget
        )
        trajectory.record(
            "model",
            _describe_reply(reply),
            duration_ms=(time.perf_counter() - t0) * 1000,
            prompt_tokens=reply.prompt_tokens,
            completion_tokens=reply.completion_tokens,
        )
        _append_assistant(messages, reply)

        parsed = parse_reply(reply)
        if isinstance(parsed, ParseFailure):
            trajectory.record("parse_error", parsed.hint, ok=False)
            _feedback(messages, reply, None, "ERROR: " + parsed.hint)
            continue

        terminal = next((c for c in parsed if c.name in ("confirm", "dismiss")), None)
        if terminal is not None:
            if terminal.name == "dismiss":
                reason = (
                    str(terminal.args.get("reason") or "").strip() or "dismissed without a reason"
                )
                trajectory.record(
                    "verdict", f"dismiss: {reason}", tool="dismiss", args=terminal.args
                )
                return done("dismiss", reason)
            finding, error = finding_from_verdict(
                terminal.args,
                scan_id=scan_id,
                target_id=target_id,
                anchor=candidate,
                ledger=toolbox.ledger,
            )
            if finding is None:
                trajectory.record(
                    "parse_error", f"confirm rejected: {error}", tool="confirm", ok=False
                )
                _feedback(messages, reply, terminal, f"ERROR: confirm rejected: {error}")
                continue
            trajectory.record(
                "verdict",
                f"confirm {finding.cwe} at {finding.location} (conf {finding.confidence:.2f})",
                tool="confirm",
                args=terminal.args,
            )
            return done("confirm", finding.description, finding)

        if last:
            return done("exhausted", "step budget exhausted without a verdict")

        for call in parsed[:MAX_CALLS_PER_TURN]:
            if call.name not in allowed:
                result = ToolResult(
                    call.name, f"ERROR: tool {call.name!r} is not available here", False
                )
            else:
                t1 = time.perf_counter()
                result = toolbox.dispatch(call)  # output already bounded by the toolbox
                log.debug(
                    "analyst tool %s took %.0f ms", call.name, (time.perf_counter() - t1) * 1000
                )
            trajectory.record("tool", result.text, tool=call.name, args=call.args, ok=result.ok)
            _feedback(messages, reply, call, result.text)
        if len(parsed) > MAX_CALLS_PER_TURN:
            _feedback(
                messages,
                reply,
                None,
                f"NOTE: only the first {MAX_CALLS_PER_TURN} tool calls of a turn are executed.",
            )

    return done("exhausted", "step budget exhausted without a verdict")  # pragma: no cover


# ---------------------------------------------------------------------------
# Prompt and message plumbing
# ---------------------------------------------------------------------------


def _task_prompt(c: Candidate, plan: InvestigationPlan, window_text: str, max_steps: int) -> str:
    return (
        "Flag from static analysis:\n"
        f"  file: {c.file}\n"
        f"  line: {c.line}\n"
        f"  suspected CWE: {c.cwe_hint or 'unknown'}\n"
        f"  rule: {c.rule}\n\n"
        f"Investigation plan ({plan.origin}):\n{plan.render()}\n\n"
        f"You have already read this window of {c.file} (each line is 'N | code'; "
        f"the flagged line is {c.line}):\n{window_text}\n\n"
        f"You have at most {max_steps} steps. {render_action_format()}"
    )


def _describe_reply(reply: ModelReply) -> str:
    if reply.tool_calls:
        calls = ", ".join(f"{c.name}({_short_args(c.args)})" for c in reply.tool_calls)
        return f"[native tool_calls] {calls}" + (f" | {reply.text}" if reply.text else "")
    return reply.text


def _short_args(args: dict[str, Any]) -> str:
    return ", ".join(f"{k}={str(v)[:40]!r}" for k, v in list(args.items())[:4])


def _append_assistant(messages: list[dict[str, Any]], reply: ModelReply) -> None:
    """Echo the assistant turn back verbatim (native tool_calls need their ids kept)."""
    if reply.protocol == "native" and reply.raw_message:
        message = {
            k: v for k, v in reply.raw_message.items() if k in ("role", "content", "tool_calls")
        }
        message["role"] = "assistant"
        if message.get("content") is None:
            message["content"] = ""
        messages.append(message)
    else:
        messages.append({"role": "assistant", "content": reply.text})


def _feedback(
    messages: list[dict[str, Any]], reply: ModelReply, call: ToolCall | None, text: str
) -> None:
    """Return a tool result (or an error) in the shape the active protocol expects."""
    if reply.protocol == "native" and call is not None and call.call_id:
        messages.append(
            {"role": "tool", "tool_call_id": call.call_id, "name": call.name, "content": text}
        )
        return
    label = f"RESULT of {call.name}" if call is not None else "HARNESS"
    messages.append({"role": "user", "content": f"{label}:\n{text}"})


# ---------------------------------------------------------------------------
# Anchoring the verdict to what was actually read
# ---------------------------------------------------------------------------


def finding_from_verdict(
    args: dict[str, Any],
    *,
    scan_id: str,
    target_id: str,
    anchor: Candidate,
    ledger: ReadLedger,
) -> tuple[Finding | None, str]:
    """``(finding, "")`` or ``(None, reason)`` when the verdict is unusable.

    File and line range are honoured only if the ledger shows the analyst read them;
    otherwise they snap to the SAST sink. Trace hops the analyst never read are dropped;
    an empty trace is replaced by the SAST sink hop so the finding is never evidence-free.
    """
    cwe_match = _CWE_NUMBER.search(str(args.get("cwe", "")))
    if cwe_match is None:
        return None, 'the "cwe" field must look like "CWE-89"'
    cwe = f"CWE-{cwe_match.group(1)}"

    file = _norm_path(str(args.get("file") or anchor.file))
    line_start = _as_int(args.get("line_start", args.get("line")), default=0)
    line_end = max(line_start, _as_int(args.get("line_end"), default=line_start))
    anchored_note = ""
    if line_start >= 1 and ledger.has_range(file, line_start, line_end):
        pass
    elif line_start >= 1 and ledger.has_line(file, line_start):
        line_end = line_start
    else:
        anchored_note = f" (model cited {file}:{line_start}, not read; anchored to the SAST sink)"
        file, line_start, line_end = anchor.file, anchor.line, anchor.line

    trace: list[TraceStep] = []
    raw_trace = args.get("trace")
    if isinstance(raw_trace, list):
        for hop in raw_trace[:MAX_TRACE_HOPS]:
            if not isinstance(hop, dict):
                continue
            hop_file = _norm_path(str(hop.get("file") or file))
            hop_line = _as_int(hop.get("line"), default=0)
            if hop_line < 1 or not ledger.has_line(hop_file, hop_line):
                log.info("analyst: dropping unread trace hop %s:%s", hop_file, hop_line)
                continue
            trace.append(
                TraceStep(
                    file=hop_file,
                    line=hop_line,
                    symbol=str(hop.get("symbol") or f"line {hop_line}")[:200],
                    note=str(hop.get("note") or "")[:300],
                )
            )
    if not trace:
        trace.append(
            TraceStep(
                file=anchor.file,
                line=anchor.line,
                symbol=anchor.excerpt.strip()[:200] or f"line {anchor.line}",
                note=f"sink flagged by SAST rule {anchor.rule}",
            )
        )

    severity = _SEVERITY_ALIASES.get(str(args.get("severity", "")).strip().lower(), "medium")
    confidence = min(1.0, max(0.0, _as_float(args.get("confidence"), default=0.5)))
    title = str(args.get("title") or f"{cwe} in {file}")[:200]
    description = (str(args.get("description") or "") + anchored_note)[:4000]
    # Rung 2 = CWE + an evidence-backed source->sink trace (distinct read lines). The patch
    # slot stays empty until the fixer (3b-2); rung 3+ needs the graded verifier.
    distinct = {(t.file, t.line) for t in trace}
    rung = 2 if len(distinct) >= 2 else 1
    return (
        Finding(
            finding_id=finding_id_for(target_id, file, line_start, cwe),
            scan_id=scan_id,
            target_id=target_id,
            title=title,
            cwe=cwe,
            severity=severity,
            file=file,
            line_range=(line_start, line_end),
            trace=trace,
            confidence=confidence,
            rung=rung,
            verified=False,  # TODO(3b-2): the graded verifier sets this
            description=description,
            patch_diff="",  # TODO(3b-2): the fixer agent fills this
        ),
        "",
    )


def _norm_path(path: str) -> str:
    path = path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def _as_int(value: object, *, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _as_float(value: object, *, default: float) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default
