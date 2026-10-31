"""The planner agent: one bounded model call -> a compact :class:`InvestigationPlan`.

The planner sees the SAST candidate and the numbered code window around the sink (read
through the sandbox by the orchestrator - the planner itself has no tools) and answers
with a small JSON plan. Parsing is tolerant; anything unusable degrades to
:func:`default_plan` so the analyst always has something to follow and the scan never
fails on a planner hiccup. Transport errors still propagate (a dead model endpoint must
fail the scan, not silently plan nothing).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from ono.agents.definitions import AgentDefinition
from ono.agents.model import CallBudget, ChatModel
from ono.agents.protocol import extract_json_object
from ono.agents.trajectory import Trajectory
from ono.sast import Candidate

__all__ = ["InvestigationPlan", "default_plan", "run_planner"]

log = logging.getLogger(__name__)

_MAX_LIST = {"greps": 4, "reads": 4, "steps": 6}
_MAX_STR = 300

PlanOrigin = Literal["planner", "default"]


@dataclass(slots=True)
class InvestigationPlan:
    """What the analyst is told to do. Small on purpose: it goes into every analyst prompt."""

    hypothesis: str
    source: str
    sink: str
    greps: list[str] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    decision_rule: str = ""
    origin: PlanOrigin = "default"

    def render(self) -> str:
        lines = [
            f"Hypothesis: {self.hypothesis}",
            f"Suspected source: {self.source}",
            f"Sink: {self.sink}",
        ]
        if self.greps:
            lines.append("Useful greps: " + "; ".join(repr(g) for g in self.greps))
        if self.reads:
            lines.append("Worth reading: " + ", ".join(self.reads))
        if self.steps:
            lines.append("Steps:")
            lines.extend(f"  {i}. {s}" for i, s in enumerate(self.steps, start=1))
        if self.decision_rule:
            lines.append(f"Decide: {self.decision_rule}")
        return "\n".join(lines)


def default_plan(c: Candidate) -> InvestigationPlan:
    """The deterministic plan used when the planner is disabled or its reply is unusable."""
    symbol = c.excerpt.strip()[:80] or f"line {c.line}"
    return InvestigationPlan(
        hypothesis=f"{c.cwe_hint or 'the flagged operation'} at {c.file}:{c.line} is reachable "
        "with attacker-controlled input",
        source="unknown - find the request handler / entry point that feeds this code",
        sink=symbol,
        greps=[],
        reads=[f"{c.file}:{max(1, c.line - 40)}-{c.line + 20}"],
        steps=[
            "Read the function containing the flagged line and identify the input variables.",
            "grep for the function's name to find its callers / the request handler.",
            "Check whether the input is validated, escaped, parameterized or constant on the way.",
            "Confirm with a source->sink trace of lines you read, or dismiss with the reason.",
        ],
        decision_rule=(
            "confirm only if untrusted input reaches the sink without effective sanitization; "
            "otherwise dismiss"
        ),
        origin="default",
    )


def run_planner(
    model: ChatModel,
    definition: AgentDefinition,
    *,
    candidate: Candidate,
    window_text: str,
    budget: CallBudget,
    trajectory: Trajectory,
) -> InvestigationPlan:
    """One model call; returns the parsed plan or :func:`default_plan` on unusable output."""
    user = (
        "Flag:\n"
        f"  file: {candidate.file}\n"
        f"  line: {candidate.line}\n"
        f"  suspected CWE: {candidate.cwe_hint or 'unknown'}\n"
        f"  rule: {candidate.rule}\n"
        f"  flagged code: {candidate.excerpt.strip()[:200] or '(see below)'}\n\n"
        "Code around the flag (each line is 'N | code'):\n"
        f"{window_text}\n\n"
        "Write the investigation plan as the JSON object described."
    )
    messages = [
        {"role": "system", "content": definition.system_prompt},
        {"role": "user", "content": user},
    ]
    t0 = time.perf_counter()
    reply = model.chat(messages, temperature=definition.temperature, budget=budget)
    trajectory.record(
        "model",
        reply.text,
        duration_ms=(time.perf_counter() - t0) * 1000,
        prompt_tokens=reply.prompt_tokens,
        completion_tokens=reply.completion_tokens,
    )
    data = extract_json_object(reply.text)
    if data is None:
        trajectory.record(
            "parse_error", "planner reply had no JSON object; using default plan", ok=False
        )
        trajectory.finish("default-plan")
        return default_plan(candidate)
    plan = plan_from_dict(data, candidate)
    trajectory.record("note", plan.render())
    trajectory.finish("plan")
    return plan


def plan_from_dict(data: dict[str, Any], c: Candidate) -> InvestigationPlan:
    fallback = default_plan(c)
    return InvestigationPlan(
        hypothesis=_text(data.get("hypothesis")) or fallback.hypothesis,
        source=_text(data.get("source")) or fallback.source,
        sink=_text(data.get("sink")) or fallback.sink,
        greps=_strings(data.get("greps"), _MAX_LIST["greps"]),
        reads=_strings(data.get("reads"), _MAX_LIST["reads"]) or fallback.reads,
        steps=_strings(data.get("steps"), _MAX_LIST["steps"]) or fallback.steps,
        decision_rule=_text(data.get("decision_rule")) or fallback.decision_rule,
        origin="planner",
    )


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()[:_MAX_STR]


def _strings(value: object, limit: int) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        text = _text(
            item
            if isinstance(item, str)
            else (item.get("path") or item.get("step") if isinstance(item, dict) else item)
        )
        if text:
            out.append(text)
        if len(out) >= limit:
            break
    return out
