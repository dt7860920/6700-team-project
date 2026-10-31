"""Agent definitions: a role prompt, the allowed tools, a step budget, a temperature.

An agent is **not** a service and holds no state. Both definitions below run on the one
pinned Qwen model through :class:`~ono.agents.model.ModelClient`; the deterministic
orchestrator (:mod:`ono.orchestrator`) decides when each runs and enforces the budgets.

* :data:`PLANNER` - one bounded call that turns a SAST candidate into a compact,
  structured investigation plan (what to read, which taint to check, how to decide).
* :data:`ANALYST` - a bounded ReAct loop over read-only sandbox tools that follows the
  plan and ends with ``confirm`` (a structured finding) or ``dismiss``.

Budgets in the constants are defaults; the orchestrator applies ``Settings`` on top via
:meth:`AgentDefinition.with_budget`.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from ono.agents.tools import READ_TOOLS, TERMINAL_TOOLS, ToolSpec

__all__ = ["ANALYST", "PLANNER", "AgentDefinition", "AgentRole"]

AgentRole = str  # "planner" | "analyst" (fixer / verifier roles arrive in 3b-2)


@dataclass(frozen=True, slots=True)
class AgentDefinition:
    """Everything that makes one role distinct on the shared model."""

    role: AgentRole
    system_prompt: str
    tools: tuple[ToolSpec, ...]
    max_steps: int
    temperature: float = 0.0

    def with_budget(
        self, *, max_steps: int | None = None, temperature: float | None = None
    ) -> AgentDefinition:
        return dataclasses.replace(
            self,
            max_steps=self.max_steps if max_steps is None else max_steps,
            temperature=self.temperature if temperature is None else temperature,
        )

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(t.name for t in self.tools)


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

_PLANNER_SYSTEM = """\
You are the PLANNER of an application-security review team. A static-analysis tool flagged
one suspicious line in a code repository. You do not have tools; another agent (the ANALYST)
will investigate with read_lines / read_file / grep / tree and must decide whether the flag
is a real, exploitable vulnerability.

Write a SHORT investigation plan. Be concrete: name files, symbols and grep patterns that
exist in the code you were shown. Respond ONLY with one JSON object, no prose, no fences:
{
  "hypothesis": "one sentence: what the vulnerability would be, if real",
  "source": "where attacker-controlled input would enter (or 'unknown')",
  "sink": "the dangerous operation at the flagged line",
  "greps": ["up to 4 regex patterns to find callers, definitions or sanitizers"],
  "reads": ["up to 4 paths (optionally path:start-end) worth reading"],
  "steps": ["up to 6 short imperative steps the analyst should follow, in order"],
  "decision_rule": "one sentence: when to confirm, when to dismiss"
}
"""

PLANNER = AgentDefinition(
    role="planner",
    system_prompt=_PLANNER_SYSTEM,
    tools=(),
    max_steps=1,
)


# ---------------------------------------------------------------------------
# Analyst
# ---------------------------------------------------------------------------

_ANALYST_SYSTEM = """\
You are the ANALYST of an application-security review team. A static-analysis tool flagged
one suspicious line; your job is to decide whether it is a GENUINE, exploitable
vulnerability by READING THE CODE, not by guessing.

You work in steps. Each step you call exactly one tool and then see its result:
  read_lines(path, start, end)   lines of a file (1-based, <= 200 per call), shown as "N | code"
  read_file(path)                a whole (short) file
  grep(pattern[, path])          regex search; returns "file:line: text" matches
  tree([path])                   list files
When you have enough evidence you END with exactly one of:
  confirm(cwe, title, severity, file, line_start, line_end, trace, confidence, description)
  dismiss(reason)

Rules:
- Follow the plan you are given, but adapt if the code says otherwise.
- Trace the data flow: where does the input come from, is it validated or escaped, does it
  reach the sink unchanged? Read the function that contains the sink and at least one caller
  or the request handler when they exist.
- Cite ONLY file:line locations you have actually read in this session; the harness
  rejects invented lines. "trace" is a list of {file, line, symbol, note} hops from the
  attacker-controlled source to the sink.
- Dismiss when the input is constant, validated, escaped, parameterized, unreachable, or
  the flag is a false positive. Do not pad: a dismissal is a good outcome.
- Never call a tool you were not given. Never run code. Never ask the user questions.
- Keep every reply short: one tool call, or one final verdict.
"""

ANALYST = AgentDefinition(
    role="analyst",
    system_prompt=_ANALYST_SYSTEM,
    tools=(*READ_TOOLS, *TERMINAL_TOOLS),
    max_steps=8,
)
