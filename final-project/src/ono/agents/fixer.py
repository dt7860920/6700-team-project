"""The fixer agent: a bounded loop that ends with a unified diff.

Like the prover it never touches the workspace itself: the deterministic verifier applies
the diff in the jail (all-or-nothing), re-runs the proof-of-concept and the test suite,
and feeds the exact failure ("hunk #1 of app/db.py does not apply", "PoC still reaches the
sink", "2 tests failed: ...") into the next attempt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ono.agents.definitions import AgentDefinition
from ono.agents.model import CallBudget, ChatModel, ToolCall
from ono.agents.protocol import render_action_format
from ono.agents.react import ReactOutcome, run_react
from ono.agents.tools import ToolBox
from ono.agents.trajectory import Trajectory
from ono.models import Finding

__all__ = ["MAX_PATCH_CHARS", "Patch", "run_fixer"]

MAX_PATCH_CHARS = 60_000
_DIFF_FENCE = re.compile(r"```(?:diff|patch)?\s*\n(.*?)```", re.DOTALL)
_HEADER = re.compile(r"^--- (?:a/)?\S", re.MULTILINE)


@dataclass(slots=True)
class Patch:
    diff: str
    summary: str = ""


def run_fixer(
    model: ChatModel,
    definition: AgentDefinition,
    *,
    finding: Finding,
    window_text: str,
    poc: str,
    toolbox: ToolBox,
    budget: CallBudget,
    deadline: float,
    trajectory: Trajectory,
    previous: Patch | None = None,
    failure: str = "",
) -> ReactOutcome[Patch]:
    """One bounded attempt. ``previous`` / ``failure`` carry the verifier's feedback."""
    return run_react(
        model,
        definition,
        task=_task_prompt(finding, window_text, poc, definition.max_steps, previous, failure),
        toolbox=toolbox,
        budget=budget,
        deadline=deadline,
        trajectory=trajectory,
        accept=_accept,
        text_fallback=_bare_diff,
        last_step_hint=(
            "This is your LAST step. Answer now with submit_patch(diff, summary) using what "
            "you have read."
        ),
    )


def _task_prompt(
    f: Finding, window_text: str, poc: str, max_steps: int, previous: Patch | None, failure: str
) -> str:
    text = (
        "Confirmed finding:\n"
        f"  title: {f.title}\n"
        f"  CWE: {f.cwe}\n"
        f"  sink: {f.location}\n"
        f"  why: {f.description[:800]}\n\n"
        f"The sink and its surroundings (each line is 'N | code'; the flagged line is "
        f"{f.line_range[0]}):\n{window_text}\n\n"
    )
    if poc:
        text += (
            "The proof-of-concept that currently reaches the sink (it must stop working, "
            f"while legitimate input keeps working):\n```python\n{poc[:3000]}\n```\n\n"
        )
    if previous is not None:
        text += (
            "Your previous patch was REJECTED. The harness reported:\n"
            f"{failure}\n\nPrevious diff:\n```diff\n{previous.diff[:4000]}\n```\n"
            "Fix the cause named above and submit a corrected diff.\n\n"
        )
    text += f"You have at most {max_steps} steps. " + render_action_format(
        "submit_patch(diff, summary)"
    )
    return text


def _accept(call: ToolCall) -> tuple[Patch | None, str]:
    diff = str(call.args.get("diff") or call.args.get("patch") or "")
    diff = _unfence(diff).strip("\n")
    if not diff.strip():
        return None, 'the "diff" field must contain the complete unified diff'
    if len(diff) > MAX_PATCH_CHARS:
        return None, f"the diff is longer than {MAX_PATCH_CHARS} characters"
    if _HEADER.search(diff) is None or "+++ " not in diff or "@@ " not in diff:
        return None, (
            'not a unified diff: it needs "--- a/<path>", "+++ b/<path>" and "@@ -s,n +s,m @@" '
            "hunk headers"
        )
    return Patch(diff=diff + "\n", summary=str(call.args.get("summary") or "")[:300]), ""


def _unfence(text: str) -> str:
    match = _DIFF_FENCE.search(text)
    return match.group(1) if match is not None else text


def _bare_diff(text: str) -> ToolCall | None:
    """A reply that is just a diff (fenced or not) is taken as the submission."""
    match = _DIFF_FENCE.search(text)
    body = match.group(1) if match is not None else text
    if _HEADER.search(body) is None or "+++ " not in body:
        return None
    start = _HEADER.search(body)
    assert start is not None
    return ToolCall(name="submit_patch", args={"diff": body[start.start() :]})
