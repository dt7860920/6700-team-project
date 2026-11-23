"""The prover agent: a bounded loop that ends with a read-only PoC script.

The prover never runs anything. It reads the code (same read-only toolbox as the analyst)
and submits a script; the deterministic verifier (:mod:`ono.verifier`) runs it in the jail
under the sink oracle and comes back with a precise reason when it did not prove the
finding, which is fed into the next attempt (the verifier-in-the-loop self-correction cycle
of plan section 3).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ono.agents.definitions import AgentDefinition
from ono.agents.model import CallBudget, ChatModel, ToolCall
from ono.agents.protocol import render_action_format
from ono.agents.react import ReactOutcome, run_react
from ono.agents.scaffolds import scaffold_for
from ono.agents.tools import ToolBox
from ono.agents.trajectory import Trajectory
from ono.models import Finding

__all__ = ["MAX_POC_CHARS", "Poc", "run_prover"]

MAX_POC_CHARS = 12_000
_PYTHON_FENCE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.DOTALL)
_PAYLOAD_REF = re.compile(r"ONO_PAYLOAD")


@dataclass(slots=True)
class Poc:
    code: str
    how: str = ""


def run_prover(
    model: ChatModel,
    definition: AgentDefinition,
    *,
    finding: Finding,
    window_text: str,
    toolbox: ToolBox,
    budget: CallBudget,
    deadline: float,
    trajectory: Trajectory,
    previous: Poc | None = None,
    failure: str = "",
    memory_hint: str = "",
    environment_note: str = "",
) -> ReactOutcome[Poc]:
    """One bounded attempt. ``previous`` / ``failure`` carry the verifier's feedback;
    ``memory_hint`` is a prior verified PoC for this sink class (the learning loop);
    ``environment_note`` says which third-party packages the jail has (or has not)."""
    return run_react(
        model,
        definition,
        task=_task_prompt(
            finding,
            window_text,
            definition.max_steps,
            previous,
            failure,
            memory_hint,
            environment_note,
        ),
        toolbox=toolbox,
        budget=budget,
        deadline=deadline,
        trajectory=trajectory,
        accept=_accept,
        text_fallback=_bare_script,
        last_step_hint=(
            "This is your LAST step. Answer now with submit_poc(code, how) using what you "
            "have read."
        ),
    )


def _task_prompt(
    f: Finding,
    window_text: str,
    max_steps: int,
    previous: Poc | None,
    failure: str,
    memory_hint: str = "",
    environment_note: str = "",
) -> str:
    trace = "\n".join(f"  {t.file}:{t.line}  {t.symbol}  ({t.note})" for t in f.trace) or "  -"
    text = (
        "Confirmed finding:\n"
        f"  title: {f.title}\n"
        f"  CWE: {f.cwe}\n"
        f"  sink: {f.location}\n"
        f"  why: {f.description[:800]}\n"
        f"Source -> sink trace (lines the analyst read):\n{trace}\n\n"
        f"The sink and its surroundings (each line is 'N | code'; the flagged line is "
        f"{f.line_range[0]}):\n{window_text}\n\n"
        f"{scaffold_for(f, window_text)}\n\n"
    )
    if environment_note:
        text += environment_note + "\n\n"
    if memory_hint and previous is None:
        text += memory_hint + "\n\n"
    if previous is not None:
        text += (
            "Your previous script did NOT prove the finding. The harness reported:\n"
            f"{failure}\n\nPrevious script:\n```python\n{previous.code[:4000]}\n```\n"
            "Fix the cause named above and submit a corrected script.\n\n"
        )
    text += f"You have at most {max_steps} steps. " + render_action_format("submit_poc(code, how)")
    return text


def _accept(call: ToolCall) -> tuple[Poc | None, str]:
    code = str(call.args.get("code") or call.args.get("script") or "").strip("\n")
    if not code.strip():
        return None, 'the "code" field must contain the complete script'
    if len(code) > MAX_POC_CHARS:
        return None, f"the script is longer than {MAX_POC_CHARS} characters; keep it short"
    if _PAYLOAD_REF.search(code) is None:
        return None, (
            'the script must read the payload with os.environ["ONO_PAYLOAD"] and pass it '
            "into the application; a hard-coded payload cannot be verified"
        )
    return Poc(code=code + "\n", how=str(call.args.get("how") or "")[:300]), ""


def _bare_script(text: str) -> ToolCall | None:
    """A reply that is just a fenced Python block is taken as the submission."""
    match = _PYTHON_FENCE.search(text)
    if match is None:
        return None
    return ToolCall(name="submit_poc", args={"code": match.group(1)})
