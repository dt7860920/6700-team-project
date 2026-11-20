"""The generic bounded ReAct loop shared by the prover and the fixer.

    reason -> call a read tool -> see the result -> ... -> <terminal tool>(answer)

It is the analyst loop (:mod:`ono.agents.analyst`) with the verdict handling factored
out: the caller supplies an ``accept`` callback that turns the terminal tool call into a
typed answer (or a rejection message the model is told about) and, optionally, a
``text_fallback`` that rescues a reply with no JSON action in it - a 7B model asked for a
script or a diff often answers with a fenced code block and nothing else, and that is a
perfectly good final answer.

Hard guarantees, identical to the analyst's: at most ``definition.max_steps`` model calls;
at most :data:`MAX_CALLS_PER_TURN` tool executions per turn, each result truncated by the
toolbox; a malformed reply, an unknown tool or a sandbox error is fed back as text and the
loop continues; only a dead model endpoint or an exhausted scan budget raises.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from ono.agents.analyst import MAX_CALLS_PER_TURN, _append_assistant, _describe_reply, _feedback
from ono.agents.definitions import AgentDefinition
from ono.agents.model import CallBudget, ChatModel, ToolCall
from ono.agents.protocol import ParseFailure, parse_reply
from ono.agents.tools import ToolBox, ToolResult, openai_tool_schemas
from ono.agents.trajectory import Trajectory

__all__ = ["ReactOutcome", "run_react"]

log = logging.getLogger(__name__)

ReactStatus = Literal["done", "exhausted", "timeout"]


@dataclass(slots=True)
class ReactOutcome[T]:
    status: ReactStatus
    answer: T | None
    reason: str
    trajectory: Trajectory


def run_react[T](
    model: ChatModel,
    definition: AgentDefinition,
    *,
    task: str,
    toolbox: ToolBox,
    budget: CallBudget,
    deadline: float,
    trajectory: Trajectory,
    accept: Callable[[ToolCall], tuple[T | None, str]],
    text_fallback: Callable[[str], ToolCall | None] | None = None,
    last_step_hint: str,
) -> ReactOutcome[T]:
    """Run the loop. ``accept(call) -> (answer, "")`` or ``(None, why it was rejected)``."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": definition.system_prompt},
        {"role": "user", "content": task},
    ]
    schemas = openai_tool_schemas(definition.tools)
    allowed = set(definition.tool_names)
    terminal = {t.name for t in definition.tools if t.terminal}

    def done(status: ReactStatus, reason: str, answer: T | None = None) -> ReactOutcome[T]:
        trajectory.finish(status if answer is None else "submitted")
        return ReactOutcome(status, answer, reason, trajectory)

    for step in range(1, definition.max_steps + 1):
        if time.monotonic() > deadline:
            trajectory.record("note", "time budget exhausted", ok=False)
            return done("timeout", "time budget exhausted before an answer")
        last = step == definition.max_steps
        if last:
            messages.append({"role": "user", "content": last_step_hint})
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
            rescued = text_fallback(reply.text) if text_fallback is not None else None
            if rescued is None:
                trajectory.record("parse_error", parsed.hint, ok=False)
                _feedback(messages, reply, None, "ERROR: " + parsed.hint)
                continue
            trajectory.record("note", f"accepted a bare {rescued.name} from the reply text")
            parsed = [rescued]

        final = next((c for c in parsed if c.name in terminal), None)
        if final is not None:
            answer, error = accept(final)
            if answer is None:
                trajectory.record(
                    "parse_error", f"{final.name} rejected: {error}", tool=final.name, ok=False
                )
                _feedback(messages, reply, final, f"ERROR: {final.name} rejected: {error}")
                continue
            trajectory.record("verdict", f"{final.name} accepted", tool=final.name)
            return done("done", "", answer)

        if last:
            return done("exhausted", "step budget exhausted without an answer")

        for call in parsed[:MAX_CALLS_PER_TURN]:
            if call.name not in allowed:
                result = ToolResult(
                    call.name, f"ERROR: tool {call.name!r} is not available here", False
                )
            else:
                result = toolbox.dispatch(call)
            trajectory.record("tool", result.text, tool=call.name, args=call.args, ok=result.ok)
            _feedback(messages, reply, call, result.text)
        if len(parsed) > MAX_CALLS_PER_TURN:
            _feedback(
                messages,
                reply,
                None,
                f"NOTE: only the first {MAX_CALLS_PER_TURN} tool calls of a turn are executed.",
            )

    return done("exhausted", "step budget exhausted without an answer")  # pragma: no cover
