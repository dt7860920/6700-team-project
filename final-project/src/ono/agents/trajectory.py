"""Trajectories: every model call, tool call and result of one agent run, in order.

This is the observability record of step 3b-1 and the raw material for the later
learning loop (verifier-passed trajectories). Each :class:`Trajectory` is logged line by
line as it happens and, when ``Settings.agent_trajectory_dir`` is set, appended as one JSON
line per agent run to ``<dir>/<scan_id>.jsonl`` by :class:`TrajectoryWriter`.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

__all__ = ["Trajectory", "TrajectoryStep", "TrajectoryWriter"]

log = logging.getLogger(__name__)

StepKind = Literal["model", "tool", "parse_error", "verdict", "note"]
_LOG_PREVIEW = 160
_STORE_PREVIEW = 4000  # per-step content kept in the JSONL record


@dataclass(slots=True)
class TrajectoryStep:
    index: int
    kind: StepKind
    content: str
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    ok: bool = True
    duration_ms: float = 0.0
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass(slots=True)
class Trajectory:
    """One agent run (planner or analyst) on one candidate."""

    scan_id: str
    role: str
    candidate: str  # "file:line (rule)"
    steps: list[TrajectoryStep] = field(default_factory=list)
    outcome: str = ""  # confirm | dismiss | exhausted | timeout | skipped | plan | default-plan
    model_calls: int = 0
    tool_calls: int = 0
    started: float = field(default_factory=time.monotonic)
    duration_ms: float = 0.0

    def record(
        self,
        kind: StepKind,
        content: str,
        *,
        tool: str = "",
        args: dict[str, Any] | None = None,
        ok: bool = True,
        duration_ms: float = 0.0,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
    ) -> TrajectoryStep:
        step = TrajectoryStep(
            index=len(self.steps) + 1,
            kind=kind,
            content=content[:_STORE_PREVIEW],
            tool=tool,
            args=_safe_args(args or {}),
            ok=ok,
            duration_ms=duration_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
        self.steps.append(step)
        if kind == "model":
            self.model_calls += 1
        elif kind == "tool":
            self.tool_calls += 1
        preview = content.replace("\n", " ")[:_LOG_PREVIEW]
        log.info(
            "trajectory[%s/%s/%s] #%d %s%s%s: %s",
            self.scan_id,
            self.role,
            self.candidate,
            step.index,
            kind,
            f" {tool}" if tool else "",
            "" if ok else " (error)",
            preview,
        )
        return step

    def finish(self, outcome: str) -> None:
        self.outcome = outcome
        self.duration_ms = (time.monotonic() - self.started) * 1000
        log.info(
            "trajectory[%s/%s/%s] done: %s after %d model call(s), %d tool call(s), %.0f ms",
            self.scan_id,
            self.role,
            self.candidate,
            outcome,
            self.model_calls,
            self.tool_calls,
            self.duration_ms,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("started", None)
        return data


class TrajectoryWriter:
    """Appends trajectories as JSON lines; a ``None`` directory disables persistence."""

    def __init__(self, directory: Path | None) -> None:
        self.directory = directory

    def write(self, trajectory: Trajectory) -> None:
        if self.directory is None:
            return
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self.directory / f"{trajectory.scan_id}.jsonl"
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(trajectory.to_dict(), ensure_ascii=False) + "\n")
        except OSError as exc:  # persistence must never fail a scan
            log.warning("trajectory: could not write %s: %s", self.directory, exc)


def _safe_args(args: dict[str, Any]) -> dict[str, Any]:
    """Args as stored: JSON-serialisable, each string value bounded."""
    out: dict[str, Any] = {}
    for key, value in list(args.items())[:20]:
        if isinstance(value, str):
            out[str(key)] = value[:500]
        elif isinstance(value, int | float | bool) or value is None:
            out[str(key)] = value
        else:
            out[str(key)] = json.dumps(value, default=str)[:500]
    return out
