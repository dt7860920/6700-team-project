"""Progress reporting for long-running scans.

A real scan (clone + Semgrep + the planner/analyst loop through a sandbox) takes
anywhere from 30 seconds to several minutes, so the pipeline reports *where it is*
while it runs. The contract is deliberately tiny:

* :class:`ProgressSink` - what the pipeline talks to. ``step(message)`` is "this is what
  I am doing now" (one short, human-readable line); ``stage(result)`` is "this pipeline
  stage just finished" with its :class:`~ono.models.StageResult`.
* :data:`ProgressCallback` - just the ``step`` half, for code that only has a message
  to report (the orchestrator's per-candidate loop).

The pipeline never depends on *who* listens: :class:`~ono.service.ScanService` plugs in
a sink that writes to the scan record, tests plug in a list. Reporting is best-effort
and must never change the analysis itself.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from ono.models import StageResult

__all__ = ["NullProgress", "ProgressCallback", "ProgressSink", "RecordingProgress"]

ProgressCallback = Callable[[str], None]
"""``callback("Analyzing candidate 2 of 3 - app/views.py:16")``."""


class ProgressSink(Protocol):
    """Receiver of pipeline progress. Implementations must be cheap and must not raise."""

    def step(self, message: str) -> None:
        """The pipeline moved on to ``message`` (what it is doing *now*)."""

    def stage(self, result: StageResult) -> None:
        """A pipeline stage finished (ok or failed) with ``result``."""


class NullProgress:
    """The default sink: discards everything."""

    def step(self, message: str) -> None:
        return None

    def stage(self, result: StageResult) -> None:
        return None


class RecordingProgress:
    """A sink that keeps every event - for tests and for ad-hoc scripts."""

    def __init__(self) -> None:
        self.steps: list[str] = []
        self.stages: list[StageResult] = []

    def step(self, message: str) -> None:
        self.steps.append(message)

    def stage(self, result: StageResult) -> None:
        self.stages.append(result)
