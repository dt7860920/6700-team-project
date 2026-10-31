"""Errors that cross module boundaries (kept here so nothing imports the analyzer for them)."""

from __future__ import annotations

__all__ = ["PipelineError", "ScanBusyError"]


class PipelineError(RuntimeError):
    """A scan cannot continue and the message is safe to show to the analyst.

    :class:`~ono.service.ScanService` copies ``str(exc)`` into the failed scan's ``message``
    (anything else is reported generically), so raise this only with operator-oriented,
    secret-free text: "executor unreachable at ...", "clone failed ...".
    """


class ScanBusyError(RuntimeError):
    """The scan worker pool and its queue are full; the request was not accepted.

    The API maps this to ``429 Too Many Requests``; the UI shows it as "busy, retry".
    """

    def __init__(self, active: int, queued: int, max_active: int, max_queued: int) -> None:
        super().__init__(
            f"ONO is busy: {active} scan(s) running and {queued} queued "
            f"(limits: MAX_ACTIVE_SCANS={max_active}, MAX_QUEUED_SCANS={max_queued}). "
            "Retry in a moment."
        )
        self.active = active
        self.queued = queued
