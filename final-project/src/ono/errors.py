"""Errors that cross module boundaries (kept here so nothing imports the analyzer for them)."""

from __future__ import annotations

__all__ = ["PipelineError"]


class PipelineError(RuntimeError):
    """A scan cannot continue and the message is safe to show to the analyst.

    :class:`~ono.service.ScanService` copies ``str(exc)`` into the failed scan's ``message``
    (anything else is reported generically), so raise this only with operator-oriented,
    secret-free text: "executor unreachable at ...", "clone failed ...".
    """
