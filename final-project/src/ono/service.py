"""Scan service - the one place that enforces the allowlist and runs the pipeline.

Both the HTTP API and the Gradio UI call :class:`ScanService`, so the
authorization check cannot be bypassed by going through a different front door.

Scans are **asynchronous**: :meth:`ScanService.submit_scan` authorizes the target,
creates a ``queued`` scan record and hands the work to a small thread pool
(``settings.max_active_scans`` workers; a scan does blocking work - subprocess,
Docker, httpx - so it must never run on the event loop). Callers poll the record,
which the worker keeps up to date through a :class:`~ono.progress.ProgressSink`:

    queued -> running (progress: "Cloning ...", "Analyzing candidate 2 of 3 ...")
           -> done (findings persisted) | failed (message)

Beyond ``max_active_scans + max_queued_scans`` in-flight scans, ``submit_scan`` raises
:class:`~ono.errors.ScanBusyError` (HTTP 429) instead of growing the queue without bound.

:meth:`ScanService.run_scan` is the synchronous variant (create -> execute -> persist on
the calling thread) that the worker, tests and scripts use.
"""

from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime

from ono.analyzer import BaseAnalyzer
from ono.config import Settings
from ono.errors import PipelineError, ScanBusyError
from ono.models import (
    Finding,
    ProgressEvent,
    Scan,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    StageResult,
    utcnow,
)
from ono.store import ScanStore
from ono.targets import Target, TargetRegistry

log = logging.getLogger(__name__)

MAX_EVENTS = 200
"""Cap on the per-scan activity log kept in the record (oldest entries are dropped)."""


class _StoreProgress:
    """A :class:`~ono.progress.ProgressSink` that writes into the live scan record."""

    def __init__(self, store: ScanStore, scan_id: str) -> None:
        self._store = store
        self._scan_id = scan_id

    def step(self, message: str) -> None:
        event = ProgressEvent(at=utcnow(), message=message)

        def change(scan: Scan) -> Scan:
            events = [*scan.events, event][-MAX_EVENTS:]
            return scan.model_copy(update={"progress": message, "events": events})

        self._store.update_scan(self._scan_id, change)

    def stage(self, result: StageResult) -> None:
        def change(scan: Scan) -> Scan:
            return scan.model_copy(update={"pipeline": [*scan.pipeline, result]})

        self._store.update_scan(self._scan_id, change)


class ScanService:
    def __init__(
        self,
        settings: Settings,
        registry: TargetRegistry,
        analyzer: BaseAnalyzer,
        store: ScanStore,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.analyzer = analyzer
        self.store = store
        self.max_active_scans = settings.max_active_scans
        self.max_queued_scans = settings.max_queued_scans
        self._pool = ThreadPoolExecutor(
            max_workers=self.max_active_scans, thread_name_prefix="ono-scan"
        )
        self._lock = threading.Lock()
        self._running: set[str] = set()
        self._queued: set[str] = set()
        self._futures: dict[str, Future[None]] = {}
        self._closed = False

    # -- Public API ---------------------------------------------------------------
    @property
    def active_scans(self) -> int:
        with self._lock:
            return len(self._running)

    @property
    def queued_scans(self) -> int:
        with self._lock:
            return len(self._queued)

    def submit_scan(self, request: ScanRequest) -> Scan:
        """Authorize, create a ``queued`` record, start the scan in the background.

        Returns immediately with the record (poll :meth:`get_scan`).

        Raises:
            UnauthorizedTargetError: if ``request.target_id`` is not in the allowlist.
            ScanBusyError: if the worker pool and its queue are both full.
        """
        # 1. Allowlist gate - exact match, before anything else happens.
        target = self.registry.require(request.target_id)

        # 2. Admission: a bounded queue, never an unbounded backlog of model sessions.
        with self._lock:
            running, queued = len(self._running), len(self._queued)
            if self._closed or running + queued >= self.max_active_scans + self.max_queued_scans:
                raise ScanBusyError(running, queued, self.max_active_scans, self.max_queued_scans)
            scan = self._create_record(target, status="queued")
            self._queued.add(scan.scan_id)
            self._futures[scan.scan_id] = self._pool.submit(
                self._worker, scan.scan_id, target, request
            )
        log.info(
            "scan %s queued for target %s (backend=%s; %d running, %d queued)",
            scan.scan_id,
            target.target_id,
            self.analyzer.backend,
            running,
            queued + 1,
        )
        return scan

    def run_scan(self, request: ScanRequest) -> ScanResponse:
        """Synchronous variant: authorize, run the pipeline here, persist, return findings.

        Raises:
            UnauthorizedTargetError: if ``request.target_id`` is not in the allowlist.
        """
        target = self.registry.require(request.target_id)
        scan = self._create_record(target, status="running")
        scan, findings = self._execute(scan.scan_id, target, request)
        return ScanResponse(**scan.model_dump(), findings=findings)

    def wait(self, scan_id: str, timeout: float | None = None) -> Scan | None:
        """Block until the background scan ``scan_id`` has ended (tests / scripts)."""
        with self._lock:
            future = self._futures.get(scan_id)
        if future is not None:
            future.result(timeout=timeout)
        return self.store.get_scan(scan_id)

    def get_scan(self, scan_id: str) -> Scan | None:
        return self.store.get_scan(scan_id)

    def get_findings(self, scan_id: str) -> list[Finding] | None:
        return self.store.get_findings(scan_id)

    def get_finding(self, finding_id: str) -> Finding | None:
        return self.store.get_finding(finding_id)

    def close(self) -> None:
        """Stop accepting scans; queued ones are marked failed, running ones finish."""
        with self._lock:
            self._closed = True
            pending = list(self._queued)
        self._pool.shutdown(wait=False, cancel_futures=True)
        for scan_id in pending:
            self._finish(
                scan_id, status="failed", message="server shut down before the scan started"
            )

    # -- Internals ----------------------------------------------------------------
    def _create_record(self, target: Target, *, status: ScanStatus) -> Scan:
        queued = status == "queued"
        scan = Scan(
            scan_id=f"scn_{uuid.uuid4().hex[:12]}",
            target_id=target.target_id,
            status=status,
            model_backend=self.analyzer.backend,
            created_at=utcnow(),
            started_at=None if queued else utcnow(),
            progress="Waiting for a free scan worker" if queued else "Starting",
        )
        self.store.put_scan(scan, [])
        return scan

    def _worker(self, scan_id: str, target: Target, request: ScanRequest) -> None:
        with self._lock:
            self._queued.discard(scan_id)
            self._running.add(scan_id)
        try:
            self._execute(scan_id, target, request)
        except Exception:  # _execute reports every failure into the record; belt and braces
            log.exception("scan %s worker crashed", scan_id)
        finally:
            with self._lock:
                self._running.discard(scan_id)
                self._futures.pop(scan_id, None)

    def _execute(
        self, scan_id: str, target: Target, request: ScanRequest
    ) -> tuple[Scan, list[Finding]]:
        """Run the pipeline for an existing record, updating it live; never raises."""
        started_at = utcnow()
        self.store.update_scan(
            scan_id,
            lambda s: s.model_copy(
                update={"status": "running", "started_at": started_at, "progress": "Starting"}
            ),
        )
        log.info(
            "scan %s started for target %s (backend=%s)",
            scan_id,
            target.target_id,
            self.analyzer.backend,
        )
        progress = _StoreProgress(self.store, scan_id)
        try:
            result = self.analyzer.run(scan_id, target, request.options, progress=progress)
        except Exception as exc:
            log.exception("scan %s failed", scan_id)
            # PipelineError carries an operator-safe reason (e.g. "executor unreachable at
            # ..."); anything else stays generic so internals never leak into the response.
            message = (
                f"analysis pipeline failed: {exc}"[:500]
                if isinstance(exc, PipelineError)
                else "analysis pipeline raised; see server logs"
            )
            scan = self._finish(scan_id, status="failed", message=message)
            return scan, []

        findings = result.findings
        scan = self._finish(
            scan_id,
            status="done",
            message=result.summary,
            findings=findings,
            pipeline=result.stages,
        )
        log.info("scan %s done: %s", scan_id, result.summary)
        return scan, findings

    def _finish(
        self,
        scan_id: str,
        *,
        status: ScanStatus,
        message: str,
        findings: list[Finding] | None = None,
        pipeline: list[StageResult] | None = None,
    ) -> Scan:
        findings = findings or []
        completed_at: datetime = utcnow()

        def change(scan: Scan) -> Scan:
            update: dict[str, object] = {
                "status": status,
                "completed_at": completed_at,
                "message": message,
                "progress": "",
                "findings_count": len(findings),
                "events": [
                    *scan.events,
                    ProgressEvent(at=completed_at, message=f"Scan {status}: {message}"),
                ][-MAX_EVENTS:],
            }
            if pipeline is not None:
                update["pipeline"] = pipeline
            return scan.model_copy(update=update)

        updated = self.store.update_scan(scan_id, change)
        if updated is None:  # the record vanished (not possible with the in-memory store)
            msg = f"scan {scan_id!r} disappeared from the store"
            raise RuntimeError(msg)
        self.store.put_scan(updated, findings)
        return updated
