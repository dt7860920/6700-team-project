"""Scan / finding persistence.

The prototype keeps state **in memory** (the compose stack deliberately has no
database yet). The :class:`ScanStore` interface is the seam where the internal
findings DB from the technical architecture will slot in; nothing outside this
module should care which implementation is behind it.

Scans are *live* records: the background worker updates them (status, progress,
stage results) while the API and UI read them, so every mutation goes through
:meth:`ScanStore.update_scan`, which applies the change atomically.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Protocol

from ono.models import Finding, Scan


class ScanStore(Protocol):
    """Minimal persistence contract used by the service and API layers."""

    def put_scan(self, scan: Scan, findings: list[Finding]) -> None: ...
    def update_scan(self, scan_id: str, change: Callable[[Scan], Scan]) -> Scan | None: ...
    def get_scan(self, scan_id: str) -> Scan | None: ...
    def get_findings(self, scan_id: str) -> list[Finding] | None: ...
    def get_finding(self, finding_id: str) -> Finding | None: ...


class InMemoryScanStore:
    """Thread-safe dict-backed store. Lost on restart - fine for the skeleton."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scans: dict[str, Scan] = {}
        self._findings_by_scan: dict[str, list[Finding]] = {}
        self._findings: dict[str, Finding] = {}

    def put_scan(self, scan: Scan, findings: list[Finding]) -> None:
        with self._lock:
            self._scans[scan.scan_id] = scan
            self._findings_by_scan[scan.scan_id] = list(findings)
            for finding in findings:
                self._findings[finding.finding_id] = finding

    def update_scan(self, scan_id: str, change: Callable[[Scan], Scan]) -> Scan | None:
        """Replace the record with ``change(current)`` under the lock; None if unknown."""
        with self._lock:
            current = self._scans.get(scan_id)
            if current is None:
                return None
            updated = change(current)
            self._scans[scan_id] = updated
            return updated

    def get_scan(self, scan_id: str) -> Scan | None:
        with self._lock:
            return self._scans.get(scan_id)

    def get_findings(self, scan_id: str) -> list[Finding] | None:
        with self._lock:
            found = self._findings_by_scan.get(scan_id)
            return list(found) if found is not None else None

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._lock:
            return self._findings.get(finding_id)
