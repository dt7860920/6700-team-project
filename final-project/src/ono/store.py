"""Scan / finding persistence.

The prototype keeps state **in memory** (the compose stack deliberately has no
database yet). The :class:`ScanStore` interface is the seam where the internal
findings DB from the technical architecture will slot in; nothing outside this
module should care which implementation is behind it.
"""

from __future__ import annotations

import threading
from typing import Protocol

from ono.models import Finding, Scan


class ScanStore(Protocol):
    """Minimal persistence contract used by the service and API layers."""

    def put_scan(self, scan: Scan, findings: list[Finding]) -> None: ...
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
