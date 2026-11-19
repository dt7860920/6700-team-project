"""Scan / finding persistence.

Two implementations behind one :class:`ScanStore` contract:

* :class:`InMemoryScanStore` - the original dict-backed store, lost on restart. Still the
  default for the mock backend and tests (fast, no file).
* :class:`SqliteScanStore` - a durable single-file store (stdlib ``sqlite3``; the plan
  blesses SQLite as the DuckDB alternative, section 8.6). Scans and their findings survive
  a restart, which is also what gives the learning loop a data substrate. Selected with
  ``scan_store=sqlite`` in settings.

Scans are *live* records: the background worker updates them (status, progress, stage
results) while the API and UI read them, so every mutation goes through
:meth:`ScanStore.update_scan`, which applies the change atomically.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
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


class SqliteScanStore:
    """Durable single-file store (stdlib sqlite3). Survives restarts; thread-safe.

    Records are stored as their pydantic JSON so the schema is just ``(id -> json)``: the
    :class:`~ono.models.Scan` / :class:`~ono.models.Finding` models stay the single source of
    truth and gain fields without a migration. A shared connection guarded by one lock is
    enough for the scan workers' short writes.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS findings_by_scan ON findings(scan_id, ordinal);
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def put_scan(self, scan: Scan, findings: list[Finding]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO scans (scan_id, created_at, data) VALUES (?, ?, ?) "
                "ON CONFLICT(scan_id) DO UPDATE SET data = excluded.data",
                (scan.scan_id, scan.created_at.timestamp(), scan.model_dump_json()),
            )
            self._conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan.scan_id,))
            self._conn.executemany(
                "INSERT OR REPLACE INTO findings (finding_id, scan_id, ordinal, data) "
                "VALUES (?, ?, ?, ?)",
                [
                    (f.finding_id, scan.scan_id, i, f.model_dump_json())
                    for i, f in enumerate(findings)
                ],
            )

    def update_scan(self, scan_id: str, change: Callable[[Scan], Scan]) -> Scan | None:
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT data FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                return None
            updated = change(Scan.model_validate_json(row["data"]))
            self._conn.execute(
                "UPDATE scans SET data = ? WHERE scan_id = ?",
                (updated.model_dump_json(), scan_id),
            )
            return updated

    def get_scan(self, scan_id: str) -> Scan | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return Scan.model_validate_json(row["data"]) if row is not None else None

    def get_findings(self, scan_id: str) -> list[Finding] | None:
        with self._lock:
            scan = self._conn.execute(
                "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if scan is None:
                return None
            rows = self._conn.execute(
                "SELECT data FROM findings WHERE scan_id = ? ORDER BY ordinal", (scan_id,)
            ).fetchall()
        return [Finding.model_validate_json(r["data"]) for r in rows]

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        return Finding.model_validate_json(row["data"]) if row is not None else None
