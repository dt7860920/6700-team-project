"""Knowledge memory: the substrate of ONO's frontier-free Level-1 self-distillation.

The plan (section 1.5) wants the harness to *learn across scans* without touching the
model's weights: keep only the trajectories the deterministic verifier *passed* and let
them seed the planner / prover on later scans. This module is that persistent memory.

A memory entry is keyed by a reusable **signature** - ``"<cwe>:<sink_kind>"`` (e.g.
``CWE-89:execute``), which generalizes across targets (the same class of SQL sink reached
the same way). For each signature we keep the best verifier-passed artifacts:

* ``poc_skeleton`` - a read-only PoC that actually drove a canary into this kind of sink,
* ``plan_hint``    - a one-line description of the approach that worked,
* counters         - how many times it has been seen and reused.

On a later scan, :meth:`KnowledgeMemory.seed_for` turns the best matching entry into a
short prompt supplement for the prover / planner - showing the frozen model a verified
prior solution so it reaches the proof in fewer steps. Nothing here trains anything; the
"learning" is entirely at the orchestration layer, exactly as the plan specifies.

The store is a single SQLite file (stdlib; the plan blesses SQLite as the durable
alternative to DuckDB), so it survives restarts and is the data substrate the earlier
in-memory prototype lacked. It is safe for concurrent scans: every write is a short,
locked ``INSERT ... ON CONFLICT`` upsert.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ono.models import Finding

__all__ = ["KnowledgeMemory", "MemoryEntry", "signature_for"]

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge (
    signature   TEXT PRIMARY KEY,
    cwe         TEXT NOT NULL,
    sink_kind   TEXT NOT NULL,
    poc_skeleton TEXT NOT NULL DEFAULT '',
    plan_hint   TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    successes   INTEGER NOT NULL DEFAULT 0,
    reuses      INTEGER NOT NULL DEFAULT 0,
    updated_at  REAL NOT NULL DEFAULT 0
);
"""


def signature_for(cwe: str, sink_kind: str) -> str:
    """The reusable memory key: the CWE plus the *kind* of sink (not the file/line)."""
    kind = (sink_kind or "sink").strip().lower().replace(" ", "_")[:40]
    return f"{cwe}:{kind}"


@dataclass(slots=True)
class MemoryEntry:
    signature: str
    cwe: str
    sink_kind: str
    poc_skeleton: str
    plan_hint: str
    evidence: str
    successes: int
    reuses: int


class KnowledgeMemory:
    """A durable, signature-keyed store of verifier-passed solutions. Thread-safe."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + our own lock: one connection shared across scan workers.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- writing ----------------------------------------------------------------------
    def record_success(
        self,
        *,
        cwe: str,
        sink_kind: str,
        poc_skeleton: str,
        plan_hint: str = "",
        evidence: str = "",
    ) -> MemoryEntry:
        """Record (or reinforce) a verifier-passed solution for this signature."""
        signature = signature_for(cwe, sink_kind)
        now = time.time()
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT poc_skeleton, plan_hint FROM knowledge WHERE signature = ?", (signature,)
            ).fetchone()
            # Keep the first working PoC skeleton; later successes only bump the counter and
            # may fill a still-empty field (never overwrite a proven one with a weaker one).
            poc = (existing["poc_skeleton"] if existing else "") or poc_skeleton
            hint = (existing["plan_hint"] if existing else "") or plan_hint
            self._conn.execute(
                """
                INSERT INTO knowledge
                    (signature, cwe, sink_kind, poc_skeleton, plan_hint, evidence,
                     successes, reuses, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?)
                ON CONFLICT(signature) DO UPDATE SET
                    successes = successes + 1,
                    poc_skeleton = excluded.poc_skeleton,
                    plan_hint = excluded.plan_hint,
                    evidence = excluded.evidence,
                    updated_at = excluded.updated_at
                """,
                (signature, cwe, sink_kind, poc, hint, evidence, now),
            )
        log.info("knowledge: recorded success for %s", signature)
        got = self.get(signature)
        assert got is not None
        return got

    def record_reuse(self, signature: str) -> None:
        """Count that an entry was seeded into a later scan (for the reuse metric)."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE knowledge SET reuses = reuses + 1 WHERE signature = ?", (signature,)
            )

    # -- reading ----------------------------------------------------------------------
    def get(self, signature: str) -> MemoryEntry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM knowledge WHERE signature = ?", (signature,)
            ).fetchone()
        return _entry(row) if row is not None else None

    def all(self) -> list[MemoryEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM knowledge ORDER BY successes DESC, updated_at DESC"
            ).fetchall()
        return [_entry(r) for r in rows]

    def lookup(self, cwe: str, sink_kind: str) -> MemoryEntry | None:
        """The best entry for this exact signature, then the best for the CWE alone."""
        exact = self.get(signature_for(cwe, sink_kind))
        if exact is not None:
            return exact
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM knowledge WHERE cwe = ? AND poc_skeleton != '' "
                "ORDER BY successes DESC, updated_at DESC LIMIT 1",
                (cwe,),
            ).fetchone()
        return _entry(row) if row is not None else None

    # -- seeding ----------------------------------------------------------------------
    def seed_for(self, finding: Finding) -> str:
        """A prompt supplement for the prover: a prior verified PoC for this sink class.

        Empty when nothing matches. When it returns a hint it also counts the reuse, so the
        improvement harness can show memory is actually being exercised.
        """
        entry = self.lookup(finding.cwe, _sink_kind_of(finding))
        if entry is None or not entry.poc_skeleton.strip():
            return ""
        self.record_reuse(entry.signature)
        hint = (
            "A read-only PoC of this shape proved a vulnerability of the SAME class "
            f"({entry.cwe}) in an earlier scan - adapt its entry point to THIS target "
            "(same idea: read os.environ['ONO_PAYLOAD'] and drive the app's own handler):\n"
            f"```python\n{entry.poc_skeleton.strip()}\n```"
        )
        if entry.plan_hint:
            hint += f"\nWhat worked: {entry.plan_hint}"
        return hint

    # -- metrics ----------------------------------------------------------------------
    def stats(self) -> dict[str, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(successes), 0) AS s, "
                "COALESCE(SUM(reuses), 0) AS r FROM knowledge"
            ).fetchone()
        return {"entries": int(row["n"]), "successes": int(row["s"]), "reuses": int(row["r"])}


def _entry(row: sqlite3.Row) -> MemoryEntry:
    return MemoryEntry(
        signature=row["signature"],
        cwe=row["cwe"],
        sink_kind=row["sink_kind"],
        poc_skeleton=row["poc_skeleton"],
        plan_hint=row["plan_hint"],
        evidence=row["evidence"],
        successes=int(row["successes"]),
        reuses=int(row["reuses"]),
    )


def _sink_kind_of(finding: Finding) -> str:
    """Derive a sink kind from the finding's verification evidence or its trace symbol."""
    v = finding.verification
    if v is not None:
        check = v.check("poc_reaches_sink")
        if check is not None and check.detail:
            # evidence detail starts with the oracle hit kind, e.g. "execute at app/db.py:14 ..."
            return check.detail.split(" at ", 1)[0].split(":", 1)[0].strip()[:40]
    if finding.trace:
        return finding.trace[-1].symbol.split("(", 1)[0].strip()[:40]
    return "sink"
