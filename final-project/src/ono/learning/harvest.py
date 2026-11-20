"""Harvest: distil verifier-passed findings into the knowledge memory.

This is the "keep only the trajectories the verifier passed" half of the plan's Level-1
self-distillation (section 1.5). After the graded verifier runs, every finding that was
proven reachable (rung >= 3) carries a :class:`~ono.models.Verification` with the exact
read-only PoC that drove a canary into its sink. :func:`harvest_findings` records those as
reusable, signature-keyed entries so a later scan's prover can be seeded with them.

Only *proven* evidence is harvested - never a model assertion - so the memory can only ever
make the harness faster, never introduce a false positive (the verifier re-proves every
seeded attempt from scratch).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from ono.learning.memory import KnowledgeMemory, _sink_kind_of
from ono.models import Finding

__all__ = ["harvest_findings", "harvest_report"]

log = logging.getLogger(__name__)

RUNG_REACHABLE = 3


def harvest_findings(findings: Iterable[Finding], memory: KnowledgeMemory) -> int:
    """Record every verifier-passed PoC into ``memory``; return how many were harvested."""
    harvested = 0
    for finding in findings:
        v = finding.verification
        if v is None or finding.rung < RUNG_REACHABLE or not v.poc.strip():
            continue
        memory.record_success(
            cwe=finding.cwe,
            sink_kind=_sink_kind_of(finding),
            poc_skeleton=v.poc,
            plan_hint=_plan_hint(finding),
            evidence=v.evidence,
        )
        harvested += 1
    if harvested:
        log.info("harvest: wrote %d verifier-passed solution(s) to knowledge memory", harvested)
    return harvested


def harvest_report(report: object, memory: KnowledgeMemory) -> int:
    """Convenience over a ``VerifyReport`` (duck-typed to avoid an import cycle)."""
    findings = getattr(report, "findings", [])
    return harvest_findings(findings, memory)


def _plan_hint(finding: Finding) -> str:
    rung = "fix proven (rung 4)" if finding.rung >= 4 else "reachability proven (rung 3)"
    return f"{finding.cwe} via {finding.location}: {rung}"
