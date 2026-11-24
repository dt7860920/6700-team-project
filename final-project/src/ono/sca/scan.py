"""Software Composition Analysis: declared dependencies vs. the OSV.dev database.

:func:`scan_dependencies` is the library entry point: walk a cloned repository's manifests
(:mod:`ono.sca.manifests`), dedupe the ``(ecosystem, name, version)`` triples, ask OSV.dev
in one batched request (:mod:`ono.sca.osv`), and return a :class:`ScaReport` of findings -
both **known-vulnerable** versions (CVE / GHSA) and **malicious** packages (OSV ``MAL-``
advisories). It is self-contained and does not touch the agentic scan pipeline.

Status is one of ``ok`` (OSV was queried), ``skipped`` (SCA disabled, offline, or nothing to
query) or ``degraded`` (OSV was unreachable / errored; a reason is attached). It never raises.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from ono.sca.intel import IntelClient
from ono.sca.manifests import ParsedDep, Triple, collect_dependencies
from ono.sca.osv import OsvClient, Vuln

if TYPE_CHECKING:
    from ono.config import Settings

log = logging.getLogger(__name__)

ScaStatus = Literal["ok", "skipped", "degraded"]

# Seam: how :func:`scan_dependencies` builds its OSV client from settings. Tests monkeypatch
# this (or pass ``client=``) so the suite never constructs a network-backed transport.
ClientFactory = Callable[["Settings"], OsvClient]

# Seam: how :func:`scan_dependencies` builds its KEV/EPSS intel client from settings. Tests
# monkeypatch this (or pass ``intel=``) so the suite never constructs a network-backed transport.
IntelFactory = Callable[["Settings"], IntelClient]


class DependencyFinding(BaseModel):
    """One vulnerable or malicious dependency, as surfaced to the API and UI."""

    ecosystem: str
    package: str
    version: str
    vuln_ids: list[str] = Field(
        default_factory=list,
        description="Advisory ids for this package, best-id first (CVE, else GHSA, else OSV).",
    )
    severity: str = Field(default="", description="CVSS vector/score if OSV carries one.")
    fixed_versions: list[str] = Field(
        default_factory=list, description="Versions that resolve the advisory, if published."
    )
    summary: str = Field(default="", description="One-line advisory summary.")
    manifest: str = Field(description="Workspace-relative manifest the dependency came from.")
    is_malicious: bool = Field(
        default=False,
        description="True for an OSV MAL- malicious-package advisory, not merely a vulnerable one.",
    )
    kev: bool = Field(
        default=False,
        description="True if any CVE alias is in CISA's Known Exploited Vulnerabilities catalog.",
    )
    epss: float | None = Field(
        default=None,
        description="Max EPSS exploitation probability (0..1) over this finding's CVEs, if known.",
    )
    epss_percentile: float | None = Field(
        default=None,
        description="EPSS percentile (0..1) of the CVE that gave this finding its EPSS score.",
    )


class ScaReport(BaseModel):
    """The result of an SCA run over one workspace."""

    status: ScaStatus = Field(description="ok | skipped | degraded.")
    detail: str = Field(default="", description="Why it was skipped/degraded, or a summary.")
    dependencies_scanned: int = Field(default=0, ge=0)
    findings: list[DependencyFinding] = Field(default_factory=list)
    priority: str = Field(
        default="",
        description="KEV/EPSS prioritization summary (counts of KEV and high-EPSS findings).",
    )

    @property
    def malicious(self) -> list[DependencyFinding]:
        return [f for f in self.findings if f.is_malicious]


def _default_client(settings: Settings) -> OsvClient:
    return OsvClient(base_url=settings.osv_api_url, timeout_s=settings.sca_timeout_s)


def _default_intel(settings: Settings) -> IntelClient:
    return IntelClient(
        kev_url=settings.cisa_kev_url,
        epss_api_url=settings.epss_api_url,
        timeout_s=settings.sca_timeout_s,
    )


def scan_dependencies(
    workspace: Path,
    *,
    settings: Settings,
    client: OsvClient | None = None,
    intel: IntelClient | None = None,
) -> ScaReport:
    """Scan a cloned repository's declared dependencies against OSV.dev.

    Pass ``client`` to inject an OSV client and ``intel`` to inject the KEV/EPSS client (tests
    do this with fake transports); otherwise each is built from ``settings`` via its factory
    seam (:data:`_client_factory` / :data:`_intel_factory`).
    """
    if not settings.sca_enabled:
        return ScaReport(status="skipped", detail="SCA is disabled (sca_enabled=false)")

    deps = collect_dependencies(Path(workspace))
    paths_by_triple = _paths_by_triple(deps)
    unique = list(paths_by_triple)
    if not unique:
        return ScaReport(status="skipped", detail="no pinned dependencies found in any manifest")

    if settings.sca_offline:
        return ScaReport(
            status="skipped",
            detail=f"offline mode (sca_offline=true); {len(unique)} dependencies not checked",
            dependencies_scanned=len(unique),
        )

    osv = client or _client_factory(settings)
    result = osv.query(unique)

    findings = _build_findings(result.vulns, paths_by_triple)
    priority = _prioritize(findings, settings=settings, intel=intel)

    if result.reason and not result.vulns:
        return ScaReport(
            status="degraded",
            detail=result.reason,
            dependencies_scanned=len(unique),
            findings=findings,
            priority=priority,
        )
    status: ScaStatus = "degraded" if result.reason else "ok"
    detail = result.reason or _ok_detail(findings, len(unique))
    if not result.reason and priority:
        detail = f"{detail}; {priority}"
    return ScaReport(
        status=status,
        detail=detail,
        dependencies_scanned=len(unique),
        findings=findings,
        priority=priority,
    )


# Reassignable factory seams (see ClientFactory / IntelFactory). Not parameters so the API route
# and the library share one default; tests monkeypatch ``ono.sca.scan._client_factory`` etc.
_client_factory: ClientFactory = _default_client
_intel_factory: IntelFactory = _default_intel


def _prioritize(
    findings: list[DependencyFinding], *, settings: Settings, intel: IntelClient | None
) -> str:
    """Enrich findings with KEV/EPSS and re-rank in place; return a short summary line.

    No-op (empty string) when disabled; never raises - the intel client degrades gracefully and
    any recorded reason is folded into the returned summary.
    """
    if not settings.kev_epss_enabled or not findings:
        return ""
    client = intel or _intel_factory(settings)
    outcome = client.prioritize(findings)
    _rerank(findings)
    summary = f"priority: {outcome.kev_count} KEV, {outcome.high_epss_count} high-EPSS"
    return f"{summary} ({outcome.reason})" if outcome.reason else summary


def _rerank(findings: list[DependencyFinding]) -> None:
    """Re-sort: malicious first, then KEV, then EPSS descending, then the base stable order."""
    findings.sort(
        key=lambda f: (
            not f.is_malicious,
            not f.kev,
            -(f.epss or 0.0),
            f.ecosystem,
            f.package,
            f.version,
        )
    )


def _paths_by_triple(deps: list[ParsedDep]) -> dict[Triple, list[str]]:
    """Dedupe to unique triples, remembering every manifest each came from (sorted)."""
    paths: dict[Triple, list[str]] = {}
    for dep in deps:
        paths.setdefault(dep.triple, [])
        if dep.manifest not in paths[dep.triple]:
            paths[dep.triple].append(dep.manifest)
    return paths


def _build_findings(
    vulns: dict[Triple, list[Vuln]], paths_by_triple: dict[Triple, list[str]]
) -> list[DependencyFinding]:
    findings: list[DependencyFinding] = []
    for triple, records in vulns.items():
        if not records:
            continue
        ecosystem, name, version = triple
        manifest = ", ".join(paths_by_triple.get(triple, [])) or "(unknown)"
        malicious = [v for v in records if v.is_malicious]
        chosen = malicious or records  # a malicious verdict dominates the summary line
        findings.append(
            DependencyFinding(
                ecosystem=ecosystem,
                package=name,
                version=version,
                vuln_ids=_dedupe([v.best_id() for v in chosen]),
                severity=next((v.severity for v in chosen if v.severity), ""),
                fixed_versions=_dedupe([fx for v in records for fx in v.fixed_versions]),
                summary=next((v.summary for v in chosen if v.summary), ""),
                manifest=manifest,
                is_malicious=bool(malicious),
            )
        )
    # Malicious first, then by ecosystem/package for a stable, reviewable order.
    findings.sort(key=lambda f: (not f.is_malicious, f.ecosystem, f.package, f.version))
    return findings


def _ok_detail(findings: list[DependencyFinding], scanned: int) -> str:
    malicious = sum(1 for f in findings if f.is_malicious)
    vulnerable = len(findings) - malicious
    return (
        f"scanned {scanned} dependencies: {vulnerable} vulnerable, {malicious} malicious"
        if findings
        else f"scanned {scanned} dependencies: no known vulnerabilities"
    )


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(i for i in items if i))
