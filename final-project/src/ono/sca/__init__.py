"""Software Composition Analysis (SCA) for ONO.

A self-contained capability that checks a cloned repository's *declared* dependencies against
the OSV.dev database and flags both known-vulnerable versions (CVE / GHSA) and malicious
packages (OSV ``MAL-`` advisories). One OSV integration generalises across every ecosystem;
adding a new ecosystem means adding one parser to :mod:`ono.sca.manifests`.

    from ono.sca import scan_dependencies
    report = scan_dependencies(workspace, settings=settings)
"""

from __future__ import annotations

from ono.sca.intel import IntelClient, IntelResult
from ono.sca.osv import OsvClient, OsvResult, Vuln
from ono.sca.scan import DependencyFinding, ScaReport, scan_dependencies

__all__ = [
    "DependencyFinding",
    "IntelClient",
    "IntelResult",
    "OsvClient",
    "OsvResult",
    "ScaReport",
    "Vuln",
    "scan_dependencies",
]
