"""Exploitation-based prioritization (CISA KEV + EPSS) - offline tests.

Every test is hermetic: both intel feeds are a fake transport injected into
:class:`~ono.sca.intel.IntelClient` (and the OSV layer a fake too), so nothing touches the
network. Coverage mirrors the acceptance criteria:

* a CVE in the KEV set flips ``kev=True`` (matched across a finding's aliases),
* ``epss`` is the MAX across a finding's CVEs, with that CVE's percentile,
* re-ranking puts malicious > KEV > high-EPSS > the rest,
* a KEV feed that is down / an EPSS timeout degrades (fields unset, a reason recorded, no raise),
* ``sca_offline`` and ``kev_epss_enabled=false`` skip the enrichment entirely.

No specific CVE or package is hardcoded as "the" exploited one; ids are arbitrary fixtures.
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any

from ono.config import Settings
from ono.sca import DependencyFinding, IntelClient, scan_dependencies
from ono.sca.osv import OsvClient

Triple = tuple[str, str, str]


# ---------------------------------------------------------------------------
# Fakes: a KEV/EPSS transport and a tiny OSV transport
# ---------------------------------------------------------------------------


class FakeIntelTransport:
    """Serves the KEV catalog and EPSS batches from in-memory fixtures."""

    def __init__(
        self,
        *,
        kev: list[str] | None = None,
        epss: dict[str, tuple[float, float]] | None = None,
    ) -> None:
        self.kev = kev or []
        self.epss = epss or {}
        self.calls: list[str] = []

    def __call__(self, url: str, body: bytes | None, timeout_s: float) -> bytes:
        self.calls.append(url)
        if "/epss" in url:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            cves = query.get("cve", [""])[0].split(",")
            rows = [
                {"cve": c, "epss": str(self.epss[c][0]), "percentile": str(self.epss[c][1])}
                for c in cves
                if c in self.epss
            ]
            return json.dumps({"data": rows}).encode()
        # Otherwise the KEV catalog URL.
        return json.dumps({"vulnerabilities": [{"cveID": c} for c in self.kev]}).encode()


def _intel(
    *,
    kev: list[str] | None = None,
    epss: dict[str, tuple[float, float]] | None = None,
) -> IntelClient:
    return IntelClient(
        kev_url="https://kev.test/kev.json",
        epss_api_url="https://epss.test/v1",
        timeout_s=5.0,
        transport=FakeIntelTransport(kev=kev, epss=epss),
    )


class FakeOsvTransport:
    """Serves OSV querybatch / vulns from a ``triple -> [records]`` map (see test_sca.py)."""

    def __init__(self, db: dict[Triple, list[dict[str, Any]]]) -> None:
        self.db = db
        self.by_id = {rec["id"]: rec for recs in db.values() for rec in recs}

    def __call__(self, url: str, body: bytes | None, timeout_s: float) -> bytes:
        if url.endswith("/v1/querybatch"):
            queries = json.loads(body or b"{}")["queries"]
            results = [
                {"vulns": [{"id": r["id"]} for r in self.db.get(_triple(q), [])]} for q in queries
            ]
            return json.dumps({"results": results}).encode()
        if "/v1/vulns/" in url:
            return json.dumps(self.by_id.get(url.rsplit("/v1/vulns/", 1)[1], {})).encode()
        raise AssertionError(f"unexpected OSV URL: {url}")


def _triple(query: dict[str, Any]) -> Triple:
    pkg = query["package"]
    return (pkg["ecosystem"], pkg["name"], query["version"])


def _osv(db: dict[Triple, list[dict[str, Any]]]) -> OsvClient:
    return OsvClient(base_url="https://osv.test", timeout_s=5.0, transport=FakeOsvTransport(db))


def _osv_record(vuln_id: str, *, aliases: list[str], malicious: bool = False) -> dict[str, Any]:
    rec: dict[str, Any] = {"id": vuln_id, "aliases": aliases, "summary": f"advisory {vuln_id}"}
    if malicious:
        rec["database_specific"] = {"malicious": True}
    return rec


def _finding(package: str, *, vuln_ids: list[str], malicious: bool = False) -> DependencyFinding:
    return DependencyFinding(
        ecosystem="PyPI",
        package=package,
        version="1.0",
        manifest="requirements.txt",
        vuln_ids=vuln_ids,
        is_malicious=malicious,
    )


# ---------------------------------------------------------------------------
# (a) KEV membership
# ---------------------------------------------------------------------------


def test_cve_in_kev_set_flags_finding() -> None:
    hit = _finding("a", vuln_ids=["GHSA-zzzz", "cve-2021-9999"])  # lowercase + non-CVE alias
    miss = _finding("b", vuln_ids=["CVE-2021-0001"])
    result = _intel(kev=["CVE-2021-9999"]).prioritize([hit, miss])
    assert hit.kev is True  # matched case-insensitively via one of its aliases
    assert miss.kev is False
    assert result.kev_count == 1 and result.reason == ""


# ---------------------------------------------------------------------------
# (b) EPSS max across a finding's CVEs
# ---------------------------------------------------------------------------


def test_epss_is_max_across_finding_cves() -> None:
    finding = _finding("a", vuln_ids=["CVE-2021-1", "CVE-2021-2", "GHSA-x"])
    _intel(epss={"CVE-2021-1": (0.10, 0.50), "CVE-2021-2": (0.80, 0.97)}).prioritize([finding])
    assert finding.epss == 0.80  # the worst of the two known CVEs
    assert finding.epss_percentile == 0.97  # percentile of that same CVE


def test_epss_none_when_no_cve_known() -> None:
    finding = _finding("a", vuln_ids=["CVE-2021-404"])
    _intel(epss={"CVE-2021-1": (0.9, 0.99)}).prioritize([finding])
    assert finding.epss is None and finding.epss_percentile is None


# ---------------------------------------------------------------------------
# (c) Re-ranking: malicious > KEV > high-EPSS > rest
# ---------------------------------------------------------------------------


def test_rerank_orders_malicious_then_kev_then_epss(tmp_path: Path) -> None:
    # Packages named so ALPHABETICAL order is the reverse of the exploitation order, proving the
    # re-rank actually reorders rather than relying on the base package sort.
    (tmp_path / "requirements.txt").write_text("aplain==1.0\nxhigh==1.0\nykev==1.0\nzmal==1.0\n")
    db: dict[Triple, list[dict[str, Any]]] = {
        ("PyPI", "aplain", "1.0"): [_osv_record("OSV-P", aliases=["CVE-P"])],
        ("PyPI", "xhigh", "1.0"): [_osv_record("OSV-H", aliases=["CVE-H"])],
        ("PyPI", "ykev", "1.0"): [_osv_record("OSV-K", aliases=["CVE-K"])],
        ("PyPI", "zmal", "1.0"): [_osv_record("MAL-1", aliases=["MAL-1"], malicious=True)],
    }
    intel = _intel(
        kev=["CVE-K"],
        epss={"CVE-H": (0.90, 0.99), "CVE-K": (0.02, 0.30), "CVE-P": (0.02, 0.30)},
    )
    settings = Settings(_env_file=None)
    report = scan_dependencies(tmp_path, settings=settings, client=_osv(db), intel=intel)

    assert [f.package for f in report.findings] == ["zmal", "ykev", "xhigh", "aplain"]
    assert report.findings[0].is_malicious is True
    assert report.findings[1].kev is True
    assert report.findings[2].epss == 0.90
    assert report.priority == "priority: 1 KEV, 1 high-EPSS"
    assert "1 KEV, 1 high-EPSS" in report.detail


# ---------------------------------------------------------------------------
# (d) Feed failures degrade gracefully (no raise, fields unset, a reason)
# ---------------------------------------------------------------------------


def test_kev_feed_unreachable_degrades() -> None:
    def transport(url: str, body: bytes | None, timeout_s: float) -> bytes:
        if "/epss" in url:
            rows = [{"cve": "CVE-1", "epss": "0.4", "percentile": "0.8"}]
            return json.dumps({"data": rows}).encode()
        raise ConnectionError("KEV feed down")

    client = IntelClient(
        kev_url="https://kev.test/kev.json",
        epss_api_url="https://epss.test/v1",
        transport=transport,
    )
    finding = _finding("a", vuln_ids=["CVE-1"])
    result = client.prioritize([finding])
    assert finding.kev is False  # left unset, no exception
    assert finding.epss == 0.4  # EPSS still enriched
    assert "CISA KEV unreachable" in result.reason


def test_epss_timeout_degrades() -> None:
    def transport(url: str, body: bytes | None, timeout_s: float) -> bytes:
        if "/epss" in url:
            raise TimeoutError("EPSS timed out")
        return json.dumps({"vulnerabilities": [{"cveID": "CVE-1"}]}).encode()

    client = IntelClient(
        kev_url="https://kev.test/kev.json",
        epss_api_url="https://epss.test/v1",
        transport=transport,
    )
    finding = _finding("a", vuln_ids=["CVE-1"])
    result = client.prioritize([finding])
    assert finding.kev is True  # KEV still enriched
    assert finding.epss is None and finding.epss_percentile is None  # left unset
    assert "EPSS unreachable" in result.reason


def test_malformed_kev_payload_degrades() -> None:
    def transport(url: str, body: bytes | None, timeout_s: float) -> bytes:
        return b"not json at all"

    client = IntelClient(transport=transport)
    finding = _finding("a", vuln_ids=["CVE-1"])
    result = client.prioritize([finding])  # must not raise
    assert finding.kev is False and finding.epss is None
    assert result.reason


# ---------------------------------------------------------------------------
# (e) Offline / disabled skip enrichment entirely
# ---------------------------------------------------------------------------


def test_offline_skips_enrichment(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==0.5\n")

    def boom(url: str, body: bytes | None, timeout_s: float) -> bytes:
        raise AssertionError("intel feeds must not be touched in offline mode")

    intel = IntelClient(transport=boom)
    settings = Settings(_env_file=None, sca_offline=True)
    report = scan_dependencies(tmp_path, settings=settings, client=_osv({}), intel=intel)
    assert report.status == "skipped" and report.priority == ""


def test_disabled_skips_enrichment(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==0.5\n")
    db: dict[Triple, list[dict[str, Any]]] = {
        ("PyPI", "flask", "0.5"): [_osv_record("OSV-1", aliases=["CVE-1"])]
    }
    transport = FakeIntelTransport(kev=["CVE-1"], epss={"CVE-1": (0.9, 0.99)})
    intel = IntelClient(
        kev_url="https://kev.test/kev.json",
        epss_api_url="https://epss.test/v1",
        transport=transport,
    )
    settings = Settings(_env_file=None, kev_epss_enabled=False)
    report = scan_dependencies(tmp_path, settings=settings, client=_osv(db), intel=intel)
    assert report.status == "ok"
    assert report.findings[0].kev is False  # not enriched
    assert report.findings[0].epss is None
    assert report.priority == ""
    assert transport.calls == []  # the feeds were never contacted
