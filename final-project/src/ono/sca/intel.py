"""Exploitation intelligence for SCA findings - CISA KEV + EPSS, stdlib only (``urllib``).

Two free, daily-updated, *ecosystem-agnostic* feeds re-rank dependency findings by how likely
they are to actually be exploited (they key purely on CVE id, so one integration serves every
ecosystem OSV covers):

* **CISA KEV** - the Known Exploited Vulnerabilities catalog (one JSON file, a list of records
  each carrying a ``cveID``). A finding is ``kev=True`` if ANY of its CVE aliases is in the set:
  these are vulnerabilities CISA has observed being exploited in the wild - the strongest public
  signal short of a malicious-package verdict.
* **EPSS** - the Exploit Prediction Scoring System (FIRST.org), a daily model giving each CVE a
  0..1 probability of exploitation in the next 30 days plus a percentile. A finding's ``epss`` is
  the MAX across its CVEs (its worst case), with that CVE's percentile.

:class:`IntelClient` fetches KEV once and EPSS in batches, then enriches findings in place. Like
:class:`~ono.sca.osv.OsvClient` it is **best effort**: the base URLs and timeout are injectable,
all I/O goes through a single :data:`~ono.sca.osv.Transport` callable (so tests never touch the
network), and any network error, timeout or malformed response degrades to "fields left unset +
a reason string" and **never** raises out of this module. No third-party HTTP dependency.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from ono.sca.osv import Transport

log = logging.getLogger(__name__)

# Number of CVE ids per EPSS request. FIRST.org accepts a comma-separated batch; stay modest so
# the query string never grows unwieldy. One request per chunk.
_EPSS_BATCH_SIZE = 100

# A finding at or above this EPSS probability is counted as "high-EPSS" in the report summary.
HIGH_EPSS = 0.5


class Finding(Protocol):
    """The slice of :class:`~ono.sca.scan.DependencyFinding` this module reads and writes.

    A structural type keeps :mod:`ono.sca.intel` free of a circular import on
    :mod:`ono.sca.scan` while staying type-checked.
    """

    vuln_ids: list[str]
    kev: bool
    epss: float | None
    epss_percentile: float | None


@dataclass(frozen=True)
class IntelResult:
    """The outcome of enriching a set of findings with KEV / EPSS intelligence.

    ``reason`` is empty on success and otherwise a short human-readable degrade reason (KEV feed
    down, EPSS timeout) - the scan appends it to the SCA report. ``kev_count`` and
    ``high_epss_count`` summarise what rose to the top.
    """

    reason: str = ""
    kev_count: int = 0
    high_epss_count: int = 0


@dataclass
class _Epss:
    """One CVE's EPSS score as parsed from the FIRST.org API (both fields 0..1)."""

    probability: float
    percentile: float | None = None


def _urllib_transport(url: str, body: bytes | None, timeout_s: float) -> bytes:
    """Default transport: a plain ``urllib`` request (GET when ``body is None``)."""
    headers = {"User-Agent": "ONO-sca", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        data: bytes = response.read()
    return data


class IntelClient:
    """Enrich SCA findings with CISA KEV membership and EPSS exploitation probability."""

    def __init__(
        self,
        *,
        kev_url: str = (
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        ),
        epss_api_url: str = "https://api.first.org/data/v1",
        timeout_s: float = 20.0,
        transport: Transport | None = None,
    ) -> None:
        self.kev_url = kev_url
        self.epss_api_url = epss_api_url.rstrip("/")
        self.timeout_s = max(1.0, float(timeout_s))
        self._transport = transport or _urllib_transport

    # -- public API -------------------------------------------------------

    def prioritize(self, findings: Sequence[Finding]) -> IntelResult:
        """Set ``kev`` / ``epss`` / ``epss_percentile`` on every finding; never raise.

        Collects every CVE id across the findings, fetches the KEV catalog once and EPSS in
        batches, then enriches in place. Any feed that fails is skipped (its fields stay unset)
        and its failure is recorded in :attr:`IntelResult.reason`.
        """
        cves = sorted({c.upper() for f in findings for c in f.vuln_ids if _is_cve(c)})
        if not cves:
            return IntelResult()

        reasons: list[str] = []

        kev_set = self._fetch_kev(reasons)
        epss = self._fetch_epss(cves, reasons)

        for finding in findings:
            finding_cves = [c.upper() for c in finding.vuln_ids if _is_cve(c)]
            if kev_set is not None:
                finding.kev = any(c in kev_set for c in finding_cves)
            scored = [(c, epss[c]) for c in finding_cves if c in epss]
            if scored:
                _cve, worst = max(scored, key=lambda pair: pair[1].probability)
                finding.epss = worst.probability
                finding.epss_percentile = worst.percentile

        return IntelResult(
            reason="; ".join(reasons),
            kev_count=sum(1 for f in findings if f.kev),
            high_epss_count=sum(1 for f in findings if f.epss is not None and f.epss >= HIGH_EPSS),
        )

    # -- CISA KEV ---------------------------------------------------------

    def _fetch_kev(self, reasons: list[str]) -> set[str] | None:
        """The set of KEV CVE ids (uppercased), or ``None`` if the feed is unreachable."""
        try:
            data = self._get(self.kev_url)
        except _IntelError as exc:
            log.info("CISA KEV feed unreachable (%s); KEV flag left unset", exc)
            reasons.append("CISA KEV unreachable")
            return None
        # The catalog is ``{"vulnerabilities": [...]}``; tolerate a bare list too.
        records = data.get("vulnerabilities") if isinstance(data, dict) else data
        if not isinstance(records, list):
            reasons.append("CISA KEV malformed")
            return None
        return {
            rec["cveID"].upper()
            for rec in records
            if isinstance(rec, dict) and isinstance(rec.get("cveID"), str)
        }

    # -- EPSS -------------------------------------------------------------

    def _fetch_epss(self, cves: list[str], reasons: list[str]) -> dict[str, _Epss]:
        """Map each known CVE to its EPSS score, batching requests; partial on failure."""
        scores: dict[str, _Epss] = {}
        failures = 0
        batches = 0
        for start in range(0, len(cves), _EPSS_BATCH_SIZE):
            batches += 1
            chunk = cves[start : start + _EPSS_BATCH_SIZE]
            query = urllib.parse.urlencode({"cve": ",".join(chunk)})
            try:
                data = self._get(f"{self.epss_api_url}/epss?{query}")
            except _IntelError as exc:
                log.info("EPSS request failed (%s); those scores left unset", exc)
                failures += 1
                continue
            rows = data.get("data") if isinstance(data, dict) else None
            for row in rows if isinstance(rows, list) else []:
                parsed = _parse_epss_row(row)
                if parsed is not None:
                    cve, score = parsed
                    scores[cve] = score
        if failures == batches:
            reasons.append("EPSS unreachable")
        elif failures:
            reasons.append(f"EPSS partially unreachable ({failures}/{batches} batches)")
        return scores

    # -- transport --------------------------------------------------------

    def _get(self, url: str) -> Any:
        try:
            raw = self._transport(url, None, self.timeout_s)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise _IntelError(f"request to {url} failed: {exc}") from exc
        except Exception as exc:  # a fake/other transport may raise anything; stay contained
            raise _IntelError(f"request to {url} errored: {exc}") from exc
        try:
            return json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise _IntelError(f"request to {url} returned invalid JSON") from exc


class _IntelError(Exception):
    """Internal: an intel call could not be completed. Never escapes this module."""


def _is_cve(advisory_id: str) -> bool:
    return advisory_id.upper().startswith("CVE-")


def _parse_epss_row(row: Any) -> tuple[str, _Epss] | None:
    """Parse one ``{cve, epss, percentile}`` row; ``None`` if unusable."""
    if not isinstance(row, dict) or not isinstance(row.get("cve"), str):
        return None
    probability = _as_float(row.get("epss"))
    if probability is None:
        return None
    score = _Epss(probability=probability, percentile=_as_float(row.get("percentile")))
    return row["cve"].upper(), score


def _as_float(value: Any) -> float | None:
    """EPSS numbers arrive as 0..1 strings; coerce, tolerating anything odd."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None
