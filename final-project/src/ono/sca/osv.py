"""A tiny OSV.dev API client - stdlib only (``urllib`` + ``json``).

OSV.dev (https://osv.dev) is a free, daily-updated, *ecosystem-general* vulnerability
database: one schema and one API cover PyPI, npm, Go, Maven, crates.io, RubyGems, NuGet,
Packagist and more, and it carries BOTH

* known-vulnerable version advisories (aliased to ``CVE-*`` / ``GHSA-*``), and
* **malicious package** advisories from the OpenSSF malicious-packages feed, whose OSV ids
  are prefixed ``MAL-`` (e.g. a typosquat on PyPI that ships a credential stealer).

The client speaks the batched ``POST /v1/querybatch`` endpoint (one request for the whole
dependency set), then *hydrates* the compact ``{id, modified}`` rows it returns into full
records via ``GET /v1/vulns/{id}``. If the batch call fails it falls back to the per-package
``POST /v1/query`` endpoint, which returns full records directly. Everything is best effort:
a network error, timeout or malformed response degrades to "no vulns + a reason string" and
**never** raises out of this module, so a scan is never aborted by OSV being unreachable.

The base URL and per-request timeout are injectable, and all I/O goes through a single
``Transport`` callable, so the unit tests drive the whole client with a fake transport and
never touch the network. No third-party HTTP dependency, matching the rest of the codebase
(see ``ono/executor/_builder.py``'s ``urllib`` PyPI lookups).
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# (ecosystem, name, version) - OSV's exact ecosystem spelling; see ono/sca/manifests.py.
Triple = tuple[str, str, str]

# One HTTP round-trip: ``(url, body_or_None, timeout_s) -> response bytes``. ``body is None``
# means GET, otherwise POST of that JSON body. Raising signals failure (any exception type).
Transport = Callable[[str, bytes | None, float], bytes]

_CVSS_TYPES = ("CVSS_V4", "CVSS_V3", "CVSS_V2")
_BATCH_SIZE = 500  # OSV accepts up to 1000 queries per batch; stay well under.


@dataclass(frozen=True)
class Vuln:
    """One parsed OSV advisory for a specific package version."""

    id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = ""
    affected_ranges: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    is_malicious: bool = False

    def best_id(self) -> str:
        """Prefer a CVE id, then a GHSA id, then the raw OSV id (what analysts cite)."""
        cve = next((a for a in self.aliases if a.upper().startswith("CVE-")), None)
        if cve:
            return cve
        ghsa = next((a for a in self.aliases if a.upper().startswith("GHSA-")), None)
        return ghsa or self.id


@dataclass(frozen=True)
class OsvResult:
    """The outcome of querying OSV for a set of triples.

    ``vulns`` maps each queried triple to its advisories (triples with none are absent).
    ``reason`` is empty on success and otherwise a short human-readable degrade reason
    (network down, timeout, bad response) - the scan surfaces it as status ``degraded``.
    """

    vulns: dict[Triple, list[Vuln]] = field(default_factory=dict)
    reason: str = ""


def _urllib_transport(url: str, body: bytes | None, timeout_s: float) -> bytes:
    """Default transport: a plain ``urllib`` request to a hardcoded-scheme OSV URL."""
    headers = {"User-Agent": "ONO-sca", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        data: bytes = response.read()
    return data


class OsvClient:
    """Query OSV.dev for vulnerabilities affecting concrete package versions."""

    def __init__(
        self,
        base_url: str = "https://api.osv.dev",
        *,
        timeout_s: float = 20.0,
        transport: Transport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = max(1.0, float(timeout_s))
        self._transport = transport or _urllib_transport

    # -- public API -------------------------------------------------------

    def query(self, triples: list[Triple]) -> OsvResult:
        """Look up every triple; batch first, per-package fallback, never raise."""
        unique = list(dict.fromkeys(triples))
        if not unique:
            return OsvResult()
        try:
            return self._query_batched(unique)
        except _OsvError as exc:
            log.info("OSV querybatch failed (%s); falling back to per-package /v1/query", exc)
        return self._query_each(unique)

    # -- batched path (primary) ------------------------------------------

    def _query_batched(self, triples: list[Triple]) -> OsvResult:
        """``/v1/querybatch`` for the ids, then ``/v1/vulns/{id}`` to hydrate full records."""
        id_lists: list[list[str]] = []
        for start in range(0, len(triples), _BATCH_SIZE):
            chunk = triples[start : start + _BATCH_SIZE]
            payload = {"queries": [_query_body(t) for t in chunk]}
            data = self._post("/v1/querybatch", payload)
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                msg = "querybatch returned a result count that does not match the queries"
                raise _OsvError(msg)
            for result in results:
                vulns = result.get("vulns") if isinstance(result, dict) else None
                id_lists.append(
                    [v["id"] for v in vulns if isinstance(v, dict) and isinstance(v.get("id"), str)]
                    if isinstance(vulns, list)
                    else []
                )
        cache: dict[str, Vuln | None] = {}
        mapping: dict[Triple, list[Vuln]] = {}
        for triple, ids in zip(triples, id_lists, strict=True):
            hydrated = [self._hydrate(vid, cache) for vid in ids]
            found = [v for v in hydrated if v is not None]
            if found:
                mapping[triple] = found
        return OsvResult(vulns=mapping)

    def _hydrate(self, vuln_id: str, cache: dict[str, Vuln | None]) -> Vuln | None:
        if vuln_id not in cache:
            record = self._get(f"/v1/vulns/{vuln_id}")
            cache[vuln_id] = parse_vuln(record) if isinstance(record, dict) else None
        return cache[vuln_id]

    # -- per-package fallback --------------------------------------------

    def _query_each(self, triples: list[Triple]) -> OsvResult:
        mapping: dict[Triple, list[Vuln]] = {}
        failures = 0
        for triple in triples:
            try:
                data = self._post("/v1/query", _query_body(triple))
            except _OsvError:
                failures += 1
                continue
            vulns = data.get("vulns") if isinstance(data, dict) else None
            parsed = [parse_vuln(v) for v in vulns if isinstance(v, dict)] if vulns else []
            if parsed:
                mapping[triple] = parsed
        if failures and not mapping:
            return OsvResult(reason=f"OSV unreachable: {failures}/{len(triples)} queries failed")
        if failures:
            return OsvResult(
                vulns=mapping,
                reason=f"OSV partially unreachable: {failures}/{len(triples)} queries failed",
            )
        return OsvResult(vulns=mapping)

    # -- transport -------------------------------------------------------

    def _post(self, path: str, payload: dict[str, Any]) -> Any:
        return self._call(path, json.dumps(payload).encode("utf-8"))

    def _get(self, path: str) -> Any:
        return self._call(path, None)

    def _call(self, path: str, body: bytes | None) -> Any:
        url = f"{self.base_url}{path}"
        try:
            raw = self._transport(url, body, self.timeout_s)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise _OsvError(f"request to {path} failed: {exc}") from exc
        except Exception as exc:  # a fake/other transport may raise anything; stay contained
            raise _OsvError(f"request to {path} errored: {exc}") from exc
        try:
            return json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise _OsvError(f"request to {path} returned invalid JSON") from exc


class _OsvError(Exception):
    """Internal: an OSV call could not be completed. Never escapes this module."""


def _query_body(triple: Triple) -> dict[str, Any]:
    ecosystem, name, version = triple
    return {"package": {"ecosystem": ecosystem, "name": name}, "version": version}


def is_malicious_record(record: dict[str, Any]) -> bool:
    """True when an OSV record describes a MALICIOUS package (not merely a vulnerable one).

    Generalises across ecosystems: the OpenSSF malicious-packages feed publishes into OSV
    with ``MAL-`` ids, so an id or alias prefixed ``MAL-`` is the signal; some records also
    carry an explicit ``malicious`` marker in ``database_specific``. No package name or
    specific advisory is hardcoded.
    """
    ids = [record.get("id", ""), *(record.get("aliases") or [])]
    if any(isinstance(i, str) and i.upper().startswith("MAL-") for i in ids):
        return True
    specific = record.get("database_specific")
    if isinstance(specific, dict):
        if specific.get("malicious") is True:
            return True
        type_hint = specific.get("type") or specific.get("category")
        if isinstance(type_hint, str) and "malicious" in type_hint.lower():
            return True
    return False


def parse_vuln(record: dict[str, Any]) -> Vuln:
    """Parse one OSV advisory (the JSON schema at https://ossf.github.io/osv-schema/)."""
    aliases = [a for a in (record.get("aliases") or []) if isinstance(a, str)]
    summary = record.get("summary")
    if not isinstance(summary, str) or not summary:
        details = record.get("details")
        summary = (
            details.strip().splitlines()[0][:300] if isinstance(details, str) and details else ""
        )
    ranges, fixed = _affected(record.get("affected"))
    return Vuln(
        id=str(record.get("id", "")),
        aliases=aliases,
        summary=summary,
        severity=_severity(record),
        affected_ranges=ranges,
        fixed_versions=fixed,
        is_malicious=is_malicious_record(record),
    )


def _severity(record: dict[str, Any]) -> str:
    """The CVSS vector/score if OSV carries one (top-level or per-affected), else ""."""
    candidates: list[Any] = list(record.get("severity") or [])
    for affected in record.get("affected") or []:
        if isinstance(affected, dict):
            candidates.extend(affected.get("severity") or [])
    by_type = {
        s.get("type"): s.get("score")
        for s in candidates
        if isinstance(s, dict) and isinstance(s.get("score"), str)
    }
    for cvss in _CVSS_TYPES:
        if by_type.get(cvss):
            return f"{cvss}:{by_type[cvss]}"
    # Any other scoring scheme OSV introduces later: take the first score as-is.
    return next((str(v) for v in by_type.values() if v), "")


def _affected(affected: Any) -> tuple[list[str], list[str]]:
    """Collect human-readable affected ranges and the concrete fixed versions."""
    ranges: list[str] = []
    fixed: list[str] = []
    if not isinstance(affected, list):
        return ranges, fixed
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        for rng in entry.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            introduced: list[str] = []
            fixes: list[str] = []
            for event in rng.get("events") or []:
                if not isinstance(event, dict):
                    continue
                if isinstance(event.get("introduced"), str):
                    introduced.append(event["introduced"])
                if isinstance(event.get("fixed"), str):
                    fixes.append(event["fixed"])
                    if event["fixed"] not in fixed:
                        fixed.append(event["fixed"])
            if introduced or fixes:
                lo = ", ".join(introduced) or "0"
                hi = ", ".join(fixes) or "(no fix listed)"
                ranges.append(f">={lo} <{hi}")
    return ranges, fixed
