"""Software Composition Analysis (SCA) - offline tests.

Every test here is hermetic: the OSV HTTP layer is a fake :class:`FakeTransport` injected
into :class:`~ono.sca.osv.OsvClient`, so nothing ever touches the network. Coverage:

* each manifest parser produces the right ``(ecosystem, name, version)`` triples,
* a known-vulnerable version becomes a CVE/GHSA finding,
* a malicious (OSV ``MAL-``) package sets ``is_malicious=True``,
* an unaffected version yields no finding,
* offline mode and a transport timeout/failure degrade (no exception).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from ono.api import create_app
from ono.config import Settings
from ono.sca import OsvClient, scan_dependencies
from ono.sca import scan as sca_scan
from ono.sca.manifests import (
    collect_dependencies,
    parse_cargo_lock,
    parse_composer_lock,
    parse_csproj,
    parse_gemfile_lock,
    parse_go_mod,
    parse_package_json,
    parse_package_lock,
    parse_packages_config,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pom_xml,
    parse_requirements_txt,
)
from ono.sca.osv import parse_vuln

Triple = tuple[str, str, str]


# ---------------------------------------------------------------------------
# A fake OSV transport
# ---------------------------------------------------------------------------


def _vuln_record(
    vuln_id: str,
    *,
    aliases: list[str] | None = None,
    fixed: str | None = None,
    summary: str = "",
    cvss: str | None = None,
    malicious: bool = False,
) -> dict[str, Any]:
    """Build a minimal but schema-shaped OSV advisory record."""
    record: dict[str, Any] = {
        "id": vuln_id,
        "aliases": aliases or [],
        "summary": summary or f"advisory {vuln_id}",
    }
    if fixed is not None:
        record["affected"] = [
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}
        ]
    if cvss is not None:
        record["severity"] = [{"type": "CVSS_V3", "score": cvss}]
    if malicious:
        record["database_specific"] = {"malicious": True}
    return record


class FakeTransport:
    """Serves querybatch / vulns / query from an in-memory ``triple -> [records]`` map."""

    def __init__(self, db: dict[Triple, list[dict[str, Any]]]) -> None:
        self.db = db
        self.by_id = {rec["id"]: rec for recs in db.values() for rec in recs}
        self.calls: list[str] = []

    def __call__(self, url: str, body: bytes | None, timeout_s: float) -> bytes:
        self.calls.append(url)
        if url.endswith("/v1/querybatch"):
            queries = json.loads(body or b"{}")["queries"]
            results = [
                {"vulns": [{"id": r["id"]} for r in self.db.get(_triple(q), [])]} for q in queries
            ]
            return json.dumps({"results": results}).encode()
        if "/v1/vulns/" in url:
            vuln_id = url.rsplit("/v1/vulns/", 1)[1]
            return json.dumps(self.by_id.get(vuln_id, {})).encode()
        if url.endswith("/v1/query"):
            query = json.loads(body or b"{}")
            return json.dumps({"vulns": self.db.get(_triple(query), [])}).encode()
        raise AssertionError(f"unexpected OSV URL: {url}")


def _triple(query: dict[str, Any]) -> Triple:
    pkg = query["package"]
    return (pkg["ecosystem"], pkg["name"], query["version"])


def _client(db: dict[Triple, list[dict[str, Any]]]) -> OsvClient:
    return OsvClient(base_url="https://osv.test", timeout_s=5.0, transport=FakeTransport(db))


# ---------------------------------------------------------------------------
# (a) Manifest parsers
# ---------------------------------------------------------------------------


def test_requirements_txt_keeps_only_exact_pins() -> None:
    text = "flask==2.0.1\nrequests>=2.0  # range, skipped\n# comment\n-r other.txt\ndjango==3.2.0\n"
    assert parse_requirements_txt(text) == [("flask", "2.0.1"), ("django", "3.2.0")]


def test_pipfile_lock_default_and_develop() -> None:
    text = json.dumps(
        {
            "default": {"flask": {"version": "==2.0.1"}, "loose": {"version": "*"}},
            "develop": {"pytest": {"version": "==7.4.0"}},
        }
    )
    assert parse_pipfile_lock(text) == [("flask", "2.0.1"), ("pytest", "7.4.0")]


def test_poetry_lock_packages() -> None:
    text = (
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
        '[[package]]\nname = "idna"\nversion = "3.4"\n'
    )
    assert parse_poetry_lock(text) == [("requests", "2.31.0"), ("idna", "3.4")]


def test_package_lock_v3_packages_map() -> None:
    text = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.19"},
                "node_modules/@scope/pkg": {"version": "1.2.3"},
            },
        }
    )
    assert parse_package_lock(text) == [("lodash", "4.17.19"), ("@scope/pkg", "1.2.3")]


def test_package_json_only_exact_pins() -> None:
    text = json.dumps(
        {
            "dependencies": {"left-pad": "1.3.0", "react": "^18.0.0"},
            "devDependencies": {"jest": "29.0.0"},
        }
    )
    assert parse_package_json(text) == [("left-pad", "1.3.0"), ("jest", "29.0.0")]


def test_go_mod_block_and_single_line() -> None:
    text = (
        "module example.com/app\n\ngo 1.21\n\n"
        "require (\n\tgithub.com/gin-gonic/gin v1.9.0\n"
        "\tgolang.org/x/text v0.3.7 // indirect\n)\n\n"
        "require github.com/pkg/errors v0.9.1\n"
        "replace github.com/old/x => github.com/new/x v1.0.0\n"
    )
    assert parse_go_mod(text) == [
        ("github.com/gin-gonic/gin", "1.9.0"),
        ("golang.org/x/text", "0.3.7"),
        ("github.com/pkg/errors", "0.9.1"),
    ]


def test_gemfile_lock_specs_only() -> None:
    text = (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        "    actionpack (6.0.3.2)\n      actionview (= 6.0.3.2)\n"
        "    rack (2.2.3)\n\nPLATFORMS\n  ruby\n"
    )
    assert parse_gemfile_lock(text) == [("actionpack", "6.0.3.2"), ("rack", "2.2.3")]


def test_pom_xml_group_artifact_version() -> None:
    text = (
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>'
        "<dependency><groupId>org.apache.logging.log4j</groupId>"
        "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"
        "<dependency><groupId>com.x</groupId><artifactId>y</artifactId>"
        "<version>${skip.me}</version></dependency>"
        "</dependencies></project>"
    )
    assert parse_pom_xml(text) == [("org.apache.logging.log4j:log4j-core", "2.14.1")]


def test_cargo_lock_packages() -> None:
    text = '[[package]]\nname = "regex"\nversion = "1.5.4"\n'
    assert parse_cargo_lock(text) == [("regex", "1.5.4")]


def test_csproj_package_reference() -> None:
    text = (
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
        '<PackageReference Include="Ranged" Version="[1.0,2.0)" />'
        "</ItemGroup></Project>"
    )
    assert parse_csproj(text) == [("Newtonsoft.Json", "12.0.1")]


def test_packages_config() -> None:
    text = '<?xml version="1.0"?><packages><package id="jQuery" version="3.1.1" /></packages>'
    assert parse_packages_config(text) == [("jQuery", "3.1.1")]


def test_composer_lock_strips_leading_v() -> None:
    text = json.dumps(
        {
            "packages": [{"name": "monolog/monolog", "version": "v2.0.0"}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}],
        }
    )
    assert parse_composer_lock(text) == [("monolog/monolog", "2.0.0"), ("phpunit/phpunit", "9.5.0")]


def test_collect_dependencies_walks_and_skips_vendored(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n")
    sub = tmp_path / "frontend"
    sub.mkdir()
    (sub / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.19"}}})
    )
    # package.json beside the lockfile is shadowed by it.
    (sub / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.19"}}))
    # Vendored dir must be ignored entirely.
    vendored = sub / "node_modules" / "evil"
    vendored.mkdir(parents=True)
    (vendored / "package.json").write_text(json.dumps({"name": "evil", "version": "9.9.9"}))

    deps = collect_dependencies(tmp_path)
    triples = {d.triple for d in deps}
    assert ("PyPI", "flask", "2.0.1") in triples
    assert ("npm", "lodash", "4.17.19") in triples
    assert all("node_modules" not in d.manifest for d in deps)
    # package.json was shadowed, so lodash came from the lockfile only (one triple).
    assert sum(1 for d in deps if d.name == "lodash") == 1


# ---------------------------------------------------------------------------
# (b) Known-vulnerable version -> CVE/GHSA finding
# ---------------------------------------------------------------------------


def test_known_vulnerable_version_maps_to_cve(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==0.5\n")
    db = {
        ("PyPI", "flask", "0.5"): [
            _vuln_record(
                "GHSA-abcd-1234-5678",
                aliases=["CVE-2019-1010083", "GHSA-abcd-1234-5678"],
                fixed="1.0",
                summary="Flask denial of service",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            )
        ]
    }
    settings = Settings(_env_file=None)
    report = scan_dependencies(tmp_path, settings=settings, client=_client(db))
    assert report.status == "ok"
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.package == "flask" and finding.version == "0.5"
    assert finding.vuln_ids == ["CVE-2019-1010083"]  # CVE preferred over GHSA/OSV id
    assert finding.fixed_versions == ["1.0"]
    assert finding.severity.startswith("CVSS_V3:")
    assert finding.is_malicious is False
    assert finding.manifest == "requirements.txt"


def test_ghsa_used_when_no_cve_alias(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.11"}}})
    )
    db = {
        ("npm", "lodash", "4.17.11"): [_vuln_record("GHSA-x", aliases=["GHSA-x"], fixed="4.17.12")]
    }
    report = scan_dependencies(tmp_path, settings=Settings(_env_file=None), client=_client(db))
    assert report.findings[0].vuln_ids == ["GHSA-x"]


# ---------------------------------------------------------------------------
# (c) Malicious package -> is_malicious=True
# ---------------------------------------------------------------------------


def test_malicious_package_by_mal_id(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("colourama==0.1.6\n")
    db = {
        ("PyPI", "colourama", "0.1.6"): [
            _vuln_record("MAL-2023-0001", summary="typosquat of colorama; steals env vars")
        ]
    }
    report = scan_dependencies(tmp_path, settings=Settings(_env_file=None), client=_client(db))
    assert len(report.findings) == 1
    assert report.findings[0].is_malicious is True
    assert report.findings[0].vuln_ids == ["MAL-2023-0001"]
    assert report.malicious and report.malicious[0].package == "colourama"


def test_malicious_flag_from_database_specific() -> None:
    record = _vuln_record("OSV-2024-1", malicious=True)
    assert parse_vuln(record).is_malicious is True


def test_mal_sorts_before_vulnerable(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("aaa==1.0\nzzz==1.0\n")
    db = {
        ("PyPI", "aaa", "1.0"): [_vuln_record("GHSA-a", aliases=["GHSA-a"])],
        ("PyPI", "zzz", "1.0"): [_vuln_record("MAL-9")],
    }
    report = scan_dependencies(tmp_path, settings=Settings(_env_file=None), client=_client(db))
    assert [f.package for f in report.findings] == ["zzz", "aaa"]  # malicious first


# ---------------------------------------------------------------------------
# (d) Unaffected version -> no finding
# ---------------------------------------------------------------------------


def test_unaffected_version_yields_no_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.3.3\n")
    db: dict[Triple, list[dict[str, Any]]] = {}  # OSV knows of nothing for this version
    report = scan_dependencies(tmp_path, settings=Settings(_env_file=None), client=_client(db))
    assert report.status == "ok"
    assert report.findings == []
    assert report.dependencies_scanned == 1


# ---------------------------------------------------------------------------
# (e) Offline / timeout / failure degrade gracefully
# ---------------------------------------------------------------------------


def test_offline_mode_skips_without_network(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==0.5\n")

    def boom(url: str, body: bytes | None, timeout_s: float) -> bytes:
        raise AssertionError("network must not be touched in offline mode")

    settings = Settings(_env_file=None, sca_offline=True)
    client = OsvClient(base_url="https://osv.test", transport=boom)
    report = scan_dependencies(tmp_path, settings=settings, client=client)
    assert report.status == "skipped"
    assert "offline" in report.detail
    assert report.dependencies_scanned == 1


def test_disabled_returns_skipped(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==0.5\n")
    settings = Settings(_env_file=None, sca_enabled=False)
    report = scan_dependencies(tmp_path, settings=settings, client=_client({}))
    assert report.status == "skipped" and "disabled" in report.detail


def test_no_manifests_returns_skipped(tmp_path: Path) -> None:
    report = scan_dependencies(tmp_path, settings=Settings(_env_file=None), client=_client({}))
    assert report.status == "skipped"


def test_network_failure_degrades(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==0.5\n")

    def timeout(url: str, body: bytes | None, timeout_s: float) -> bytes:
        raise TimeoutError("OSV timed out")

    client = OsvClient(base_url="https://osv.test", transport=timeout)
    report = scan_dependencies(tmp_path, settings=Settings(_env_file=None), client=client)
    assert report.status == "degraded"
    assert report.findings == []
    assert "unreachable" in report.detail or "timed out" in report.detail


def test_client_never_raises_on_bad_json() -> None:
    def garbage(url: str, body: bytes | None, timeout_s: float) -> bytes:
        return b"not json at all"

    client = OsvClient(base_url="https://osv.test", transport=garbage)
    result = client.query([("PyPI", "flask", "0.5")])
    assert result.vulns == {} and result.reason  # degraded, no exception


def test_per_package_fallback_when_querybatch_fails(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==0.5\n")
    db = {("PyPI", "flask", "0.5"): [_vuln_record("CVE-x", aliases=["CVE-x"], fixed="1.0")]}
    base = FakeTransport(db)

    def flaky(url: str, body: bytes | None, timeout_s: float) -> bytes:
        if url.endswith("/v1/querybatch"):
            raise ConnectionError("batch endpoint down")
        return base(url, body, timeout_s)

    client = OsvClient(base_url="https://osv.test", transport=flaky)
    report = scan_dependencies(tmp_path, settings=Settings(_env_file=None), client=client)
    assert report.status == "ok"
    assert report.findings[0].vuln_ids == ["CVE-x"]


# ---------------------------------------------------------------------------
# FastAPI route wiring
# ---------------------------------------------------------------------------


def test_sca_route_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(_env_file=None, sca_offline=True)
    with TestClient(create_app(settings, mount_ui=False)) as client:
        resp = client.post("/sca", json={"manifests": {"requirements.txt": "flask==0.5\n"}})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "skipped" and body["dependencies_scanned"] == 1


def test_sca_route_reports_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    db = {("PyPI", "flask", "0.5"): [_vuln_record("CVE-y", aliases=["CVE-y"], fixed="1.0")]}
    monkeypatch.setattr(sca_scan, "_client_factory", lambda _settings: _client(db))
    settings = Settings(_env_file=None)
    with TestClient(create_app(settings, mount_ui=False)) as client:
        resp = client.post("/sca", json={"manifests": {"requirements.txt": "flask==0.5\n"}})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["findings"][0]["vuln_ids"] == ["CVE-y"]


def test_sca_route_rejects_path_traversal() -> None:
    settings = Settings(_env_file=None, sca_offline=True)
    with TestClient(create_app(settings, mount_ui=False)) as client:
        resp = client.post("/sca", json={"manifests": {"../escape.txt": "flask==0.5\n"}})
    assert resp.status_code == 422
