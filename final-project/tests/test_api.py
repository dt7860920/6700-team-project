"""HTTP API smoke tests, including the blocking allowlist security test."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from ono.api import create_app
from ono.config import Settings


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_info_has_no_secrets(client: TestClient) -> None:
    r = client.get("/info")
    assert r.status_code == 200
    body = r.json()
    assert body["model_backend"] == "mock"
    assert body["environment"] == "local"
    assert "model_service_api_key" not in body
    assert body["targets_registered"] >= 3


def test_targets_returns_allowlist(client: TestClient) -> None:
    r = client.get("/targets")
    assert r.status_code == 200
    ids = {t["target_id"] for t in r.json()["targets"]}
    assert {"pygoat", "juice-shop", "snippet"} <= ids
    assert all(t["authorized"] is True for t in r.json()["targets"])


def test_scan_valid_target_returns_findings(client: TestClient) -> None:
    r = client.post("/scans", json={"target_id": "pygoat"})
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "done"
    assert scan["target_id"] == "pygoat"
    assert scan["findings_count"] == len(scan["findings"]) >= 1
    assert [s["stage"] for s in scan["pipeline"]] == ["ingest", "sast", "plan", "analyze", "verify"]

    f = scan["findings"][0]
    for key in (
        "finding_id",
        "cwe",
        "severity",
        "file",
        "line_range",
        "trace",
        "confidence",
        "rung",
        "verified",
        "patch_diff",
    ):
        assert key in f, key
    assert f["cwe"] == "CWE-89"
    assert f["verified"] is True
    assert f["patch_diff"].startswith("--- a/")


def test_scan_unknown_target_is_403_and_does_not_start(client: TestClient) -> None:
    """Security smoke test #1: an unknown target_id -> 403, no scan starts."""
    r = client.post("/scans", json={"target_id": "example.com"})
    assert r.status_code == 403
    assert "not an authorized target" in r.json()["detail"]


def test_scan_url_like_target_is_rejected(client: TestClient) -> None:
    """URLs are never valid target ids (pattern validation -> 422 before the allowlist)."""
    r = client.post("/scans", json={"target_id": "https://example.com"})
    assert r.status_code in (403, 422)


def test_scan_roundtrip_via_get_endpoints(client: TestClient) -> None:
    created = client.post("/scans", json={"target_id": "juice-shop"}).json()
    scan_id = created["scan_id"]

    scan = client.get(f"/scans/{scan_id}")
    assert scan.status_code == 200
    assert scan.json()["findings_count"] == 1
    assert "findings" not in scan.json()  # metadata only

    findings = client.get(f"/scans/{scan_id}/findings").json()
    assert len(findings) == 1
    assert findings[0]["rung"] == 5
    assert findings[0]["detection_rule"]

    one = client.get(f"/findings/{findings[0]['finding_id']}")
    assert one.status_code == 200
    assert one.json()["cwe"] == "CWE-89"


def test_unknown_scan_and_finding_are_404(client: TestClient) -> None:
    assert client.get("/scans/scn_nope").status_code == 404
    assert client.get("/scans/scn_nope/findings").status_code == 404
    assert client.get("/findings/fnd_nope").status_code == 404


def test_snippet_target_reacts_to_input(client: TestClient) -> None:
    code = 'cur.execute(f"SELECT * FROM t WHERE id = {uid}")\nprint("safe line")\n'
    r = client.post("/scans", json={"target_id": "snippet", "options": {"snippet": code}})
    assert r.status_code == 201
    findings = r.json()["findings"]
    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-89"
    assert findings[0]["line_range"] == [1, 1]


def test_scan_options_are_validated(client: TestClient) -> None:
    r = client.post("/scans", json={"target_id": "pygoat", "options": {"bogus": 1}})
    assert r.status_code == 422


def test_openapi_documents_the_endpoints(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    for p in (
        "/health",
        "/info",
        "/targets",
        "/scans",
        "/scans/{scan_id}",
        "/scans/{scan_id}/findings",
        "/findings/{finding_id}",
    ):
        assert p in paths, p
    assert client.get("/docs").status_code == 200


def test_ui_mounted_and_root_redirects() -> None:
    app = create_app(Settings(_env_file=None), mount_ui=True)
    with TestClient(app) as c:
        root = c.get("/", follow_redirects=False)
        assert root.status_code in (302, 307)
        assert root.headers["location"] == "/ui"
        ui = c.get("/ui/")
        assert ui.status_code == 200
        assert "gradio" in ui.text.lower()


async def test_async_client_health(app: object) -> None:
    """pytest-asyncio path, mirroring how scripts/golden_path.py talks to the app."""
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://ono") as ac:
        r = await ac.get("/health")
    assert r.status_code == 200
