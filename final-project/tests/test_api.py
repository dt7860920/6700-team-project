"""HTTP API smoke tests, including the blocking allowlist security test.

``POST /scans`` is asynchronous (202 + ``scan_id``); the helpers below poll
``GET /scans/{id}`` to completion. The mock backend finishes in milliseconds.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from ono.api import create_app
from ono.config import Settings

TERMINAL = {"done", "failed"}


def wait_for_scan(client: TestClient, scan_id: str, timeout: float = 10.0) -> dict[str, Any]:
    """Poll ``GET /scans/{scan_id}`` until the scan has ended; return the final record."""
    deadline = time.monotonic() + timeout
    while True:
        r = client.get(f"/scans/{scan_id}")
        assert r.status_code == 200, r.text
        scan: dict[str, Any] = r.json()
        if scan["status"] in TERMINAL:
            return scan
        assert time.monotonic() < deadline, f"scan {scan_id} still {scan['status']}"
        time.sleep(0.01)


def start_and_wait(client: TestClient, body: dict[str, Any]) -> dict[str, Any]:
    accepted = client.post("/scans", json=body)
    assert accepted.status_code == 202, accepted.text
    return wait_for_scan(client, accepted.json()["scan_id"])


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
    assert body["max_active_scans"] >= 1 and body["max_queued_scans"] >= 0  # #34


def test_targets_returns_allowlist(client: TestClient) -> None:
    r = client.get("/targets")
    assert r.status_code == 200
    ids = {t["target_id"] for t in r.json()["targets"]}
    assert {"pygoat", "juice-shop", "snippet"} <= ids
    assert all(t["authorized"] is True for t in r.json()["targets"])


def test_scan_is_accepted_then_completes_with_findings(client: TestClient) -> None:
    r = client.post("/scans", json={"target_id": "pygoat"})
    assert r.status_code == 202, r.text
    accepted = r.json()
    assert accepted["status"] in ("queued", "running")
    assert accepted["scan_id"].startswith("scn_")
    assert accepted["target_id"] == "pygoat"
    assert "findings" not in accepted  # 202: the record, not the result

    scan = wait_for_scan(client, accepted["scan_id"])
    assert scan["status"] == "done", scan
    assert scan["findings_count"] >= 1
    assert scan["progress"] == "" and scan["completed_at"] and scan["started_at"]
    assert [s["stage"] for s in scan["pipeline"]] == ["ingest", "sast", "plan", "analyze", "verify"]
    assert any("Static analysis" in e["message"] for e in scan["events"])

    findings = client.get(f"/scans/{scan['scan_id']}/findings").json()
    assert len(findings) == scan["findings_count"]
    f = findings[0]
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
    """#29: a URL is not on the allowlist either - same 403 and pointer as an unknown id."""
    r = client.post("/scans", json={"target_id": "https://example.com"})
    assert r.status_code == 403
    assert "GET /targets" in r.json()["detail"]
    assert client.post("/scans", json={}).status_code == 422  # missing is still a 422


def test_oversized_snippet_422_does_not_echo_the_code(client: TestClient) -> None:
    """#41: the error names the size and the limit, never the pasted code."""
    code = "x = 1  # " + "a" * 20_000
    r = client.post("/scans", json={"target_id": "snippet", "options": {"snippet": code}})
    assert r.status_code == 422
    assert "aaaaaaaaaa" not in r.text
    (err,) = r.json()["detail"]
    assert err["msg"] == f"snippet is {len(code):,} characters; the limit is 20,000"


@pytest.mark.parametrize(
    ("body", "needle"),
    [
        ({"target_id": "snippet"}, "needs code to scan"),  # #28
        ({"target_id": "snippet", "options": {"snippet": "  \n"}}, "needs code to scan"),
        ({"target_id": "pygoat", "options": {"snippet": "eval(input())"}}, "would be ignored"),
    ],
)
def test_snippet_must_match_the_target(client: TestClient, body: Any, needle: str) -> None:
    """#28 / #45: no code for 'snippet', or code that would be silently ignored, is a 422."""
    r = client.post("/scans", json=body)
    assert r.status_code == 422 and needle in r.text


def test_scan_roundtrip_via_get_endpoints(client: TestClient) -> None:
    done = start_and_wait(client, {"target_id": "juice-shop"})
    scan_id = done["scan_id"]

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


def test_rescanning_a_target_keeps_each_scans_findings_addressable(client: TestClient) -> None:
    """Issue #37: a second scan of the same target must not overwrite the first's findings."""
    first = start_and_wait(client, {"target_id": "vulpy"})["scan_id"]
    second = start_and_wait(client, {"target_id": "vulpy"})["scan_id"]
    (f1,) = client.get(f"/scans/{first}/findings").json()
    (f2,) = client.get(f"/scans/{second}/findings").json()

    assert f1["finding_id"] != f2["finding_id"]
    assert f1["fingerprint"] == f2["fingerprint"] != ""  # same sink, matchable across scans
    assert client.get(f"/findings/{f1['finding_id']}").json()["scan_id"] == first
    assert client.get(f"/findings/{f2['finding_id']}").json()["scan_id"] == second


def test_unknown_scan_and_finding_are_404(client: TestClient) -> None:
    assert client.get("/scans/scn_nope").status_code == 404
    assert client.get("/scans/scn_nope/findings").status_code == 404
    assert client.get("/findings/fnd_nope").status_code == 404


def test_snippet_target_reacts_to_input(client: TestClient) -> None:
    code = 'cur.execute(f"SELECT * FROM t WHERE id = {uid}")\nprint("safe line")\n'
    done = start_and_wait(client, {"target_id": "snippet", "options": {"snippet": code}})
    findings = client.get(f"/scans/{done['scan_id']}/findings").json()
    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-89"
    assert findings[0]["line_range"] == [1, 1]


def test_javascript_snippet_gets_javascript_rules(client: TestClient) -> None:
    """Issue #65: pasted JS SQL concatenation is a finding, not 'no vulnerabilities'."""
    code = 'const name = req.query.name;\ndb.query("SELECT * FROM u WHERE n = \'" + name + "\'");\n'
    done = start_and_wait(client, {"target_id": "snippet", "options": {"snippet": code}})
    findings = client.get(f"/scans/{done['scan_id']}/findings").json()
    assert [(f["cwe"], f["file"], f["line_range"]) for f in findings] == [
        ("CWE-89", "snippet.js", [2, 2])
    ]
    assert done["pipeline"][0]["summary"].startswith("snapshot inline javascript snippet")


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
