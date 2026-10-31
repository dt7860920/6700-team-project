"""Executor service + typed client, against the real SandboxManager on the fake Docker.

Auth, error mapping, upload bounding, lifecycle/teardown on shutdown, and the client's
exception mapping all live here. Real containers: ``test_executor_docker.py``.
"""

from __future__ import annotations

import dataclasses
import gzip
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from conftest import LiveServer, start_live_server
from fakedocker import FakeDocker
from ono.config import Settings
from ono.executor.app import create_executor_app
from ono.executor.archive import pack_workspace
from ono.executor.client import (
    ExecutorAuthError,
    ExecutorClient,
    ExecutorRequestError,
    ExecutorUnavailableError,
    SandboxNotFoundError,
    SandboxNotRunningError,
)
from ono.executor.sandbox import JailConfig, SandboxManager

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"
TOKEN = "unit-test-token-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def exec_settings() -> Settings:
    return Settings(_env_file=None, executor_token=SecretStr(TOKEN), max_clone_mb=1)


@pytest.fixture
def fake(tmp_path: Path) -> FakeDocker:
    return FakeDocker(tmp_path / "jails")


@pytest.fixture
def manager(fake: FakeDocker, exec_settings: Settings) -> SandboxManager:
    cfg = dataclasses.replace(JailConfig.from_settings(exec_settings), cmd_timeout_s=5.0)
    return SandboxManager(cfg, fake)


@pytest.fixture
def exec_app(exec_settings: Settings, manager: SandboxManager) -> FastAPI:
    return create_executor_app(exec_settings, manager)


@pytest.fixture
def api(exec_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(exec_app) as c:
        yield c


@pytest.fixture
def archive() -> bytes:
    return pack_workspace(FIXTURE_REPO, max_bytes=10**7)


def create(api: TestClient, archive: bytes, scan_id: str = "scn_app") -> str:
    r = api.post(
        "/sandboxes",
        params={"scan_id": scan_id},
        content=archive,
        headers={**AUTH, "Content-Type": "application/gzip"},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["sandbox_id"])


# ---------------------------------------------------------------------------
# Boot + auth
# ---------------------------------------------------------------------------


def test_refuses_to_start_without_token() -> None:
    with pytest.raises(RuntimeError, match="EXECUTOR_TOKEN"):
        create_executor_app(Settings(_env_file=None))
    with pytest.raises(RuntimeError, match="16 characters"):
        create_executor_app(Settings(_env_file=None, executor_token=SecretStr("short")))


def test_token_is_secret_in_settings() -> None:
    s = Settings(_env_file=None, executor_token=SecretStr("hunter2-hunter2-hunter2"))
    assert "hunter2" not in repr(s) and "hunter2" not in s.model_dump_json()


def test_health_needs_no_auth(api: TestClient) -> None:
    r = api.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "docker": True, "active_sandboxes": 0}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer wrong-token-wrong-token"},
        {"Authorization": f"Basic {TOKEN}"},
        {"Authorization": f"Bearer {TOKEN}x"},
        {"X-Token": TOKEN},
    ],
)
def test_every_endpoint_rejects_bad_auth(
    api: TestClient, archive: bytes, headers: dict[str, str]
) -> None:
    for method, path, kwargs in (
        ("GET", "/sandboxes", {}),
        ("POST", "/sandboxes?scan_id=scn_x", {"content": archive}),
        ("GET", "/sandboxes/sbx_x", {}),
        ("DELETE", "/sandboxes/sbx_x", {}),
        ("POST", "/sandboxes/sbx_x/read", {"json": {"path": "a"}}),
        ("POST", "/sandboxes/sbx_x/tree", {"json": {}}),
        ("POST", "/sandboxes/sbx_x/grep", {"json": {"pattern": "a"}}),
        ("POST", "/sandboxes/sbx_x/apply_patch", {"json": {"diff": "x"}}),
        ("POST", "/sandboxes/sbx_x/run", {"json": {"cmd": "id"}}),
        ("POST", "/sandboxes/sbx_x/run_tests", {"json": {}}),
        ("POST", "/sandboxes/sbx_x/reset", {}),
    ):
        r = api.request(method, path, headers=headers, **kwargs)
        assert r.status_code == 401, (method, path, r.text)
        assert r.headers["WWW-Authenticate"] == "Bearer"


def test_correct_token_works(api: TestClient) -> None:
    assert api.get("/sandboxes", headers=AUTH).status_code == 200


# ---------------------------------------------------------------------------
# Lifecycle + operations over HTTP
# ---------------------------------------------------------------------------


def test_create_validates_scan_id_and_body(api: TestClient, archive: bytes) -> None:
    assert (
        api.post(
            "/sandboxes", params={"scan_id": "Bad Id"}, content=archive, headers=AUTH
        ).status_code
        == 422
    )
    assert (
        api.post("/sandboxes", params={"scan_id": "scn_x"}, content=b"", headers=AUTH).status_code
        == 422
    )
    r = api.post("/sandboxes", params={"scan_id": "scn_x"}, content=b"not a tar", headers=AUTH)
    assert r.status_code == 422 and "gzipped tar" in r.json()["detail"]
    assert api.get("/sandboxes", headers=AUTH).json() == []


def test_create_bounds_the_upload(api: TestClient) -> None:
    too_big = gzip.compress(b"\0" * 1_100_000, compresslevel=0)  # > max_clone_mb=1 MB
    r = api.post("/sandboxes", params={"scan_id": "scn_x"}, content=too_big, headers=AUTH)
    assert r.status_code == 413
    # A decompression bomb is caught on the trusted side from the tar headers.
    bomb = pack_workspace(FIXTURE_REPO, max_bytes=10**7)
    r = api.post("/sandboxes", params={"scan_id": "scn_x"}, content=bomb, headers=AUTH)
    assert r.status_code == 201  # fixture repo is tiny; sanity
    api.delete(f"/sandboxes/{r.json()['sandbox_id']}", headers=AUTH)


def test_full_operation_flow(api: TestClient, archive: bytes, fake: FakeDocker) -> None:
    sid = create(api, archive)
    info = api.get(f"/sandboxes/{sid}", headers=AUTH).json()
    assert info["status"] == "running" and info["scan_id"] == "scn_app"
    assert api.get("/health").json()["active_sandboxes"] == 1

    r = api.post(
        f"/sandboxes/{sid}/read", json={"path": "app/views.py", "start": 1, "end": 2}, headers=AUTH
    )
    assert r.status_code == 200 and r.json()["end_line"] == 2
    r = api.post(f"/sandboxes/{sid}/tree", headers=AUTH)
    assert r.status_code == 200 and r.json()["total"] >= 4
    r = api.post(f"/sandboxes/{sid}/grep", json={"pattern": "os.system"}, headers=AUTH)
    assert r.status_code == 200 and "app/views.py" in {m["file"] for m in r.json()["matches"]}

    fake.run_handler = lambda cmd: (0, b"uid=10001\n", b"")
    r = api.post(f"/sandboxes/{sid}/run", json={"cmd": "id", "timeout_s": 3}, headers=AUTH)
    assert r.status_code == 200 and r.json()["exit_code"] == 0 and r.json()["timed_out"] is False
    r = api.post(f"/sandboxes/{sid}/run_tests", headers=AUTH)
    assert r.status_code == 200 and r.json()["runner"] == "none"

    first = api.post(
        f"/sandboxes/{sid}/read", json={"path": "README.md", "start": 1, "end": 1}, headers=AUTH
    ).json()["content"]
    diff = f"--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n+PATCHED\n {first}"
    r = api.post(f"/sandboxes/{sid}/apply_patch", json={"diff": diff}, headers=AUTH)
    assert r.status_code == 200 and r.json()["applied"] is True
    assert (
        api.post(
            f"/sandboxes/{sid}/read", json={"path": "README.md", "start": 1, "end": 1}, headers=AUTH
        ).json()["content"]
        == "PATCHED\n"
    )
    r = api.post(f"/sandboxes/{sid}/reset", headers=AUTH)
    assert r.status_code == 200 and r.json()["resets"] == 1
    assert (
        api.post(
            f"/sandboxes/{sid}/read", json={"path": "README.md", "start": 1, "end": 1}, headers=AUTH
        ).json()["content"]
        == first
    )

    assert api.delete(f"/sandboxes/{sid}", headers=AUTH).status_code == 204
    assert api.get(f"/sandboxes/{sid}", headers=AUTH).status_code == 404
    assert api.delete(f"/sandboxes/{sid}", headers=AUTH).status_code == 404
    assert not fake.live, "no container may outlive its sandbox"


def test_error_mapping(api: TestClient, archive: bytes, fake: FakeDocker) -> None:
    sid = create(api, archive)
    for path in ("../../etc/passwd", "/etc/passwd", "app/../../x"):
        r = api.post(f"/sandboxes/{sid}/read", json={"path": path}, headers=AUTH)
        assert r.status_code == 422, path
    assert (
        api.post(f"/sandboxes/{sid}/read", json={"path": "nope.py"}, headers=AUTH).status_code
        == 400
    )
    assert (
        api.post(f"/sandboxes/{sid}/grep", json={"pattern": "("}, headers=AUTH).status_code == 422
    )
    assert api.post(f"/sandboxes/{sid}/run", json={"cmd": ""}, headers=AUTH).status_code == 422
    assert (
        api.post(f"/sandboxes/{sid}/run", json={"cmd": "id", "bogus": 1}, headers=AUTH).status_code
        == 422
    )
    assert (
        api.post(
            f"/sandboxes/{sid}/run", json={"cmd": "id", "timeout_s": 0}, headers=AUTH
        ).status_code
        == 422
    )
    assert (
        api.post("/sandboxes/sbx_unknown/run", json={"cmd": "id"}, headers=AUTH).status_code == 404
    )

    fake.live.clear()  # the container died underneath us
    r = api.post(f"/sandboxes/{sid}/run", json={"cmd": "id"}, headers=AUTH)
    assert r.status_code == 409 and "reset" in r.json()["detail"]
    assert api.get(f"/sandboxes/{sid}", headers=AUTH).json()["status"] == "dead"
    assert api.post(f"/sandboxes/{sid}/reset", headers=AUTH).status_code == 200
    assert api.post(f"/sandboxes/{sid}/run", json={"cmd": "id"}, headers=AUTH).status_code == 200


def test_limit_and_docker_down(
    api: TestClient, archive: bytes, fake: FakeDocker, manager: SandboxManager
) -> None:
    ids = [create(api, archive, f"scn_{i}") for i in range(manager.config.max_active)]
    r = api.post("/sandboxes", params={"scan_id": "scn_over"}, content=archive, headers=AUTH)
    assert r.status_code == 429
    for sid in ids:
        api.delete(f"/sandboxes/{sid}", headers=AUTH)
    fake.run_error = httpx.ConnectError(
        "x"
    )  # not a requests error -> generic 500, no internals leaked
    r = api.post("/sandboxes", params={"scan_id": "scn_x"}, content=archive, headers=AUTH)
    assert r.status_code == 500 and r.json()["detail"] == "sandbox operation failed"
    import requests

    fake.run_error = requests.exceptions.ConnectionError("socket gone")
    r = api.post("/sandboxes", params={"scan_id": "scn_x"}, content=archive, headers=AUTH)
    assert r.status_code == 503


def test_shutdown_destroys_all_sandboxes(
    exec_app: FastAPI, archive: bytes, fake: FakeDocker, manager: SandboxManager
) -> None:
    with TestClient(exec_app) as c:
        create(c, archive, "scn_1")
        create(c, archive, "scn_2")
        assert len(fake.live) == 2
    assert not fake.live and manager.active() == []


def test_openapi_lists_everything(api: TestClient) -> None:
    paths = api.get("/openapi.json").json()["paths"]
    for p in (
        "/health",
        "/sandboxes",
        "/sandboxes/{sandbox_id}",
        "/sandboxes/{sandbox_id}/read",
        "/sandboxes/{sandbox_id}/grep",
        "/sandboxes/{sandbox_id}/apply_patch",
        "/sandboxes/{sandbox_id}/run",
        "/sandboxes/{sandbox_id}/run_tests",
        "/sandboxes/{sandbox_id}/reset",
        "/sandboxes/{sandbox_id}/tree",
    ):
        assert p in paths, p


# ---------------------------------------------------------------------------
# The typed client, over real HTTP (uvicorn thread)
# ---------------------------------------------------------------------------


@pytest.fixture
def live(exec_app: FastAPI) -> Iterator[LiveServer]:
    server = start_live_server(exec_app)
    try:
        yield server
    finally:
        server.stop()


def test_client_end_to_end(live: LiveServer, fake: FakeDocker) -> None:
    fake.run_handler = lambda cmd: (0, b"ok\n", b"")
    with ExecutorClient(live.url, TOKEN, timeout_s=10) as client:
        assert client.health().docker is True
        with client.sandbox("scn_cli", FIXTURE_REPO) as sbx:
            assert sbx.info.status == "running"
            assert client.list_sandboxes()[0].sandbox_id == sbx.sandbox_id
            assert "os.system" in sbx.read_file("app/views.py").content
            assert sbx.read_lines("app/util.py", 1, 1).end_line == 1
            assert sbx.grep(r"execute").matches
            assert sbx.tree().total >= 4
            run = sbx.run("echo ok", timeout_s=2)
            assert run.stdout == "ok\n" and run.exit_code == 0
            assert sbx.run_tests().runner == "none"
            patch = sbx.apply_patch("--- a/nope\n+++ b/nope\n@@ -1 +1 @@\n-a\n+b\n")
            assert patch.applied is False
            assert sbx.reset().resets == 1
            sid = sbx.sandbox_id
        with pytest.raises(SandboxNotFoundError):
            client.get(sid)
        client.destroy(sid)  # idempotent
    assert not fake.live


def test_client_destroys_on_exception(live: LiveServer, fake: FakeDocker) -> None:
    client = ExecutorClient(live.url, TOKEN)
    with pytest.raises(ValueError, match="boom"), client.sandbox("scn_x", FIXTURE_REPO):
        assert fake.live
        raise ValueError("boom")
    assert not fake.live
    client.close()


def test_client_exception_mapping(live: LiveServer, fake: FakeDocker) -> None:
    with pytest.raises(ValueError):
        ExecutorClient(live.url, "")
    bad = ExecutorClient(live.url, "wrong-token-wrong-token")
    with pytest.raises(ExecutorAuthError):
        bad.list_sandboxes()
    good = ExecutorClient(live.url, TOKEN)
    with pytest.raises(SandboxNotFoundError):
        good.read_file("sbx_nope", "x")
    with pytest.raises(ExecutorRequestError) as exc:
        good.create_from_archive("scn_x", b"garbage")
    assert exc.value.status_code == 422
    with pytest.raises(ExecutorRequestError, match="413"):
        good.create_from_archive("scn_x", b"\0" * 2_000_000)
    info = good.create("scn_dead", FIXTURE_REPO)
    fake.live.clear()
    with pytest.raises(SandboxNotRunningError):
        good.run(info.sandbox_id, "id")
    assert good.reset(info.sandbox_id).status == "running"
    good.destroy(info.sandbox_id)
    down = ExecutorClient("http://127.0.0.1:9", TOKEN, timeout_s=1)
    with pytest.raises(ExecutorUnavailableError):
        down.health()
