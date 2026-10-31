"""Shared fixtures. Tests never read the developer's ``.env``.

Docker gating: tests marked ``@pytest.mark.docker`` spin up REAL jailed containers.
They run when a daemon is reachable and we are not in CI (``CI`` env var set, as on
GitHub Actions). Force them with ``ONO_DOCKER_TESTS=1``; skip them with
``ONO_DOCKER_TESTS=0``. Run only them with ``pytest -m docker``.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

# Gradio's version-check thread must never run in CI (no outbound calls, no log noise).
os.environ.setdefault("GRADIO_ANALYTICS_ENABLED", "False")

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ono.api import create_app
from ono.config import Settings

# ---------------------------------------------------------------------------
# Main app fixtures (unchanged)
# ---------------------------------------------------------------------------


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, environment="local", model_backend="mock")


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    # The Gradio mount is exercised separately (test_api::test_ui_mounted); most
    # tests skip it to keep the suite fast.
    return create_app(settings, mount_ui=False)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Docker gating
# ---------------------------------------------------------------------------


def _docker_reachable() -> bool:
    try:
        import docker

        return bool(docker.from_env(timeout=5).ping())
    except Exception:
        return False


def docker_tests_enabled() -> tuple[bool, str]:
    flag = os.environ.get("ONO_DOCKER_TESTS")
    if flag == "0":
        return False, "ONO_DOCKER_TESTS=0"
    if flag != "1" and os.environ.get("CI"):
        return False, "real-Docker stress tests are skipped in CI (set ONO_DOCKER_TESTS=1 to force)"
    if not _docker_reachable():
        return False, "no reachable Docker daemon"
    return True, ""


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if not any("docker" in item.keywords for item in items):
        return
    enabled, reason = docker_tests_enabled()
    if enabled:
        return
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip)


# ---------------------------------------------------------------------------
# A live uvicorn server (for the typed client, which talks real HTTP)
# ---------------------------------------------------------------------------


@dataclass
class LiveServer:
    url: str
    server: uvicorn.Server
    thread: threading.Thread

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def start_live_server(asgi_app: FastAPI) -> LiveServer:
    port = _free_port()
    config = uvicorn.Config(asgi_app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="test-uvicorn", daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            msg = "uvicorn did not start"
            raise RuntimeError(msg)
        time.sleep(0.02)
    return LiveServer(url=f"http://127.0.0.1:{port}", server=server, thread=thread)
