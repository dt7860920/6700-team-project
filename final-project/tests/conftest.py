"""Shared fixtures. Tests never read the developer's ``.env``."""

from __future__ import annotations

import os
from collections.abc import Iterator

# Gradio's version-check thread must never run in CI (no outbound calls, no log noise).
os.environ.setdefault("GRADIO_ANALYTICS_ENABLED", "False")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ono.api import create_app
from ono.config import Settings


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
