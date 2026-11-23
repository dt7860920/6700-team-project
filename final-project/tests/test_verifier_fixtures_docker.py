"""REAL-JAIL prove-rate on the harder fixtures (``pytest -m docker``).

The same cases as :mod:`test_verifier_fixtures`, but run against a genuine
``python:3.13-slim`` container through a live Executor: the stdlib-only apps import and run
inside the jail, the in-jail sink oracle (``python3 -I``) picks the canary, and a PoC counts
only when that canary reaches the flagged sink's dangerous argument with the flagged line on
the call stack. Only the model is scripted; the oracle, the container and the egress block
are real.

This is the measurement that matters for the deliverable: before = naive from-scratch PoCs
(prove-rate 0), after = entry-point-driven PoCs (prove-rate N/N), plus a planted false
positive that stays unproven and a cheating PoC that is rejected - all against the real
oracle.

Skipped automatically without a Docker daemon or in CI (``conftest.docker_tests_enabled``).
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from agentfakes import ScriptedModel, action
from conftest import LiveServer, start_live_server
from fixturecases import (
    CHEAT_POC,
    REACHABLE_CASES,
    SAFE_QUERY_CASE,
    SQLI_LOGIN_CASE,
    FixtureCase,
)
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.executor.app import create_executor_app
from ono.executor.client import ExecutorClient
from ono.models import Finding
from ono.verifier import GradedVerifier

pytestmark = pytest.mark.docker

TOKEN = "docker-fixtures-token-0123456789"
_NOOP_PATCH = "--- a/does/not/exist.py\n+++ b/does/not/exist.py\n@@ -1 +1 @@\n-x\n+y\n"


@pytest.fixture(scope="module")
def live_executor() -> Iterator[LiveServer]:
    settings = Settings(
        _env_file=None,
        executor_token=SecretStr(TOKEN),
        sandbox_mem_mb=256,
        sandbox_pids_limit=64,
        sandbox_cmd_timeout_s=60,
        sandbox_workspace_mb=128,
    )
    server = start_live_server(create_executor_app(settings))
    try:
        yield server
    finally:
        server.stop()


def _verify_in_jail(
    case: FixtureCase, poc_code: str, live: LiveServer, tmp_path: Path, scan: str
) -> Finding:
    workspace = tmp_path / scan
    shutil.copytree(case.dir, workspace)

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == PROVER.system_prompt:
            return action("submit_poc", code=poc_code, how="drive the real entry point")
        if system == FIXER.system_prompt:
            return action("submit_patch", diff=_NOOP_PATCH, summary="noop")
        raise AssertionError("unexpected agent role")

    settings = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://model.invalid/v1",
        executor_url=live.url,
        executor_token=SecretStr(TOKEN),
        workspace_dir=tmp_path,
        context_lines=6,
        verifier_poc_timeout_s=60.0,
        max_verifier_retries=1,
    )
    with ExecutorClient(live.url, TOKEN, timeout_s=120) as client:
        verifier = GradedVerifier(settings, model=ScriptedModel(script=script), executor=client)
        report = verifier.verify(scan, workspace, [case.finding(scan)])
    return report.findings[0]


@pytest.mark.parametrize("case", REACHABLE_CASES, ids=[c.name for c in REACHABLE_CASES])
def test_entry_point_poc_proves_the_sink_in_a_real_jail(
    case: FixtureCase, live_executor: LiveServer, tmp_path: Path
) -> None:
    proven = _verify_in_jail(case, case.honest_poc, live_executor, tmp_path, f"scn_j_{case.name}")
    assert proven.verified is True and proven.rung >= 3
    v = proven.verification
    assert v is not None and v.check("poc_reaches_sink").status == "passed"
    assert v.evidence


@pytest.mark.parametrize("case", REACHABLE_CASES, ids=[c.name for c in REACHABLE_CASES])
def test_naive_poc_fails_in_a_real_jail(
    case: FixtureCase, live_executor: LiveServer, tmp_path: Path
) -> None:
    proven = _verify_in_jail(case, case.naive_poc, live_executor, tmp_path, f"scn_n_{case.name}")
    assert proven.verified is False and proven.rung <= 2


def test_prove_rate_before_after_in_a_real_jail(live_executor: LiveServer, tmp_path: Path) -> None:
    """0/N before (naive) -> N/N after (entry-point) against the REAL oracle."""
    before = sum(
        1
        for i, case in enumerate(REACHABLE_CASES)
        if _verify_in_jail(case, case.naive_poc, live_executor, tmp_path, f"scn_rb{i}").rung >= 3
    )
    after = sum(
        1
        for i, case in enumerate(REACHABLE_CASES)
        if _verify_in_jail(case, case.honest_poc, live_executor, tmp_path, f"scn_ra{i}").rung >= 3
    )
    assert before == 0
    assert after == len(REACHABLE_CASES)


def test_planted_false_positive_stays_unproven_in_a_real_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    proven = _verify_in_jail(
        SAFE_QUERY_CASE, SAFE_QUERY_CASE.honest_poc, live_executor, tmp_path, "scn_fp"
    )
    assert proven.verified is False and proven.rung <= 2


def test_cheating_poc_is_rejected_in_a_real_jail(live_executor: LiveServer, tmp_path: Path) -> None:
    proven = _verify_in_jail(SQLI_LOGIN_CASE, CHEAT_POC, live_executor, tmp_path, "scn_cheat")
    assert proven.verified is False and proven.rung <= 2
