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
    DEPENDENCY_CASES,
    FLASK_SAFE_CASE,
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
from ono.verifier import GradedVerifier, VerifyReport

pytestmark = pytest.mark.docker

TOKEN = "docker-fixtures-token-0123456789"
_NOOP_PATCH = "--- a/does/not/exist.py\n+++ b/does/not/exist.py\n@@ -1 +1 @@\n-x\n+y\n"


@pytest.fixture(scope="module")
def live_executor() -> Iterator[LiveServer]:
    settings = Settings(
        _env_file=None,
        executor_token=SecretStr(TOKEN),
        sandbox_mem_mb=512,  # the builder's tmpfs (snapshot + packages + pip temp) counts
        sandbox_pids_limit=64,
        sandbox_cmd_timeout_s=60,
        sandbox_workspace_mb=128,
        sandbox_deps_max_mb=128,
        sandbox_deps_timeout_s=240,
    )
    server = start_live_server(create_executor_app(settings))
    try:
        yield server
    finally:
        server.stop()


def _verify_in_jail(
    case: FixtureCase,
    poc_code: str,
    live: LiveServer,
    tmp_path: Path,
    scan: str,
    *,
    provision: bool = True,
) -> Finding:
    return _verify_report(case, poc_code, live, tmp_path, scan, provision=provision).findings[0]


def _verify_report(
    case: FixtureCase,
    poc_code: str,
    live: LiveServer,
    tmp_path: Path,
    scan: str,
    *,
    provision: bool = True,
) -> VerifyReport:
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
        sandbox_deps_enabled=provision,  # False = the pre-provisioning verifier
        sandbox_deps_timeout_s=240,
    )
    with ExecutorClient(live.url, TOKEN, timeout_s=120) as client:
        verifier = GradedVerifier(settings, model=ScriptedModel(script=script), executor=client)
        return verifier.verify(scan, workspace, [case.finding(scan)])


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


def test_stdlib_fixture_without_a_manifest_reports_skipped_provisioning(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """A repo with no manifest: no builder, 'skipped' recorded, and the proof is unchanged."""
    report = _verify_report(
        SQLI_LOGIN_CASE, SQLI_LOGIN_CASE.honest_poc, live_executor, tmp_path, "scn_nomani"
    )
    assert report.dependencies is not None and report.dependencies.status == "skipped"
    proven = report.findings[0]
    assert proven.verified is True and proven.rung >= 3
    assert proven.verification is not None
    assert proven.verification.dependencies.startswith("skipped: no dependency manifest")


# ---------------------------------------------------------------------------
# REAL framework apps: the dependency wall, before and after provisioning
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", DEPENDENCY_CASES, ids=[c.name for c in DEPENDENCY_CASES])
def test_framework_app_cannot_be_proven_without_its_dependencies(
    case: FixtureCase, live_executor: LiveServer, tmp_path: Path
) -> None:
    """BEFORE: the honest entry-point PoC dies at `import flask` / `import fastapi` in the
    stock jail - the exact failure the live 10-repo run showed (prove-rate 0)."""
    report = _verify_report(
        case, case.honest_poc, live_executor, tmp_path, f"scn_before_{case.name}", provision=False
    )
    assert report.dependencies is not None and report.dependencies.status == "disabled"
    proven = report.findings[0]
    assert proven.verified is False and proven.rung <= 2
    v = proven.verification
    assert v is not None
    check = v.check("poc_reaches_sink")
    assert check is not None and check.status == "failed"
    module = case.expected_packages[0]
    assert f"ModuleNotFoundError: No module named '{module}'" in check.detail, check.detail


@pytest.mark.parametrize("case", DEPENDENCY_CASES, ids=[c.name for c in DEPENDENCY_CASES])
def test_framework_app_is_proven_once_dependencies_are_provisioned(
    case: FixtureCase, live_executor: LiveServer, tmp_path: Path
) -> None:
    """AFTER: the builder installs the declared packages (requirements.txt / pyproject.toml),
    they are shipped read-only into the network-less jail, the real app imports, the test
    client drives the route, and the oracle's canary reaches the flagged sink -> rung 3."""
    report = _verify_report(
        case, case.honest_poc, live_executor, tmp_path, f"scn_after_{case.name}"
    )
    deps = report.dependencies
    assert deps is not None and deps.status == "provisioned", deps
    installed = {p.split()[0].lower() for p in deps.installed}
    assert set(case.expected_packages) <= installed, deps.installed
    proven = report.findings[0]
    assert proven.verified is True and proven.rung >= 3, proven.verification
    v = proven.verification
    assert v is not None and v.check("poc_reaches_sink").status == "passed"
    assert v.evidence and "<PAYLOAD>" in v.evidence
    assert v.dependencies.startswith("provisioned")
    assert v.poc == case.honest_poc


@pytest.mark.parametrize("case", DEPENDENCY_CASES, ids=[c.name for c in DEPENDENCY_CASES])
def test_naive_poc_still_fails_with_dependencies_provisioned(
    case: FixtureCase, live_executor: LiveServer, tmp_path: Path
) -> None:
    """Provisioning makes the app importable; it does NOT make a precondition-skipping PoC
    count. The route's own 401/403 stops it before the sink."""
    proven = _verify_in_jail(
        case, case.naive_poc, live_executor, tmp_path, f"scn_naive_{case.name}"
    )
    assert proven.verified is False and proven.rung <= 2


def test_prove_rate_before_after_provisioning_in_a_real_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """The headline: 0/N real framework apps proven without their deps -> N/N with them."""
    before = sum(
        1
        for i, case in enumerate(DEPENDENCY_CASES)
        if _verify_in_jail(
            case, case.honest_poc, live_executor, tmp_path, f"scn_pb{i}", provision=False
        ).rung
        >= 3
    )
    after = sum(
        1
        for i, case in enumerate(DEPENDENCY_CASES)
        if _verify_in_jail(case, case.honest_poc, live_executor, tmp_path, f"scn_pa{i}").rung >= 3
    )
    assert before == 0
    assert after == len(DEPENDENCY_CASES)


def test_planted_flask_false_positive_stays_unproven_with_dependencies(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """Flask provisioned, route driven, parameter bound: the canary never enters the SQL text,
    so the verifier must NOT false-positive just because the app now imports."""
    report = _verify_report(
        FLASK_SAFE_CASE, FLASK_SAFE_CASE.honest_poc, live_executor, tmp_path, "scn_flask_fp"
    )
    assert report.dependencies is not None and report.dependencies.status == "provisioned"
    proven = report.findings[0]
    assert proven.verified is False and proven.rung <= 2
    v = proven.verification
    assert v is not None
    check = v.check("poc_reaches_sink")
    assert check is not None and check.status == "failed"
    assert "NOT in its dangerous argument" in check.detail, check.detail
