"""REAL-JAIL proving of JS/TS findings (``pytest -m docker``): the headline measurement for
the Node sink oracle, the JS sibling of :mod:`test_verifier_fixtures_docker`.

Before this oracle existed, EVERY JS/TS finding came back ``poc_reaches_sink: skipped``
unconditionally (:func:`ono.verifier.oracle.oracle_supports` said "Python only" for any
non-``.py`` file) - see ``test_verifier_oracle_js.py`` for the offline dispatch tests that
now route a JS/TS CWE to the new oracle instead. This file proves the NEW path
against a genuine combined Python+Node jail (``select_image``'s ``"node"`` choice): the
Executor builds a real ``node_modules`` in an ephemeral, network-enabled builder (``npm ci``/
``npm install``) and ships it read-only into the egress-blocked jail, the real Express app
is driven through its own route (behind an import-time secret and an API-key header, exactly
like the Python framework fixtures' login walls), and the in-jail ``node`` oracle's canary
must reach the flagged ``child_process``/``eval`` call with the flagged file:line on the
call stack. Only the model is scripted; the oracle, the container, the builder and the
egress block are all real.

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
from fixturecases import FixtureCase
from jscases import (
    EXPRESS_CMDI_CASE,
    EXPRESS_EVAL_CASE,
    EXPRESS_SAFE_CASE,
    JS_CHEAT_POC,
    JS_REACHABLE_CASES,
)
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.executor.app import create_executor_app
from ono.executor.client import ExecutorClient
from ono.models import Finding
from ono.verifier import GradedVerifier, VerifyReport

pytestmark = pytest.mark.docker

TOKEN = "docker-js-fixtures-token-0123456789"
_NOOP_PATCH = "--- a/does/not/exist.js\n+++ b/does/not/exist.js\n@@ -1 +1 @@\n-x\n+y\n"


@pytest.fixture(scope="module")
def live_executor() -> Iterator[LiveServer]:
    settings = Settings(
        _env_file=None,
        executor_token=SecretStr(TOKEN),
        sandbox_mem_mb=768,  # the combined python+node image + npm's install + pip's tmpfs
        sandbox_pids_limit=128,
        sandbox_cmd_timeout_s=90,
        sandbox_workspace_mb=128,
        sandbox_deps_max_mb=192,
        sandbox_deps_timeout_s=300,  # npm install's registry round-trip
    )
    server = start_live_server(create_executor_app(settings))
    try:
        yield server
    finally:
        server.stop()


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
            return action("submit_poc", code=poc_code, how="drive the real Express route")
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
        sandbox_deps_enabled=provision,
        sandbox_deps_timeout_s=300,
    )
    with ExecutorClient(live.url, TOKEN, timeout_s=180) as client:
        verifier = GradedVerifier(settings, model=ScriptedModel(script=script), executor=client)
        return verifier.verify(scan, workspace, [case.finding(scan)])


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


# ---------------------------------------------------------------------------
# The headline: before (no npm deps -> express does not import) / after (provisioned)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", JS_REACHABLE_CASES, ids=[c.name for c in JS_REACHABLE_CASES])
def test_express_finding_cannot_be_proven_without_npm_dependencies(
    case: FixtureCase, live_executor: LiveServer, tmp_path: Path
) -> None:
    """BEFORE: the honest entry-point PoC dies at `require('express')` in the stock (no-deps)
    jail - the JS equivalent of the Python framework fixtures' prove-rate-0 failure mode."""
    report = _verify_report(
        case,
        case.honest_poc,
        live_executor,
        tmp_path,
        f"scn_js_before_{case.name}",
        provision=False,
    )
    assert report.dependencies is not None and report.dependencies.status == "disabled"
    proven = report.findings[0]
    assert proven.verified is False and proven.rung <= 2
    v = proven.verification
    assert v is not None
    check = v.check("poc_reaches_sink")
    assert check is not None and check.status == "failed"
    assert "MODULE_NOT_FOUND" in check.detail or "Cannot find module 'express'" in check.detail


@pytest.mark.parametrize("case", JS_REACHABLE_CASES, ids=[c.name for c in JS_REACHABLE_CASES])
def test_express_finding_is_proven_rung_3_once_npm_dependencies_are_provisioned(
    case: FixtureCase, live_executor: LiveServer, tmp_path: Path
) -> None:
    """AFTER: the builder runs `npm ci`/`npm install` in an ephemeral, network-enabled
    container and ships node_modules read-only into the egress-blocked combined-image jail;
    the real Express route runs, and the node oracle's canary reaches the flagged sink."""
    report = _verify_report(
        case, case.honest_poc, live_executor, tmp_path, f"scn_js_after_{case.name}"
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


def test_prove_rate_before_after_npm_provisioning_in_a_real_node_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """The headline: 0/N JS findings proven without npm deps -> N/N with them, real jail."""
    before = sum(
        1
        for i, case in enumerate(JS_REACHABLE_CASES)
        if _verify_in_jail(
            case, case.honest_poc, live_executor, tmp_path, f"scn_js_pb{i}", provision=False
        ).rung
        >= 3
    )
    after = sum(
        1
        for i, case in enumerate(JS_REACHABLE_CASES)
        if _verify_in_jail(case, case.honest_poc, live_executor, tmp_path, f"scn_js_pa{i}").rung
        >= 3
    )
    assert before == 0
    assert after == len(JS_REACHABLE_CASES)


# ---------------------------------------------------------------------------
# Integrity: cheat rejection + the planted false positive, same real jail
# ---------------------------------------------------------------------------


def test_naive_js_poc_still_fails_once_provisioned(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """Provisioning makes `require('express')` work; it does NOT make a precondition-
    skipping PoC count - the app's own 401 (missing APP_SECRET) stops it before the sink."""
    proven = _verify_in_jail(
        EXPRESS_CMDI_CASE, EXPRESS_CMDI_CASE.naive_poc, live_executor, tmp_path, "scn_js_naive"
    )
    assert proven.verified is False and proven.rung <= 2


def test_cheating_js_poc_is_rejected_in_a_real_node_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """A PoC that reaches child_process.execSync itself, never through server.js, proves
    nothing - the flagged file:line is never on the call stack."""
    proven = _verify_in_jail(
        EXPRESS_CMDI_CASE, JS_CHEAT_POC, live_executor, tmp_path, "scn_js_cheat"
    )
    assert proven.verified is False and proven.rung <= 2
    v = proven.verification
    assert v is not None
    check = v.check("poc_reaches_sink")
    assert check is not None and check.status == "failed"
    assert "not the flagged sink" in check.detail


def test_planted_js_false_positive_stays_unproven_in_a_real_node_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """spawnSync with an argv array (no shell) runs AT the sink line but is never tainted -
    the verifier must not false-positive just because the route now runs end-to-end."""
    report = _verify_report(
        EXPRESS_SAFE_CASE, EXPRESS_SAFE_CASE.honest_poc, live_executor, tmp_path, "scn_js_fp"
    )
    assert report.dependencies is not None and report.dependencies.status == "provisioned"
    proven = report.findings[0]
    assert proven.verified is False and proven.rung <= 2
    v = proven.verification
    assert v is not None
    check = v.check("poc_reaches_sink")
    assert check is not None and check.status == "failed"
    assert "NOT in its dangerous argument" in check.detail, check.detail


def test_eval_code_injection_is_proven_in_a_real_node_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """A second sink family (CWE-94, eval) through the SAME real jail/app, for breadth."""
    proven = _verify_in_jail(
        EXPRESS_EVAL_CASE, EXPRESS_EVAL_CASE.honest_poc, live_executor, tmp_path, "scn_js_eval"
    )
    assert proven.verified is True and proven.rung >= 3
    v = proven.verification
    assert v is not None and v.check("poc_reaches_sink").status == "passed"
