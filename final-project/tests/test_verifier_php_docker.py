"""REAL-JAIL proving of PHP findings (``pytest -m docker``): the headline measurement for the
PHP sink oracle, the PHP sibling of :mod:`test_verifier_js_docker`.

Before this oracle existed, EVERY PHP finding came back ``poc_reaches_sink: skipped``
unconditionally (:func:`ono.verifier.oracle.oracle_supports` said "Python and JS/TS only" for
any ``.php`` file). This file proves the NEW path against a genuine PHP jail
(``select_image``'s ``"php"`` choice): the real procedural PHP app is driven through its own
``handle()`` route (behind an include-time secret and an API-key check, exactly like the JS
and Python framework fixtures' login walls), and the in-jail ``php`` oracle - hooking
``system`` through the ``uopz`` extension - must observe the canary reach the flagged
``system`` call with the flagged file:line on the ``debug_backtrace`` call stack. Only the
model is scripted; the oracle, the container, the uopz hook and the egress block are all real.

Skipped automatically without a Docker daemon or in CI (``conftest.docker_tests_enabled``), and
also when the PHP jail image is not present on the host (build it with
``docker build -f docker/php-jail.Dockerfile -t ono-php-jail:local .``) - the unit tests in
``test_verifier_oracle_php.py`` cover the pure dispatch/command logic without any image.
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
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.executor.app import create_executor_app
from ono.executor.client import ExecutorClient
from ono.models import Finding
from ono.verifier import GradedVerifier, VerifyReport
from phpcases import PHP_CHEAT_POC, PHP_CMDI_CASE, PHP_SAFE_CASE

pytestmark = pytest.mark.docker

TOKEN = "docker-php-fixtures-token-0123456789"
PHP_IMAGE = "ono-php-jail:local"
_NOOP_PATCH = "--- a/does/not/exist.php\n+++ b/does/not/exist.php\n@@ -1 +1 @@\n-x\n+y\n"


def _php_image_present() -> bool:
    try:
        import docker

        client = docker.from_env(timeout=5)
        client.images.get(PHP_IMAGE)
        return True
    except Exception:
        return False


# The php jail image is built locally (not pulled from a registry), so a host that has Docker
# but has not built it must skip - not error - the whole module.
php_image_required = pytest.mark.skipif(
    not _php_image_present(),
    reason=f"the PHP jail image {PHP_IMAGE} is not present (build docker/php-jail.Dockerfile)",
)


@pytest.fixture(scope="module")
def live_executor() -> Iterator[LiveServer]:
    settings = Settings(
        _env_file=None,
        executor_token=SecretStr(TOKEN),
        sandbox_image_php=PHP_IMAGE,
        sandbox_mem_mb=512,
        sandbox_pids_limit=128,
        sandbox_cmd_timeout_s=60,
        sandbox_workspace_mb=64,
        sandbox_deps_enabled=False,  # no composer provisioning in this piece
    )
    server = start_live_server(create_executor_app(settings))
    try:
        yield server
    finally:
        server.stop()


def _verify_report(
    case: FixtureCase, poc_code: str, live: LiveServer, tmp_path: Path, scan: str
) -> VerifyReport:
    workspace = tmp_path / scan
    shutil.copytree(case.dir, workspace)

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == PROVER.system_prompt:
            return action("submit_poc", code=poc_code, how="drive the real handle() route")
        if system == FIXER.system_prompt:
            return action("submit_patch", diff=_NOOP_PATCH, summary="noop")
        raise AssertionError("unexpected agent role")

    settings = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://model.invalid/v1",
        executor_url=live.url,
        executor_token=SecretStr(TOKEN),
        sandbox_image_php=PHP_IMAGE,
        workspace_dir=tmp_path,
        context_lines=6,
        verifier_poc_timeout_s=45.0,
        max_verifier_retries=1,
        sandbox_deps_enabled=False,
    )
    with ExecutorClient(live.url, TOKEN, timeout_s=180) as client:
        verifier = GradedVerifier(settings, model=ScriptedModel(script=script), executor=client)
        return verifier.verify(scan, workspace, [case.finding(scan)])


def _verify_in_jail(
    case: FixtureCase, poc_code: str, live: LiveServer, tmp_path: Path, scan: str
) -> Finding:
    return _verify_report(case, poc_code, live, tmp_path, scan).findings[0]


# ---------------------------------------------------------------------------
# The headline: the real php+uopz jail proves a PHP command-injection finding at rung 3
# ---------------------------------------------------------------------------


@php_image_required
def test_php_command_injection_is_proven_rung_3_in_a_real_php_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """The real procedural PHP app is driven through handle('/diagnose'); the uopz-hooked
    system() call sees the canary with app.php:32 on the debug_backtrace stack."""
    proven = _verify_in_jail(
        PHP_CMDI_CASE, PHP_CMDI_CASE.honest_poc, live_executor, tmp_path, "scn_php_cmdi"
    )
    assert proven.verified is True and proven.rung >= 3, proven.verification
    v = proven.verification
    assert v is not None and v.check("poc_reaches_sink").status == "passed"
    assert v.evidence and "<PAYLOAD>" in v.evidence
    assert v.poc == PHP_CMDI_CASE.honest_poc


@php_image_required
def test_naive_php_poc_cannot_satisfy_the_include_time_secret(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """A PoC that requires app.php without first setting APP_SECRET throws at include time -
    the real-app failure mode - so it never reaches the sink and stays rung <= 2."""
    proven = _verify_in_jail(
        PHP_CMDI_CASE, PHP_CMDI_CASE.naive_poc, live_executor, tmp_path, "scn_php_naive"
    )
    assert proven.verified is False and proven.rung <= 2


@php_image_required
def test_cheating_php_poc_is_rejected_in_a_real_php_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """A PoC that calls system() itself, never through app.php, proves nothing - the flagged
    file:line is never on the call stack (only the PoC's own .ono/poc.php frame is)."""
    proven = _verify_in_jail(PHP_CMDI_CASE, PHP_CHEAT_POC, live_executor, tmp_path, "scn_php_cheat")
    assert proven.verified is False and proven.rung <= 2
    v = proven.verification
    assert v is not None
    check = v.check("poc_reaches_sink")
    assert check is not None and check.status == "failed"
    assert "not the flagged sink" in check.detail


@php_image_required
def test_planted_php_false_positive_stays_unproven_in_a_real_php_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """proc_open with an argv array (no shell) runs AT the sink line but is never tainted -
    the verifier must not false-positive just because the route now runs end-to-end."""
    proven = _verify_in_jail(
        PHP_SAFE_CASE, PHP_SAFE_CASE.honest_poc, live_executor, tmp_path, "scn_php_fp"
    )
    assert proven.verified is False and proven.rung <= 2
    v = proven.verification
    assert v is not None
    check = v.check("poc_reaches_sink")
    assert check is not None and check.status == "failed"
    assert "NOT in its dangerous argument" in check.detail, check.detail
