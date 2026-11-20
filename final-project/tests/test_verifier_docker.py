"""REAL-JAIL integration test for the graded verifier (``pytest -m docker``).

Only the model is scripted; everything else is real: a live Executor service, a genuine
``python:3.13-slim`` jailed container holding the fixture app, the in-jail sink oracle
started with ``python3 -I``, the real unified-diff applier, and the egress-blocked network.
It proves that ``verified=True`` / rung 4 is reached only when a read-only PoC really drove
a canary into the flagged SQL sink inside the container and a patch then stopped it.

Skipped automatically without a Docker daemon or in CI (``conftest.docker_tests_enabled``).
The base image has no pytest, so the target here carries no test suite and ``tests_pass`` is
reported as ``skipped`` (an honest limitation: proving rung 4 with a passing suite needs the
target's own test deps in the sandbox image).
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr

from agentfakes import ScriptedModel, action
from conftest import LiveServer, start_live_server
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.executor.app import create_executor_app
from ono.executor.client import ExecutorClient
from ono.models import Finding, TraceStep, finding_id_for, fingerprint_for
from ono.verifier import GradedVerifier
from test_verifier import SQLI_PATCH, SQLI_POC

pytestmark = pytest.mark.docker

POC_REPO = Path(__file__).parent / "fixtures" / "poc_repo"
TOKEN = "docker-verify-token-0123456789"


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


def _finding() -> Finding:
    file, line, cwe = "app/db.py", 14, "CWE-89"
    return Finding(
        finding_id=finding_id_for("scn_vd", "poc", file, line, cwe),
        fingerprint=fingerprint_for("poc", file, line, cwe),
        scan_id="scn_vd",
        target_id="poc",
        title="SQLi in find_user",
        cwe=cwe,
        severity="high",
        file=file,
        line_range=(line, line),
        trace=[TraceStep(file=file, line=line, symbol="cur.execute", note="sink")],
        confidence=0.8,
        rung=2,
        verified=False,
        description="uid interpolated into SQL",
        patch_diff="",
    )


def _script() -> ScriptedModel:
    def script(messages: list[dict], tools: object) -> str:
        system = messages[0]["content"]
        if system == PROVER.system_prompt:
            return action("submit_poc", code=SQLI_POC, how="drive user_view")
        if system == FIXER.system_prompt:
            return action("submit_patch", diff=SQLI_PATCH, summary="parameterize")
        raise AssertionError("unexpected role")

    return ScriptedModel(script=script)


def test_verifier_proves_and_fixes_in_a_real_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    # A copy of the fixture with no test suite: the base image has no pytest.
    workspace = tmp_path / "scn_vd"
    shutil.copytree(POC_REPO, workspace)
    shutil.rmtree(workspace / "tests")

    settings = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://model.invalid/v1",
        executor_url=live_executor.url,
        executor_token=SecretStr(TOKEN),
        workspace_dir=tmp_path,
        context_lines=6,
        verifier_poc_timeout_s=60.0,
    )
    with ExecutorClient(live_executor.url, TOKEN, timeout_s=120) as client:
        verifier = GradedVerifier(settings, model=_script(), executor=client)
        report = verifier.verify("scn_vd", workspace, [_finding()])
        assert client.list_sandboxes() == []  # the verifier's jail is gone

    proven = report.findings[0]
    assert proven.verified is True and proven.rung == 4
    assert report.reachable == 1 and report.fixed == 1
    v = proven.verification
    assert v is not None
    statuses = {c.name: c.status for c in v.checks}
    assert statuses["poc_reaches_sink"] == "passed"
    assert statuses["patch_applies"] == "passed"
    assert statuses["poc_no_longer_fires"] == "passed"
    assert statuses["tests_pass"] == "skipped"  # no suite in the slim image
    # The proof is anchored to the real jailed run: the oracle saw the canary in the SQL text.
    poc_check = v.check("poc_reaches_sink")
    assert poc_check is not None and "execute" in poc_check.detail
