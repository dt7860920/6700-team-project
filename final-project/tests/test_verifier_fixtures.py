"""Prove-rate on the harder, realistic fixtures (offline oracle via :class:`LocalExecSandbox`,
which runs the REAL ``_oracle.py`` under the host interpreter; the stdlib-only fixtures
behave identically in the jail, and ``tests/test_verifier_fixtures_docker.py`` reruns the
same cases against a genuine ``python:3.13-slim`` container).

What these lock in:

* BEFORE (a naive from-scratch PoC) the sink is never reached -> rung stays <= 2. This is
  the live-run failure the fix targets.
* AFTER (an entry-point-driven PoC, the kind the new scaffold guides the prover to write)
  the canary reaches the flagged sink -> rung 3. Prove-rate goes 0 -> N.
* A planted false positive (a parameterized query) is NOT proven even with an honest
  entry-point PoC: the verifier does not false-positive.
* A cheating PoC (triggers a SQL sink itself, not through the flagged line) is rejected.

Integrity: the oracle picks the canary at verify time; every PoC reads it from
``os.environ["ONO_PAYLOAD"]`` and drives the real request path. Nothing here hands the model
a payload or the canary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from agentfakes import FakeExecExecutor, ScriptedModel, action
from fixturecases import (
    ALL_CASES,
    CHEAT_POC,
    REACHABLE_CASES,
    SAFE_QUERY_CASE,
    SQLI_LOGIN_CASE,
    FixtureCase,
)
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.models import Finding
from ono.verifier import GradedVerifier

# A patch the fixer offers that will not apply: it keeps reachable cases at rung 3 (proven
# reachable) without us having to hand-write a correct diff per fixture - rung 4 is covered
# by test_verifier.py. The prove-rate we measure here is "reached rung 3".
_NOOP_PATCH = "--- a/does/not/exist.py\n+++ b/does/not/exist.py\n@@ -1 +1 @@\n-x\n+y\n"


def _settings(workspace: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "model_backend": "service",
        "model_service_url": "http://model.test/v1",
        "executor_token": SecretStr("unit-test-token-0123456789"),
        "workspace_dir": workspace,
        "context_lines": 6,
        "verifier_poc_timeout_s": 60.0,
        "verifier_tests_timeout_s": 60.0,
        "max_verifier_retries": 1,
    }
    return Settings(_env_file=None, **{**base, **overrides})


def _run(case: FixtureCase, poc_code: str, tmp_path: Path, scan: str = "scn_fx") -> Finding:
    """Verify ``case`` with a scripted prover returning ``poc_code`` (fixer offers a no-op)."""
    workspace = tmp_path / scan
    import shutil

    shutil.copytree(case.dir, workspace)

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == PROVER.system_prompt:
            return action("submit_poc", code=poc_code, how="drive the real entry point")
        if system == FIXER.system_prompt:
            return action("submit_patch", diff=_NOOP_PATCH, summary="noop")
        raise AssertionError("unexpected agent role")

    verifier = GradedVerifier(
        _settings(workspace), model=ScriptedModel(script=script), executor=FakeExecExecutor()
    )
    report = verifier.verify(scan, workspace, [case.finding(scan)])
    return report.findings[0]


@pytest.mark.parametrize("case", REACHABLE_CASES, ids=[c.name for c in REACHABLE_CASES])
def test_naive_poc_does_not_reach_the_sink(case: FixtureCase, tmp_path: Path) -> None:
    """BEFORE: a from-scratch script that ignores import-time setup / route preconditions
    never reaches the sink, so the finding stays model-asserted (rung <= 2, unverified)."""
    proven = _run(case, case.naive_poc, tmp_path)
    assert proven.verified is False
    assert proven.rung <= 2
    v = proven.verification
    assert v is not None
    poc_check = v.check("poc_reaches_sink")
    assert poc_check is not None and poc_check.status == "failed"


@pytest.mark.parametrize("case", REACHABLE_CASES, ids=[c.name for c in REACHABLE_CASES])
def test_entry_point_poc_proves_the_sink(case: FixtureCase, tmp_path: Path) -> None:
    """AFTER: driving the real entry point carries the canary into the flagged sink -> rung 3."""
    proven = _run(case, case.honest_poc, tmp_path)
    assert proven.verified is True, f"{case.name} should be proven reachable"
    assert proven.rung >= 3
    v = proven.verification
    assert v is not None
    assert v.check("poc_reaches_sink").status == "passed"
    assert v.evidence  # the oracle recorded what it saw at the sink


def test_prove_rate_improves_from_zero(tmp_path: Path) -> None:
    """The headline metric: 0/N with naive PoCs, N/N with entry-point PoCs."""
    before = sum(
        1
        for i, case in enumerate(REACHABLE_CASES)
        if _run(case, case.naive_poc, tmp_path, scan=f"scn_b{i}").rung >= 3
    )
    after = sum(
        1
        for i, case in enumerate(REACHABLE_CASES)
        if _run(case, case.honest_poc, tmp_path, scan=f"scn_a{i}").rung >= 3
    )
    assert before == 0
    assert after == len(REACHABLE_CASES)


def test_planted_false_positive_is_not_proven(tmp_path: Path) -> None:
    """A parameterized query flagged as SQLi: the sink runs but the payload is a bound
    parameter, so the verifier must leave it unproven (no false positive)."""
    proven = _run(SAFE_QUERY_CASE, SAFE_QUERY_CASE.honest_poc, tmp_path)
    assert proven.verified is False
    assert proven.rung <= 2
    v = proven.verification
    assert v is not None
    poc_check = v.check("poc_reaches_sink")
    assert poc_check is not None and poc_check.status == "failed"
    # The honest reason: the sink executed but the canary was not in its dangerous argument.
    assert "NOT in its dangerous argument" in poc_check.detail or "sanitized" in poc_check.detail


def test_cheating_poc_is_rejected(tmp_path: Path) -> None:
    """A PoC that triggers a SQL sink itself (not via the flagged line) does not count."""
    proven = _run(SQLI_LOGIN_CASE, CHEAT_POC, tmp_path)
    assert proven.verified is False
    assert proven.rung <= 2


def test_cases_cover_the_supported_cwe_families() -> None:
    assert {c.cwe for c in ALL_CASES} == {"CWE-89", "CWE-78", "CWE-22"}
