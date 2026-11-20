"""The graded verifier (step 3b-2), offline: a real in-jail sink oracle, real patch applier
and a real pytest run against a working copy of ``tests/fixtures/poc_repo`` - only the model
is scripted (:class:`agentfakes.ScriptedModel`) and Docker is replaced by
:class:`agentfakes.LocalExecSandbox`.

These prove the claims the product makes: ``verified=True`` is set only when a read-only PoC
really carried a secret canary into the flagged sink (rung 3) and, for rung 4, a patch
applied, that same PoC no longer fired and the tests still passed. Nothing is faked: the
canary flows through the application's own code, and a PoC that cheats (calls the sink
itself) does not count.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from agentfakes import FakeExecExecutor, LocalExecSandbox, ScriptedModel, action
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.executor.models import RunResult
from ono.models import Finding, TraceStep, finding_id_for, fingerprint_for
from ono.verifier import GradedVerifier, verify_anchor
from ono.verifier.oracle import OracleResult, explain, parse_result

POC_REPO = Path(__file__).parent / "fixtures" / "poc_repo"

# A PoC that drives the application's own handler so the payload reaches the SQL sink.
SQLI_POC = (
    "import os\n"
    "from app.handlers import user_view\n"
    'user_view({"args": {"id": os.environ["ONO_PAYLOAD"]}})\n'
)
# A PoC that "cheats": it triggers the sink itself instead of through the app. Must NOT count.
SQLI_CHEAT_POC = (
    "import os, sqlite3\n"
    "sqlite3.connect(':memory:').execute('SELECT ' + os.environ['ONO_PAYLOAD'])\n"
)
# Parameterized-query fix for app/db.py:14 (offset-tolerant context).
SQLI_PATCH = (
    "--- a/app/db.py\n"
    "+++ b/app/db.py\n"
    "@@ -13,3 +13,3 @@\n"
    "     cur = conn.cursor()\n"
    '-    cur.execute(f"SELECT name FROM users WHERE id = {uid}")\n'
    '+    cur.execute("SELECT name FROM users WHERE id = ?", (uid,))\n'
    "     row = cur.fetchone()\n"
)
# A patch that will not apply (wrong context).
SQLI_BAD_PATCH = (
    "--- a/app/db.py\n"
    "+++ b/app/db.py\n"
    "@@ -13,3 +13,3 @@\n"
    "     not a real line\n"
    '-    cur.execute("nope")\n'
    '+    cur.execute("SELECT name FROM users WHERE id = ?", (uid,))\n'
    "     another missing line\n"
)


def _settings(workspace: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "model_backend": "service",
        "model_service_url": "http://model.test/v1",
        "model_name": "qwen2.5-coder:7b",
        "executor_token": SecretStr("unit-test-token-0123456789"),
        "workspace_dir": workspace,
        "context_lines": 6,
        "verifier_poc_timeout_s": 60.0,
        "verifier_tests_timeout_s": 120.0,
    }
    return Settings(_env_file=None, **{**base, **overrides})


def _finding(
    *, file: str, line: int, cwe: str, scan_id: str = "scn_v", target_id: str = "poc"
) -> Finding:
    return Finding(
        finding_id=finding_id_for(scan_id, target_id, file, line, cwe),
        fingerprint=fingerprint_for(target_id, file, line, cwe),
        scan_id=scan_id,
        target_id=target_id,
        title=f"{cwe} at {file}:{line}",
        cwe=cwe,
        severity="high",
        file=file,
        line_range=(line, line),
        trace=[TraceStep(file=file, line=line, symbol="sink", note="flagged by SAST")],
        confidence=0.8,
        rung=2,
        verified=False,
        description="model-asserted finding",
        patch_diff="",
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A writable copy of the dependency-free vulnerable fixture app."""
    ws = tmp_path / "scn_v"
    shutil.copytree(POC_REPO, ws)
    return ws


def _prover_fixer_script(poc_replies: list[str], patch_replies: list[str]) -> Any:
    provers = list(poc_replies)
    fixers = list(patch_replies)

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == PROVER.system_prompt:
            return provers.pop(0)
        if system == FIXER.system_prompt:
            return fixers.pop(0)
        raise AssertionError("unexpected agent role in verifier test")

    return script


def _verifier(settings: Settings, model: ScriptedModel) -> tuple[GradedVerifier, FakeExecExecutor]:
    executor = FakeExecExecutor()
    return GradedVerifier(settings, model=model, executor=executor), executor


# ---------------------------------------------------------------------------
# anchor + oracle unit behaviour
# ---------------------------------------------------------------------------


def test_anchor_passes_on_a_real_sink_line(workspace: Path) -> None:
    sandbox = LocalExecSandbox(workspace)
    check = verify_anchor(_finding(file="app/db.py", line=14, cwe="CWE-89"), sandbox)
    assert check.status == "passed"


def test_anchor_fails_on_a_blank_or_out_of_range_line(workspace: Path) -> None:
    sandbox = LocalExecSandbox(workspace)
    check = verify_anchor(_finding(file="app/db.py", line=999, cwe="CWE-89"), sandbox)
    assert check.status == "failed" and "blank or out of range" in check.detail


def test_parse_result_handles_a_timeout() -> None:
    run = RunResult(
        cmd="x", stdout="", stderr="", exit_code=None, duration_ms=100.0, timed_out=True
    )
    result = parse_result(run)
    assert result.ok is False and "did not finish" in result.error


def test_explain_names_the_cheating_poc() -> None:
    finding = _finding(file="app/shell.py", line=5, cwe="CWE-78")
    result = OracleResult(
        ok=True,
        fired=False,
        reached_elsewhere=[{"kind": "os.system", "stack": [{"file": ".ono/poc.py", "line": 2}]}],
    )
    assert "not the flagged sink" in explain(result, finding)


# ---------------------------------------------------------------------------
# rung 3 + rung 4 end to end (real oracle, real patch, real pytest)
# ---------------------------------------------------------------------------


def test_sqli_is_proven_reachable_and_fixed(workspace: Path) -> None:
    model = ScriptedModel(
        script=_prover_fixer_script(
            [action("submit_poc", code=SQLI_POC, how="drive user_view")],
            [action("submit_patch", diff=SQLI_PATCH, summary="parameterize")],
        )
    )
    verifier, executor = _verifier(_settings(workspace), model)
    finding = _finding(file="app/db.py", line=14, cwe="CWE-89")

    report = verifier.verify("scn_v", workspace, [finding])

    assert executor.events == ["create scn_v", "destroy scn_v"]
    assert report.reachable == 1 and report.fixed == 1
    proven = report.findings[0]
    assert proven.verified is True and proven.rung == 4
    assert proven.patch_diff.strip() and "execute(" in proven.patch_diff
    v = proven.verification
    assert v is not None
    statuses = {c.name: c.status for c in v.checks}
    assert statuses == {
        "anchor": "passed",
        "poc_reaches_sink": "passed",
        "patch_applies": "passed",
        "poc_no_longer_fires": "passed",
        "tests_pass": "passed",
    }
    assert v.poc.strip() == SQLI_POC.strip()
    assert "execute" in (v.check("poc_reaches_sink").detail if v.check("poc_reaches_sink") else "")


def test_prover_self_corrects_after_a_cheating_poc(workspace: Path) -> None:
    """First PoC triggers the sink itself (does not count); the second drives the app."""
    model = ScriptedModel(
        script=_prover_fixer_script(
            [
                action("submit_poc", code=SQLI_CHEAT_POC, how="cheat"),
                action("submit_poc", code=SQLI_POC, how="real"),
            ],
            [action("submit_patch", diff=SQLI_PATCH, summary="parameterize")],
        )
    )
    verifier, _ = _verifier(_settings(workspace), model)
    finding = _finding(file="app/db.py", line=14, cwe="CWE-89")

    report = verifier.verify("scn_v", workspace, [finding])

    proven = report.findings[0]
    assert proven.verified is True and proven.rung == 4
    v = proven.verification
    assert v is not None and v.attempts >= 2  # the cheat attempt plus the real one


def test_fixer_self_corrects_after_a_patch_that_does_not_apply(workspace: Path) -> None:
    model = ScriptedModel(
        script=_prover_fixer_script(
            [action("submit_poc", code=SQLI_POC, how="real")],
            [
                action("submit_patch", diff=SQLI_BAD_PATCH, summary="broken"),
                action("submit_patch", diff=SQLI_PATCH, summary="parameterize"),
            ],
        )
    )
    verifier, _ = _verifier(_settings(workspace), model)
    finding = _finding(file="app/db.py", line=14, cwe="CWE-89")

    report = verifier.verify("scn_v", workspace, [finding])

    proven = report.findings[0]
    assert proven.verified is True and proven.rung == 4
    v = proven.verification
    assert v is not None
    # The final record shows the patch that actually applied and closed the hole.
    assert {c.name: c.status for c in v.checks}["patch_applies"] == "passed"


def test_reachable_but_unfixable_stays_rung_3(workspace: Path) -> None:
    """A proven PoC with no working patch keeps rung 3 (verified: it IS reachable)."""
    model = ScriptedModel(
        script=_prover_fixer_script(
            [action("submit_poc", code=SQLI_POC, how="real")],
            [action("submit_patch", diff=SQLI_BAD_PATCH, summary="still broken")]
            * (_settings(workspace).max_verifier_retries),
        )
    )
    verifier, _ = _verifier(_settings(workspace), model)
    finding = _finding(file="app/db.py", line=14, cwe="CWE-89")

    report = verifier.verify("scn_v", workspace, [finding])

    proven = report.findings[0]
    assert proven.rung == 3 and proven.verified is True
    assert report.reachable == 1 and report.fixed == 0
    v = proven.verification
    assert v is not None
    assert {c.name: c.status for c in v.checks}.get("patch_applies") == "failed"


def test_give_up_when_no_poc_reaches_the_sink(workspace: Path) -> None:
    """Only cheating PoCs: the finding is never proven and stays model-asserted (rung 2)."""
    settings = _settings(workspace)
    model = ScriptedModel(
        script=_prover_fixer_script(
            [action("submit_poc", code=SQLI_CHEAT_POC, how="cheat")]
            * settings.max_verifier_retries,
            [],
        )
    )
    verifier, _ = _verifier(settings, model)
    finding = _finding(file="app/db.py", line=14, cwe="CWE-89")

    report = verifier.verify("scn_v", workspace, [finding])

    unproven = report.findings[0]
    assert unproven.verified is False and unproven.rung == 2
    assert report.reachable == 0
    v = unproven.verification
    assert v is not None
    poc_check = v.check("poc_reaches_sink")
    assert poc_check is not None and poc_check.status == "failed"
    assert v.attempts == settings.max_verifier_retries


def test_unsupported_language_skips_the_oracle_without_claiming_proof(workspace: Path) -> None:
    (workspace / "app.js").write_text("app.get('/x', (req) => db.query(req.query.id))\n")
    model = ScriptedModel(script=_prover_fixer_script([], []))  # no agent should be called
    verifier, _ = _verifier(_settings(workspace), model)
    finding = _finding(file="app.js", line=1, cwe="CWE-89")

    report = verifier.verify("scn_v", workspace, [finding])

    unproven = report.findings[0]
    assert unproven.verified is False and unproven.rung == 2
    assert model.n_calls == 0  # the prover never ran
    v = unproven.verification
    assert v is not None
    poc_check = v.check("poc_reaches_sink")
    assert (
        poc_check is not None
        and poc_check.status == "skipped"
        and "Python only" in poc_check.detail
    )
