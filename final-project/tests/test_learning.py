"""The learning loop (plan section 1.5), offline and end to end.

Two kinds of test:

* unit - the durable SQLite scan store, the knowledge memory, and the harvest step.
* **the demonstration** - run the real graded verifier over the same finding across several
  rounds against a *memory-sensitive* model (it writes a correct PoC only once a prior
  verified PoC has been seeded into its prompt - which is how a frozen 7B actually behaves
  when shown a worked example). Round 1 has an empty memory and needs a self-correction
  round; the harvested PoC then seeds round 2, which fires on the first attempt. The headline
  metric - mean prover attempts-to-fire - drops, and we assert it.

Everything is deterministic: a real in-jail oracle (via LocalExecSandbox), the real diff
applier and a real pytest run; only the model is scripted.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from agentfakes import FakeExecExecutor, ScriptedModel, action
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.learning import KnowledgeMemory, improvement, round_metrics, signature_for
from ono.learning.harvest import harvest_findings
from ono.models import (
    Finding,
    Scan,
    TraceStep,
    Verification,
    VerificationCheck,
    finding_id_for,
    fingerprint_for,
    utcnow,
)
from ono.store import SqliteScanStore
from ono.verifier import GradedVerifier
from test_verifier import SQLI_CHEAT_POC, SQLI_PATCH, SQLI_POC

POC_REPO = Path(__file__).parent / "fixtures" / "poc_repo"


# ---------------------------------------------------------------------------
# Durable scan store
# ---------------------------------------------------------------------------


def _scan(scan_id: str = "scn_a") -> Scan:
    return Scan(
        scan_id=scan_id,
        target_id="pygoat",
        status="done",
        model_backend="service",
        created_at=utcnow(),
        findings_count=1,
    )


def _finding(file: str = "app/db.py", line: int = 14, cwe: str = "CWE-89") -> Finding:
    return Finding(
        finding_id=finding_id_for("scn_a", "poc", file, line, cwe),
        fingerprint=fingerprint_for("poc", file, line, cwe),
        scan_id="scn_a",
        target_id="poc",
        title=f"{cwe} at {file}:{line}",
        cwe=cwe,
        severity="high",
        file=file,
        line_range=(line, line),
        trace=[TraceStep(file=file, line=line, symbol="cur.execute", note="sink")],
        confidence=0.8,
        rung=2,
        verified=False,
        description="model-asserted",
        patch_diff="",
    )


def test_sqlite_store_survives_a_reopen(tmp_path: Path) -> None:
    path = tmp_path / "scans.sqlite3"
    store = SqliteScanStore(path)
    store.put_scan(_scan(), [_finding()])
    store.close()

    reopened = SqliteScanStore(path)  # a fresh process would do exactly this
    scan = reopened.get_scan("scn_a")
    assert scan is not None and scan.status == "done"
    findings = reopened.get_findings("scn_a")
    assert findings is not None and len(findings) == 1 and findings[0].cwe == "CWE-89"
    assert reopened.get_findings("nope") is None


def test_sqlite_store_update_is_atomic(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "s.sqlite3")
    store.put_scan(_scan(), [])
    updated = store.update_scan("scn_a", lambda s: s.model_copy(update={"status": "failed"}))
    assert updated is not None and updated.status == "failed"
    assert store.get_scan("scn_a").status == "failed"  # type: ignore[union-attr]
    assert store.update_scan("missing", lambda s: s) is None


# ---------------------------------------------------------------------------
# Knowledge memory + harvest
# ---------------------------------------------------------------------------


def _proven_finding(poc: str = SQLI_POC) -> Finding:
    f = _finding()
    return f.model_copy(
        update={
            "rung": 4,
            "verified": True,
            "verification": Verification(
                poc=poc,
                poc_attempts=1,
                evidence="execute at app/db.py:14 received the payload",
                checks=[
                    VerificationCheck(
                        name="poc_reaches_sink",
                        status="passed",
                        detail="execute at app/db.py:14 ...",
                    )
                ],
            ),
        }
    )


def test_memory_records_and_seeds(tmp_path: Path) -> None:
    memory = KnowledgeMemory(tmp_path / "k.sqlite3")
    memory.record_success(cwe="CWE-89", sink_kind="execute", poc_skeleton=SQLI_POC, plan_hint="h")
    assert memory.get(signature_for("CWE-89", "execute")) is not None

    seed = memory.seed_for(_finding())  # same CWE + sink kind
    assert "earlier scan" in seed and "ONO_PAYLOAD" in seed
    assert memory.stats()["reuses"] == 1  # seeding counted a reuse

    # A different CWE with no entry yields no seed.
    assert memory.seed_for(_finding(cwe="CWE-78")) == ""


def test_harvest_only_keeps_verified_findings(tmp_path: Path) -> None:
    memory = KnowledgeMemory(tmp_path / "k.sqlite3")
    harvested = harvest_findings([_proven_finding(), _finding()], memory)  # one proven, one not
    assert harvested == 1
    assert memory.stats()["entries"] == 1
    entry = memory.lookup("CWE-89", "execute")
    assert entry is not None and entry.poc_skeleton.strip() == SQLI_POC.strip()


def test_memory_reopen_is_durable(tmp_path: Path) -> None:
    path = tmp_path / "k.sqlite3"
    KnowledgeMemory(path).record_success(cwe="CWE-89", sink_kind="execute", poc_skeleton=SQLI_POC)
    assert KnowledgeMemory(path).lookup("CWE-89", "execute") is not None


# ---------------------------------------------------------------------------
# The demonstration: the metric moves across rounds
# ---------------------------------------------------------------------------


def _settings(workspace: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "model_backend": "service",
        "model_service_url": "http://model.test/v1",
        "model_name": "qwen2.5-coder:7b",
        "executor_token": SecretStr("unit-test-token-0123456789"),
        "workspace_dir": workspace,
        "context_lines": 6,
        "learning_enabled": True,
    }
    return Settings(_env_file=None, **{**base, **overrides})


def _memory_sensitive_model() -> ScriptedModel:
    """Models a frozen 7B shown a worked example: it writes the correct PoC immediately when
    a prior verified PoC is seeded into its prompt, and otherwise flails once (a cheating PoC)
    before the verifier's feedback corrects it."""

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == FIXER.system_prompt:
            return action("submit_patch", diff=SQLI_PATCH, summary="parameterize")
        assert system == PROVER.system_prompt
        task = messages[1]["content"]
        seeded = "earlier scan" in task
        corrected = any(
            m["role"] == "user" and "did NOT prove" in m.get("content", "") for m in messages
        )
        if seeded or corrected:
            return action("submit_poc", code=SQLI_POC, how="drive user_view")
        return action("submit_poc", code=SQLI_CHEAT_POC, how="cheat")

    return ScriptedModel(script=script)


def _round(workspace: Path, memory: KnowledgeMemory, settings: Settings) -> Any:
    ws = workspace.parent / "round_ws"
    if ws.exists():
        shutil.rmtree(ws)
    shutil.copytree(POC_REPO, ws)
    verifier = GradedVerifier(
        settings, model=_memory_sensitive_model(), executor=FakeExecExecutor(), memory=memory
    )
    finding = _finding()
    return verifier.verify("scn_r", ws, [finding])


def test_learning_reduces_prover_attempts_across_rounds(tmp_path: Path) -> None:
    workspace = tmp_path / "scn_r"
    shutil.copytree(POC_REPO, workspace)
    settings = _settings(workspace)
    memory = KnowledgeMemory(tmp_path / "knowledge.sqlite3")

    reports = [_round(workspace, memory, settings) for _ in range(3)]
    metrics = [round_metrics(r, i, memory.stats()["entries"]) for i, r in enumerate(reports)]

    # Round 0: empty memory -> the prover cheats once, is corrected, fires on attempt 2.
    assert metrics[0].seeded == 0
    assert metrics[0].mean_poc_attempts == 2.0
    assert metrics[0].reachable == 1  # still proven, just with a self-correction round

    # Round 0 harvested the working PoC; later rounds are seeded and fire on attempt 1.
    assert metrics[1].seeded == 1
    assert metrics[-1].mean_poc_attempts == 1.0

    imp = improvement(metrics)
    assert imp.improved and imp.attempts_delta == -1.0
    # The memory holds exactly the one harvested solution, reused on the later rounds.
    assert memory.stats()["entries"] == 1 and memory.stats()["reuses"] >= 2


def test_learning_disabled_leaves_no_memory_effect(tmp_path: Path) -> None:
    """With learning off there is no seeding and nothing is harvested (control)."""
    workspace = tmp_path / "scn_r"
    shutil.copytree(POC_REPO, workspace)
    settings = _settings(workspace, learning_enabled=False)
    verifier = GradedVerifier(
        settings, model=_memory_sensitive_model(), executor=FakeExecExecutor(), memory=None
    )
    report = verifier.verify("scn_r", workspace, [_finding()])
    proven = report.findings[0]
    assert proven.verification is not None and proven.verification.seeded is False
    assert report.harvested == 0
