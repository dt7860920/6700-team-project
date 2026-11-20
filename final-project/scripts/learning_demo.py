"""Reproducible demonstration that ONO's learning loop moves a real number.

Runs the graded verifier over the same proven finding for several rounds against a
*memory-sensitive* model (it writes a correct PoC immediately when a prior verified PoC has
been seeded into its prompt - how a frozen 7B behaves when shown a worked example, and
otherwise flails once before the verifier corrects it). Round 1 starts with an empty
knowledge memory; the PoC it eventually proves is harvested and seeds the next round.

It prints the per-round table and the improvement in the headline metric - mean prover
attempts-to-fire - and exits non-zero if the metric did not improve. Same mechanism as
``tests/test_learning.py``, runnable by hand:

    uv run scripts/learning_demo.py --rounds 4
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from pydantic import SecretStr

from agentfakes import FakeExecExecutor, ScriptedModel, action
from ono.agents.definitions import FIXER
from ono.config import Settings
from ono.learning import KnowledgeMemory, improvement, round_metrics
from ono.models import Finding, TraceStep, finding_id_for, fingerprint_for
from ono.verifier import GradedVerifier
from test_verifier import SQLI_CHEAT_POC, SQLI_PATCH, SQLI_POC

POC_REPO = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "poc_repo"


def model() -> ScriptedModel:
    def script(messages: list[dict], tools: object) -> str:
        system = messages[0]["content"]
        if system == FIXER.system_prompt:
            return action("submit_patch", diff=SQLI_PATCH, summary="parameterize")
        task = messages[1]["content"]
        corrected = any("did NOT prove" in m.get("content", "") for m in messages)
        if "earlier scan" in task or corrected:
            return action("submit_poc", code=SQLI_POC, how="real")
        return action("submit_poc", code=SQLI_CHEAT_POC, how="cheat")

    return ScriptedModel(script=script)


def finding() -> Finding:
    f, line, cwe = "app/db.py", 14, "CWE-89"
    return Finding(
        finding_id=finding_id_for("scn", "poc", f, line, cwe),
        fingerprint=fingerprint_for("poc", f, line, cwe),
        scan_id="scn",
        target_id="poc",
        title="SQLi",
        cwe=cwe,
        severity="high",
        file=f,
        line_range=(line, line),
        trace=[TraceStep(file=f, line=line, symbol="cur.execute", note="sink")],
        confidence=0.8,
        rung=2,
        verified=False,
        description="uid interpolated into SQL",
        patch_diff="",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()

    tmp = Path(tempfile.mkdtemp())
    settings = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://model.test/v1",
        executor_token=SecretStr("demo-token-0123456789"),
        workspace_dir=tmp,
        context_lines=6,
        learning_enabled=True,
    )
    memory = KnowledgeMemory(tmp / "knowledge.sqlite3")

    print(f"Learning-loop demo: {args.rounds} rounds over the same CWE-89 finding\n")
    metrics = []
    for i in range(args.rounds):
        ws = tmp / f"ws_{i}"
        shutil.copytree(POC_REPO, ws)
        verifier = GradedVerifier(
            settings, model=model(), executor=FakeExecExecutor(), memory=memory
        )
        report = verifier.verify("scn", ws, [finding()])
        m = round_metrics(report, i, memory.stats()["entries"])
        metrics.append(m)
        print("  " + m.as_row())

    imp = improvement(metrics)
    print("\n" + imp.summary())
    shutil.rmtree(tmp, ignore_errors=True)
    if not imp.improved:
        print("\nFAIL: the metric did not improve across rounds")
        return 1
    print("\nLearning loop: GREEN (mean prover attempts-to-fire trended down)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
