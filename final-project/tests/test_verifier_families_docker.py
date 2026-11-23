"""REAL-JAIL validation of the nearest-manifest fix and the added CWE families
(``pytest -m docker``).

Everything but the model is real: a live Executor, the hardened builder that installs the
target's declared Flask into a ``python:3.13-slim`` network-none jail, and the in-jail sink
oracle started with ``python3 -I``. A family is proven only when the oracle's secret canary
reaches that family's dangerous argument with the flagged line on the call stack.

Two things are measured here:

* the nearest-manifest lever: a pygoat-shaped repo (Django root, nested Flask lab) whose sink
  cannot be proven when provisioned from the ROOT manifest (no Flask) but reaches rung 3 once
  provisioned from the lab's OWN requirements.txt - before/after on the real oracle;
* the new families (SSTI, open redirect, reflected unescaped output, file-path control,
  XPath) each reachable on the real oracle only after the framework is provisioned, with a
  planted false positive and a cheating/precondition-skipping PoC that stay rung <= 2.

Skipped automatically without a Docker daemon or in CI (``conftest.docker_tests_enabled``).
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from agentfakes import ScriptedModel, action
from conftest import LiveServer, start_live_server
from fixturecases import NESTED_FLASK_SQLI_CASE
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.executor.app import create_executor_app
from ono.executor.client import ExecutorClient
from ono.models import Finding, TraceStep, finding_id_for, fingerprint_for
from ono.verifier import GradedVerifier, VerifyReport
from ono.verifier.oracle import SinkOracle, new_canary

pytestmark = pytest.mark.docker

TOKEN = "docker-families-token-0123456789"
FAMILY_APP = Path(__file__).parent / "fixtures" / "flask_family_app"
NESTED_SINK = "dockerized_labs/sqli_lab/app.py"
_NOOP_PATCH = "--- a/does/not/exist.py\n+++ b/does/not/exist.py\n@@ -1 +1 @@\n-x\n+y\n"

_LOGIN = 'c.post("/login", data={"username": "admin", "password": "s3cret"})\n'
_TOKEN_HDR = '{"x-token": "ops-token-7f3a"}'


@dataclass(slots=True)
class FamilyCase:
    name: str
    cwe: str
    sink_line: int
    source_line: int
    poc: str
    reachable: bool = True

    def finding(self, scan: str = "scn_fam") -> Finding:
        trace = [
            TraceStep(
                file="app.py", line=self.source_line, symbol="request.args", note="attacker param"
            ),
            TraceStep(file="app.py", line=self.sink_line, symbol="sink", note=f"sink ({self.cwe})"),
        ]
        return Finding(
            finding_id=finding_id_for(scan, "famapp", "app.py", self.sink_line, self.cwe),
            fingerprint=fingerprint_for("famapp", "app.py", self.sink_line, self.cwe),
            scan_id=scan,
            target_id="famapp",
            title=f"{self.cwe} in flask_family_app",
            cwe=self.cwe,
            severity="high",
            file="app.py",
            line_range=(self.sink_line, self.sink_line),
            trace=trace,
            confidence=0.8,
            rung=2,
            verified=False,
            description="family route behind a precondition",
            patch_diff="",
        )


# -- the reachable families (login / ops-token precondition + the payload at the sink) -------
SSTI_CASE = FamilyCase(
    "ssti",
    "CWE-1336",
    46,
    45,
    "import os\nfrom app import app\nc = app.test_client()\n"
    f"{_LOGIN}c.get('/render', query_string={{'tpl': os.environ['ONO_PAYLOAD']}})\n",
)
REDIRECT_CASE = FamilyCase(
    "open_redirect",
    "CWE-601",
    60,
    59,
    "import os\nfrom app import app\np = os.environ['ONO_PAYLOAD']\n"
    f"app.test_client().get('/go', query_string={{'next': '//evil.example/' + p}}, "
    f"headers={_TOKEN_HDR})\n",
)
XSS_CASE = FamilyCase(
    "reflected_xss",
    "CWE-79",
    67,
    66,
    "import os\nfrom app import app\nc = app.test_client()\n"
    f"{_LOGIN}c.get('/show', query_string={{'comment': os.environ['ONO_PAYLOAD']}})\n",
)
FILEPATH_CASE = FamilyCase(
    "file_path",
    "CWE-73",
    74,
    73,
    "import os\nfrom app import app\np = os.environ['ONO_PAYLOAD']\n"
    f"app.test_client().get('/fetch', query_string={{'path': '../' + p}}, headers={_TOKEN_HDR})\n",
)
XPATH_CASE = FamilyCase(
    "xpath",
    "CWE-643",
    82,
    81,
    "import os\nfrom app import app\nc = app.test_client()\n"
    f"{_LOGIN}c.get('/xpath', query_string={{'name': os.environ['ONO_PAYLOAD']}})\n",
)
REACHABLE_FAMILIES = [SSTI_CASE, REDIRECT_CASE, XSS_CASE, FILEPATH_CASE, XPATH_CASE]

# a planted FALSE POSITIVE: the SSTI-safe route puts the value in the template CONTEXT
SSTI_SAFE_CASE = FamilyCase(
    "ssti_safe",
    "CWE-1336",
    53,
    52,
    "import os\nfrom app import app\nc = app.test_client()\n"
    f"{_LOGIN}c.get('/render_safe', query_string={{'name': os.environ['ONO_PAYLOAD']}})\n",
    reachable=False,
)
# a PRECONDITION-SKIPPING PoC: no login, so the route's own 401 stops it before the sink
SSTI_NAIVE_POC = (
    "import os\nfrom app import app\n"
    "app.test_client().get('/render', query_string={'tpl': os.environ['ONO_PAYLOAD']})\n"
)
# a CHEATING PoC: renders the payload as a template ITSELF, not through the flagged line
SSTI_CHEAT_POC = (
    "import os\nfrom jinja2 import Environment\n"
    "Environment().from_string('x' + os.environ['ONO_PAYLOAD'])\n"
)


@pytest.fixture(scope="module")
def live_executor() -> Iterator[LiveServer]:
    settings = Settings(
        _env_file=None,
        executor_token=SecretStr(TOKEN),
        sandbox_mem_mb=512,
        sandbox_pids_limit=64,
        sandbox_cmd_timeout_s=60,
        sandbox_workspace_mb=128,
        sandbox_deps_max_mb=160,
        sandbox_deps_timeout_s=300,
    )
    server = start_live_server(create_executor_app(settings))
    try:
        yield server
    finally:
        server.stop()


def _verify_report(
    fixture_dir: Path, finding: Finding, poc: str, live: LiveServer, tmp_path: Path, scan: str
) -> VerifyReport:
    workspace = tmp_path / scan
    shutil.copytree(fixture_dir, workspace)

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == PROVER.system_prompt:
            return action("submit_poc", code=poc, how="drive the real entry point")
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
        sandbox_deps_timeout_s=300,
    )
    with ExecutorClient(live.url, TOKEN, timeout_s=360) as client:
        verifier = GradedVerifier(settings, model=ScriptedModel(script=script), executor=client)
        return verifier.verify(scan, workspace, [finding])


# ---------------------------------------------------------------------------
# 1. The nearest-manifest lever, before and after, on the real oracle
# ---------------------------------------------------------------------------


def test_nearest_manifest_before_after_on_a_real_jail(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    workspace = tmp_path / "pygoat"
    shutil.copytree(NESTED_FLASK_SQLI_CASE.dir, workspace)
    finding = NESTED_FLASK_SQLI_CASE.finding("scn_pygoat")
    poc = NESTED_FLASK_SQLI_CASE.honest_poc
    with (
        ExecutorClient(live_executor.url, TOKEN, timeout_s=360) as client,
        client.sandbox("scn_pygoat", workspace) as sbx,
    ):
        # BEFORE: the root manifest only (Django). No Flask -> the lab cannot be imported.
        before = sbx.provision(timeout_s=300, near=[])
        assert before.status == "provisioned", before
        names_before = {p.split()[0].lower() for p in before.installed}
        assert "django" in names_before and "flask" not in names_before
        oracle = SinkOracle(sbx, timeout_s=60.0)
        canary = new_canary(finding.cwe)
        res_before = oracle.run(finding, poc, canary)
        assert res_before.fired is False
        assert "No module named 'flask'" in (res_before.poc_error or res_before.error)
        oracle.cleanup()

        # AFTER: the NEAREST manifest (the lab's own requirements.txt) -> Flask installed.
        after = sbx.provision(timeout_s=300, near=[NESTED_SINK])
        assert after.status == "provisioned", after
        assert "flask" in {p.split()[0].lower() for p in after.installed}
        assert "dockerized_labs/sqli_lab/requirements.txt" in after.manifests
        res_after = oracle.run(finding, poc, canary)
        assert res_after.fired is True, res_after.error or res_after.poc_error
        oracle.cleanup()


def test_nested_flask_sqli_reaches_rung3_via_nearest_manifest(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """End to end: the verifier provisions from each finding's nearest manifest by itself."""
    report = _verify_report(
        NESTED_FLASK_SQLI_CASE.dir,
        NESTED_FLASK_SQLI_CASE.finding("scn_nested"),
        NESTED_FLASK_SQLI_CASE.honest_poc,
        live_executor,
        tmp_path,
        "scn_nested",
    )
    assert report.dependencies is not None and report.dependencies.status == "provisioned"
    assert "flask" in {p.split()[0].lower() for p in report.dependencies.installed}
    proven = report.findings[0]
    assert proven.verified is True and proven.rung >= 3, proven.verification
    assert proven.verification is not None and proven.verification.evidence


# ---------------------------------------------------------------------------
# 2. The added families, each reachable on the real oracle once Flask is provisioned
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", REACHABLE_FAMILIES, ids=[c.name for c in REACHABLE_FAMILIES])
def test_family_sink_is_proven_in_a_real_jail(
    case: FamilyCase, live_executor: LiveServer, tmp_path: Path
) -> None:
    report = _verify_report(
        FAMILY_APP,
        case.finding(f"scn_{case.name}"),
        case.poc,
        live_executor,
        tmp_path,
        f"scn_{case.name}",
    )
    assert report.dependencies is not None and report.dependencies.status == "provisioned", report
    assert "flask" in {p.split()[0].lower() for p in report.dependencies.installed}
    proven = report.findings[0]
    assert proven.verified is True and proven.rung >= 3, proven.verification
    v = proven.verification
    assert v is not None and v.check("poc_reaches_sink").status == "passed"
    assert v.evidence and "<PAYLOAD>" in v.evidence


def test_family_sink_cannot_be_proven_without_its_framework(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    """BEFORE provisioning: the real Flask app dies at ``import flask`` - the family stays
    model-asserted (rung <= 2), exactly like the live run's prove-rate 0."""
    workspace = tmp_path / "scn_fam_nodeps"
    shutil.copytree(FAMILY_APP, workspace)

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        if messages[0]["content"] == PROVER.system_prompt:
            return action("submit_poc", code=SSTI_CASE.poc, how="drive")
        return action("submit_patch", diff=_NOOP_PATCH, summary="noop")

    settings = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://model.invalid/v1",
        executor_url=live_executor.url,
        executor_token=SecretStr(TOKEN),
        workspace_dir=tmp_path,
        context_lines=6,
        verifier_poc_timeout_s=60.0,
        max_verifier_retries=1,
        sandbox_deps_enabled=False,  # the pre-provisioning verifier
    )
    with ExecutorClient(live_executor.url, TOKEN, timeout_s=360) as client:
        verifier = GradedVerifier(settings, model=ScriptedModel(script=script), executor=client)
        proven = verifier.verify(
            "scn_fam_nodeps", workspace, [SSTI_CASE.finding("scn_fam_nodeps")]
        ).findings[0]
    assert proven.verified is False and proven.rung <= 2
    v = proven.verification
    assert v is not None
    check = v.check("poc_reaches_sink")
    assert check is not None and "No module named 'flask'" in check.detail


def test_planted_false_positive_family_stays_unproven(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    report = _verify_report(
        FAMILY_APP,
        SSTI_SAFE_CASE.finding("scn_fam_fp"),
        SSTI_SAFE_CASE.poc,
        live_executor,
        tmp_path,
        "scn_fam_fp",
    )
    assert report.dependencies is not None and report.dependencies.status == "provisioned"
    proven = report.findings[0]
    assert proven.verified is False and proven.rung <= 2
    v = proven.verification
    assert v is not None and v.check("poc_reaches_sink").status == "failed"


def test_precondition_skipping_poc_stays_unproven(
    live_executor: LiveServer, tmp_path: Path
) -> None:
    report = _verify_report(
        FAMILY_APP,
        SSTI_CASE.finding("scn_fam_naive"),
        SSTI_NAIVE_POC,
        live_executor,
        tmp_path,
        "scn_fam_naive",
    )
    assert report.dependencies is not None and report.dependencies.status == "provisioned"
    proven = report.findings[0]
    assert proven.verified is False and proven.rung <= 2


def test_cheating_poc_is_rejected_in_a_real_jail(live_executor: LiveServer, tmp_path: Path) -> None:
    report = _verify_report(
        FAMILY_APP,
        SSTI_CASE.finding("scn_fam_cheat"),
        SSTI_CHEAT_POC,
        live_executor,
        tmp_path,
        "scn_fam_cheat",
    )
    proven = report.findings[0]
    assert proven.verified is False and proven.rung <= 2
