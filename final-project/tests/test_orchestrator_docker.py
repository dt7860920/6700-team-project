"""REAL-JAIL integration test for the detection core (``pytest -m docker``).

The model is scripted; everything else is real: the Executor service on a live uvicorn,
the typed ``ExecutorClient``, a genuine jailed container holding the fixture repo, and
``ServiceAnalyzer.run`` driving ingest -> SAST -> orchestrator (planner + analyst) through
it. Skipped automatically without a Docker daemon or in CI (``conftest.docker_tests_enabled``).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import docker
import pytest
from pydantic import SecretStr

from agentfakes import ScriptedModel, action, confirm_args
from conftest import LiveServer, start_live_server
from ono import sast
from ono.agents.definitions import PLANNER
from ono.analyzer import ServiceAnalyzer
from ono.config import Settings
from ono.executor.app import create_executor_app
from ono.executor.client import ExecutorClient
from ono.executor.sandbox import LABEL_SANDBOX
from ono.models import ScanOptions
from ono.targets import Target

pytestmark = pytest.mark.docker

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"
TOKEN = "docker-test-token-0123456789"


@pytest.fixture(autouse=True)
def _offline_sast(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(root: Path, rulesets: Any) -> dict[str, object]:
        raise sast.SemgrepUnavailableError("semgrep disabled in tests")

    monkeypatch.setattr(sast, "run_semgrep", unavailable)


@pytest.fixture(scope="module")
def live_executor() -> Iterator[LiveServer]:
    settings = Settings(
        _env_file=None,
        executor_token=SecretStr(TOKEN),
        sandbox_mem_mb=256,
        sandbox_pids_limit=64,
        sandbox_cmd_timeout_s=30,
        sandbox_workspace_mb=128,
    )
    server = start_live_server(create_executor_app(settings))
    try:
        yield server
    finally:
        server.stop()


def _script() -> Any:
    """Planner -> plan; analyst -> grep the real jail, read what it found, then decide."""

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        if messages[0]["content"] == PLANNER.system_prompt:
            return json.dumps(
                {"hypothesis": "tainted input reaches the sink", "steps": ["grep", "read"]}
            )
        task = messages[1]["content"]
        results = [
            m["content"]
            for m in messages
            if m["role"] == "user" and m["content"].startswith("RESULT")
        ]
        if "file: app/views.py\n  line: 16\n" in task:
            if not results:
                return action("grep", pattern=r"request\.args\.get", path="app")
            if len(results) == 1:
                return action("read_lines", path="app/views.py", start=11, end=17)
            return action(
                "confirm",
                **confirm_args(
                    trace=[
                        {
                            "file": "app/views.py",
                            "line": 13,
                            "symbol": "request.args.get('id')",
                            "note": "source",
                        },
                        {
                            "file": "app/views.py",
                            "line": 16,
                            "symbol": "cur.execute",
                            "note": "sink",
                        },
                        {
                            "file": "app/views.py",
                            "line": 99,
                            "symbol": "invented",
                            "note": "must be dropped",
                        },
                    ]
                ),
            )
        if "file: app/views.py\n  line: 23\n" in task:
            if not results:
                return action("read_file", path="../../etc/passwd")  # the jail must refuse this
            return action("dismiss", reason="jail refused the escape; host is a constant in tests")
        if not results:
            return action("tree", path=".")
        return action("dismiss", reason="pickle.loads is only called from tests")

    return script


def test_service_analyzer_against_a_real_jail(live_executor: LiveServer, tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://model.invalid/v1",
        executor_url=live_executor.url,
        executor_token=SecretStr(TOKEN),
        workspace_dir=tmp_path / "ws",
        context_lines=5,
        agent_trajectory_dir=tmp_path / "traj",
    )
    target = Target(
        target_id="fixture-repo",
        name="f",
        kind="repo",
        languages=["python"],
        source=str(FIXTURE_REPO),
        snapshot="fixture",
    )
    model = ScriptedModel(script=_script())
    raw = docker.from_env()
    before = {c.id for c in raw.containers.list(all=True, filters={"label": f"{LABEL_SANDBOX}=1"})}

    with ExecutorClient(live_executor.url, TOKEN, timeout_s=60) as client:
        analyzer = ServiceAnalyzer(settings, model=model, executor=client)
        result = analyzer.run("scn_agents_e2e", target, ScanOptions())
        assert client.list_sandboxes() == []  # the scan's jail is gone

    assert all(s.status == "ok" for s in result.stages), result.stages
    assert result.stages[1].summary == "3 candidate(s)"
    report = analyzer.last_report
    assert report is not None and report.sandbox_id.startswith("sbx_")
    assert [o.state for o in report.outcomes] == ["dismissed", "confirmed", "dismissed"]

    # The SQLi finding is anchored to lines the analyst really read from inside the jail:
    # the grep hit (13) and the read range (11-17); the invented line 99 was dropped.
    assert len(result.findings) == 1
    f = result.findings[0]
    assert (f.file, f.line_range, f.cwe, f.rung, f.verified) == (
        "app/views.py",
        (16, 16),
        "CWE-89",
        2,
        False,
    )
    assert [t.line for t in f.trace] == [13, 16]

    # The analyst saw real jail output: grep matches and numbered lines from the container.
    msgs = [m["content"] for c in model.calls for m in c["messages"] if m["role"] == "user"]
    assert any("app/views.py:13: " in m and "request.args.get" in m for m in msgs)
    assert any("   16 | " in m and 'cur.execute(f"SELECT' in m for m in msgs)
    # ... and the jail refused the path escape, as error text, without failing the scan.
    assert any("ERROR:" in m and "sandbox error" in m for m in msgs)

    # Trajectories were persisted for every agent run.
    records = [
        json.loads(ln)
        for ln in (tmp_path / "traj" / "scn_agents_e2e.jsonl").read_text().splitlines()
    ]
    assert [r["role"] for r in records] == ["planner", "analyst"] * 3

    # Nothing leaked: workspace removed, no sandbox container left behind.
    assert not (tmp_path / "ws" / "scn_agents_e2e").exists()
    after = {c.id for c in raw.containers.list(all=True, filters={"label": f"{LABEL_SANDBOX}=1"})}
    assert after == before
