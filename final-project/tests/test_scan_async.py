"""The asynchronous scan flow: background workers, live progress, the concurrency cap
and the failure path. Everything runs offline on the mock backend (or tiny fakes).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentfakes import FakeExecutor, ScriptedModel, action
from ono.analyzer import BaseAnalyzer, MockAnalyzer, Plan
from ono.api import create_app
from ono.config import Settings
from ono.errors import PipelineError, ScanBusyError
from ono.models import Finding, ScanOptions, ScanRequest
from ono.orchestrator import DetectionOrchestrator
from ono.progress import RecordingProgress
from ono.sast import Candidate
from ono.service import ScanService
from ono.store import InMemoryScanStore
from ono.targets import Target, TargetRegistry, get_registry

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"


# ---------------------------------------------------------------------------
# Test analyzers: controllable timing and failure modes, no model, no sandbox
# ---------------------------------------------------------------------------


class GatedAnalyzer(MockAnalyzer):
    """A mock analyzer whose ``ingest`` blocks until the test opens the gate."""

    backend = "gated"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.gate = threading.Event()
        self.entered = threading.Semaphore(0)  # released once per scan that reached ingest

    def ingest(self, target: Target, options: ScanOptions) -> str:
        self.entered.release()
        self.report("Cloning the target repository")
        assert self.gate.wait(timeout=10), "test forgot to open the gate"
        return super().ingest(target, options)


class FailingAnalyzer(BaseAnalyzer):
    backend = "failing"

    def __init__(self, settings: Settings, exc: Exception) -> None:
        super().__init__(settings)
        self.exc = exc

    def ingest(self, target: Target, options: ScanOptions) -> str:
        return "snap"

    def sast_shortlist(self, target: Target, options: ScanOptions) -> list[Candidate]:
        raise self.exc

    def plan(self, target: Target, candidates: list[Candidate]) -> Plan:
        return Plan(steps=[])

    def analyze(
        self, scan_id: str, target: Target, candidates: list[Candidate], plan: Plan
    ) -> list[Finding]:
        return []

    def verify(self, target: Target, findings: list[Finding]) -> list[Finding]:
        return findings


def _service(analyzer: BaseAnalyzer, settings: Settings) -> ScanService:
    return ScanService(settings, get_registry(), analyzer, InMemoryScanStore())


def _wait(service: ScanService, scan_id: str, timeout: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        scan = service.get_scan(scan_id)
        assert scan is not None
        if scan.status in ("done", "failed"):
            return scan
        assert time.monotonic() < deadline, f"scan still {scan.status}: {scan.progress}"
        time.sleep(0.005)


# ---------------------------------------------------------------------------
# Lifecycle: queued -> running -> done, findings appear, record updates live
# ---------------------------------------------------------------------------


def test_submit_returns_immediately_and_the_scan_completes(settings: Settings) -> None:
    service = _service(MockAnalyzer(settings), settings)
    try:
        accepted = service.submit_scan(ScanRequest(target_id="pygoat"))
        assert accepted.status == "queued" and accepted.started_at is None
        assert accepted.progress == "Waiting for a free scan worker"
        assert service.get_findings(accepted.scan_id) == []  # nothing yet, but the id exists

        done = service.wait(accepted.scan_id, timeout=10)
        assert done is not None and done.status == "done"
        assert done.started_at is not None and done.completed_at is not None
        assert done.findings_count == 2 and done.progress == ""
        assert done.message == "2 verified findings"
        assert [s.stage for s in done.pipeline] == ["ingest", "sast", "plan", "analyze", "verify"]
        findings = service.get_findings(accepted.scan_id)
        assert findings is not None and {f.cwe for f in findings} == {"CWE-89", "CWE-78"}
        assert all(f.scan_id == accepted.scan_id for f in findings)
    finally:
        service.close()


def test_progress_field_and_events_update_while_running(settings: Settings) -> None:
    settings = settings.model_copy(update={"max_active_scans": 1})
    analyzer = GatedAnalyzer(settings)
    service = _service(analyzer, settings)
    try:
        scan = service.submit_scan(ScanRequest(target_id="vulpy"))
        assert analyzer.entered.acquire(timeout=5)  # the worker picked it up
        live = service.get_scan(scan.scan_id)
        assert live is not None
        assert live.status == "running" and live.started_at is not None
        assert live.progress == "Cloning the target repository"
        assert [e.message for e in live.events][-2:] == [
            "Fetching the target snapshot (vulpy (ingested OSS repo))",
            "Cloning the target repository",
        ]
        assert live.pipeline == []  # ingest has not finished

        analyzer.gate.set()
        done = _wait(service, scan.scan_id)
        messages = [e.message for e in done.events]
        assert "Static analysis: building the candidate shortlist" in messages
        assert messages[-1].startswith("Scan done: ")
        assert done.pipeline[0].stage == "ingest" and done.pipeline[0].status == "ok"
        assert done.progress == ""
    finally:
        analyzer.gate.set()
        service.close()


def test_run_scan_is_the_synchronous_path(settings: Settings) -> None:
    service = _service(MockAnalyzer(settings), settings)
    try:
        response = service.run_scan(ScanRequest(target_id="juice-shop"))
        assert response.status == "done" and len(response.findings) == 1
        assert service.get_scan(response.scan_id) is not None
        assert service.active_scans == 0 and service.queued_scans == 0
    finally:
        service.close()


# ---------------------------------------------------------------------------
# Concurrency cap: N run, M wait, the rest are refused with a clear "busy"
# ---------------------------------------------------------------------------


def test_concurrency_cap_queues_then_refuses(settings: Settings) -> None:
    settings = settings.model_copy(update={"max_active_scans": 1, "max_queued_scans": 1})
    analyzer = GatedAnalyzer(settings)
    service = _service(analyzer, settings)
    try:
        first = service.submit_scan(ScanRequest(target_id="pygoat"))
        assert analyzer.entered.acquire(timeout=5)
        second = service.submit_scan(ScanRequest(target_id="vulpy"))
        assert service.active_scans == 1 and service.queued_scans == 1
        assert service.get_scan(second.scan_id) is not None
        assert service.get_scan(second.scan_id).status == "queued"  # type: ignore[union-attr]

        with pytest.raises(ScanBusyError, match="1 scan\\(s\\) running and 1 queued") as info:
            service.submit_scan(ScanRequest(target_id="juice-shop"))
        assert "MAX_ACTIVE_SCANS=1" in str(info.value)

        analyzer.gate.set()
        assert _wait(service, first.scan_id).status == "done"
        assert _wait(service, second.scan_id).status == "done"
        assert service.active_scans == 0 and service.queued_scans == 0
        # capacity is back
        third = service.submit_scan(ScanRequest(target_id="juice-shop"))
        assert _wait(service, third.scan_id).status == "done"
    finally:
        analyzer.gate.set()
        service.close()


def test_busy_is_429_over_http(settings: Settings) -> None:
    settings = settings.model_copy(update={"max_active_scans": 1, "max_queued_scans": 0})
    analyzer = GatedAnalyzer(settings)
    app = create_app(settings, mount_ui=False)
    app.state.service = _service(analyzer, settings)
    try:
        with TestClient(app) as client:
            first = client.post("/scans", json={"target_id": "pygoat"})
            assert first.status_code == 202
            assert analyzer.entered.acquire(timeout=5)
            busy = client.post("/scans", json={"target_id": "vulpy"})
            assert busy.status_code == 429, busy.text
            assert busy.headers["retry-after"] == "10"
            assert "busy" in busy.json()["detail"].lower()
            # the allowlist is checked *before* admission: unknown targets stay 403
            assert client.post("/scans", json={"target_id": "nope"}).status_code == 403
            analyzer.gate.set()
            scan = client.get(f"/scans/{first.json()['scan_id']}")
            assert scan.status_code == 200
    finally:
        analyzer.gate.set()
        app.state.service.close()


# ---------------------------------------------------------------------------
# Failure path
# ---------------------------------------------------------------------------


def test_pipeline_error_fails_the_scan_with_its_message(settings: Settings) -> None:
    exc = PipelineError("executor unreachable at http://127.0.0.1:8081 (connection refused)")
    service = _service(FailingAnalyzer(settings, exc), settings)
    try:
        scan = service.submit_scan(ScanRequest(target_id="pygoat"))
        failed = _wait(service, scan.scan_id)
        assert failed.status == "failed"
        assert failed.message == f"analysis pipeline failed: {exc}"
        assert failed.completed_at is not None and failed.progress == ""
        assert failed.findings_count == 0 and service.get_findings(scan.scan_id) == []
        # the stage that blew up is recorded as failed, the rest never ran
        assert [(s.stage, s.status) for s in failed.pipeline] == [
            ("ingest", "ok"),
            ("sast", "failed"),
        ]
        assert failed.events[-1].message.startswith("Scan failed: analysis pipeline failed")
    finally:
        service.close()


def test_unexpected_exception_is_reported_generically(settings: Settings) -> None:
    service = _service(FailingAnalyzer(settings, RuntimeError("secret internals")), settings)
    try:
        scan = service.submit_scan(ScanRequest(target_id="pygoat"))
        failed = _wait(service, scan.scan_id)
        assert failed.status == "failed"
        assert failed.message == "analysis pipeline raised; see server logs"
        assert "secret" not in failed.message
    finally:
        service.close()


def test_close_fails_queued_scans_cleanly(settings: Settings) -> None:
    settings = settings.model_copy(update={"max_active_scans": 1, "max_queued_scans": 2})
    analyzer = GatedAnalyzer(settings)
    service = _service(analyzer, settings)
    running = service.submit_scan(ScanRequest(target_id="pygoat"))
    assert analyzer.entered.acquire(timeout=5)
    queued = service.submit_scan(ScanRequest(target_id="vulpy"))
    service.close()
    assert service.get_scan(queued.scan_id).status == "failed"  # type: ignore[union-attr]
    assert "shut down" in service.get_scan(queued.scan_id).message  # type: ignore[union-attr]
    with pytest.raises(ScanBusyError):
        service.submit_scan(ScanRequest(target_id="pygoat"))
    analyzer.gate.set()
    assert _wait(service, running.scan_id).status == "done"  # in-flight work still finishes


# ---------------------------------------------------------------------------
# Progress plumbing in the pipeline itself (no service involved)
# ---------------------------------------------------------------------------


def test_base_analyzer_reports_steps_and_stage_results(settings: Settings) -> None:
    progress = RecordingProgress()
    result = MockAnalyzer(settings).run(
        "scn_p", get_registry()["pygoat"], ScanOptions(), progress=progress
    )
    assert progress.steps == [
        "Fetching the target snapshot (OWASP PyGoat)",
        "Static analysis: building the candidate shortlist",
        "Planning the investigation of 2 candidate(s)",
        "Analyzing 2 candidate(s)",
        "Verifying 2 raw finding(s)",
    ]
    assert progress.stages == result.stages  # every stage result, in order, as it completed


def test_progress_is_bound_per_thread(settings: Settings) -> None:
    """One analyzer instance serves concurrent scans; each thread sees only its own sink."""
    analyzer = MockAnalyzer(settings)
    sinks = [RecordingProgress() for _ in range(4)]
    targets = ["pygoat", "vulpy", "juice-shop", "pygoat"]

    def work(i: int) -> None:
        analyzer.run(f"s{i}", get_registry()[targets[i]], ScanOptions(), progress=sinks[i])

    threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sinks[1].steps[0] == "Fetching the target snapshot (vulpy (ingested OSS repo))"
    assert sinks[2].steps[0] == "Fetching the target snapshot (OWASP Juice Shop)"
    assert all(len(s.stages) == 5 for s in sinks)
    assert analyzer.report("outside a run") is None  # no sink bound -> silently dropped


def test_orchestrator_reports_each_candidate() -> None:
    settings = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://localhost:11434/v1",
        executor_token="unit-test-token-0123456789",
        planner_enabled=False,
        context_lines=5,
    )
    model = ScriptedModel(default=action("dismiss", reason="sanitized upstream"))
    orch = DetectionOrchestrator(settings, model=model, executor=FakeExecutor())
    candidates = [
        Candidate("app/util.py", 5, "CWE-502", "pickle-load"),
        Candidate("app/views.py", 16, "CWE-89", "sqli"),
    ]
    seen: list[str] = []
    report = orch.detect("scn_o", "fixture", FIXTURE_REPO, candidates, progress=seen.append)
    assert [o.state for o in report.outcomes] == ["dismissed", "dismissed"]
    assert seen == [
        "Opening the jailed sandbox for 2 candidate(s)",
        "Analyzing candidate 1 of 2 - app/util.py:5 (CWE-502)",
        "Candidate 1 of 2 dismissed: app/util.py:5 - sanitized upstream",
        "Analyzing candidate 2 of 2 - app/views.py:16 (CWE-89)",
        "Candidate 2 of 2 dismissed: app/views.py:16 - sanitized upstream",
    ]
    # without a callback nothing changes
    assert orch.detect("scn_q", "fixture", FIXTURE_REPO, candidates).outcomes[0].state == (
        "dismissed"
    )


def test_registry_target_names_are_what_progress_shows() -> None:
    """Guard the labels the UI shows against silent registry renames."""
    registry = TargetRegistry({"x": get_registry()["snippet"]})
    progress = RecordingProgress()
    MockAnalyzer(Settings(_env_file=None)).run(
        "s", registry["x"], ScanOptions(snippet="print(1)"), progress=progress
    )
    assert progress.steps[0] == "Preparing the pasted snippet"
