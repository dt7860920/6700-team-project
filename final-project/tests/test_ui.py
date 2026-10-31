"""The Gradio handoff UI, tested as plain functions: the analyze/poll generator, the
status card and the finding cards. No browser, no server, no network.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import gradio as gr

from ono import ui
from ono.analyzer import MockAnalyzer
from ono.config import Settings
from ono.models import Finding, ProgressEvent, Scan, ScanRequest, StageResult, TraceStep
from ono.service import ScanService
from ono.store import InMemoryScanStore
from ono.targets import get_registry

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _service(settings: Settings, **overrides: Any) -> ScanService:
    settings = settings.model_copy(update=overrides) if overrides else settings
    return ScanService(settings, get_registry(), MockAnalyzer(settings), InMemoryScanStore())


def _scan(**overrides: Any) -> Scan:
    base: dict[str, Any] = {
        "scan_id": "scn_abc",
        "target_id": "vulpy",
        "status": "running",
        "model_backend": "service",
        "created_at": T0,
        "started_at": T0,
    }
    return Scan(**{**base, **overrides})


def _finding(**overrides: Any) -> Finding:
    base: dict[str, Any] = {
        "finding_id": "fnd_1",
        "scan_id": "scn_abc",
        "target_id": "vulpy",
        "title": "SQL injection in login",
        "cwe": "CWE-89",
        "severity": "critical",
        "file": "bad/libuser.py",
        "line_range": (12, 12),
        "trace": [
            TraceStep(file="bad/mod_user.py", line=16, symbol="request.form", note="source"),
            TraceStep(file="bad/libuser.py", line=12, symbol="c.execute(...)", note="sink"),
        ],
        "confidence": 0.93,
        "rung": 4,
        "verified": True,
        "description": "The username is formatted straight into SQL.",
        "patch_diff": "--- a/bad/libuser.py\n+++ b/bad/libuser.py\n@@ -1 +1 @@\n-bad\n+good\n",
    }
    return Finding(**{**base, **overrides})


class ScriptedService:
    """Stands in for ScanService: returns the scripted records one poll at a time."""

    def __init__(self, records: list[Scan | None], findings: list[Finding] | None = None):
        self.records = list(records)
        self.findings = findings or []
        self.polls = 0

    def get_scan(self, scan_id: str) -> Scan | None:
        self.polls += 1
        return self.records.pop(0) if len(self.records) > 1 else self.records[0]

    def get_findings(self, scan_id: str) -> list[Finding] | None:
        return list(self.findings)


# ---------------------------------------------------------------------------
# The analyze -> poll generator, end to end on the mock backend
# ---------------------------------------------------------------------------


def test_analyze_streams_progress_then_findings(settings: Settings) -> None:
    service = _service(settings)
    try:
        views = list(
            ui.analyze(service, "pygoat", "", poll_interval=0.01, timeout=10, sleep=lambda s: None)
        )
    finally:
        service.close()
    assert len(views) >= 2  # at least one in-flight view, then the final one
    status, findings, raw = views[-1]
    assert 'class="ono-pill done"' in status and "2 findings" in status
    assert "Finished in" in status
    assert "Static analysis" in status and "✔" in status  # the stage checklist
    assert "Activity log" in status
    assert "2 findings" in findings
    assert "CWE-89" in findings and "https://cwe.mitre.org/data/definitions/89.html" in findings
    assert "rung 4/5" in findings and "fix proven" in findings
    assert "✔ verified" in findings
    assert "introduction/views.py:210-211" in findings
    assert "How the input reaches the sink" in findings
    assert "Proposed patch" in findings and 'class="add"' in findings
    assert raw["scan"]["status"] == "done" and len(raw["findings"]) == 2
    # the first view is the in-flight record: the page never waits for the whole scan
    assert "Findings appear here" in views[0][1] or views[0][1] == findings


def test_analyze_snippet_uses_the_pasted_code(settings: Settings) -> None:
    service = _service(settings)
    try:
        *_, (status, findings, raw) = ui.analyze(
            service,
            "snippet",
            "x = eval(user_input)\n",
            poll_interval=0.01,
            timeout=10,
            sleep=lambda s: None,
        )
    finally:
        service.close()
    assert "1 finding" in status and "CWE-95" in findings
    assert raw["scan"]["target_id"] == "snippet"


def test_analyze_clean_snippet_shows_the_empty_state(settings: Settings) -> None:
    service = _service(settings)
    try:
        *_, (_, findings, _) = ui.analyze(
            service,
            "snippet",
            "print('hi')\n",
            poll_interval=0.01,
            timeout=10,
            sleep=lambda s: None,
        )
    finally:
        service.close()
    assert "No vulnerabilities found" in findings


def test_analyze_rejects_unknown_and_busy_and_invalid_without_raising(
    settings: Settings,
) -> None:
    service = _service(settings, max_active_scans=1, max_queued_scans=0)
    try:
        views = list(ui.analyze(service, "evil.com", "", poll_interval=0, timeout=1))
        assert len(views) == 1 and "Not allowed:" in views[0][0]
        assert "not an authorized target" in views[0][0] and views[0][1] == ""

        too_long = "x" * 20_001
        views = list(ui.analyze(service, "snippet", too_long, poll_interval=0, timeout=1))
        assert len(views) == 1 and "Invalid request:" in views[0][0]
        assert "snippet: String should have at most 20000" in views[0][0]

        views = list(ui.analyze(service, "", "", poll_interval=0, timeout=1))
        assert "Invalid request:" in views[0][0]

        service.submit_scan(ScanRequest(target_id="pygoat"))  # occupies the single worker...
        service._closed = True  # ...and make admission refuse deterministically
        views = list(ui.analyze(service, "pygoat", "", poll_interval=0, timeout=1))
        assert len(views) == 1 and "Busy:" in views[0][0] and "Retry" in views[0][0]
    finally:
        service._closed = False
        service.close()


# ---------------------------------------------------------------------------
# The poll loop on scripted records (no timing, no threads)
# ---------------------------------------------------------------------------


def test_watch_yields_each_state_until_terminal() -> None:
    records = [
        _scan(status="queued", started_at=None, progress="Waiting for a free scan worker"),
        _scan(
            progress="Cloning the target repository",
            events=[ProgressEvent(at=T0, message="Cloning the target repository")],
        ),
        _scan(
            progress="Analyzing candidate 2 of 3 - app/views.py:16 (CWE-89)",
            pipeline=[
                StageResult(stage="ingest", duration_ms=1200, summary="snapshot x"),
                StageResult(stage="sast", duration_ms=300, summary="3 candidate(s)"),
                StageResult(stage="plan", duration_ms=1, summary="q"),
            ],
        ),
        _scan(
            status="done",
            completed_at=T0 + timedelta(seconds=95),
            findings_count=0,
            message="0 verified findings",
            events=[
                ProgressEvent(at=T0, message="Candidate 1 of 3 dismissed: a.py:1 - x"),
                ProgressEvent(at=T0, message="Candidate 2 of 3 confirmed: b.py:2"),
                ProgressEvent(at=T0, message="Candidate 3 of 3 dismissed: c.py:3 - y"),
            ],
        ),
    ]
    svc = ScriptedService(records)
    sleeps: list[float] = []
    views = list(
        ui.watch(
            svc, "scn_abc", poll_interval=1.5, timeout=600, sleep=sleeps.append, clock=lambda: 0.0
        )  # type: ignore[arg-type]
    )
    assert len(views) == 4 and sleeps == [1.5, 1.5, 1.5]
    assert "Queued" in views[0][0] and "Waiting for a free scan worker" in views[0][0]
    assert "Running" in views[1][0] and "Cloning the target repository" in views[1][0]
    assert "Findings appear here" in views[1][1]
    third = views[2][0]
    assert "Analyzing candidate 2 of 3" in third
    assert third.index("Fetch target") < third.index("1.2s") < third.index("Agent analysis")
    assert 'class="ono-stage active"' in third and third.count('class="ono-stage ok"') == 3
    last_status, last_findings, raw = views[3]
    assert "Done" in last_status and "1m 35s" in last_status
    assert "No vulnerabilities found" in last_findings
    assert "1 confirmed, 2 dismissed" in last_findings  # dismissed-vs-confirmed is legible
    assert raw["scan"]["status"] == "done"


def test_watch_failed_scan_shows_message_and_hint() -> None:
    failed = _scan(
        status="failed",
        completed_at=T0 + timedelta(seconds=3),
        message="analysis pipeline failed: executor unreachable at http://127.0.0.1:8081",
        pipeline=[StageResult(stage="ingest", status="failed", duration_ms=5, summary="boom")],
    )
    (status, findings, _raw), *_ = ui.watch(
        ScriptedService([failed]),
        "scn_abc",
        poll_interval=0,
        timeout=10,  # type: ignore[arg-type]
    )
    assert 'class="ono-pill failed"' in status
    assert "Scan failed:" in status and "executor unreachable" in status
    assert "MODEL_SERVICE_URL" in status and "make executor" in status
    assert "not reached" in status  # the stages after the failure
    assert "did not complete" in findings
    assert "Traceback" not in status


def test_watch_unknown_scan_and_timeout() -> None:
    views = list(ui.watch(ScriptedService([None]), "scn_nope", poll_interval=0, timeout=1))  # type: ignore[arg-type]
    assert len(views) == 1 and "Unknown scan:" in views[0][0]

    ticks = iter([0.0, 0.0, 100.0, 100.0])
    views = list(
        ui.watch(
            ScriptedService([_scan()]),  # type: ignore[arg-type]
            "scn_abc",
            poll_interval=0,
            timeout=50,
            sleep=lambda s: None,
            clock=lambda: next(ticks),
        )
    )
    assert "Stopped watching" in views[-1][0] and "scn_abc" in views[-1][0]
    assert "Look up a scan" in views[-1][0]


# ---------------------------------------------------------------------------
# Rendering details
# ---------------------------------------------------------------------------


def test_finding_card_marks_unverified_and_escapes_html() -> None:
    f = _finding(
        title="<script>alert(1)</script>",
        verified=False,
        rung=2,
        severity="high",
        patch_diff="",
        detection_rule=None,
        trace=[],
    )
    card = ui.render_finding_card(1, f)
    assert "<script>" not in card and "&lt;script&gt;" in card
    assert "⚠ not verified" in card and "✔ verified" not in card
    assert "rung 2/5" in card and "CWE + patch" in card
    assert "No patch proposed yet" in card
    assert "No source-to-sink trace" in card
    assert 'class="ono-badge sev high"' in card


def test_findings_header_orders_by_severity_and_counts_verified() -> None:
    low = _finding(finding_id="f_low", title="Low thing", severity="low", verified=False, rung=1)
    crit = _finding(finding_id="f_crit", title="Critical thing")
    html = ui.render_findings(_scan(status="done", completed_at=T0), [low, crit])
    assert html.index("Critical thing") < html.index("Low thing")
    assert "1 of 2 verified" in html
    assert "1 critical" in html and "1 low" in html
    assert "Detection rule" not in html
    rung5 = _finding(finding_id="f5", rung=5, detection_rule="rules: []")
    assert "Detection rule (rung 5)" in ui.render_findings(_scan(status="done"), [rung5])


def test_status_card_elapsed_uses_completed_at_or_now() -> None:
    running = _scan()
    assert "Running for 42s" in ui.render_status(running, now=T0 + timedelta(seconds=42))
    done = _scan(status="done", completed_at=T0 + timedelta(hours=1, minutes=2), findings_count=1)
    assert "Finished in 1h 02m - 1 finding" in ui.render_status(done, now=T0 + timedelta(days=9))


# ---------------------------------------------------------------------------
# The Blocks app builds (components wired, nothing launched)
# ---------------------------------------------------------------------------


def test_build_ui_constructs_blocks(settings: Settings) -> None:
    service = _service(settings)
    try:
        blocks = ui.build_ui(service)
    finally:
        service.close()
    assert isinstance(blocks, gr.Blocks)
    dropdowns = [b for b in blocks.blocks.values() if isinstance(b, gr.Dropdown)]
    assert len(dropdowns) == 1
    labels = [label for label, _value in dropdowns[0].choices]
    assert any("practice app" in label for label in labels)
    assert any("paste code" in label for label in labels)
    buttons = {b.value for b in blocks.blocks.values() if isinstance(b, gr.Button)}
    assert {"Analyze", "Show scan"} <= buttons
    assert "cwe.mitre.org" in ui._LEGEND and "pick a target" in ui._HEADER
