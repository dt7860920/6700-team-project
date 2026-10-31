"""Gradio analyst UI - the handoff surface.

The reviewer picks an authorized target (or pastes a snippet), clicks **Analyze**, and
watches the scan run: the handler submits the scan to :class:`~ono.service.ScanService`
(the same object the HTTP API uses - one allowlist check) and then *polls* the live
scan record, yielding a fresh status card every ``ui_poll_interval_s`` seconds. The
browser never waits on a long request, so a 5-minute agentic scan looks like
"Cloning -> Static analysis -> Analyzing candidate 2 of 3 -> Done" instead of a frozen
button. Findings render as cards (CWE, severity, rung, verified, file:line, trace,
patch), failures as a plain-language message.

Everything the Blocks app calls is a module-level function that takes the service as
its first argument, so the handlers are unit-tested without a browser or a server.
"""

from __future__ import annotations

import html
import re
import time
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any

import gradio as gr
from pydantic import ValidationError

from ono.errors import ScanBusyError
from ono.models import Finding, Scan, ScanOptions, ScanRequest, StageName, utcnow
from ono.service import ScanService
from ono.targets import UnauthorizedTargetError

__all__ = [
    "UI_CSS",
    "UiView",
    "analyze",
    "build_ui",
    "render_findings",
    "render_status",
    "watch",
]

UiView = tuple[str, str, dict[str, Any]]
"""(status card HTML, findings HTML, raw JSON) - the three outputs of every handler."""

# ---------------------------------------------------------------------------
# Vocabulary shown to the reviewer
# ---------------------------------------------------------------------------

RUNG_LABELS: dict[int, str] = {
    1: "flagged line",
    2: "CWE + patch",
    3: "reachability proven",
    4: "fix proven",
    5: "detection rule",
}

RUNG_HELP: dict[int, str] = {
    1: "A line looks vulnerable. No CWE, no fix yet.",
    2: "Plus the weakness class (CWE) and a proposed patch.",
    3: "Plus a read-only proof that attacker input really reaches the sink.",
    4: "Plus proof the fix works: patch applies, the proof no longer fires, tests pass.",
    5: "Plus a detection rule to catch exploitation until the patch ships.",
}

STAGE_LABELS: dict[StageName, str] = {
    "ingest": "Fetch target",
    "sast": "Static analysis",
    "plan": "Plan",
    "analyze": "Agent analysis",
    "verify": "Verify",
}
STAGE_ORDER: tuple[StageName, ...] = ("ingest", "sast", "plan", "analyze", "verify")

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")

KIND_LABELS: dict[str, str] = {
    "practice-app": "practice app",
    "repo": "repository",
    "snippet": "paste code",
}

EXAMPLE_SNIPPET = """\
import sqlite3, subprocess

def find_user(conn, name):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchone()

def ping(host):
    return subprocess.check_output("ping -c1 " + host, shell=True)
"""

_CANDIDATE_VERDICT = re.compile(r"^Candidate \d+ of \d+ (\w+):")

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _e(text: object) -> str:
    """HTML-escape anything that came from a target, a model or a user."""
    return html.escape(str(text), quote=True)


def _fmt_duration(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"{seconds:.0f}s" if seconds >= 10 else f"{seconds:.1f}s"
    minutes, rest = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {rest:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def _fmt_ms(ms: float) -> str:
    return f"{ms:.0f} ms" if ms < 1000 else _fmt_duration(ms / 1000)


def elapsed_seconds(scan: Scan, now: datetime | None = None) -> float:
    end = scan.completed_at or (now or utcnow())
    return (end - scan.created_at).total_seconds()


def cwe_url(cwe: str) -> str:
    number = cwe.split("-", 1)[1] if "-" in cwe else cwe
    return f"https://cwe.mitre.org/data/definitions/{number}.html"


def candidate_verdicts(scan: Scan) -> dict[str, int]:
    """Count the orchestrator's per-candidate verdicts from the activity log."""
    counts: dict[str, int] = {}
    for event in scan.events:
        match = _CANDIDATE_VERDICT.match(event.message)
        if match:
            counts[match.group(1)] = counts.get(match.group(1), 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Rendering: the status card
# ---------------------------------------------------------------------------


def _stage_rows(scan: Scan) -> str:
    done = {s.stage: s for s in scan.pipeline}
    rows: list[str] = []
    current_marked = False
    for stage in STAGE_ORDER:
        label = _e(STAGE_LABELS[stage])
        result = done.get(stage)
        if result is not None:
            if result.status == "failed":
                icon, cls, detail = "✖", "failed", f"failed - {_e(result.summary)}"
            elif result.status == "skipped":
                icon, cls, detail = "-", "skipped", "skipped"
            else:
                icon, cls = "✔", "ok"
                detail = f"{_fmt_ms(result.duration_ms)} · {_e(result.summary)}"
        elif scan.status == "running" and not current_marked:
            icon, cls, detail = "●", "active", "in progress"
            current_marked = True
        elif scan.status in ("done", "failed"):
            icon, cls, detail = "-", "skipped", "not reached"
        else:
            icon, cls, detail = "○", "pending", "pending"
        rows.append(
            f'<li class="ono-stage {cls}"><span class="ono-stage-icon">{icon}</span>'
            f'<span class="ono-stage-name">{label}</span>'
            f'<span class="ono-stage-detail">{detail}</span></li>'
        )
    return "".join(rows)


def _activity_log(scan: Scan) -> str:
    if not scan.events:
        return ""
    items = "".join(
        f"<li><time>{_e(ev.at.strftime('%H:%M:%S'))}</time> {_e(ev.message)}</li>"
        for ev in scan.events[-60:]
    )
    return (
        f'<details class="ono-log"><summary>Activity log ({len(scan.events)})</summary>'
        f"<ul>{items}</ul></details>"
    )


def _failure_hint(scan: Scan) -> str:
    if scan.model_backend == "mock":
        return "The mock backend should not fail; see the server logs."
    return (
        "Check that the model endpoint (MODEL_SERVICE_URL) and the sandbox Executor "
        "(EXECUTOR_URL, started with <code>make executor</code>) are running, then try again."
    )


def render_status(scan: Scan, *, now: datetime | None = None) -> str:
    """The live status card: status pill, elapsed time, current step, stage checklist."""
    elapsed = _fmt_duration(elapsed_seconds(scan, now))
    status = scan.status
    pill = {
        "queued": "Queued",
        "running": "Running",
        "done": "Done",
        "failed": "Failed",
    }[status]
    if status == "done":
        n = scan.findings_count
        headline = f"Finished in {elapsed} - {n} finding{'s' if n != 1 else ''}"
    elif status == "failed":
        headline = f"Scan failed after {elapsed}"
    elif status == "queued":
        headline = f"Waiting for a free scan worker ({elapsed})"
    else:
        headline = f"Running for {elapsed}"
    progress = ""
    if status in ("queued", "running"):
        progress = (
            f'<div class="ono-progress"><span class="ono-spinner"></span>'
            f"{_e(scan.progress or 'Starting')}</div>"
        )
    elif status == "failed":
        progress = (
            f'<div class="ono-error"><strong>Scan failed:</strong> {_e(scan.message)}'
            f'<div class="ono-hint">{_failure_hint(scan)}</div></div>'
        )
    return (
        f'<div class="ono-status {status}">'
        f'<div class="ono-status-head"><span class="ono-pill {status}">{pill}</span>'
        f'<span class="ono-headline">{_e(headline)}</span></div>'
        f'<div class="ono-meta">target <code>{_e(scan.target_id)}</code> · scan '
        f"<code>{_e(scan.scan_id)}</code> · backend <code>{_e(scan.model_backend)}</code></div>"
        f"{progress}"
        f'<ol class="ono-stages">{_stage_rows(scan)}</ol>'
        f"{_activity_log(scan)}"
        "</div>"
    )


def render_error(title: str, detail: str, *, hint: str = "") -> str:
    hint_html = f'<div class="ono-hint">{hint}</div>' if hint else ""
    return (
        f'<div class="ono-status failed"><div class="ono-error"><strong>{_e(title)}</strong> '
        f"{_e(detail)}{hint_html}</div></div>"
    )


# ---------------------------------------------------------------------------
# Rendering: findings
# ---------------------------------------------------------------------------


def _diff_html(diff: str) -> str:
    lines: list[str] = []
    for raw in diff.rstrip().splitlines():
        cls = ""
        if raw.startswith("+++") or raw.startswith("---"):
            cls = "file"
        elif raw.startswith("@@"):
            cls = "hunk"
        elif raw.startswith("+"):
            cls = "add"
        elif raw.startswith("-"):
            cls = "del"
        lines.append(f'<span class="{cls}">{_e(raw)}</span>' if cls else _e(raw))
    return "\n".join(lines)


def render_finding_card(index: int, f: Finding) -> str:
    verified = (
        '<span class="ono-badge verified" title="The deterministic verifier passed">'
        "✔ verified</span>"
        if f.verified
        else '<span class="ono-badge unverified" title="Asserted by the model; the verifier '
        'has not confirmed it">⚠ not verified</span>'
    )
    rung = f.rung
    rung_badge = (
        f'<span class="ono-badge rung" title="{_e(RUNG_HELP[rung])}">rung {rung}/5 · '
        f"{_e(RUNG_LABELS[rung])}</span>"
    )
    trace_items = "".join(
        f"<li><code>{_e(t.file)}:{t.line}</code> <code class='sym'>{_e(t.symbol)}</code>"
        + (f' <span class="note">{_e(t.note)}</span>' if t.note else "")
        + "</li>"
        for t in f.trace
    )
    trace = (
        f'<div class="ono-trace"><div class="ono-h">How the input reaches the sink</div>'
        f"<ol>{trace_items}</ol></div>"
        if f.trace
        else '<div class="ono-trace muted">No source-to-sink trace recorded.</div>'
    )
    patch = (
        f'<details class="ono-patch"><summary>Proposed patch</summary>'
        f'<pre class="ono-diff">{_diff_html(f.patch_diff)}</pre></details>'
        if f.patch_diff.strip()
        else '<div class="muted">No patch proposed yet (the fixer agent is not enabled).</div>'
    )
    rule = (
        f'<details class="ono-patch"><summary>Detection rule (rung 5)</summary>'
        f"<pre>{_e(f.detection_rule.rstrip())}</pre></details>"
        if f.detection_rule
        else ""
    )
    description = (
        f'<p class="ono-desc">{_e(f.description)}</p>'
        if f.description
        else '<p class="ono-desc muted">No description.</p>'
    )
    return (
        f'<article class="ono-card sev-{_e(f.severity)}">'
        f'<header><span class="ono-idx">{index}</span><h3>{_e(f.title)}</h3></header>'
        '<div class="ono-badges">'
        f'<a class="ono-badge cwe" href="{_e(cwe_url(f.cwe))}" target="_blank" '
        f'rel="noopener">{_e(f.cwe)} ↗</a>'
        f'<span class="ono-badge sev {_e(f.severity)}">{_e(f.severity)}</span>'
        f"{rung_badge}{verified}"
        f'<span class="ono-badge conf">confidence {f.confidence:.0%}</span>'
        "</div>"
        f'<div class="ono-loc">📄 <code>{_e(f.location)}</code></div>'
        f"{description}{trace}{patch}{rule}"
        "</article>"
    )


def render_findings(scan: Scan | None, findings: list[Finding]) -> str:
    """Finding cards, or the friendly empty / not-yet / failed states."""
    if scan is None:
        return ""
    if scan.status in ("queued", "running"):
        return '<div class="ono-empty muted">Findings appear here when the scan finishes.</div>'
    if scan.status == "failed":
        return '<div class="ono-empty muted">No findings: the scan did not complete.</div>'

    verdicts = candidate_verdicts(scan)
    verdict_line = ""
    if verdicts:
        parts = ", ".join(f"{n} {state}" for state, n in sorted(verdicts.items()))
        verdict_line = (
            f'<div class="ono-verdicts">Candidates reviewed by the agents: {_e(parts)}. '
            "Only <em>confirmed</em> candidates become findings; dismissed ones are logged "
            "in the activity log.</div>"
        )
    if not findings:
        return (
            '<div class="ono-empty"><div class="ono-empty-title">✅ No vulnerabilities found'
            "</div><div>The pipeline ran to completion and nothing passed the analysis for "
            f"this target.</div>{verdict_line}</div>"
        )

    by_sev = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    sev_summary = " · ".join(
        f'<span class="ono-badge sev {s}">{n} {s}</span>' for s, n in by_sev.items() if n
    )
    n_verified = sum(1 for f in findings if f.verified)
    verified_summary = (
        f"{n_verified} of {len(findings)} verified by the deterministic verifier"
        if n_verified
        else "none verified yet - these are model-asserted (rung ≤ 2)"
    )
    header = (
        f'<div class="ono-findings-head"><h2>{len(findings)} finding'
        f"{'s' if len(findings) != 1 else ''}</h2>"
        f'<div class="ono-badges">{sev_summary}</div>'
        f'<div class="muted">{_e(verified_summary)}</div>{verdict_line}</div>'
    )
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), -f.rung))
    return header + "".join(render_finding_card(i, f) for i, f in enumerate(ordered, start=1))


def _raw(scan: Scan | None, findings: list[Finding]) -> dict[str, Any]:
    if scan is None:
        return {}
    return {
        "scan": scan.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def _view(scan: Scan, findings: list[Finding], *, now: datetime | None = None) -> UiView:
    return render_status(scan, now=now), render_findings(scan, findings), _raw(scan, findings)


# ---------------------------------------------------------------------------
# Handlers (service-first, generator-based, no network)
# ---------------------------------------------------------------------------


def watch(
    service: ScanService,
    scan_id: str,
    *,
    poll_interval: float,
    timeout: float,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Iterator[UiView]:
    """Poll the live scan record, yielding a fresh view each time, until it ends."""
    scan_id = scan_id.strip()
    deadline = clock() + timeout
    while True:
        scan = service.get_scan(scan_id)
        if scan is None:
            yield render_error("Unknown scan:", f"{scan_id!r} was not found."), "", {}
            return
        findings = service.get_findings(scan_id) or []
        yield _view(scan, findings)
        if scan.status in ("done", "failed"):
            return
        if clock() >= deadline:
            yield (
                render_status(scan)
                + render_error(
                    "Stopped watching:",
                    f"the scan is still {scan.status} after {_fmt_duration(timeout)}. It "
                    f"continues in the background - paste scan id {scan.scan_id} into "
                    "'Look up a scan' later.",
                ),
                render_findings(scan, findings),
                _raw(scan, findings),
            )
            return
        sleep(poll_interval)


def analyze(
    service: ScanService,
    target_id: str,
    snippet: str,
    *,
    poll_interval: float,
    timeout: float,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Iterator[UiView]:
    """Submit a scan and stream its progress. Every error becomes a readable card."""
    try:
        request = ScanRequest(
            target_id=target_id or "",
            options=ScanOptions(snippet=snippet if target_id == "snippet" else None),
        )
        scan = service.submit_scan(request)
    except UnauthorizedTargetError as exc:
        detail = f"{exc}. Only allowlisted targets can be scanned."
        yield render_error("Not allowed:", detail), "", {"detail": str(exc)}
        return
    except ScanBusyError as exc:
        yield render_error("Busy:", str(exc)), "", {"detail": str(exc)}
        return
    except ValidationError as exc:
        errors = exc.errors()
        where = ".".join(str(p) for p in errors[0]["loc"]) if errors else "request"
        reason = errors[0]["msg"] if errors else str(exc)
        yield (
            render_error("Invalid request:", f"{where}: {reason}"),
            "",
            {"detail": [{"loc": list(e["loc"]), "msg": e["msg"]} for e in errors]},
        )
        return
    yield from watch(
        service,
        scan.scan_id,
        poll_interval=poll_interval,
        timeout=timeout,
        sleep=sleep,
        clock=clock,
    )


# ---------------------------------------------------------------------------
# The Blocks app
# ---------------------------------------------------------------------------

_HEADER = """\
# Operation: Negative One

**ONO finds security vulnerabilities in code you are authorized to test, shows how an \
attacker's input reaches the dangerous line, and proposes a fix.** It only scans targets \
on its allowlist - never an arbitrary website or URL.

**How to use it:** pick a target below (or choose *Paste code* and paste a snippet), \
click **Analyze**, and watch the progress card. A real scan clones the code, runs static \
analysis, then lets two agents investigate each candidate inside a sandbox - expect \
anywhere from a few seconds (mock backend) to several minutes. Findings appear as cards \
when it finishes.
"""

_LEGEND = """\
Every finding carries a **rung** on the output-strength ladder and a **verified** flag.

| Rung | Meaning |
|---|---|
| 1 · flagged line | A line looks vulnerable. No CWE, no fix yet. |
| 2 · CWE + patch | Plus the weakness class ([CWE](https://cwe.mitre.org/)) and a proposed patch. |
| 3 · reachability proven | Plus a read-only proof that attacker input really reaches the sink. |
| 4 · fix proven | Plus proof the fix works: patch applies, the proof no longer fires, tests pass. |
| 5 · detection rule | Plus a rule to catch exploitation until the patch ships. |

* **✔ verified** - a deterministic checker (plain code, no model) confirmed the claim.
* **⚠ not verified** - asserted by the analysis agents; treat it as a strong lead, not a proof.
* **Severity** (critical / high / medium / low) is the impact if the flaw is real; \
**confidence** is how sure the analysis is that it *is* real.
* **Candidates** are the suspicious lines static analysis flags; the agents **confirm** or \
**dismiss** each one. Only confirmed candidates become findings - dismissed ones are \
listed in the activity log so you can see what was ruled out.
"""


def build_ui(service: ScanService) -> gr.Blocks:
    """Create the Gradio Blocks app bound to a :class:`ScanService`."""
    settings = service.settings
    choices: list[tuple[str, str]] = [
        (f"{t.name}  ·  {KIND_LABELS.get(t.kind, t.kind)}", t.target_id)
        for t in service.registry.all()
    ]
    default_target = "pygoat" if service.registry.is_authorized("pygoat") else choices[0][1]
    poll_interval = settings.ui_poll_interval_s
    timeout = settings.ui_poll_timeout_s
    # One watcher per possible in-flight scan, so a second reviewer never queues behind
    # the first one's polling loop.
    concurrency = settings.max_active_scans + settings.max_queued_scans

    def on_analyze(target_id: str, snippet: str) -> Iterator[UiView]:
        yield from analyze(
            service, target_id, snippet, poll_interval=poll_interval, timeout=timeout
        )

    def on_lookup(scan_id: str) -> Iterator[UiView]:
        yield from watch(service, scan_id, poll_interval=poll_interval, timeout=timeout)

    def toggle_snippet(target_id: str) -> Any:
        return gr.update(visible=target_id == "snippet")

    backend_note = (
        "Backend: **mock** - instant, canned findings (for demos and CI)."
        if settings.model_backend == "mock"
        else f"Backend: **{settings.model_backend}** - real model + sandbox; scans take minutes."
    )

    # analytics_enabled=False: a security tool must not phone home (no outbound calls).
    with gr.Blocks(title="Operation: Negative One", analytics_enabled=False) as blocks:
        gr.Markdown(_HEADER, elem_classes=["ono-header"])
        with gr.Row():
            with gr.Column(scale=2, min_width=320):
                target = gr.Dropdown(
                    choices=choices,
                    value=default_target,
                    label="Target",
                    info="Only these allowlisted targets can be scanned.",
                )
                snippet = gr.Code(
                    value=EXAMPLE_SNIPPET,
                    language="python",
                    label="Code to analyze (Paste code target only)",
                    lines=10,
                    visible=default_target == "snippet",
                )
                run = gr.Button("Analyze", variant="primary", size="lg")
                gr.Markdown(backend_note, elem_classes=["ono-note"])
                with gr.Accordion("Look up a scan by id", open=False):
                    scan_id_box = gr.Textbox(label="Scan id", placeholder="scn_…", max_lines=1)
                    lookup = gr.Button("Show scan")
            with gr.Column(scale=3):
                status = gr.HTML(
                    value='<div class="ono-status idle muted">No scan yet - pick a target '
                    "and click <strong>Analyze</strong>.</div>",
                    label="Progress",
                )
        findings = gr.HTML()
        with gr.Accordion("How to read a finding (rungs, verified, severity)", open=False):
            gr.Markdown(_LEGEND)
        with gr.Accordion("Raw JSON (what the API returns)", open=False):
            raw = gr.JSON()

        target.change(toggle_snippet, inputs=target, outputs=snippet)
        run.click(
            on_analyze,
            inputs=[target, snippet],
            outputs=[status, findings, raw],
            show_progress="minimal",
            concurrency_limit=concurrency,
        )
        lookup.click(
            on_lookup,
            inputs=scan_id_box,
            outputs=[status, findings, raw],
            show_progress="minimal",
            concurrency_limit=concurrency,
        )

    return blocks


UI_CSS = """
.ono-header h1 { margin-bottom: 0.2em; }
.ono-note p { opacity: 0.75; font-size: 0.9em; margin: 0; }
.muted { opacity: 0.7; }

/* status card */
.ono-status { border: 1px solid var(--border-color-primary); border-radius: 10px;
  padding: 14px 16px; background: var(--block-background-fill); }
.ono-status.idle { padding: 24px; text-align: center; }
.ono-status-head { display: flex; align-items: center; gap: 10px; font-size: 1.05em; }
.ono-headline { font-weight: 600; }
.ono-meta { opacity: 0.7; font-size: 0.85em; margin: 4px 0 10px; }
.ono-pill { padding: 2px 10px; border-radius: 999px; font-size: 0.8em; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.04em; color: #fff; }
.ono-pill.queued  { background: #6b7280; }
.ono-pill.running { background: #2563eb; }
.ono-pill.done    { background: #16a34a; }
.ono-pill.failed  { background: #dc2626; }
.ono-progress { display: flex; align-items: center; gap: 10px; padding: 8px 10px;
  margin: 6px 0 10px; border-radius: 8px; background: rgba(37, 99, 235, 0.10);
  font-weight: 500; }
.ono-spinner { width: 14px; height: 14px; border-radius: 50%; flex: none;
  border: 2px solid rgba(37, 99, 235, 0.3); border-top-color: #2563eb;
  animation: ono-spin 0.9s linear infinite; }
@keyframes ono-spin { to { transform: rotate(360deg); } }
.ono-error { padding: 10px 12px; border-radius: 8px; margin: 6px 0 10px;
  background: rgba(220, 38, 38, 0.10); border: 1px solid rgba(220, 38, 38, 0.35); }
.ono-hint { opacity: 0.8; font-size: 0.9em; margin-top: 4px; }
.ono-stages { list-style: none; margin: 0; padding: 0; display: grid;
  grid-template-columns: 1.4em minmax(8em, max-content) 1fr; row-gap: 3px; column-gap: 8px; }
.ono-stage { display: contents; font-size: 0.92em; }
.ono-stage-icon { text-align: center; }
.ono-stage.ok .ono-stage-icon { color: #16a34a; }
.ono-stage.failed .ono-stage-icon, .ono-stage.failed .ono-stage-detail { color: #dc2626; }
.ono-stage.active .ono-stage-icon { color: #2563eb; }
.ono-stage.active .ono-stage-name { font-weight: 600; }
.ono-stage.pending, .ono-stage.skipped { opacity: 0.55; }
.ono-stage-detail { opacity: 0.8; overflow-wrap: anywhere; }
.ono-log { margin-top: 10px; font-size: 0.85em; }
.ono-log summary { cursor: pointer; opacity: 0.8; }
.ono-log ul { list-style: none; padding: 6px 0 0; margin: 0; max-height: 14em; overflow: auto; }
.ono-log time { opacity: 0.6; font-family: var(--font-mono); margin-right: 6px; }

/* findings */
.ono-findings-head h2 { margin: 12px 0 6px; }
.ono-verdicts { margin-top: 6px; font-size: 0.9em; opacity: 0.85; }
.ono-empty { border: 1px dashed var(--border-color-primary); border-radius: 10px;
  padding: 22px; margin-top: 12px; text-align: center; }
.ono-empty-title { font-size: 1.2em; font-weight: 600; margin-bottom: 4px; }
.ono-card { border: 1px solid var(--border-color-primary); border-left-width: 6px;
  border-radius: 10px; padding: 14px 16px; margin: 12px 0;
  background: var(--block-background-fill); }
.ono-card.sev-critical { border-left-color: #b91c1c; }
.ono-card.sev-high     { border-left-color: #ea580c; }
.ono-card.sev-medium   { border-left-color: #ca8a04; }
.ono-card.sev-low      { border-left-color: #16a34a; }
.ono-card header { display: flex; align-items: baseline; gap: 10px; }
.ono-card h3 { margin: 0; font-size: 1.1em; }
.ono-idx { opacity: 0.5; font-weight: 700; }
.ono-badges { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
.ono-badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 0.8em;
  font-weight: 600; border: 1px solid var(--border-color-primary); text-decoration: none;
  color: var(--body-text-color); background: var(--background-fill-secondary); }
.ono-badge.cwe { border-color: #2563eb; color: #2563eb; }
.ono-badge.sev.critical { background: #b91c1c; color: #fff; border-color: #b91c1c; }
.ono-badge.sev.high     { background: #ea580c; color: #fff; border-color: #ea580c; }
.ono-badge.sev.medium   { background: #ca8a04; color: #fff; border-color: #ca8a04; }
.ono-badge.sev.low      { background: #16a34a; color: #fff; border-color: #16a34a; }
.ono-badge.verified   { border-color: #16a34a; color: #16a34a; }
.ono-badge.unverified { border-color: #ca8a04; color: #b45309; }
.ono-loc { font-size: 0.95em; margin: 4px 0; }
.ono-desc { margin: 8px 0; }
.ono-h { font-weight: 600; margin-bottom: 2px; }
.ono-trace ol { margin: 4px 0 8px 1.2em; padding: 0; }
.ono-trace li { margin: 2px 0; overflow-wrap: anywhere; }
.ono-trace .sym { opacity: 0.9; }
.ono-trace .note { opacity: 0.75; font-style: italic; }
.ono-patch summary { cursor: pointer; font-weight: 600; margin: 6px 0; }
.ono-patch pre { margin: 4px 0 0; padding: 10px; border-radius: 8px; overflow-x: auto;
  font-size: 0.85em; line-height: 1.4; background: var(--background-fill-secondary);
  border: 1px solid var(--border-color-primary); }
.ono-diff .add  { color: #15803d; background: rgba(22, 163, 74, 0.12); display: inline-block;
  width: 100%; }
.ono-diff .del  { color: #b91c1c; background: rgba(220, 38, 38, 0.12); display: inline-block;
  width: 100%; }
.ono-diff .hunk { color: #2563eb; }
.ono-diff .file { font-weight: 700; }
"""
