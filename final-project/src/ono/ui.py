"""Gradio analyst UI.

One meaningful input -> one corresponding output: the analyst picks an
authorized target (or pastes a snippet), clicks **Analyze**, and sees the
findings rendered as cards - CWE, severity, ``file:line``, rung, confidence,
the source->sink trace, and the unified-diff patch.

The UI is mounted *inside* the FastAPI app (``api.create_app``) and calls the
same :class:`~ono.service.ScanService` the HTTP API uses, so there is one
process, one published port, and one allowlist check.
"""

from __future__ import annotations

import json
from typing import Any

import gradio as gr
from pydantic import ValidationError

from ono.models import Finding, ScanOptions, ScanRequest, ScanResponse
from ono.service import ScanService
from ono.targets import UnauthorizedTargetError

_RUNG_LABELS = {
    1: "bare flag",
    2: "CWE + patch",
    3: "+ proof it is reachable",
    4: "+ proof the fix works",
    5: "+ detection rule",
}

_SEVERITY_BADGE = {
    "critical": "🟥 critical",
    "high": "🟧 high",
    "medium": "🟨 medium",
    "low": "🟩 low",
}

_EXAMPLE_SNIPPET = """\
import sqlite3, subprocess

def find_user(conn, name):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchone()

def ping(host):
    return subprocess.check_output("ping -c1 " + host, shell=True)
"""

_CSS = """
.ono-header h1 { margin-bottom: 0.1em; }
.ono-header p  { margin-top: 0; opacity: 0.8; }
"""


def _render_scan_summary(scan: ScanResponse) -> str:
    stages = (
        " → ".join(f"`{s.stage}` ({s.duration_ms:.1f} ms)" for s in scan.pipeline)
        or "_no stages recorded_"
    )
    return (
        f"**Scan** `{scan.scan_id}` · target `{scan.target_id}` · status **{scan.status}** · "
        f"backend `{scan.model_backend}` · **{scan.findings_count}** finding(s)\n\n"
        f"Pipeline: {stages}"
    )


def _render_finding(index: int, f: Finding) -> str:
    verified = "✅ verified" if f.verified else "⚠️ unverified"
    trace_lines = (
        "\n".join(
            f"{i}. `{t.file}:{t.line}` — `{t.symbol}`" + (f" — {t.note}" if t.note else "")
            for i, t in enumerate(f.trace, start=1)
        )
        or "_no trace_"
    )
    parts = [
        f"### {index}. {f.title}",
        f"**{f.cwe}** · {_SEVERITY_BADGE.get(f.severity, f.severity)} · "
        f"`{f.location}` · rung **{f.rung}/5** ({_RUNG_LABELS[f.rung]}) · "
        f"confidence **{f.confidence:.0%}** · {verified}",
        "",
        f.description or "",
        "",
        "**Source → sink trace**",
        trace_lines,
        "",
        "**Proposed patch**",
        f"```diff\n{f.patch_diff.rstrip()}\n```",
    ]
    if f.detection_rule:
        parts += ["", "**Detection rule (rung 5)**", f"```yaml\n{f.detection_rule.rstrip()}\n```"]
    parts += ["", "---"]
    return "\n".join(parts)


def _render_findings(scan: ScanResponse) -> str:
    if not scan.findings:
        return (
            "## No verified findings\n\n"
            "The pipeline ran but nothing passed the verifier for this target/input."
        )
    header = f"## {len(scan.findings)} verified finding(s)\n\n"
    return header + "\n".join(_render_finding(i, f) for i, f in enumerate(scan.findings, start=1))


def build_ui(service: ScanService) -> gr.Blocks:
    """Create the Gradio Blocks app bound to a :class:`ScanService`."""

    choices: list[tuple[str, str]] = [
        (f"{t.name}  —  {t.target_id}  ({t.kind}, {', '.join(t.languages)})", t.target_id)
        for t in service.registry.all()
    ]
    default_target = "pygoat" if service.registry.is_authorized("pygoat") else choices[0][1]

    def analyze(target_id: str, snippet: str) -> tuple[str, str, dict[str, Any]]:
        try:
            request = ScanRequest(
                target_id=target_id,
                options=ScanOptions(snippet=snippet if target_id == "snippet" else None),
            )
            scan = service.start_scan(request)
        except UnauthorizedTargetError as exc:
            return f"**403 — {exc}**", "", {"detail": str(exc)}
        except ValidationError as exc:
            return "**Invalid request**", f"```\n{exc}\n```", json.loads(exc.json())
        return (
            _render_scan_summary(scan),
            _render_findings(scan),
            scan.model_dump(mode="json"),
        )

    def toggle_snippet(target_id: str) -> Any:
        return gr.update(visible=target_id == "snippet")

    # analytics_enabled=False: a security tool must not phone home (no outbound calls).
    with gr.Blocks(title="Operation: Negative One", analytics_enabled=False) as blocks:
        gr.Markdown(
            "# Operation: Negative One\n"
            "Agentic vulnerability analysis of **authorized** code targets — find it, prove it, "
            "fix it. *Deliverable 2 prototype: the analyzer backend is mocked; API, config, "
            "container and UI are real.*",
            elem_classes=["ono-header"],
        )
        with gr.Row():
            with gr.Column(scale=2):
                target = gr.Dropdown(
                    choices=choices,
                    value=default_target,
                    label="Authorized target",
                    info="Only targets in the allowlist can be scanned (GET /targets).",
                )
                snippet = gr.Code(
                    value=_EXAMPLE_SNIPPET,
                    language="python",
                    label="Code snippet (used only for the 'snippet' target)",
                    lines=10,
                    visible=default_target == "snippet",
                )
                run = gr.Button("Analyze", variant="primary")
            with gr.Column(scale=3):
                summary = gr.Markdown(label="Scan")
        findings = gr.Markdown(label="Findings")
        with gr.Accordion("Raw JSON response (what the API returns)", open=False):
            raw = gr.JSON()

        target.change(toggle_snippet, inputs=target, outputs=snippet)
        run.click(analyze, inputs=[target, snippet], outputs=[summary, findings, raw])

    return blocks


UI_CSS = _CSS
