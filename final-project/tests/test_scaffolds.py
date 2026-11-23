"""The prover's framework-aware PoC scaffolding (ono.agents.scaffolds).

These lock in two things: the scaffold points the prover at the real entry point and the
right test client, and it is NOT an answer key - it never contains a concrete payload or
the oracle's canary, only the instruction to read ``os.environ["ONO_PAYLOAD"]``.
"""

from __future__ import annotations

import pytest

from ono.agents.scaffolds import detect_framework, entry_hint, scaffold_for
from ono.models import Finding, TraceStep


def _finding(file: str = "app/server.py", cwe: str = "CWE-89") -> Finding:
    return Finding(
        finding_id="fnd_x",
        fingerprint="fp",
        scan_id="s",
        target_id="t",
        title="t",
        cwe=cwe,
        severity="high",
        file=file,
        line_range=(41, 41),
        trace=[
            TraceStep(file=file, line=12, symbol='request.args.get("q")', note="attacker input"),
            TraceStep(file=file, line=41, symbol="cur.execute", note="sink"),
        ],
        confidence=0.8,
        rung=2,
        verified=False,
        description="d",
        patch_diff="",
    )


@pytest.mark.parametrize(
    ("window", "expected"),
    [
        ("from flask import Flask\napp = Flask(__name__)\n@app.route('/x')", "flask"),
        ("from fastapi import FastAPI\n@app.get('/x')", "fastapi"),
        ("from django.http import HttpResponse\nrequest.GET.get('q')", "django"),
        ("def handle(request):\n    return db.run(request['q'])", ""),  # framework-free
    ],
)
def test_detect_framework(window: str, expected: str) -> None:
    assert detect_framework(_finding(), window) == expected


def test_detect_framework_for_js() -> None:
    f = _finding(file="server.js", cwe="CWE-78")
    assert detect_framework(f, "const app = express();\napp.get('/run', ...)") == "express"


def test_detect_framework_for_nestjs() -> None:
    f = _finding(file="app.controller.ts", cwe="CWE-78")
    window = "import { Controller, Get } from '@nestjs/common';\n@Controller('cats')"
    assert detect_framework(f, window) == "nestjs"


def test_detect_framework_for_next() -> None:
    f = _finding(file="pages/api/run.js", cwe="CWE-78")
    window = "export default function handler(req, res) { res.json({}); }"
    assert detect_framework(f, window) == "next"


def test_scaffold_for_js_reads_process_env_not_os_environ() -> None:
    f = _finding(file="server.js", cwe="CWE-78")
    scaffold = scaffold_for(f, "const app = express();\napp.get('/run', ...)")
    assert "process.env.ONO_PAYLOAD" in scaffold
    assert "ephemeral loopback" in scaffold.lower() or "loopback port" in scaffold.lower()
    for leak in ("' OR '1'='1", "; rm -rf", "../../etc/passwd", "UNION SELECT"):
        assert leak.lower() not in scaffold.lower()


def test_scaffold_for_python_still_reads_os_environ() -> None:
    f = _finding(file="app/server.py", cwe="CWE-89")
    scaffold = scaffold_for(f, "from flask import Flask\napp = Flask(__name__)")
    assert 'os.environ["ONO_PAYLOAD"]' in scaffold
    assert "process.env" not in scaffold


def test_entry_hint_reads_the_first_trace_hop() -> None:
    hint = entry_hint(_finding())
    assert "request.args.get" in hint and "app/server.py:12" in hint


def test_entry_hint_without_a_trace() -> None:
    f = _finding()
    f.trace = []
    assert "no data-flow trace" in entry_hint(f)


def test_scaffold_names_the_entry_and_sink_and_is_not_an_answer_key() -> None:
    scaffold = scaffold_for(_finding(), "from flask import Flask\napp = Flask(__name__)")
    assert "ONO_PAYLOAD" in scaffold  # it tells the prover to read the canary from the env
    assert "test_client()" in scaffold  # the flask-specific recipe
    assert "import-time" in scaffold.lower()  # the import-stub guidance
    assert "app/server.py:41" in scaffold  # the sink location
    # It must NOT contain anything that looks like a concrete injection payload.
    for leak in ("' OR '1'='1", "; drop table", "../../etc/passwd", "UNION SELECT"):
        assert leak.lower() not in scaffold.lower()


def test_scaffold_falls_back_to_generic_without_a_framework() -> None:
    scaffold = scaffold_for(_finding(), "def handle(request):\n    return run(request['q'])")
    assert "front-controller" in scaffold.lower() or "front controller" in scaffold.lower()
    assert "test_client()" not in scaffold  # no framework-specific block was added
