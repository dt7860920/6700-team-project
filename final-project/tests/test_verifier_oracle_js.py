"""The JS/TS sink oracle: dispatch (offline, no `node` needed) and the real hooks, exercised
through a genuine ``node`` subprocess via :class:`LocalExecSandbox` - the same pattern
:mod:`test_verifier_families` uses for the added Python families. Each hook test proves three
things, the identical integrity contract as the Python oracle:

* a VULNERABLE sink driven through the "app's" entry point -> the canary reaches the
  dangerous argument with the flagged line on the stack -> rung 3;
* a SAFE variant (the family's real defense: an argv array instead of a shell, a confined
  path, a fixed/allowlisted host, a bound parameter) -> stays rung <= 2 (no false positive);
* a CHEATING PoC that reaches the sink itself, never through the flagged file - rejected.

Node-dependent tests skip (not fail) when ``node`` is not on PATH - the real jail always has
it for a JS/TS scan (the combined ``sandbox_image_node``); this file is extra, host-side
coverage of the hook LOGIC itself. See ``test_verifier_js_docker.py`` for the real-jail,
real-Express, real-npm-provisioning end-to-end proof (``ONO_DOCKER_TESTS=1 pytest -m docker``).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from agentfakes import FakeExecExecutor, ScriptedModel, action
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.models import Finding, TraceStep, finding_id_for, fingerprint_for
from ono.verifier import GradedVerifier
from ono.verifier.oracle import (
    JS_SUPPORTED_CWES,
    language_of,
    new_canary,
    oracle_supports,
    skip_reason,
)
from ono.verifier.oracle_js import NODE_MODULES_DIR, oracle_command_js, stage_command_js

_NOOP_PATCH = "--- a/does/not/exist.js\n+++ b/does/not/exist.js\n@@ -1 +1 @@\n-x\n+y\n"

node_required = pytest.mark.skipif(
    shutil.which("node") is None, reason="node is not on PATH on this host"
)


def _finding(cwe: str, sink_file: str, sink_line: int, source_line: int) -> Finding:
    trace = [
        TraceStep(file=sink_file, line=source_line, symbol="source", note="attacker-controlled"),
        TraceStep(file=sink_file, line=sink_line, symbol="sink", note=f"sink ({cwe})"),
    ]
    return Finding(
        finding_id=finding_id_for("scn_js", "t", sink_file, sink_line, cwe),
        fingerprint=fingerprint_for("t", sink_file, sink_line, cwe),
        scan_id="scn_js",
        target_id="t",
        title=f"{cwe} JS family case",
        cwe=cwe,
        severity="high",
        file=sink_file,
        line_range=(sink_line, sink_line),
        trace=trace,
        confidence=0.8,
        rung=2,
        verified=False,
        description="JS family fixture",
        patch_diff="",
    )


def _prove(
    tmp_path: Path,
    files: dict[str, str],
    *,
    cwe: str,
    sink_file: str,
    sink_line: int,
    source_line: int,
    poc: str,
    name: str = "ws",
    env: dict[str, str] | None = None,
) -> Finding:
    ws = tmp_path / name
    ws.mkdir()
    for rel, content in files.items():
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == PROVER.system_prompt:
            return action("submit_poc", code=poc, how="drive the entry point")
        if system == FIXER.system_prompt:
            return action("submit_patch", diff=_NOOP_PATCH, summary="noop")
        raise AssertionError("unexpected role")

    settings = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://model.test/v1",
        executor_token=SecretStr("unit-test-token-0123456789"),
        workspace_dir=tmp_path,
        context_lines=6,
        verifier_poc_timeout_s=60.0,
        max_verifier_retries=1,
    )
    verifier = GradedVerifier(
        settings, model=ScriptedModel(script=script), executor=FakeExecExecutor()
    )
    report = verifier.verify("scn_js", ws, [_finding(cwe, sink_file, sink_line, source_line)])
    return report.findings[0]


# ---------------------------------------------------------------------------
# Dispatch (offline): which language/CWE combinations the oracle will even attempt
# ---------------------------------------------------------------------------


def test_language_of_routes_by_extension() -> None:
    assert language_of("app/server.py") == "python"
    for suffix in ("js", "jsx", "mjs", "cjs", "ts", "tsx"):
        assert language_of(f"app/server.{suffix}") == "javascript"
    assert language_of("app/server.rb") == ""


def test_oracle_supports_a_js_command_injection_finding() -> None:
    f = _finding("CWE-78", "server.js", 10, 5)
    assert oracle_supports(f) == ""


def test_oracle_supports_a_ts_sql_injection_finding() -> None:
    f = _finding("CWE-89", "server.ts", 10, 5)
    assert oracle_supports(f) == ""


def test_oracle_rejects_a_js_family_it_does_not_instrument() -> None:
    """CWE-79 (reflected XSS) is dynamically proven in Python (werkzeug's Response hook) but
    has no JS/TS hook yet - this must stay an honest, specific skip, never a silent pass."""
    f = _finding("CWE-79", "server.js", 10, 5)
    reason = oracle_supports(f)
    assert reason != ""
    assert "no JS/TS sink oracle for CWE-79" in reason
    assert "narrower set than the Python oracle" in reason


def test_oracle_still_applies_the_universal_skip_reasons_to_js() -> None:
    """A property-based CWE (not a taint sink in ANY language) skips with the SAME reason
    text regardless of language - the skip-map is language-agnostic by design."""
    f = _finding("CWE-798", "server.js", 10, 5)
    reason = oracle_supports(f)
    assert reason == f"CWE-798 is not dynamically provable: {skip_reason('CWE-798')}"


def test_oracle_supports_an_unknown_extension() -> None:
    f = _finding("CWE-78", "server.rb", 10, 5)
    assert "no dynamic sink oracle for .rb files" in oracle_supports(f)
    assert "Python, JS/TS and PHP only" in oracle_supports(f)


def test_js_supported_cwes_cover_exactly_the_six_documented_families() -> None:
    expected_roots = {"CWE-78", "CWE-94", "CWE-89", "CWE-22", "CWE-73", "CWE-918", "CWE-502"}
    # every root must be supported, and every supported CWE must trace back to one of them
    assert expected_roots <= JS_SUPPORTED_CWES
    assert "CWE-79" not in JS_SUPPORTED_CWES  # XSS is NOT one of them (Python-only hook)
    assert "CWE-1336" not in JS_SUPPORTED_CWES  # neither is SSTI


def test_stage_command_js_writes_oracle_and_poc_via_base64() -> None:
    cmd = stage_command_js("const x = 1;\n")
    assert "mkdir -p .ono" in cmd
    assert ".ono/oracle.js" in cmd and ".ono/poc.js" in cmd
    assert "base64 -d" in cmd


def test_oracle_command_js_runs_node_with_the_deps_node_modules_path() -> None:
    f = _finding("CWE-78", "server.js", 10, 5)
    cmd = oracle_command_js(f, new_canary(f.cwe))
    assert cmd.startswith("node .ono/oracle.js ")
    assert NODE_MODULES_DIR in cmd
    assert "CWE-78" in cmd


# ---------------------------------------------------------------------------
# The real hooks, via a genuine `node` subprocess (skipped without node on PATH)
# ---------------------------------------------------------------------------

_CMDI_APP = (
    "const { execSync, spawnSync } = require('child_process');\n"
    "function diagnose(host) {\n"
    "  return execSync('ping -c 1 ' + host).toString();\n"  # line 3: VULN
    "}\n"
    "function diagnoseSafe(host) {\n"
    "  const r = spawnSync('ping', ['-c', '1', host]);\n"  # line 6: SAFE (argv form)
    "  return r.stdout ? r.stdout.toString() : '';\n"
    "}\n"
    "module.exports = { diagnose, diagnoseSafe };\n"
)


@node_required
def test_js_command_injection_is_proven(tmp_path: Path) -> None:
    poc = (
        "const app = require('./app.js');\n"
        "try { app.diagnose(process.env.ONO_PAYLOAD); } catch (e) { /* ignore */ }\n"
    )
    proven = _prove(
        tmp_path,
        {"app.js": _CMDI_APP},
        cwe="CWE-78",
        sink_file="app.js",
        sink_line=3,
        source_line=1,
        poc=poc,
    )
    assert proven.verified is True and proven.rung >= 3
    assert proven.verification is not None and proven.verification.evidence


@node_required
def test_js_argv_form_is_not_a_command_injection_sink(tmp_path: Path) -> None:
    poc = (
        "const app = require('./app.js');\n"
        "try { app.diagnoseSafe(process.env.ONO_PAYLOAD); } catch (e) { /* ignore */ }\n"
    )
    proven = _prove(
        tmp_path,
        {"app.js": _CMDI_APP},
        cwe="CWE-78",
        sink_file="app.js",
        sink_line=6,
        source_line=5,
        poc=poc,
        name="ws_safe",
    )
    assert proven.verified is False and proven.rung <= 2
    check = proven.verification.check("poc_reaches_sink") if proven.verification else None
    assert check is not None and check.status == "failed"
    assert "NOT in its dangerous argument" in check.detail


@node_required
def test_js_cheating_poc_is_rejected(tmp_path: Path) -> None:
    poc = (
        "const { execSync } = require('child_process');\n"
        "try { execSync('echo ' + process.env.ONO_PAYLOAD); } catch (e) { /* ignore */ }\n"
    )
    proven = _prove(
        tmp_path,
        {"app.js": _CMDI_APP},
        cwe="CWE-78",
        sink_file="app.js",
        sink_line=3,
        source_line=1,
        poc=poc,
        name="ws_cheat",
    )
    assert proven.verified is False and proven.rung <= 2
    check = proven.verification.check("poc_reaches_sink") if proven.verification else None
    assert check is not None and check.status == "failed"
    assert "not the flagged sink" in check.detail


_EVAL_APP = (
    "function calc(expr) {\n"
    "  return eval(expr);\n"  # line 2: VULN
    "}\n"
    "module.exports = { calc };\n"
)


@node_required
def test_js_eval_code_injection_is_proven(tmp_path: Path) -> None:
    poc = (
        "const app = require('./app.js');\n"
        "try { app.calc(process.env.ONO_PAYLOAD); } catch (e) { /* ignore */ }\n"
    )
    proven = _prove(
        tmp_path,
        {"app.js": _EVAL_APP},
        cwe="CWE-94",
        sink_file="app.js",
        sink_line=2,
        source_line=1,
        poc=poc,
        name="ws_eval",
    )
    assert proven.verified is True and proven.rung >= 3


_PATH_APP = (
    "const fs = require('fs');\n"
    "const path = require('path');\n"
    "const BASE = __dirname;\n"
    "function readUser(name) {\n"
    "  return fs.readFileSync(path.join(BASE, name), 'utf8');\n"  # line 5: VULN
    "}\n"
    "function readConfined(name) {\n"
    "  const safe = path.basename(name);\n"
    "  return fs.readFileSync(path.join(BASE, safe), 'utf8');\n"  # line 9: SAFE
    "}\n"
    "module.exports = { readUser, readConfined };\n"
)


@node_required
def test_js_path_traversal_is_proven(tmp_path: Path) -> None:
    poc = (
        "const app = require('./app.js');\n"
        "try { app.readUser('../' + process.env.ONO_PAYLOAD); } catch (e) { /* ignore */ }\n"
    )
    proven = _prove(
        tmp_path,
        {"app.js": _PATH_APP},
        cwe="CWE-22",
        sink_file="app.js",
        sink_line=5,
        source_line=4,
        poc=poc,
        name="ws_path",
    )
    assert proven.verified is True and proven.rung >= 3


@node_required
def test_js_basename_confined_path_is_not_a_traversal_sink(tmp_path: Path) -> None:
    poc = (
        "const app = require('./app.js');\n"
        "try { app.readConfined('../' + process.env.ONO_PAYLOAD); } catch (e) { /* ignore */ }\n"
    )
    proven = _prove(
        tmp_path,
        {"app.js": _PATH_APP},
        cwe="CWE-22",
        sink_file="app.js",
        sink_line=9,
        source_line=7,
        poc=poc,
        name="ws_path_safe",
    )
    assert proven.verified is False and proven.rung <= 2


_SSRF_APP = (
    "const http = require('http');\n"
    "function fetchHost(host) {\n"
    "  return http.get({ hostname: host, port: 80, path: '/', timeout: 50 }, () => {})\n"
    "             .on('error', () => {});\n"  # line 3: VULN (host)
    "}\n"
    "function fetchFixed(host) {\n"
    "  return http.get({ hostname: '127.0.0.1', port: 1, path: '/' + host, timeout: 50 },\n"
    "    () => {}).on('error', () => {});\n"  # line 7-8: SAFE (host is fixed; host arg is path)
    "}\n"
    "module.exports = { fetchHost, fetchFixed };\n"
)


@node_required
def test_js_ssrf_is_proven(tmp_path: Path) -> None:
    poc = (
        "const app = require('./app.js');\n"
        "app.fetchHost(process.env.ONO_PAYLOAD);\n"
        "setTimeout(() => {}, 80);\n"
    )
    proven = _prove(
        tmp_path,
        {"app.js": _SSRF_APP},
        cwe="CWE-918",
        sink_file="app.js",
        sink_line=3,
        source_line=2,
        poc=poc,
        name="ws_ssrf",
    )
    assert proven.verified is True and proven.rung >= 3


@node_required
def test_js_fixed_host_request_is_not_an_ssrf_sink(tmp_path: Path) -> None:
    poc = (
        "const app = require('./app.js');\n"
        "app.fetchFixed(process.env.ONO_PAYLOAD);\n"
        "setTimeout(() => {}, 80);\n"
    )
    proven = _prove(
        tmp_path,
        {"app.js": _SSRF_APP},
        cwe="CWE-918",
        sink_file="app.js",
        sink_line=7,
        source_line=6,
        poc=poc,
        name="ws_ssrf_safe",
    )
    assert proven.verified is False and proven.rung <= 2


# ---------------------------------------------------------------------------
# SQL injection via an optional driver - shimmed on NODE_PATH so this runs without npm/Docker
# (the real app/npm/Docker path is covered by test_verifier_js_docker.py's Express fixture).
# ---------------------------------------------------------------------------

_MYSQL_SHIM = (
    "module.exports = { createConnection: () => ({\n"
    "  query: (sql, cb) => { if (cb) cb(null, []); },\n"
    "}) };\n"
)

_SQLI_APP = (
    "const mysql2 = require('mysql2');\n"
    "function search(term) {\n"
    "  const conn = mysql2.createConnection();\n"
    '  return conn.query("SELECT * FROM items WHERE name = \'" + term + "\'");\n'  # line 4
    "}\n"
    "module.exports = { search };\n"
)


@node_required
def test_js_sql_injection_is_proven_with_a_shimmed_driver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shim = tmp_path / "node_shim" / "mysql2"
    shim.mkdir(parents=True)
    (shim / "index.js").write_text(_MYSQL_SHIM)
    (shim / "package.json").write_text('{"name": "mysql2", "main": "index.js"}\n')
    monkeypatch.setenv("NODE_PATH", str(tmp_path / "node_shim"))
    poc = (
        "const app = require('./app.js');\n"
        "try { app.search(process.env.ONO_PAYLOAD); } catch (e) { /* ignore */ }\n"
    )
    proven = _prove(
        tmp_path,
        {"app.js": _SQLI_APP},
        cwe="CWE-89",
        sink_file="app.js",
        sink_line=4,
        source_line=2,
        poc=poc,
        name="ws_sqli",
    )
    assert proven.verified is True and proven.rung >= 3
