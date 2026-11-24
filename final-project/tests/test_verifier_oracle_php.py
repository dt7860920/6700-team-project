"""The PHP sink oracle: dispatch (offline, no `php` needed) and the real uopz hooks, exercised
through a genuine ``php`` subprocess via :class:`LocalExecSandbox` - the PHP sibling of
:mod:`test_verifier_oracle_js`. The offline tests pin the language/CWE routing and the shell
commands the host builds; the hook tests prove the integrity contract end to end:

* a VULNERABLE sink driven through the "app's" entry point -> the canary reaches the
  dangerous argument with the flagged line on the stack -> rung 3;
* a SAFE variant (proc_open's argv array - no shell) -> stays rung <= 2 (no false positive);
* a CHEATING PoC that reaches the sink itself, never through the flagged file - rejected.

The hook tests skip (not fail) unless ``php`` is on PATH *with* the ``uopz`` extension - the
real jail always has both (the ``ono-php-jail`` image); this file is extra host-side coverage
of the hook LOGIC. See ``test_verifier_php_docker.py`` for the real-jail end-to-end proof
(``ONO_DOCKER_TESTS=1 pytest -m docker``).
"""

from __future__ import annotations

import shutil
import subprocess
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
    PHP_EXTENSIONS,
    PHP_SUPPORTED_CWES,
    language_of,
    new_canary,
    oracle_supports,
    skip_reason,
)
from ono.verifier.oracle_php import oracle_command_php, stage_command_php

_NOOP_PATCH = "--- a/does/not/exist.php\n+++ b/does/not/exist.php\n@@ -1 +1 @@\n-x\n+y\n"


def _php_uopz_available() -> bool:
    if shutil.which("php") is None:
        return False
    try:
        out = subprocess.run(
            ["php", "-r", "echo extension_loaded('uopz') ? 'yes' : 'no';"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.stdout.strip() == "yes"


php_uopz_required = pytest.mark.skipif(
    not _php_uopz_available(), reason="php with the uopz extension is not available on this host"
)


def _finding(cwe: str, sink_file: str, sink_line: int, source_line: int) -> Finding:
    trace = [
        TraceStep(file=sink_file, line=source_line, symbol="source", note="attacker-controlled"),
        TraceStep(file=sink_file, line=sink_line, symbol="sink", note=f"sink ({cwe})"),
    ]
    return Finding(
        finding_id=finding_id_for("scn_php", "t", sink_file, sink_line, cwe),
        fingerprint=fingerprint_for("t", sink_file, sink_line, cwe),
        scan_id="scn_php",
        target_id="t",
        title=f"{cwe} PHP family case",
        cwe=cwe,
        severity="high",
        file=sink_file,
        line_range=(sink_line, sink_line),
        trace=trace,
        confidence=0.8,
        rung=2,
        verified=False,
        description="PHP family fixture",
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
        verifier_poc_timeout_s=45.0,
        max_verifier_retries=1,
    )
    verifier = GradedVerifier(
        settings, model=ScriptedModel(script=script), executor=FakeExecExecutor()
    )
    report = verifier.verify("scn_php", ws, [_finding(cwe, sink_file, sink_line, source_line)])
    return report.findings[0]


# ---------------------------------------------------------------------------
# Dispatch (offline): which language/CWE combinations the oracle will even attempt
# ---------------------------------------------------------------------------


def test_language_of_routes_php_by_extension() -> None:
    for suffix in PHP_EXTENSIONS:
        assert language_of(f"app/index{suffix}") == "php"
    assert language_of("app/index.php") == "php"
    assert language_of("app/server.py") == "python"
    assert language_of("app/server.js") == "javascript"


def test_oracle_supports_a_php_command_injection_finding() -> None:
    assert oracle_supports(_finding("CWE-78", "index.php", 10, 5)) == ""


def test_oracle_supports_php_sql_and_code_injection_and_inclusion() -> None:
    assert oracle_supports(_finding("CWE-89", "db.php", 10, 5)) == ""
    assert oracle_supports(_finding("CWE-95", "calc.php", 10, 5)) == ""
    assert oracle_supports(_finding("CWE-98", "inc.php", 10, 5)) == ""


def test_oracle_rejects_a_php_cwe_it_does_not_instrument() -> None:
    """CWE-611 (XXE) is dynamically proven in Python but has no PHP hook - this must stay an
    honest, specific skip, never a silent pass."""
    reason = oracle_supports(_finding("CWE-611", "parse.php", 10, 5))
    assert reason != "" and "no PHP sink oracle for CWE-611" in reason


def test_oracle_still_applies_the_universal_skip_reasons_to_php() -> None:
    """A property-based CWE (not a taint sink in ANY language) skips with the SAME reason text
    regardless of language - the skip-map is language-agnostic by design."""
    reason = oracle_supports(_finding("CWE-798", "config.php", 10, 5))
    assert reason == f"CWE-798 is not dynamically provable: {skip_reason('CWE-798')}"


def test_php_supported_cwes_cover_exactly_the_catalog_families() -> None:
    # The eight roots the PHP catalog emits (ono.planning.catalog).
    expected_roots = {
        "CWE-78",
        "CWE-95",
        "CWE-89",
        "CWE-98",
        "CWE-22",
        "CWE-502",
        "CWE-918",
        "CWE-79",
    }
    assert expected_roots <= PHP_SUPPORTED_CWES
    # CWE-95 belongs to the code-injection family root CWE-94, so that is accepted too.
    assert "CWE-94" in PHP_SUPPORTED_CWES
    # SSTI / XXE have no PHP hook and are not claimed.
    assert "CWE-1336" not in PHP_SUPPORTED_CWES
    assert "CWE-611" not in PHP_SUPPORTED_CWES


def test_stage_command_php_writes_oracle_and_poc_via_base64() -> None:
    cmd = stage_command_php("<?php echo 1;\n")
    assert "mkdir -p .ono" in cmd
    assert ".ono/oracle.php" in cmd and ".ono/poc.php" in cmd
    assert "base64 -d" in cmd


def test_oracle_command_php_runs_php_with_the_finding_config() -> None:
    f = _finding("CWE-78", "index.php", 32, 28)
    cmd = oracle_command_php(f, new_canary(f.cwe))
    assert cmd.startswith("php ")
    assert ".ono/oracle.php" in cmd
    assert "CWE-78" in cmd and "index.php" in cmd


# ---------------------------------------------------------------------------
# The real uopz hooks, via a genuine `php` subprocess (skipped without php+uopz on PATH)
# ---------------------------------------------------------------------------

_CMDI_APP = (
    "<?php\n"
    "function diagnose($host) {\n"
    "  return system('ping -c 1 ' . $host);\n"  # line 3: VULN (shell string)
    "}\n"
    "function diagnoseSafe($host) {\n"
    "  $p = proc_open(['ping', '-c', '1', $host], [], $pipes);\n"  # line 6: SAFE (argv form)
    "  if (is_resource($p)) { proc_close($p); }\n"
    "  return '';\n"
    "}\n"
)

_HONEST_POC = (
    "<?php\n"
    "require getcwd() . '/app.php';\n"
    "try { diagnose(getenv('ONO_PAYLOAD')); } catch (\\Throwable $e) {}\n"
)


@php_uopz_required
def test_php_command_injection_is_proven(tmp_path: Path) -> None:
    proven = _prove(
        tmp_path,
        {"app.php": _CMDI_APP},
        cwe="CWE-78",
        sink_file="app.php",
        sink_line=3,
        source_line=2,
        poc=_HONEST_POC,
    )
    assert proven.verified is True and proven.rung >= 3
    assert proven.verification is not None and proven.verification.evidence


@php_uopz_required
def test_php_proc_open_argv_form_is_not_a_command_injection_sink(tmp_path: Path) -> None:
    poc = (
        "<?php\n"
        "require getcwd() . '/app.php';\n"
        "try { diagnoseSafe(getenv('ONO_PAYLOAD')); } catch (\\Throwable $e) {}\n"
    )
    proven = _prove(
        tmp_path,
        {"app.php": _CMDI_APP},
        cwe="CWE-78",
        sink_file="app.php",
        sink_line=6,
        source_line=5,
        poc=poc,
        name="ws_safe",
    )
    assert proven.verified is False and proven.rung <= 2
    check = proven.verification.check("poc_reaches_sink") if proven.verification else None
    assert check is not None and check.status == "failed"
    assert "NOT in its dangerous argument" in check.detail


@php_uopz_required
def test_php_cheating_poc_is_rejected(tmp_path: Path) -> None:
    poc = "<?php\ntry { system('echo ' . getenv('ONO_PAYLOAD')); } catch (\\Throwable $e) {}\n"
    proven = _prove(
        tmp_path,
        {"app.php": _CMDI_APP},
        cwe="CWE-78",
        sink_file="app.php",
        sink_line=3,
        source_line=2,
        poc=poc,
        name="ws_cheat",
    )
    assert proven.verified is False and proven.rung <= 2
    check = proven.verification.check("poc_reaches_sink") if proven.verification else None
    assert check is not None and check.status == "failed"
    assert "not the flagged sink" in check.detail


_EVAL_APP = (
    "<?php\n"
    "function calc($expr) {\n"
    "  return assert($expr);\n"  # line 3: VULN (assert evaluates a string as code)
    "}\n"
)


@php_uopz_required
def test_php_assert_code_injection_is_proven(tmp_path: Path) -> None:
    poc = (
        "<?php\n"
        "require getcwd() . '/app.php';\n"
        "try { calc(getenv('ONO_PAYLOAD')); } catch (\\Throwable $e) {}\n"
    )
    proven = _prove(
        tmp_path,
        {"app.php": _EVAL_APP},
        cwe="CWE-95",
        sink_file="app.php",
        sink_line=3,
        source_line=2,
        poc=poc,
        name="ws_eval",
    )
    assert proven.verified is True and proven.rung >= 3
