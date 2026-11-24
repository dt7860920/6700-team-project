"""Host side of the PHP sink oracle: stage the files, run it in the jail with ``php``.

The PHP sibling of :mod:`ono.verifier.oracle_js`. Everything here goes through the same
:class:`~ono.agents.tools.SandboxExecutor` the Python and JS oracles use (``run`` under the
jail's timeout, memory and PID limits; egress blocked by the Executor's network policy); the
host never runs target code or PoCs itself.

The wire protocol (what the in-jail script prints) is byte-for-byte the same as the Python
and JS oracles' - one ``ONO_ORACLE_RESULT <json>`` line with the same fields - so
:func:`ono.verifier.oracle.parse_result`, :func:`~ono.verifier.oracle.explain` and
:func:`~ono.verifier.oracle.summarize` are reused unchanged: a CWE number means the same
thing in any language, and those functions only ever look at ``finding.cwe`` and the hits
list. :class:`PhpSinkOracle` exposes the identical ``stage`` / ``run`` / ``run_staged`` /
``cleanup`` surface as :class:`~ono.verifier.oracle.SinkOracle` and
:class:`~ono.verifier.oracle_js.JsSinkOracle` so :mod:`ono.verifier.verify` can pick any
oracle for a finding without caring which one it got (see
:data:`~ono.verifier.oracle.PHP_EXTENSIONS` / :func:`~ono.verifier.oracle.language_of`).

The dangerous PHP builtins (``system``, ``shell_exec``, ``unserialize``, ``mysqli_query``,
...) cannot be redefined in pure PHP, so the in-jail oracle (:file:`oracle_hooks.php`) uses
the ``uopz`` PECL extension to hook them at runtime - it observes a call's arguments and lets
the original proceed. The canary never reaches the prover (same no-answer-key rule as the
Python and JS oracles); the oracle requires the flagged file:line on the ``debug_backtrace``
call stack with the canary in the dangerous argument before it counts a finding as proven.
"""

from __future__ import annotations

import base64
import json
import logging
import shlex
from importlib import resources

from ono.agents.tools import SandboxExecutor
from ono.executor.models import RunResult
from ono.models import Finding
from ono.verifier._oracle import RESULT_MARKER
from ono.verifier.oracle import ORACLE_DIR, OracleResult, parse_result

__all__ = ["PhpSinkOracle", "oracle_command_php", "stage_command_php"]

log = logging.getLogger(__name__)

ORACLE_FILE = f"{ORACLE_DIR}/oracle.php"
POC_FILE = f"{ORACLE_DIR}/poc.php"
_TAIL = 600


def _oracle_source() -> str:
    return resources.files("ono.verifier").joinpath("oracle_hooks.php").read_text(encoding="utf-8")


def stage_command_php(poc_code: str) -> str:
    """The shell command that (re)writes ``.ono/oracle.php`` and ``.ono/poc.php``."""
    oracle_b64 = base64.b64encode(_oracle_source().encode("utf-8")).decode("ascii")
    poc_b64 = base64.b64encode(poc_code.encode("utf-8")).decode("ascii")
    return (
        f"rm -rf {ORACLE_DIR} && mkdir -p {ORACLE_DIR} && "
        f"printf '%s' {oracle_b64} | base64 -d > {ORACLE_FILE} && "
        f"printf '%s' {poc_b64} | base64 -d > {POC_FILE}"
    )


def oracle_command_php(finding: Finding, canary: str) -> str:
    config = {
        "cwe": finding.cwe,
        "sink_file": finding.file,
        "line_start": finding.line_range[0],
        "line_end": finding.line_range[1],
        "canary": canary,
        "poc": POC_FILE,
        "tolerance": 3,
    }
    # ``-d error_reporting=0`` keeps PHP deprecation/notice chatter out of the result stream;
    # the oracle emits its single ONO_ORACLE_RESULT line to stdout regardless. (No composer /
    # third-party include path yet - dependency provisioning for PHP is a follow-up.)
    return f"php -d error_reporting=0 {ORACLE_FILE} {shlex.quote(json.dumps(config))}"


class PhpSinkOracle:
    """Runs PHP PoCs for one finding inside one jail. Same contract as ``SinkOracle``."""

    def __init__(self, sandbox: SandboxExecutor, *, timeout_s: float) -> None:
        self.sandbox = sandbox
        self.timeout_s = timeout_s
        self.runs = 0

    def stage(self, poc_code: str) -> str:
        """Write ``.ono/oracle.php`` and ``.ono/poc.php``; "" on success, else why not."""
        staged = self.sandbox.run(stage_command_php(poc_code), timeout_s=30.0)
        if staged.exit_code != 0:
            tail = (staged.stderr or staged.stdout).strip()[-_TAIL:]
            return f"could not stage the PoC in the sandbox: {tail}"
        return ""

    def run_staged(self, finding: Finding, canary: str) -> OracleResult:
        """Run the oracle against whatever PoC is currently staged on disk."""
        self.runs += 1
        run = self.sandbox.run(oracle_command_php(finding, canary), timeout_s=self.timeout_s)
        result = _parse(run)
        _log(finding, result, run)
        return result

    def run(self, finding: Finding, poc_code: str, canary: str) -> OracleResult:
        """Stage the oracle + PoC and run them; never raises for a failing PoC."""
        error = self.stage(poc_code)
        if error:
            return OracleResult(ok=False, error=error)
        self.runs += 1
        run = self.sandbox.run(oracle_command_php(finding, canary), timeout_s=self.timeout_s)
        result = _parse(run)
        _log(finding, result, run)
        return result

    def cleanup(self) -> None:
        self.sandbox.run(f"rm -rf {ORACLE_DIR}", timeout_s=10.0)


def _parse(run: RunResult) -> OracleResult:
    """Identical to :func:`ono.verifier.oracle.parse_result`, with a PHP-specific hint when
    ``php`` itself is missing from the jail image (exit 127 / "not found") - a no-php base
    image (a scan with no PHP findings never ends up here) stays an honest "did not fire",
    not a crash."""
    if run.exit_code in (126, 127) and "php" in (run.stderr or "").lower():
        return OracleResult(
            ok=False,
            error="php is not available in this sandbox image (no PHP runtime); "
            f"{(run.stderr or run.stdout).strip()[-_TAIL:]}",
            run=run,
        )
    return parse_result(run)


def _log(finding: Finding, result: OracleResult, run: RunResult) -> None:
    log.info(
        "oracle_php[%s]: %s (exit %s, %.0f ms, %d hit(s))",
        finding.location,
        "FIRED" if result.fired else ("error: " + result.error if not result.ok else "quiet"),
        run.exit_code,
        run.duration_ms,
        len(result.hits),
    )


assert RESULT_MARKER == "ONO_ORACLE_RESULT ", "oracle_hooks.php's RESULT_MARKER must match this"
assert RESULT_MARKER in _oracle_source(), "oracle_hooks.php must emit the shared RESULT_MARKER"
