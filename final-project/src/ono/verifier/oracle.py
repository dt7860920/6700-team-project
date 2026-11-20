"""Host side of the sink oracle: stage the files, run it in the jail, read the verdict.

Everything executed here goes through the :class:`~ono.agents.tools.SandboxExecutor`
(``run`` under the jail's timeout, memory and PID limits; egress blocked by the
Executor's network policy). The host never runs target code or PoCs itself.

Staging writes two files under ``.ono/`` in the workspace through a ``base64 -d`` shell
command (no quoting hazards, no dependency on the patch applier), the oracle is started
with ``python3 -I`` and its single ``ONO_ORACLE_RESULT`` line is parsed back into an
:class:`OracleResult`. :func:`explain` turns a negative result into the specific feedback
the prover gets on its next attempt.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import shlex
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from ono.agents.tools import SandboxExecutor
from ono.executor.models import RunResult
from ono.models import Finding
from ono.verifier._oracle import RESULT_MARKER, SUPPORTED_CWES, family_of

__all__ = [
    "ORACLE_DIR",
    "OracleResult",
    "SinkOracle",
    "explain",
    "new_canary",
    "oracle_supports",
    "parse_result",
    "stage_command",
]

log = logging.getLogger(__name__)

ORACLE_DIR = ".ono"
ORACLE_FILE = f"{ORACLE_DIR}/oracle.py"
POC_FILE = f"{ORACLE_DIR}/poc.py"
_TAIL = 600


def _oracle_source() -> str:
    return resources.files("ono.verifier").joinpath("_oracle.py").read_text(encoding="utf-8")


def new_canary() -> str:
    """A fresh, unguessable payload: letters and digits only, so it survives any sink."""
    return "ONO" + secrets.token_hex(8)


def oracle_supports(finding: Finding) -> str:
    """Empty if the oracle can judge this finding, else why not (language / CWE)."""
    if not finding.file.endswith(".py"):
        suffix = finding.file.rsplit(".", 1)[-1] if "." in finding.file else "?"
        return f"no dynamic sink oracle for .{suffix} files (Python only for now)"
    if finding.cwe not in SUPPORTED_CWES:
        return (
            f"no sink oracle for {finding.cwe} (supported: SQL/command/code injection, "
            "unsafe deserialization, path traversal, SSRF)"
        )
    return ""


@dataclass(slots=True)
class OracleResult:
    """What one PoC run established. ``fired`` is the rung-3 verdict."""

    ok: bool
    fired: bool = False
    reached_elsewhere: list[dict[str, Any]] = field(default_factory=list)
    untainted_at_sink: bool = False
    hits: list[dict[str, Any]] = field(default_factory=list)
    poc_exit: int | None = None
    poc_error: str = ""
    poc_stdout: str = ""
    poc_stderr: str = ""
    error: str = ""
    run: RunResult | None = None

    @property
    def evidence(self) -> str:
        hit = next((h for h in self.hits if h.get("at_sink")), None)
        if hit is None:
            return ""
        frame: dict[str, Any] = next(iter(hit.get("stack") or []), {})
        where = f"{frame.get('file')}:{frame.get('line')}" if frame else "?"
        return f"{hit.get('kind')} at {where} received the payload: {hit.get('argument')!r}"


def stage_command(poc_code: str) -> str:
    """The shell command that (re)writes ``.ono/oracle.py`` and ``.ono/poc.py``."""
    oracle_b64 = base64.b64encode(_oracle_source().encode("utf-8")).decode("ascii")
    poc_b64 = base64.b64encode(poc_code.encode("utf-8")).decode("ascii")
    return (
        f"rm -rf {ORACLE_DIR} && mkdir -p {ORACLE_DIR} && "
        f"printf '%s' {oracle_b64} | base64 -d > {ORACLE_FILE} && "
        f"printf '%s' {poc_b64} | base64 -d > {POC_FILE}"
    )


def oracle_command(finding: Finding, canary: str) -> str:
    config = {
        "cwe": finding.cwe,
        "sink_file": finding.file,
        "line_start": finding.line_range[0],
        "line_end": finding.line_range[1],
        "canary": canary,
        "poc": POC_FILE,
        "tolerance": 3,
    }
    return f"python3 -I {ORACLE_FILE} {shlex.quote(json.dumps(config))}"


def parse_result(run: RunResult) -> OracleResult:
    """The result line out of the run's stdout; anything else is an ``ok=False`` result."""
    line = next(
        (ln for ln in reversed(run.stdout.splitlines()) if ln.startswith(RESULT_MARKER)), None
    )
    if line is None:
        if run.timed_out:
            reason = f"the PoC did not finish within the time limit ({run.duration_ms:.0f} ms)"
        elif run.oom_killed:
            reason = "the PoC exceeded the sandbox memory limit"
        else:
            tail = (run.stderr or run.stdout).strip()[-_TAIL:]
            reason = f"the oracle produced no result (exit {run.exit_code}): {tail or 'no output'}"
        return OracleResult(ok=False, error=reason, run=run)
    try:
        data = json.loads(line[len(RESULT_MARKER) :])
    except ValueError:
        return OracleResult(ok=False, error="the oracle result was not valid JSON", run=run)
    if not isinstance(data, dict) or not data.get("ok"):
        err = str(data.get("error", "unknown")) if isinstance(data, dict) else "unknown"
        return OracleResult(ok=False, error=f"the oracle failed: {err}", run=run)
    return OracleResult(
        ok=True,
        fired=bool(data.get("fired")),
        reached_elsewhere=[h for h in data.get("reached_elsewhere", []) if isinstance(h, dict)],
        untainted_at_sink=bool(data.get("untainted_at_sink")),
        hits=[h for h in data.get("hits", []) if isinstance(h, dict)],
        poc_exit=data.get("poc_exit") if isinstance(data.get("poc_exit"), int) else None,
        poc_error=str(data.get("poc_error") or ""),
        poc_stdout=str(data.get("poc_stdout") or ""),
        poc_stderr=str(data.get("poc_stderr") or ""),
        run=run,
    )


def explain(result: OracleResult, finding: Finding) -> str:
    """Why a run did not prove the finding - specific enough for the prover to act on."""
    if not result.ok:
        return result.error
    if result.fired:
        return ""
    accepted = sorted(family_of(finding.cwe))
    parts: list[str] = []
    if result.reached_elsewhere:
        hit = result.reached_elsewhere[0]
        frame: dict[str, Any] = next(iter(hit.get("stack") or []), {})
        where = f"{frame.get('file')}:{frame.get('line')}" if frame else "outside the repository"
        parts.append(
            f"the payload reached {hit.get('kind')} at {where}, not the flagged sink "
            f"{finding.location}; the flagged line must be on the call stack when the sink "
            "fires (drive the application's own entry point, do not call the sink yourself)"
        )
    elif result.untainted_at_sink:
        parts.append(
            f"the sink at {finding.location} executed but the payload was NOT in its dangerous "
            "argument (it was sanitized, parameterized, or placed in the wrong input field); "
            "put ONO_PAYLOAD exactly where the attacker-controlled value enters"
        )
    elif result.hits:
        kinds = ", ".join(sorted({f"{h.get('cwe')}/{h.get('kind')}" for h in result.hits}))
        parts.append(
            f"the payload reached other sinks ({kinds}) but none matching "
            f"{'/'.join(accepted)} at {finding.location}"
        )
    else:
        parts.append(
            f"no instrumented sink saw the payload; the script never reached {finding.location}"
        )
    if result.poc_error:
        parts.append("the script raised:\n" + result.poc_error.strip()[-_TAIL:])
    elif result.poc_exit not in (0, None):
        parts.append(f"the script exited with status {result.poc_exit}")
    if result.poc_stderr.strip():
        parts.append("stderr tail:\n" + result.poc_stderr.strip()[-_TAIL:])
    return "; ".join(parts) if len(parts) == 1 else parts[0] + "\n" + "\n".join(parts[1:])


class SinkOracle:
    """Runs PoCs for one finding inside one jail."""

    def __init__(self, sandbox: SandboxExecutor, *, timeout_s: float) -> None:
        self.sandbox = sandbox
        self.timeout_s = timeout_s
        self.runs = 0

    def stage(self, poc_code: str) -> str:
        """Write ``.ono/oracle.py`` and ``.ono/poc.py``; return "" on success, else why not."""
        staged = self.sandbox.run(stage_command(poc_code), timeout_s=30.0)
        if staged.exit_code != 0:
            tail = (staged.stderr or staged.stdout).strip()[-_TAIL:]
            return f"could not stage the PoC in the sandbox: {tail}"
        return ""

    def run_staged(self, finding: Finding, canary: str) -> OracleResult:
        """Run the oracle against whatever PoC is currently staged on disk."""
        self.runs += 1
        run = self.sandbox.run(oracle_command(finding, canary), timeout_s=self.timeout_s)
        result = parse_result(run)
        log.info(
            "oracle[%s]: %s (exit %s, %.0f ms, %d hit(s))",
            finding.location,
            "FIRED" if result.fired else ("error: " + result.error if not result.ok else "quiet"),
            run.exit_code,
            run.duration_ms,
            len(result.hits),
        )
        return result

    def run(self, finding: Finding, poc_code: str, canary: str) -> OracleResult:
        """Stage the oracle + PoC and run them; never raises for a failing PoC."""
        error = self.stage(poc_code)
        if error:
            return OracleResult(ok=False, error=error)
        self.runs += 1
        run = self.sandbox.run(oracle_command(finding, canary), timeout_s=self.timeout_s)
        result = parse_result(run)
        log.info(
            "oracle[%s]: %s (exit %s, %.0f ms, %d hit(s))",
            finding.location,
            "FIRED" if result.fired else ("error: " + result.error if not result.ok else "quiet"),
            run.exit_code,
            run.duration_ms,
            len(result.hits),
        )
        return result

    def cleanup(self) -> None:
        self.sandbox.run(f"rm -rf {ORACLE_DIR}", timeout_s=10.0)
