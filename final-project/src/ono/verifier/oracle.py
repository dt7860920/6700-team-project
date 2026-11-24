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
from typing import Any, Protocol

from ono.agents.tools import SandboxExecutor
from ono.executor.models import SANDBOX_DEPS, RunResult
from ono.models import Finding
from ono.verifier._oracle import RESULT_MARKER, SUPPORTED_CWES, family_of, probe_for

__all__ = [
    "JS_EXTENSIONS",
    "JS_SUPPORTED_CWES",
    "ORACLE_DIR",
    "PHP_EXTENSIONS",
    "PHP_SUPPORTED_CWES",
    "SKIP_REASONS",
    "OracleResult",
    "SinkOracle",
    "SinkOracleProtocol",
    "explain",
    "language_of",
    "new_canary",
    "oracle_supports",
    "parse_result",
    "skip_reason",
    "stage_command",
    "summarize",
]

log = logging.getLogger(__name__)

ORACLE_DIR = ".ono"
ORACLE_FILE = f"{ORACLE_DIR}/oracle.py"
POC_FILE = f"{ORACLE_DIR}/poc.py"
_TAIL = 600


def _oracle_source() -> str:
    return resources.files("ono.verifier").joinpath("_oracle.py").read_text(encoding="utf-8")


def new_canary(cwe: str = "") -> str:
    """A fresh, unguessable payload. The core is letters and digits only, so it survives any
    sink unchanged; for the escaping-defended families (XSS/LDAP) a metacharacter probe is
    appended so an escaped copy no longer matches (see ``_oracle.CANARY_PROBE``)."""
    return "ONO" + secrets.token_hex(8) + probe_for(cwe)


# CWEs the dynamic oracle deliberately does NOT try to prove: there is no runtime observation
# where a secret canary reaching a dangerous argument distinguishes vulnerable from safe.
# These findings stay honestly model-asserted (rung <= 2), never false-failed.
SKIP_REASONS: dict[str, str] = {
    "CWE-327": "weak/broken cryptography is a property of the ALGORITHM chosen, not of tainted "
    "input reaching a sink - nothing a canary can trigger at runtime (stays model-asserted)",
    "CWE-328": "use of a weak hash is an algorithm-choice property, not a tainted-data-flow sink",
    "CWE-326": "inadequate key strength is a configuration property, not a runtime taint sink",
    "CWE-798": "hard-coded credentials are static constants in the source; no canary flows into "
    "them at runtime (detect by reading the code, not by driving a sink)",
    "CWE-259": "a hard-coded password is a static constant, not a tainted-input sink",
    "CWE-285": "improper authorization is a missing/weak CHECK; there is no dangerous argument a "
    "canary lands in (stays model-asserted)",
    "CWE-306": "missing authentication is the ABSENCE of a check, not a sink reached by taint",
    "CWE-862": "missing authorization is an absent check, not a dangerous-argument sink",
    "CWE-863": "incorrect authorization is a logic property of a check, not a taint sink",
    "CWE-352": "CSRF is the absence of a token check; no canary-in-argument observation applies",
    "CWE-319": "cleartext transmission is a transport-configuration property, not a runtime sink",
    "CWE-16": "insecure configuration is a static property; nothing a canary triggers",
    "CWE-732": "incorrect permission assignment is a filesystem-state property, not a taint sink",
    "CWE-113": "CR/LF response-splitting is blocked at set-time by current WSGI/ASGI header "
    "validation, so a tainted header value cannot reach a splittable response (model-asserted)",
    "CWE-209": "information exposure through an error message is observed in output, not as a "
    "canary in a dangerous argument; not dynamically proven this way",
}


def skip_reason(cwe: str) -> str:
    """A precise reason this CWE is not dynamically provable, or '' if none is recorded."""
    return SKIP_REASONS.get(cwe, "")


JS_EXTENSIONS: tuple[str, ...] = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
"""File suffixes routed to the Node sink oracle (:mod:`ono.verifier.oracle_js`)."""

# The CWE families the Node oracle (``oracle_hooks.js``) actually instruments: command
# injection, code injection (eval/Function/vm), SQL injection, path traversal / external
# control of file name, SSRF and unsafe deserialization. These are the SAME CWE roots the
# Python oracle already defines in ``_oracle.CWE_FAMILIES`` - a CWE number means the same
# thing regardless of language, so :func:`~ono.verifier._oracle.family_of` and :func:`explain`
# work unchanged for a JS result. Every other dynamically-provable-in-Python family (SSTI,
# XPath, LDAP, NoSQL, XXE, open redirect, reflected output) has no JS hook yet - a JS/TS
# finding in one of those stays honestly ``skipped``, never falsely failed.
JS_SUPPORTED_CWES: frozenset[str] = frozenset(
    {"CWE-78", "CWE-77", "CWE-88"}  # command injection
    | {"CWE-94", "CWE-95", "CWE-96"}  # code injection
    | {"CWE-89"}  # SQL injection
    | {"CWE-22", "CWE-23", "CWE-36"}  # path traversal
    | {"CWE-73"}  # external control of file name/path
    | {"CWE-918"}  # SSRF
    | {"CWE-502", "CWE-20"}  # unsafe deserialization
)


PHP_EXTENSIONS: tuple[str, ...] = (".php", ".phtml", ".php3", ".php4", ".php5", ".phps")
"""File suffixes routed to the PHP sink oracle (:mod:`ono.verifier.oracle_php`). Mirrors the
suffixes :mod:`ono.planning.php_frontend` already lowers to IR language ``"php"``."""

# The CWE families the PHP oracle (``oracle_hooks.php``) accepts - exactly the CWEs the PHP
# catalog emits (see ``ono.planning.catalog``): OS command injection (78), code injection via
# eval/assert/create_function (95), SQL injection (89), file inclusion (98), path traversal
# (22), unsafe deserialization (502), SSRF (918) and reflected XSS (79), plus their family
# alternates (a CWE number means the same thing in any language, so the shared
# ``_oracle.family_of`` works unchanged). The FUNCTION-form members of each family are hooked
# at runtime with ``uopz``; the PHP LANGUAGE CONSTRUCTS ``eval`` / ``include`` / ``echo`` /
# backtick cannot be hooked, so a finding whose sink is purely one of those (notably CWE-98)
# stays honestly ``skipped``/unproven at rung <= 2, never falsely failed (documented in
# ``oracle_hooks.php``). Composer dependency provisioning is a follow-up; target
# procedural/dependency-light PHP first.
PHP_SUPPORTED_CWES: frozenset[str] = frozenset(
    {"CWE-78", "CWE-77", "CWE-88"}  # command injection
    | {"CWE-94", "CWE-95", "CWE-96"}  # code injection (eval/assert/create_function)
    | {"CWE-89"}  # SQL injection
    | {"CWE-98"}  # file inclusion (RFI/LFI) - language construct, stays unproven
    | {"CWE-22", "CWE-23", "CWE-36"}  # path traversal
    | {"CWE-502", "CWE-20"}  # unsafe deserialization
    | {"CWE-918"}  # SSRF
    | {"CWE-79", "CWE-80"}  # reflected unescaped output (echo/print/printf)
)


def language_of(file: str) -> str:
    """``"python"`` / ``"javascript"`` / ``"php"`` / ``""`` (unknown) from a relative path."""
    if file.endswith(".py"):
        return "python"
    if file.endswith(JS_EXTENSIONS):
        return "javascript"
    if file.endswith(PHP_EXTENSIONS):
        return "php"
    return ""


def oracle_supports(finding: Finding) -> str:
    """Empty if the oracle can judge this finding, else why not (language / CWE)."""
    language = language_of(finding.file)
    if language == "python":
        if finding.cwe not in SUPPORTED_CWES:
            reason = skip_reason(finding.cwe)
            if reason:
                return f"{finding.cwe} is not dynamically provable: {reason}"
            return (
                f"no sink oracle for {finding.cwe} (dynamically proven families: SQL/command/"
                "code injection, unsafe deserialization, path traversal, SSRF, SSTI, XPath, "
                "LDAP, NoSQL, XXE, open redirect, file-name control, reflected unescaped output)"
            )
        return ""
    if language == "javascript":
        if finding.cwe not in JS_SUPPORTED_CWES:
            reason = skip_reason(finding.cwe)
            if reason:
                return f"{finding.cwe} is not dynamically provable: {reason}"
            return (
                f"no JS/TS sink oracle for {finding.cwe} (dynamically proven JS/TS families: "
                "command injection, code injection (eval/Function/vm), SQL injection, path "
                "traversal / external control of file name, SSRF, unsafe deserialization - a "
                "narrower set than the Python oracle covers)"
            )
        return ""
    if language == "php":
        if finding.cwe not in PHP_SUPPORTED_CWES:
            reason = skip_reason(finding.cwe)
            if reason:
                return f"{finding.cwe} is not dynamically provable: {reason}"
            return (
                f"no PHP sink oracle for {finding.cwe} (dynamically proven PHP families: OS "
                "command injection, code injection (assert/create_function), SQL injection, "
                "path traversal, unsafe deserialization, SSRF, reflected output - the "
                "function-form sinks the uopz oracle hooks)"
            )
        return ""
    suffix = finding.file.rsplit(".", 1)[-1] if "." in finding.file else "?"
    return f"no dynamic sink oracle for .{suffix} files (Python, JS/TS and PHP only for now)"


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
        # Provisioned dependencies (read-only, Executor-controlled); appended to sys.path
        # by the oracle only if the directory exists - a no-deps jail is unaffected.
        "sys_path": [SANDBOX_DEPS],
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
    return _explain(result, finding, full_traceback=True)


def summarize(result: OracleResult, finding: Finding) -> str:
    """The same verdict for the finding's record: the exception's LAST line instead of the
    traceback tail, so a clipped detail still names the cause (``ModuleNotFoundError: ...``)."""
    return _explain(result, finding, full_traceback=False)


def _explain(result: OracleResult, finding: Finding, *, full_traceback: bool) -> str:
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
        if full_traceback:
            parts.append("the script raised:\n" + result.poc_error.strip()[-_TAIL:])
        else:
            parts.append("the script raised: " + _last_line(result.poc_error))
        hint = _import_failure_hint(result.poc_error)
        if hint:
            parts.append(hint)
    elif result.poc_exit not in (0, None):
        parts.append(f"the script exited with status {result.poc_exit}")
    if result.poc_stderr.strip() and full_traceback:
        parts.append("stderr tail:\n" + result.poc_stderr.strip()[-_TAIL:])
    return "; ".join(parts) if len(parts) == 1 else parts[0] + "\n" + "\n".join(parts[1:])


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    return lines[-1][:300] if lines else ""


def _import_failure_hint(traceback_text: str) -> str:
    """Turn a common import-time crash into an actionable instruction for the next attempt.

    The dominant real-app failure is the PoC dying while importing the app (module-level
    code needs a DB / secret / service the jail lacks), never reaching the sink. Naming the
    fix - stub it - is what turns a stuck loop into a proof. This is technique, not an
    answer key: it never carries a payload or a canary.
    """
    tail = traceback_text.strip().splitlines()[-1:] or [""]
    last = tail[0]
    if "KeyError" in last and "environ" in traceback_text:
        return (
            "the app read a required environment variable at import time; set it with "
            'os.environ.setdefault("<VAR>", "x") BEFORE importing the app'
        )
    if last.startswith(("ModuleNotFoundError", "ImportError")):
        return (
            "a module could not be imported at load time; only drive modules the repository "
            "already ships - stub an optional/third-party dependency with unittest.mock, or "
            "import the specific handler module rather than the whole package"
        )
    if last.startswith(("OperationalError", "ConnectionError", "ConnectionRefusedError")) or (
        "connect" in traceback_text and ("Error" in last)
    ):
        return (
            "the app opened a database/network connection at import time; stub it with "
            "unittest.mock (patch the connect/engine factory the module imports, .start() it "
            "before the import) so execution can reach the sink"
        )
    return ""


class SinkOracleProtocol(Protocol):
    """What :mod:`ono.verifier.verify` needs from a sink oracle - satisfied by both
    :class:`SinkOracle` (Python) and :class:`~ono.verifier.oracle_js.JsSinkOracle` (JS/TS)
    so the verifier can pick either one for a finding without caring which it got."""

    sandbox: SandboxExecutor
    runs: int

    def stage(self, poc_code: str) -> str: ...

    def run(self, finding: Finding, poc_code: str, canary: str) -> OracleResult: ...

    def run_staged(self, finding: Finding, canary: str) -> OracleResult: ...

    def cleanup(self) -> None: ...


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
