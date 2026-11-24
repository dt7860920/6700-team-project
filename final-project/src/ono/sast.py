"""Stage 2 - SAST shortlist.

Runs Semgrep over an ingested workspace and normalizes its JSON ``results`` into
:class:`Candidate` entries (file relative to the clone root, sink line, CWE hint,
rule id, matched excerpt). The shortlist is what bounds the model stage: the
analyst only ever reasons about *candidates*, never the whole repository.

Graceful degradation is required, not optional: if Semgrep is missing, crashes,
times out, or emits something unparseable, :func:`shortlist` falls back to a
lightweight built-in regex scanner (the same patterns the mock backend uses for
pasted snippets) so the SAST stage always yields candidates and never fails a scan.

Hardening - the workspace is an untrusted clone, scanned on the host: the fallback
never follows symlinks when walking or reading (a planted ``evil.py -> /etc/passwd`` or
``x.py -> /dev/zero`` is skipped, not read), every read is bounded in bytes, line length
and wall-clock, Semgrep runs with a scrubbed environment, and its output is size-capped
before it is parsed. A Semgrep run that did not complete is never reported as "clean".

Network - registry rulesets (``p/owasp-top-ten`` and the per-language ``p/...`` packs)
are fetched from semgrep.dev by the Semgrep CLI at scan time and cached locally, so this
stage is *not* air-gapped by default even though metrics and version checks are off.
For fully offline operation point ``sast_ruleset`` at a local rules file or directory
(any ``--config`` value Semgrep accepts) instead of ``p/...`` names (issue #105).

Sandbox - on Linux semgrep-core is run under ``setarch -R`` to disable ASLR (it segfaults
on some kernels otherwise), but that prefix cannot set the process personality inside a
hardened container that drops capabilities and sets no-new-privileges: ``setarch`` then
exits "Operation not permitted" and semgrep never starts. :func:`run_semgrep` detects that
and transparently retries without the prefix, so SAST does not silently collapse to the
Python-only regex fallback (which returns zero candidates on JS/Java/Go/... targets).

Deliberately NOT here yet (later steps): CodeQL / SARIF ingestion, call-graph
enrichment of candidates, entry-point union.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ono.models import Severity

log = logging.getLogger(__name__)

SastEngine = Literal["semgrep", "regex"]

# Overall wall-clock budget for one Semgrep run (the CLI's --timeout is per rule+file).
_SEMGREP_RUN_TIMEOUT_S = 600.0
# Per-rule/per-file memory cap (MB) + bounded jobs: without these semgrep-core
# can be OOM-killed on real repos and silently return zero results.
_SEMGREP_MAX_MEMORY_MB = 2000
_SEMGREP_JOBS = 2
_SEMGREP_RULE_TIMEOUT_S = 30
# Output bounds (issue #102): a JSON document larger than this is not parsed at all and more
# results than this are not iterated, so a pathological or adversarial target cannot drive
# the parser's memory. The first makes the run "unavailable" (regex fallback), the second
# truncates with a warning.
_SEMGREP_MAX_STDOUT_BYTES = 64 * 1024 * 1024
_SEMGREP_MAX_RESULTS = 5_000
# Exit codes after which a *zero-result* document is still evidence of a clean target
# (issue #104): 0 = ran to completion, 1 = findings with --error (not passed; listed for
# completeness), 3 = some target files could not be parsed (partial - each is in ``errors``).
# Anything else - 2 fatal / engine crash, 4-8 bad rules or config, 13 registry access denied,
# 14 could not execute - means the scan did not complete, so "no results" proves nothing.
_SEMGREP_COMPLETED_EXIT_CODES = frozenset({0, 1, 3})
# Structured ``errors[].type`` values that mean the engine itself failed (as Semgrep's JSON
# spells them, compared case-insensitively) plus the prose markers older versions emit.
_SEMGREP_FATAL_ERROR_TYPES = frozenset({"fatal error", "out of memory", "stack overflow"})
_SEMGREP_CRASH_MARKERS = ("exited with", "engine was killed", "Fatal error", "out of memory")
# The ``setarch -R`` ASLR-off prefix (see ``_aslr_safe_prefix``) cannot change the process
# personality inside a hardened sandbox - the app container drops all capabilities and sets
# no-new-privileges, so ``setarch`` fails with "Operation not permitted" and the whole
# ``setarch ... semgrep`` command exits non-zero BEFORE semgrep ever runs (so there is no
# JSON to parse). Detecting these markers in stderr lets ``run_semgrep`` transparently retry
# without the prefix instead of silently falling back to the Python-only regex scanner.
_SEMGREP_SETARCH_FAILURE_MARKERS = (
    "setarch:",
    "failed to set personality",
    "operation not permitted",
)
# Environment handed to the Semgrep subprocess (issue #106): what it needs to run, keep its
# settings / rule cache and (for ``p/...`` packs) reach the registry through a proxy or a
# custom CA - never the host's model keys, executor token or anything else this process
# inherited. ``SEMGREP_*`` variables are the tool's own configuration and pass through.
_SEMGREP_ENV_PASSTHROUGH = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }
)
_SEMGREP_ENV_PREFIXES = ("SEMGREP_",)

# Semgrep registry language packs appended per target language (unknown languages are skipped).
LANGUAGE_PACKS: dict[str, str] = {
    "python": "p/python",
    "javascript": "p/javascript",
    "typescript": "p/typescript",
    "java": "p/java",
    "go": "p/golang",
    "ruby": "p/ruby",
    "php": "p/php",
    "c": "p/c",
    "c#": "p/csharp",
    # C++ has no dedicated Semgrep registry pack (p/cpp is 404); .cpp/.cc/.hpp files are still
    # scanned by the language-agnostic base ruleset (config.sast_base_ruleset), and C++ is
    # recognised at ingest + reported by the regex fallback (see _UNCOVERED_EXTENSIONS).
}

_CWE_NUMBER = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
_SEVERITY_RANK = {"ERROR": 0, "WARNING": 1, "INFO": 2}
_REGEX_SEVERITY = {"critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO"}


@dataclass(slots=True)
class Candidate:
    """A SAST-style shortlist entry handed to the agent. ``line`` is the suspected sink."""

    file: str
    line: int
    cwe_hint: str
    rule: str
    excerpt: str = ""
    severity: str = ""  # Semgrep's ERROR / WARNING / INFO; used only to rank the queue
    # Filled by the threat-mapping stage (ono.planning): how the sink was found reachable.
    reach: str = ""  # direct / one-hop / param / in-entry / dynamic / unmapped ("" = not mapped)
    entry: str = ""  # the entry point, e.g. "GET /user -> app/views.py:11 user()"
    source: str = (
        ""  # the attacker-controlled expression, e.g. "request.args.get(\"id\") at views.py:13"
    )
    path: tuple[str, ...] = ()  # source -> sink hops, "file:line symbol - note" each


@dataclass(slots=True)
class Shortlist:
    """The candidate queue plus which engine produced it (surfaced in logs / tests)."""

    candidates: list[Candidate]
    engine: SastEngine
    note: str = ""
    dropped: list[str] = field(default_factory=list)
    # Non-empty when the queue is known to be incomplete (issue #101): the regex fallback ran
    # on a target with languages it cannot see, or stopped at its time budget. Downstream
    # must surface it - an empty queue with this set is *not* a clean target.
    degraded: str = ""


class SemgrepUnavailableError(RuntimeError):
    """Semgrep could not produce usable results (missing, crashed, timed out, bad JSON)."""


# ---------------------------------------------------------------------------
# Built-in regex rules (shared with the mock backend's snippet "SAST")
# ---------------------------------------------------------------------------

PATTERN_RULES: tuple[tuple[str, re.Pattern[str], str, Severity], ...] = (
    (
        "CWE-89",
        re.compile(
            r"\.(execute|executemany|raw)\(\s*(f[\"']|[\"'].*%|.*\+\s*\w|[\"'].*\.format\()"
        ),
        "sql-string-built-from-input",
        "high",
    ),
    (
        "CWE-78",
        re.compile(r"(os\.system\(|subprocess\.\w+\(.*shell\s*=\s*True|os\.popen\()"),
        "shell-command-from-string",
        "high",
    ),
    (
        "CWE-95",
        re.compile(r"\b(eval|exec)\(\s*[^\"')]"),
        "eval-of-dynamic-input",
        "critical",
    ),
    (
        "CWE-502",
        re.compile(r"(pickle\.loads?\(|yaml\.load\((?!.*Loader=yaml\.SafeLoader))"),
        "unsafe-deserialization",
        "high",
    ),
)

_REGEX_EXTENSIONS = frozenset({".py"})
_REGEX_LANGUAGES = frozenset({"python"})  # what the fallback can honestly claim to cover
# Source files of the other LANGUAGE_PACKS languages (issue #101): seen on disk during a
# fallback walk they mean part of the target went unanalyzed, which the shortlist reports.
_UNCOVERED_EXTENSIONS: dict[str, str] = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cc": "c++",
    ".cpp": "c++",
    ".cxx": "c++",
    ".hpp": "c++",
    ".hh": "c++",
    ".cs": "c#",
}
_WALK_EXTENSIONS = _REGEX_EXTENSIONS | frozenset(_UNCOVERED_EXTENSIONS)
_SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "site-packages", ".tox", "dist"}
)
_MAX_FILE_BYTES = 1_000_000
# Lines longer than this are skipped, not matched (issue #103): minified / generated code
# would make the patterns' ``.*`` groups quadratic in the line length.
_MAX_LINE_CHARS = 4_000
# Wall-clock budget for one fallback walk, checked between files (issue #103). When it runs
# out the walk stops and the shortlist says so instead of looking complete.
_REGEX_SCAN_TIMEOUT_S = 60.0


def scan_text(code: str, file: str) -> list[Candidate]:
    """Apply :data:`PATTERN_RULES` line by line (at most one candidate per line).

    Lines over :data:`_MAX_LINE_CHARS` are skipped: they are minified or generated code, and
    matching them would be quadratic in the line length.
    """
    candidates: list[Candidate] = []
    for lineno, line in enumerate(code.splitlines(), start=1):
        if len(line) > _MAX_LINE_CHARS:
            continue
        for cwe, pattern, rule, sev in PATTERN_RULES:
            if pattern.search(line):
                candidates.append(
                    Candidate(
                        file=file,
                        line=lineno,
                        cwe_hint=cwe,
                        rule=rule,
                        excerpt=line,
                        severity=_REGEX_SEVERITY[sev],
                    )
                )
                break
    return candidates


def iter_source_files(root: Path, extensions: frozenset[str] = _REGEX_EXTENSIONS) -> Iterator[Path]:
    """Yield regular source files under ``root`` (sorted walk, skipping vendored/VCS directories).

    Symlinks - to files or to directories - are neither followed nor yielded: the workspace
    is an untrusted clone and a planted link can point anywhere on the host (issue #100).
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath, name)
            if path.suffix in extensions and not path.is_symlink() and path.is_file():
                yield path


def read_source_file(path: Path, max_bytes: int = _MAX_FILE_BYTES) -> str | None:
    """Read ``path`` only if it is a regular file of at most ``max_bytes``; ``None`` otherwise.

    Symlinks are refused at every step - ``lstat`` first, ``O_NOFOLLOW`` on open, ``fstat``
    on the descriptor - and the read itself is bounded, so a repo-planted
    ``evil.py -> /etc/passwd`` reads nothing off the host and ``x.py -> /dev/zero``
    (``st_size`` 0, so it passes a size check) cannot hang the scan (issue #100). Devices,
    FIFOs and sockets are refused the same way; unreadable files are skipped, never raised.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        chunks: list[bytes] = []
        remaining = max_bytes + 1  # one byte over the cap proves the file grew past it
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 16))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > max_bytes:
        return None
    return raw.decode("utf-8", errors="replace")


@dataclass(slots=True)
class RegexScanReport:
    """What one fallback walk produced and how complete it was (feeds ``Shortlist.degraded``)."""

    candidates: list[Candidate] = field(default_factory=list)
    files_scanned: int = 0
    # LANGUAGE_PACKS languages whose source files were seen but which the patterns cannot see.
    uncovered_languages: set[str] = field(default_factory=set)
    timed_out: bool = False  # the wall-clock budget ran out before the walk finished


def regex_scan_report(root: Path, *, budget_s: float = _REGEX_SCAN_TIMEOUT_S) -> RegexScanReport:
    """The fallback engine: walk the workspace and apply the built-in patterns, bounded.

    Only regular ``.py`` files of at most :data:`_MAX_FILE_BYTES` are read (see
    :func:`read_source_file`), over-long lines are skipped (see :func:`scan_text`) and the
    whole walk stops once ``budget_s`` seconds have elapsed; the report says what was left
    out so the caller can mark the shortlist as incomplete rather than clean.
    """
    report = RegexScanReport()
    deadline = time.monotonic() + budget_s
    for path in iter_source_files(root, _WALK_EXTENSIONS):
        if time.monotonic() > deadline:
            report.timed_out = True
            log.warning(
                "sast(regex): stopping at the %.0fs budget after %d file(s); results incomplete",
                budget_s,
                report.files_scanned,
            )
            break
        if path.suffix in _UNCOVERED_EXTENSIONS:
            report.uncovered_languages.add(_UNCOVERED_EXTENSIONS[path.suffix])
            continue
        code = read_source_file(path)
        if code is None:
            log.debug(
                "sast(regex): skipping %s (not a regular file, too large or unreadable)", path
            )
            continue
        report.files_scanned += 1
        report.candidates.extend(scan_text(code, path.relative_to(root).as_posix()))
    return report


def regex_scan(root: Path) -> list[Candidate]:
    """The fallback engine's hits alone (:func:`regex_scan_report` also tells how complete)."""
    return regex_scan_report(root).candidates


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------


def semgrep_executable() -> str | None:
    """Prefer the ``semgrep`` installed next to this interpreter (the venv), then PATH."""
    venv_bin = Path(sys.executable).parent / "semgrep"
    if venv_bin.is_file():
        return str(venv_bin)
    return shutil.which("semgrep")


def semgrep_command(root: Path, rulesets: Iterable[str], executable: str = "semgrep") -> list[str]:
    """The exact CLI invocation (exposed so tests can assert on it)."""
    cmd = [
        executable,
        "scan",
        "--json",
        "--quiet",
        "--metrics=off",  # never phone home from the analysis box
        "--disable-version-check",
        "--no-git-ignore",  # .git was stripped at ingest; scan what is on disk
        f"--timeout={_SEMGREP_RULE_TIMEOUT_S}",
        f"--max-memory={_SEMGREP_MAX_MEMORY_MB}",
        f"--jobs={_SEMGREP_JOBS}",
    ]
    for ruleset in rulesets:
        cmd.extend(["--config", ruleset])
    cmd.append(".")  # relative target + cwd=root => paths relative to the clone root
    return cmd


def _aslr_safe_prefix() -> list[str]:
    """On Linux, run semgrep-core with ASLR disabled (``setarch -R``).

    semgrep-core (an OCaml binary) can segfault on some newer kernels due to
    address-space-layout randomization; ``setarch -R`` avoids it. A no-op where
    ``setarch`` is unavailable (e.g. macOS / CI), so behaviour there is unchanged.
    """
    if sys.platform.startswith("linux") and shutil.which("setarch"):
        return ["setarch", platform.machine(), "-R"]
    return []


def semgrep_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The scrubbed environment Semgrep runs with (``base`` defaults to ``os.environ``).

    Only :data:`_SEMGREP_ENV_PASSTHROUGH` and ``SEMGREP_*`` variables survive, so model API
    keys, the executor token or anything else this process inherited never reach a tool
    that scans untrusted code and talks to a registry (issue #106). Telemetry stays off.
    """
    source = os.environ if base is None else base
    env = {
        key: value
        for key, value in source.items()
        if key in _SEMGREP_ENV_PASSTHROUGH or key.startswith(_SEMGREP_ENV_PREFIXES)
    }
    env.setdefault("SEMGREP_SEND_METRICS", "off")
    env.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")
    return env


def semgrep_failure_reason(returncode: int, errors: list[object]) -> str | None:
    """Why a zero-result Semgrep run cannot be trusted, or ``None`` if it completed (issue #104).

    Two independent signals, either one decides: the process exit code (anything outside
    :data:`_SEMGREP_COMPLETED_EXIT_CODES`) and the structured ``errors`` array (an entry
    whose ``type`` is a fatal engine failure, or whose message carries one of the prose
    crash markers older versions emit).
    """
    if returncode not in _SEMGREP_COMPLETED_EXIT_CODES:
        return f"exited with code {returncode}"
    for error in errors:
        if _is_fatal_error(error):
            return f"reported a fatal error: {str(error)[:200]}"
    return None


def _is_fatal_error(error: object) -> bool:
    if not isinstance(error, dict):
        return False
    if str(error.get("type", "")).strip().lower() in _SEMGREP_FATAL_ERROR_TYPES:
        return True
    message = str(error.get("message", ""))
    return any(marker in message for marker in _SEMGREP_CRASH_MARKERS)


def _run_semgrep_subprocess(cmd: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    """One Semgrep invocation (fixed argv, no shell, cwd is our workspace, scrubbed env)."""
    return subprocess.run(
        cmd,
        cwd=root,
        env=semgrep_env(),
        capture_output=True,
        text=True,
        timeout=_SEMGREP_RUN_TIMEOUT_S,
        check=False,
    )


def setarch_failed(proc: subprocess.CompletedProcess[str]) -> bool:
    """Did the ``setarch`` ASLR-off prefix fail to set the process personality?

    True when the command exited non-zero and its stderr carries a ``setarch`` personality
    marker - the signature of a cap-dropped / no-new-privileges sandbox where ``setarch``
    cannot run (so semgrep never started and there is nothing to parse).
    """
    if proc.returncode == 0:
        return False
    stderr = (proc.stderr or "").lower()
    return any(marker in stderr for marker in _SEMGREP_SETARCH_FAILURE_MARKERS)


def run_semgrep(root: Path, rulesets: Iterable[str]) -> dict[str, object]:
    """Execute Semgrep and return its parsed JSON document.

    Raises :class:`SemgrepUnavailableError` on any failure mode - including a run that
    produced no results but did not complete (see :func:`semgrep_failure_reason`) and an
    output document over :data:`_SEMGREP_MAX_STDOUT_BYTES`. Separated from
    :func:`parse_semgrep_results` so tests can feed canned JSON without a binary.

    The ``setarch -R`` ASLR-off prefix guards semgrep-core against a kernel-specific segfault,
    but it cannot run in a hardened sandbox (dropped caps + no-new-privileges). When the
    prefixed attempt fails with a ``setarch`` personality error, this retries WITHOUT the
    prefix so real Semgrep still runs inside the container instead of silently degrading to
    the Python-only regex fallback (which returns zero candidates on JS/Java/Go/... repos).
    """
    executable = semgrep_executable()
    if executable is None:
        raise SemgrepUnavailableError("semgrep is not installed")
    base_cmd = semgrep_command(root, rulesets, executable)
    prefix = _aslr_safe_prefix()
    try:
        if prefix:
            proc = _run_semgrep_subprocess(prefix + base_cmd, root)
            if setarch_failed(proc):
                log.warning(
                    "sast(semgrep): the setarch ASLR-off prefix could not set the process "
                    "personality (%s); retrying without it so semgrep runs in this sandbox",
                    (proc.stderr or "").strip().splitlines()[-1:] or ["no stderr"],
                )
                proc = _run_semgrep_subprocess(base_cmd, root)
        else:
            proc = _run_semgrep_subprocess(base_cmd, root)
    except FileNotFoundError as exc:
        raise SemgrepUnavailableError(f"semgrep is not installed: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        msg = f"semgrep timed out after {_SEMGREP_RUN_TIMEOUT_S:.0f}s"
        raise SemgrepUnavailableError(msg) from exc

    stdout = proc.stdout or ""
    if len(stdout) > _SEMGREP_MAX_STDOUT_BYTES:
        msg = f"semgrep output too large to parse ({len(stdout)} > {_SEMGREP_MAX_STDOUT_BYTES})"
        raise SemgrepUnavailableError(msg)
    # Semgrep exits non-zero on partial errors but may still emit a full JSON document;
    # trust the document when it has a ``results`` list, otherwise report the failure.
    try:
        data = json.loads(stdout)
    except ValueError:
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        stderr = (proc.stderr or "").strip().splitlines()
        tail = stderr[-1] if stderr else "no output"
        raise SemgrepUnavailableError(f"semgrep exit {proc.returncode}: {tail}")
    raw_errors = data.get("errors")
    errors: list[object] = raw_errors if isinstance(raw_errors, list) else []
    if errors:
        log.warning("sast(semgrep): %d error(s) reported, e.g. %r", len(errors), errors[0])
    if not data["results"]:
        # No results is only evidence of a clean target when the run completed: a crash
        # (e.g. a semgrep-core segfault), a fatal error or a failing exit code with nothing
        # found must not be reported as clean - raise so the caller uses the regex fallback.
        reason = semgrep_failure_reason(proc.returncode, errors)
        if reason is not None:
            raise SemgrepUnavailableError(f"semgrep produced no results and {reason}")
    return data


def normalize_cwe(value: object) -> str | None:
    """``"CWE-89: Improper ..."`` / ``["CWE-89", ...]`` / ``89`` -> ``"CWE-89"``."""
    if isinstance(value, list):
        for item in value:
            cwe = normalize_cwe(item)
            if cwe:
                return cwe
        return None
    if isinstance(value, int):
        return f"CWE-{value}"
    if isinstance(value, str):
        match = _CWE_NUMBER.search(value)
        if match is None and value.strip().isdigit():
            return f"CWE-{value.strip()}"
        return f"CWE-{match.group(1)}" if match else None
    return None


def parse_semgrep_results(data: dict[str, object], root: Path) -> tuple[list[Candidate], list[str]]:
    """Map Semgrep's ``results`` onto candidates; returns ``(candidates, dropped_rule_ids)``.

    Results without a CWE in ``extra.metadata.cwe`` are dropped (they are style /
    correctness rules, not vulnerability sinks) and reported in the second element.
    """
    candidates: list[Candidate] = []
    dropped: list[str] = []
    results = data.get("results")
    if not isinstance(results, list):
        return candidates, dropped
    if len(results) > _SEMGREP_MAX_RESULTS:
        log.warning(
            "sast(semgrep): %d results; parsing only the first %d",
            len(results),
            _SEMGREP_MAX_RESULTS,
        )
        results = results[:_SEMGREP_MAX_RESULTS]
    lines_cache: dict[str, list[str]] = {}
    for raw in results:
        if not isinstance(raw, dict):
            continue
        rule = str(raw.get("check_id") or "semgrep")
        extra = _as_dict(raw.get("extra"))
        metadata = _as_dict(extra.get("metadata"))
        cwe = normalize_cwe(metadata.get("cwe"))
        if cwe is None:
            dropped.append(rule)
            continue
        start = _as_dict(raw.get("start"))
        try:
            line = max(1, int(str(start.get("line", 1))))
        except ValueError:
            line = 1
        file = _relative_path(str(raw.get("path") or ""), root)
        if not file:
            continue
        candidates.append(
            Candidate(
                file=file,
                line=line,
                cwe_hint=cwe,
                rule=rule,
                excerpt=_line_at(root, file, line, lines_cache),
                severity=str(extra.get("severity") or "").upper(),
            )
        )
    return candidates, dropped


def _line_at(root: Path, file: str, line: int, cache: dict[str, list[str]] | None = None) -> str:
    """The sink line from disk. (Semgrep CE's ``extra.lines`` reads ``"requires login"``.)

    Reads only a regular file inside ``root``: a path that is a symlink, goes through one,
    or resolves outside the workspace yields ``""`` rather than host content (issue #106).
    """
    lines = cache.get(file) if cache is not None else None
    if lines is None:
        lines = _workspace_lines(root, file)
        if cache is not None:
            cache[file] = lines
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _workspace_lines(root: Path, file: str) -> list[str]:
    target = root / file
    try:
        inside = target.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except OSError:
        return []
    if not inside or target.is_symlink():
        return []
    code = read_source_file(target)
    return code.splitlines() if code is not None else []


def _as_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _relative_path(path: str, root: Path) -> str:
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.relative_to(root.resolve())
        except ValueError:
            try:
                p = p.relative_to(root)
            except ValueError:
                return p.name
    if ".." in p.parts:
        return ""  # never let a reported path climb out of the workspace
    rel = p.as_posix()
    return rel[2:] if rel.startswith("./") else rel


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def rank(c: Candidate) -> tuple[int, int]:
    """Lower sorts first: Semgrep ERROR before WARNING/INFO, hard rules before ``.audit.`` ones.

    This is what decides which candidates survive the ``max_candidates`` cut, so an
    audit-class hit (plain-http request, debug=True) never crowds out an injection sink.
    """
    return (_SEVERITY_RANK.get(c.severity, 1), 1 if ".audit." in c.rule else 0)


def dedupe(candidates: Iterable[Candidate]) -> list[Candidate]:
    """(file, line, cwe) de-duplication keeping the highest-ranked rule per sink; ranked order."""
    ordered = sorted(candidates, key=lambda c: (*rank(c), c.file, c.line, c.cwe_hint))
    seen: set[tuple[str, int, str]] = set()
    unique: list[Candidate] = []
    for c in ordered:
        key = (c.file, c.line, c.cwe_hint)
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)
    return unique


def shortlist(
    root: Path,
    *,
    rulesets: Iterable[str],
    languages: Iterable[str] = (),
    max_candidates: int,
) -> Shortlist:
    """Semgrep first, regex fallback; always returns a bounded, deduplicated queue.

    When the fallback ran on a target it cannot fully see, ``Shortlist.degraded`` says so
    (see :func:`fallback_degradation`); callers must surface it rather than read an empty
    or short queue as a clean target.
    """
    langs = [lang.strip().lower() for lang in languages]
    configs = [r.strip() for r in rulesets if r.strip()]
    configs += [LANGUAGE_PACKS[lang] for lang in langs if lang in LANGUAGE_PACKS]
    configs = list(dict.fromkeys(configs))  # de-dup, keep order

    engine: SastEngine
    dropped: list[str] = []
    degraded = ""
    try:
        if not configs:
            raise SemgrepUnavailableError("no Semgrep rulesets configured (sast_ruleset is empty)")
        data = run_semgrep(root, configs)
        candidates, dropped = parse_semgrep_results(data, root)
        engine = "semgrep"
        note = f"semgrep ({', '.join(configs)})"
        log.info(
            "sast: semgrep produced %d result(s) with a CWE (%d dropped without one)",
            len(candidates),
            len(dropped),
        )
    except SemgrepUnavailableError as exc:
        report = regex_scan_report(root)
        candidates = report.candidates
        engine = "regex"
        note = "built-in regex fallback"
        log.warning(
            "sast: %s - using the built-in regex fallback (%d hit(s))", exc, len(candidates)
        )
        degraded = fallback_degradation(exc, report, langs)
        if degraded:
            log.warning("sast: static analysis degraded - %s", degraded)

    unique = dedupe(candidates)
    if len(unique) > max_candidates:
        log.info("sast: trimming %d candidate(s) to max_candidates=%d", len(unique), max_candidates)
        unique = unique[:max_candidates]
    return Shortlist(
        candidates=unique, engine=engine, note=note, dropped=dropped, degraded=degraded
    )


def fallback_degradation(
    cause: Exception, report: RegexScanReport, languages: Iterable[str]
) -> str:
    """Why a regex-fallback shortlist is incomplete, or ``""`` when it is not (issue #101).

    The fallback knows Python only. When the target declares another language Semgrep
    would have covered, or source files of such a language are on disk, or the walk hit its
    time budget, an empty or short queue is *not* a clean result - this spells out what was
    left unanalyzed, for the stage summary / UI ("static analysis degraded, results
    incomplete"). Languages neither engine covers are not reported: nothing was lost.
    """
    declared = {
        lang
        for lang in (str(lang).strip().lower() for lang in languages)
        if lang in LANGUAGE_PACKS and lang not in _REGEX_LANGUAGES
    }
    uncovered = sorted(declared | report.uncovered_languages)
    parts: list[str] = []
    if uncovered:
        parts.append(
            f"the regex fallback covers Python only; {', '.join(uncovered)} source was not analyzed"
        )
    if report.timed_out:
        parts.append(
            f"the fallback stopped at its {_REGEX_SCAN_TIMEOUT_S:.0f}s budget "
            f"after {report.files_scanned} file(s)"
        )
    if not parts:
        return ""
    return f"Semgrep unavailable ({cause}); " + "; ".join(parts) + " - results are incomplete"
