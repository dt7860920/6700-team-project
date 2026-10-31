"""Stage 2 - SAST shortlist.

Runs Semgrep over an ingested workspace and normalizes its JSON ``results`` into
:class:`Candidate` entries (file relative to the clone root, sink line, CWE hint,
rule id, matched excerpt). The shortlist is what bounds the model stage: the
analyst only ever reasons about *candidates*, never the whole repository.

Graceful degradation is required, not optional: if Semgrep is missing, crashes,
times out, or emits something unparseable, :func:`shortlist` falls back to a
lightweight built-in regex scanner (the same patterns the mock backend uses for
pasted snippets) so the SAST stage always yields candidates and never fails a scan.

Deliberately NOT here yet (later steps): CodeQL / SARIF ingestion, call-graph
enrichment of candidates, entry-point union.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Iterator
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

# Semgrep registry language packs appended per target language (unknown languages are skipped).
LANGUAGE_PACKS: dict[str, str] = {
    "python": "p/python",
    "javascript": "p/javascript",
    "typescript": "p/typescript",
    "java": "p/java",
    "go": "p/golang",
    "ruby": "p/ruby",
    "php": "p/php",
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


@dataclass(slots=True)
class Shortlist:
    """The candidate queue plus which engine produced it (surfaced in logs / tests)."""

    candidates: list[Candidate]
    engine: SastEngine
    note: str = ""
    dropped: list[str] = field(default_factory=list)


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
_SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "site-packages", ".tox", "dist"}
)
_MAX_FILE_BYTES = 1_000_000


def scan_text(code: str, file: str) -> list[Candidate]:
    """Apply :data:`PATTERN_RULES` line by line (at most one candidate per line)."""
    candidates: list[Candidate] = []
    for lineno, line in enumerate(code.splitlines(), start=1):
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
    """Yield source files under ``root`` (sorted, skipping vendored/VCS directories)."""
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in extensions:
            continue
        if _SKIP_DIRS.intersection(path.relative_to(root).parts[:-1]):
            continue
        yield path


def regex_scan(root: Path) -> list[Candidate]:
    """The fallback engine: walk the workspace and apply the built-in patterns."""
    candidates: list[Candidate] = []
    for path in iter_source_files(root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.debug("sast(regex): skipping %s: %s", path, exc)
            continue
        rel = path.relative_to(root).as_posix()
        candidates.extend(scan_text(code, rel))
    return candidates


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


def run_semgrep(root: Path, rulesets: Iterable[str]) -> dict[str, object]:
    """Execute Semgrep and return its parsed JSON document.

    Raises :class:`SemgrepUnavailableError` on any failure mode. Separated from
    :func:`parse_semgrep_results` so tests can feed canned JSON without a binary.
    """
    executable = semgrep_executable()
    if executable is None:
        raise SemgrepUnavailableError("semgrep is not installed")
    cmd = semgrep_command(root, rulesets, executable)
    try:
        proc = subprocess.run(  # fixed argv, no shell, cwd is our own workspace
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=_SEMGREP_RUN_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SemgrepUnavailableError(f"semgrep is not installed: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        msg = f"semgrep timed out after {_SEMGREP_RUN_TIMEOUT_S:.0f}s"
        raise SemgrepUnavailableError(msg) from exc

    # Semgrep exits non-zero on partial errors but may still emit a full JSON document;
    # trust the document when it has a ``results`` list, otherwise report the failure.
    try:
        data = json.loads(proc.stdout or "")
    except ValueError:
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        stderr = (proc.stderr or "").strip().splitlines()
        tail = stderr[-1] if stderr else "no output"
        raise SemgrepUnavailableError(f"semgrep exit {proc.returncode}: {tail}")
    errors = data.get("errors")
    if isinstance(errors, list) and errors:
        log.warning("sast(semgrep): %d non-fatal error(s), e.g. %r", len(errors), errors[0])
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
                excerpt=_line_at(root, file, line),
                severity=str(extra.get("severity") or "").upper(),
            )
        )
    return candidates, dropped


def _line_at(root: Path, file: str, line: int) -> str:
    """The sink line from disk. (Semgrep CE's ``extra.lines`` reads ``"requires login"``.)"""
    try:
        lines = (root / file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1] if 0 < line <= len(lines) else ""


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
    """Semgrep first, regex fallback; always returns a bounded, deduplicated queue."""
    configs = [r.strip() for r in rulesets if r.strip()]
    configs += [LANGUAGE_PACKS[lang] for lang in languages if lang in LANGUAGE_PACKS]
    configs = list(dict.fromkeys(configs))  # de-dup, keep order

    engine: SastEngine
    dropped: list[str] = []
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
        candidates = regex_scan(root)
        engine = "regex"
        note = "built-in regex fallback"
        log.warning(
            "sast: %s - using the built-in regex fallback (%d hit(s))", exc, len(candidates)
        )

    unique = dedupe(candidates)
    if len(unique) > max_candidates:
        log.info("sast: trimming %d candidate(s) to max_candidates=%d", len(unique), max_candidates)
        unique = unique[:max_candidates]
    return Shortlist(candidates=unique, engine=engine, note=note, dropped=dropped)
