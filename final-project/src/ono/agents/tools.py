"""The analyst's tools: read-only views of the target, every one dispatched to the jail.

Nothing here touches the host filesystem. A :class:`ToolBox` wraps one
:class:`SandboxReader` (the Executor's :class:`~ono.executor.client.SandboxHandle` in
production, a fake in unit tests), dispatches a validated :class:`~ono.agents.model.ToolCall`
to it, renders the result as text for the model (truncated to a hard character cap), and
records in a :class:`ReadLedger` exactly which ``file:line`` pairs the model has actually
seen. The ledger is what makes a finding *anchored*: a line the model claims is honoured
only if it is in the ledger.

Deliberately read-only (step 3b-1). ``apply_patch`` / ``run`` / ``run_tests`` arrive with
the fixer and the graded verifier (3b-2).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ono.agents.model import ToolCall
from ono.executor.client import ExecutorRequestError
from ono.executor.models import FileContent, GrepResult, TreeListing

__all__ = [
    "READ_TOOLS",
    "TERMINAL_TOOLS",
    "ReadLedger",
    "SandboxReader",
    "ToolBox",
    "ToolResult",
    "ToolSpec",
    "openai_tool_schemas",
]

log = logging.getLogger(__name__)

MAX_LINES_PER_READ = 200
MAX_GREP_MATCHES = 40
MAX_TREE_ENTRIES = 300
MAX_TREE_DEPTH = 6
MAX_PATTERN_CHARS = 200


class SandboxReader(Protocol):
    """The read-only subset of :class:`~ono.executor.client.SandboxHandle`."""

    def read_file(self, path: str) -> FileContent: ...

    def read_lines(self, path: str, start: int, end: int) -> FileContent: ...

    def tree(
        self, path: str = ".", *, max_entries: int = 2000, max_depth: int = 12
    ) -> TreeListing: ...

    def grep(
        self, pattern: str, path: str = ".", *, ignore_case: bool = False, max_matches: int = 200
    ) -> GrepResult: ...


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One tool as the model sees it: name, purpose, JSON-schema parameters."""

    name: str
    description: str
    parameters: dict[str, Any]
    terminal: bool = False  # confirm / dismiss end the loop instead of returning data


def _obj(props: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required}


READ_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "read_lines",
        "Read a line range of a file (1-based, inclusive; at most 200 lines per call). "
        "Output is 'N | code' per line.",
        _obj(
            {
                "path": {"type": "string", "description": "Path relative to the repo root."},
                "start": {"type": "integer", "minimum": 1},
                "end": {"type": "integer", "minimum": 1},
            },
            ["path", "start", "end"],
        ),
    ),
    ToolSpec(
        "read_file",
        "Read a whole file (truncated if long; prefer read_lines for big files). "
        "Output is 'N | code' per line.",
        _obj(
            {"path": {"type": "string", "description": "Path relative to the repo root."}}, ["path"]
        ),
    ),
    ToolSpec(
        "grep",
        "Regex search (Python re syntax) across the repo or under a path. Returns "
        "'file:line: text' matches - use it to find callers, definitions and sources.",
        _obj(
            {
                "pattern": {"type": "string"},
                "path": {
                    "type": "string",
                    "description": "Directory or file to search; default '.'.",
                },
            },
            ["pattern"],
        ),
    ),
    ToolSpec(
        "tree",
        "List files under a directory (bounded depth and count).",
        _obj({"path": {"type": "string", "description": "Directory; default '.'."}}, []),
    ),
)

TERMINAL_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "confirm",
        "Final answer: the flagged code IS a real, exploitable vulnerability. Cite only "
        "file:line locations you actually read.",
        _obj(
            {
                "cwe": {"type": "string", "description": "e.g. CWE-89"},
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "file": {"type": "string", "description": "File of the sink."},
                "line_start": {"type": "integer", "minimum": 1},
                "line_end": {"type": "integer", "minimum": 1},
                "trace": {
                    "type": "array",
                    "description": "Source -> sink hops, each a line you read.",
                    "items": _obj(
                        {
                            "file": {"type": "string"},
                            "line": {"type": "integer", "minimum": 1},
                            "symbol": {"type": "string"},
                            "note": {"type": "string"},
                        },
                        ["file", "line", "symbol"],
                    ),
                },
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "description": {"type": "string", "description": "Why it is exploitable, how."},
            },
            [
                "cwe",
                "title",
                "severity",
                "file",
                "line_start",
                "line_end",
                "trace",
                "confidence",
                "description",
            ],
        ),
        terminal=True,
    ),
    ToolSpec(
        "dismiss",
        "Final answer: the flagged code is NOT exploitable (validated, constant, "
        "unreachable, or a false positive). Give the reason.",
        _obj({"reason": {"type": "string"}}, ["reason"]),
        terminal=True,
    ),
)

ALL_TOOLS: tuple[ToolSpec, ...] = (*READ_TOOLS, *TERMINAL_TOOLS)
_BY_NAME: dict[str, ToolSpec] = {t.name: t for t in ALL_TOOLS}


def openai_tool_schemas(tools: Iterable[ToolSpec]) -> list[dict[str, Any]]:
    """The ``tools`` request field for native function calling."""
    return [
        {
            "type": "function",
            "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
        }
        for t in tools
    ]


# ---------------------------------------------------------------------------
# What the model has actually seen
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ReadLedger:
    """``file -> set of 1-based line numbers`` the analyst has read through the sandbox."""

    seen: dict[str, set[int]] = field(default_factory=dict)

    def add_range(self, path: str, start: int, end: int) -> None:
        if end < start:
            return
        self.seen.setdefault(path, set()).update(range(start, end + 1))

    def add_line(self, path: str, line: int) -> None:
        self.seen.setdefault(path, set()).add(line)

    def has_file(self, path: str) -> bool:
        return path in self.seen

    def has_line(self, path: str, line: int) -> bool:
        return line in self.seen.get(path, ())

    def has_range(self, path: str, start: int, end: int) -> bool:
        lines = self.seen.get(path)
        return lines is not None and all(n in lines for n in range(start, end + 1))

    @property
    def files(self) -> list[str]:
        return sorted(self.seen)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ToolResult:
    """What goes back to the model (``text``) plus what the trajectory records."""

    name: str
    text: str
    ok: bool
    truncated: bool = False


class ToolBox:
    """Dispatches tool calls to one sandbox; renders, truncates and records results."""

    def __init__(self, sandbox: SandboxReader, *, max_output_chars: int) -> None:
        self.sandbox = sandbox
        self.max_output_chars = max_output_chars
        self.ledger = ReadLedger()
        self.calls = 0

    @staticmethod
    def spec(name: str) -> ToolSpec | None:
        return _BY_NAME.get(name)

    def dispatch(self, call: ToolCall) -> ToolResult:
        """Run one read tool. Bad input and jail-side rejections become text, never exceptions."""
        self.calls += 1
        spec = _BY_NAME.get(call.name)
        if spec is None or spec.terminal:
            known = ", ".join(t.name for t in ALL_TOOLS)
            return self._error(call.name, f"unknown tool {call.name!r}; available: {known}")
        if "__malformed__" in call.args:
            return self._error(call.name, "arguments were not valid JSON; resend the call")
        try:
            if call.name == "read_lines":
                return self._read_lines(call.args)
            if call.name == "read_file":
                return self._read_file(call.args)
            if call.name == "grep":
                return self._grep(call.args)
            return self._tree(call.args)
        except ExecutorRequestError as exc:
            # 4xx from the jail (bad path, no such file, invalid regex) is the model's
            # mistake: report it and let it retry. Transport failures, auth errors and a
            # dead/swept sandbox propagate so the orchestrator fails the scan loudly.
            return self._error(call.name, f"sandbox error: {exc.detail}")
        except ValueError as exc:
            return self._error(call.name, f"bad arguments: {exc}")

    # -- tools ----------------------------------------------------------------------
    def _read_lines(self, args: dict[str, Any]) -> ToolResult:
        path = _path_arg(args)
        start = max(1, _int_arg(args, "start", default=1))
        end = max(start, _int_arg(args, "end", default=start + MAX_LINES_PER_READ - 1))
        note = ""
        if end - start + 1 > MAX_LINES_PER_READ:
            end = start + MAX_LINES_PER_READ - 1
            note = f"(range capped at {MAX_LINES_PER_READ} lines)\n"
        content = self.sandbox.read_lines(path, start, end)
        return self._render_file("read_lines", content, note)

    def _read_file(self, args: dict[str, Any]) -> ToolResult:
        path = _path_arg(args)
        # Whole-file reads are bounded by the same line cap as read_lines so a 5k-line
        # file cannot flood the context; the model is told to continue with read_lines.
        content = self.sandbox.read_lines(path, 1, MAX_LINES_PER_READ)
        note = ""
        if content.total_lines is None or content.total_lines > MAX_LINES_PER_READ:
            note = (
                f"(showing lines 1-{content.end_line}; the file is longer - "
                "use read_lines for the rest)\n"
            )
        return self._render_file("read_file", content, note)

    def _render_file(self, name: str, content: FileContent, note: str) -> ToolResult:
        lines = content.content.splitlines()
        if content.end_line == 0 or not lines:
            total = "unknown" if content.total_lines is None else str(content.total_lines)
            return ToolResult(name, f"{content.path}: empty range (file has {total} lines)", True)
        # Truncate on whole lines so the ledger records exactly the lines the model saw.
        header = f"{note}{content.path}\n"
        budget = max(80, self.max_output_chars - len(header))
        rendered: list[str] = []
        used = 0
        for i, line in enumerate(lines):
            row = f"{content.start_line + i:5d} | {line}"
            if used + len(row) + 1 > budget:
                if not rendered:  # one line alone is over budget: show what fits
                    rendered.append(row[:budget] + " ...")
                break
            rendered.append(row)
            used += len(row) + 1
        shown = len(rendered)
        truncated = shown < len(lines)
        text = header + "\n".join(rendered)
        if truncated:
            text += (
                f"\n... [truncated: {len(lines) - shown} more line(s) in this range; "
                "use read_lines for the rest]"
            )
        self.ledger.add_range(content.path, content.start_line, content.start_line + shown - 1)
        return ToolResult(name, text, True, truncated or content.truncated)

    def _grep(self, args: dict[str, Any]) -> ToolResult:
        pattern = str(args.get("pattern") or "").strip()
        if not pattern:
            raise ValueError("grep needs a non-empty 'pattern'")
        if len(pattern) > MAX_PATTERN_CHARS:
            raise ValueError(f"pattern longer than {MAX_PATTERN_CHARS} characters")
        path = str(args.get("path") or ".").strip() or "."
        result = self.sandbox.grep(pattern, path, max_matches=MAX_GREP_MATCHES)
        if not result.matches:
            return ToolResult("grep", f"no matches for {pattern!r} under {path!r}", True)
        rows = [f"{m.file}:{m.line}: {m.text.strip()[:300]}" for m in result.matches]
        for m in result.matches:
            self.ledger.add_line(m.file, m.line)
        suffix = "\n(more matches exist; narrow the pattern or path)" if result.truncated else ""
        text, truncated = self._truncate("\n".join(rows) + suffix)
        return ToolResult("grep", text, True, truncated or result.truncated)

    def _tree(self, args: dict[str, Any]) -> ToolResult:
        path = str(args.get("path") or ".").strip() or "."
        listing = self.sandbox.tree(path, max_entries=MAX_TREE_ENTRIES, max_depth=MAX_TREE_DEPTH)
        rows = [f"{e.path}{'/' if e.kind == 'dir' else ''}" for e in listing.entries]
        if not rows:
            return ToolResult("tree", f"{path!r} is empty", True)
        suffix = "\n(listing truncated)" if listing.truncated else ""
        text, truncated = self._truncate("\n".join(rows) + suffix)
        return ToolResult("tree", text, True, truncated or listing.truncated)

    # -- helpers --------------------------------------------------------------------
    def _error(self, name: str, message: str) -> ToolResult:
        log.info("agents: tool %s failed: %s", name, message)
        return ToolResult(name, f"ERROR: {message}", False)

    def _truncate(self, text: str) -> tuple[str, bool]:
        if len(text) <= self.max_output_chars:
            return text, False
        cut = text[: self.max_output_chars]
        return cut + f"\n... [truncated to {self.max_output_chars} chars]", True


def _path_arg(args: dict[str, Any]) -> str:
    path = str(args.get("path") or "").strip()
    if not path:
        raise ValueError("'path' is required")
    return path


def _int_arg(args: dict[str, Any], key: str, *, default: int) -> int:
    value = args.get(key)
    if value is None or value == "":
        return default
    try:
        return int(str(value))
    except ValueError as exc:
        raise ValueError(f"{key!r} must be an integer") from exc
