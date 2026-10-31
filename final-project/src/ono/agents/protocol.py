"""Turning a model reply into actions - tolerant of everything a 7B model actually emits.

The analyst must answer each turn with either a native tool call or **one JSON action**
in its text::

    {"tool": "read_lines", "args": {"path": "app/views.py", "start": 1, "end": 40}}
    {"tool": "confirm", "args": {"cwe": "CWE-89", ...}}
    {"tool": "dismiss", "args": {"reason": "input is validated at line 12"}}

:func:`parse_reply` returns the list of :class:`~ono.agents.model.ToolCall` it could find:
native ``tool_calls`` first; otherwise the first JSON object in the text, accepting the
spellings models tend to drift into (``{"name": ..., "arguments": ...}``,
``{"function": ..., "parameters": ...}``, ``{"finding": {...}}``, ``{"dismiss": true}``,
``{"vulnerable": false, ...}``), inside markdown fences or surrounded by prose. Anything
else is a :class:`ParseFailure` with a message the loop feeds back so the model can
retry - it never raises.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ono.agents.model import ModelReply, ToolCall

__all__ = ["ParseFailure", "extract_json_object", "parse_reply", "render_action_format"]

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)
_TOOL_KEYS = ("tool", "name", "function", "action", "tool_name")
_ARG_KEYS = ("args", "arguments", "parameters", "input", "params")


@dataclass(slots=True)
class ParseFailure:
    """Why the reply yielded no action; ``hint`` is what the model is told."""

    hint: str


def render_action_format() -> str:
    """The one-paragraph protocol reminder used in prompts and retry hints."""
    return (
        'Reply with exactly ONE JSON object and nothing else: {"tool": "<name>", "args": {...}}. '
        "Tools: read_lines(path,start,end), read_file(path), grep(pattern[,path]), tree([path]), "
        "confirm(cwe,title,severity,file,line_start,line_end,trace,confidence,description), "
        "dismiss(reason)."
    )


def parse_reply(reply: ModelReply) -> list[ToolCall] | ParseFailure:
    """Native tool calls win; else the text is searched for one JSON action."""
    if reply.tool_calls:
        return list(reply.tool_calls)
    text = reply.text.strip()
    if not text:
        return ParseFailure("empty reply. " + render_action_format())
    for blob in _json_candidates(text):
        data = _loads(blob)
        if data is None:
            continue
        call = _action_from(data)
        if call is not None:
            return [call]
    return ParseFailure("could not find a JSON action in your reply. " + render_action_format())


def extract_json_object(text: str) -> dict[str, Any] | None:
    """The first JSON object found in ``text`` (fenced, bare, or buried in prose), else None."""
    for blob in _json_candidates(text.strip()):
        data = _loads(blob)
        if data is not None:
            return data
    return None


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------


def _json_candidates(text: str) -> list[str]:
    """Fenced blocks, the whole text, then every balanced ``{...}`` region (first first)."""
    out = [m.strip() for m in _FENCE.findall(text)]
    out.append(text)
    out.extend(_balanced_objects(text, limit=5))
    return [c for c in out if c]


def _balanced_objects(text: str, *, limit: int) -> list[str]:
    """Top-level ``{...}`` spans found by brace matching (string-aware)."""
    spans: list[str] = []
    depth = 0
    start = -1
    in_str = False
    escape = False
    for i, ch in enumerate(text):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start >= 0:
                spans.append(text[start : i + 1])
                if len(spans) >= limit:
                    break
    return spans


def _loads(blob: str) -> dict[str, Any] | None:
    try:
        data = json.loads(blob)
    except ValueError:
        try:  # a trailing comma or a single-quoted string is the usual damage
            data = json.loads(_repair(blob))
        except ValueError:
            return None
    return data if isinstance(data, dict) else None


_TRAILING_COMMA = re.compile(r",\s*([}\]])")


def _repair(blob: str) -> str:
    return _TRAILING_COMMA.sub(r"\1", blob)


# ---------------------------------------------------------------------------
# Action shapes
# ---------------------------------------------------------------------------


def _action_from(data: dict[str, Any]) -> ToolCall | None:
    # {"tool": "x", "args": {...}} and its common misspellings
    name = _first_str(data, _TOOL_KEYS)
    if name and (_normalize(name) in KNOWN_TOOLS or not _looks_like_verdict(data)):
        args = _first_dict(data, _ARG_KEYS)
        if args is None:  # flat form: {"tool": "grep", "pattern": "..."}
            args = {k: v for k, v in data.items() if k not in _TOOL_KEYS and k not in _ARG_KEYS}
        return ToolCall(name=_normalize(name), args=args)
    # {"tool_calls": [{"function": {"name":..., "arguments":...}}]} typed out as text
    calls = data.get("tool_calls")
    if isinstance(calls, list) and calls:
        inner = calls[0]
        if isinstance(inner, dict):
            fn = inner.get("function")
            if isinstance(fn, dict) and isinstance(fn.get("name"), str):
                raw = fn.get("arguments")
                args = (
                    raw
                    if isinstance(raw, dict)
                    else (_loads(raw) if isinstance(raw, str) else None)
                )
                return ToolCall(name=_normalize(fn["name"]), args=args or {})
            return _action_from(inner)
    # {"finding": {...}} / {"confirm": {...}}
    for key in ("finding", "confirm"):
        inner = data.get(key)
        if isinstance(inner, dict):
            return ToolCall(name="confirm", args=inner)
    # {"dismiss": true, "reason": ...} / {"dismiss": {"reason": ...}}
    dismiss = data.get("dismiss")
    if isinstance(dismiss, dict):
        return ToolCall(name="dismiss", args=dismiss)
    if dismiss is True or str(dismiss).strip().lower() in {"true", "yes"}:
        return ToolCall(name="dismiss", args={"reason": str(data.get("reason") or "")})
    # The step-2 verdict shape: {"vulnerable": bool, "cwe": ..., ...}
    if "vulnerable" in data:
        value = data["vulnerable"]
        positive = (
            value if isinstance(value, bool) else str(value).strip().lower() in {"true", "yes", "1"}
        )
        if positive:
            return ToolCall(name="confirm", args=data)
        return ToolCall(
            name="dismiss",
            args={"reason": str(data.get("description") or data.get("reason") or "")},
        )
    if "cwe" in data and "file" in data:  # a bare finding object
        return ToolCall(name="confirm", args=data)
    return None


KNOWN_TOOLS = frozenset({"read_lines", "read_file", "grep", "tree", "confirm", "dismiss"})


def _looks_like_verdict(data: dict[str, Any]) -> bool:
    """A finding object that happens to carry a ``name`` key is a verdict, not a tool call."""
    return "cwe" in data or "vulnerable" in data or "finding" in data


_ALIASES = {
    "readlines": "read_lines",
    "read_line": "read_lines",
    "readfile": "read_file",
    "read": "read_file",
    "cat": "read_file",
    "search": "grep",
    "rg": "grep",
    "ls": "tree",
    "list": "tree",
    "list_files": "tree",
    "report": "confirm",
    "finding": "confirm",
    "final": "confirm",
    "reject": "dismiss",
    "safe": "dismiss",
}


def _normalize(name: str) -> str:
    key = name.strip().lower().replace("-", "_")
    for prefix in ("functions.", "tools.", "tool."):
        key = key.removeprefix(prefix)
    return _ALIASES.get(key, key)


def _first_str(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, dict) and isinstance(
            value.get("name"), str
        ):  # {"function": {"name":..}}
            return str(value["name"])
    return None


def _first_dict(data: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any] | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            parsed = _loads(value)
            if parsed is not None:
                return parsed
    fn = data.get("function")
    if isinstance(fn, dict):
        return _first_dict(fn, keys)
    return None
