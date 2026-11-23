"""In-jail sink oracle: runs a read-only PoC INSIDE the sandbox and reports whether a
verifier-chosen canary reached the flagged sink.

The verifier ships this module's *source text* into the jail (``.ono/oracle.py``) next
to the PoC the prover wrote (``.ono/poc.py``) and runs::

    python3 -I .ono/oracle.py '<json config>'

The config names the finding's CWE, sink ``file`` + line range, the canary string, and
the PoC path. The oracle then:

1. installs **sink hooks** - audit hooks (:func:`sys.addaudithook`) for the dangerous
   operations the interpreter already reports (``os.system``, ``subprocess.Popen``,
   ``compile``/``exec``/``eval``, ``open``, sockets) plus thin wrappers on the module
   attributes the interpreter does not audit (``sqlite3.connect`` and other DB-API
   drivers -> a cursor proxy that inspects the SQL text; ``pickle.loads``; ``yaml.load``;
   ``marshal.loads``);
2. exposes the canary to the PoC as ``ONO_PAYLOAD`` in the environment - the PoC must
   put it wherever attacker input enters and drive the target code;
3. runs the PoC (``runpy``) from the workspace root with stdout/stderr captured;
4. prints ONE line ``ONO_ORACLE_RESULT <json>`` describing every hit: which sink fired,
   whether the canary was in the *dangerous argument* (the SQL text, the shell command
   string, the code being compiled, the unpickled blob, the opened path with a ``..``
   segment, the host being resolved), and the in-repo call stack at that moment.

A hit counts as **the finding being real** only if (a) its CWE matches the finding and
(b) the finding's sink ``file:line`` (within a small tolerance) is on the stack when the
sink fired. The PoC calling ``os.system(canary)`` itself therefore proves nothing; the
target code must be the one reaching the sink.

What the hooks mean by "unsanitized" (this is what separates a vulnerable sink from the
patched version of the same line):

* CWE-89  the canary appears in the SQL *text* (a bound parameter never reaches it)
* CWE-78  the canary appears in a shell command string (``os.system`` / ``sh -c``); the
          argv-list form passing it as its own argument does not fire
* CWE-94/95 the canary appears in source handed to ``compile`` (``eval`` / ``exec``)
* CWE-502 the canary appears in a blob given to ``pickle`` / ``marshal`` / unsafe
          ``yaml.load``
* CWE-22  the canary appears in a path opened/removed/renamed that still carries a
          ``..`` segment
* CWE-918 the canary appears in a host name being resolved / connected to or a URL
          opened with ``urllib``

Stdlib only, Python >= 3.9 syntax (the sandbox image's interpreter may be older than
ours). Importable on the host: the unit tests exercise it directly.
"""

from __future__ import annotations

import io
import json
import os
import re
import runpy
import sys
import time
import traceback
from types import FrameType
from typing import Any

RESULT_MARKER = "ONO_ORACLE_RESULT "
PAYLOAD_ENV = "ONO_PAYLOAD"
MAX_HITS = 50
MAX_STACK = 12
PREVIEW_CHARS = 240
TAIL_CHARS = 2000
SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ash", "ksh"})

# CWE families: a hit of one member proves a finding labelled with any other member.
# The KEY is the family's canonical root; members are alternate labels detectors may use.
CWE_FAMILIES: dict[str, frozenset[str]] = {
    "CWE-89": frozenset({"CWE-89"}),
    "CWE-78": frozenset({"CWE-78", "CWE-77", "CWE-88"}),
    "CWE-94": frozenset({"CWE-94", "CWE-95", "CWE-96"}),
    "CWE-502": frozenset({"CWE-502", "CWE-20"}),
    "CWE-22": frozenset({"CWE-22", "CWE-23", "CWE-36"}),
    "CWE-918": frozenset({"CWE-918"}),
    # -- added families (a secret canary reaching the dangerous argument is observable) --
    "CWE-1336": frozenset({"CWE-1336", "CWE-917"}),  # server-side template injection (SSTI)
    "CWE-643": frozenset({"CWE-643"}),  # XPath injection
    "CWE-90": frozenset({"CWE-90"}),  # LDAP injection
    "CWE-943": frozenset({"CWE-943"}),  # NoSQL / query-object injection
    "CWE-611": frozenset({"CWE-611", "CWE-827"}),  # XML external entity (XXE)
    "CWE-601": frozenset({"CWE-601"}),  # open redirect
    "CWE-73": frozenset({"CWE-73"}),  # external control of file name/path (write & read)
    "CWE-79": frozenset({"CWE-79", "CWE-80"}),  # reflected unescaped output (tainted->response)
}
SUPPORTED_CWES: frozenset[str] = frozenset().union(*CWE_FAMILIES.values())

# The canary is normally alphanumeric so it survives transport and any sink unchanged:
# for families whose SOLE defense is to RELOCATE the value out of the dangerous position
# (SQL/LDAP-NoSQL bound parameters, XPath variable binding, template context vs. template
# body, a hard-coded redirect target, a confined path) the plain core either reaches the
# dangerous argument or it does not. A few families defend by NEUTRALISING a metacharacter
# while keeping the surrounding text, so the alphanumeric core would match an escaped copy
# too; for those the canary carries that metacharacter as a suffix probe and the sink hook
# requires the WHOLE canary (probe intact) - an escaped/stripped copy no longer matches it.
CANARY_CORE_LEN = 19  # "ONO" + secrets.token_hex(8)
CANARY_PROBE: dict[str, str] = {
    "CWE-79": "<x>",  # HTML-escaping turns < > into &lt; &gt;
    "CWE-90": ")(|",  # LDAP filter escaping encodes ) ( \\ and *
}


def family_root(cwe: str) -> str:
    """The canonical family key for ``cwe`` (itself if it heads no known family)."""
    for root, members in CWE_FAMILIES.items():
        if cwe in members:
            return root
    return cwe


def family_of(cwe: str) -> frozenset[str]:
    """Every CWE a hit of ``cwe`` proves (at least ``cwe`` itself)."""
    for members in CWE_FAMILIES.values():
        if cwe in members:
            return members
    return frozenset({cwe})


def probe_for(cwe: str) -> str:
    """The metacharacter suffix the canary must carry for ``cwe`` ("" for most families)."""
    return CANARY_PROBE.get(family_root(cwe), "")


class _State:
    """Everything a hook needs: the canary, the sink to match, the hits so far."""

    def __init__(self, config: dict[str, Any], root: str) -> None:
        # ``canary`` is the full value the PoC injects (with any metacharacter probe); the
        # alphanumeric ``core`` is what survives transport and is matched generically. The
        # escaping-sensitive hooks additionally require the full canary (probe intact).
        self.canary: str = str(config["canary"])
        self.core: str = self.canary[:CANARY_CORE_LEN]
        self.canary_bytes = self.core.encode("utf-8")
        self.full_bytes = self.canary.encode("utf-8")
        self.sink_file: str = str(config["sink_file"]).replace("\\", "/").lstrip("./")
        self.line_start = int(config.get("line_start", 1))
        self.line_end = int(config.get("line_end", self.line_start))
        self.tolerance = int(config.get("tolerance", 3))
        self.root = root.rstrip("/") + "/"
        self.poc_file: str = os.path.abspath(str(config["poc"]))
        self.hits: list[dict[str, Any]] = []
        self.truncated = False
        self.active = False  # hooks only record while the PoC runs

    # -- stack ------------------------------------------------------------
    def repo_stack(self) -> list[dict[str, Any]]:
        """In-repo frames, innermost first; the oracle and the PoC are labelled, not hidden."""
        frames: list[dict[str, Any]] = []
        frame: FrameType | None = sys._getframe(1)
        while frame is not None and len(frames) < MAX_STACK:
            path = frame.f_code.co_filename
            abspath = os.path.abspath(path) if path and not path.startswith("<") else path
            if abspath.startswith(self.root):
                rel = abspath[len(self.root) :]
                if not rel.startswith(".ono/oracle"):  # the oracle's own frames are noise
                    frames.append(
                        {"file": rel, "line": frame.f_lineno, "func": frame.f_code.co_name}
                    )
            frame = frame.f_back
        return frames

    def at_sink(self, stack: list[dict[str, Any]], *, innermost_only: bool = False) -> bool:
        """Is the finding's sink line on the stack?

        A tainted hit may happen in a helper the flagged line calls, so any in-repo frame
        within the tolerance counts. For the *untainted* "sink ran but clean" signal only
        the frame that made the call is considered (``innermost_only``), otherwise setup
        work near the flagged line (``CREATE TABLE`` two lines above it) would register.
        """
        lo = self.line_start - self.tolerance
        hi = self.line_end + self.tolerance
        frames = [f for f in stack if not _is_poc(f["file"])]
        if innermost_only:
            frames = frames[:1]
            lo, hi = self.line_start, self.line_end
        return any(f["file"] == self.sink_file and lo <= int(f["line"]) <= hi for f in frames)

    # -- recording --------------------------------------------------------
    def record(self, cwe: str, kind: str, argument: Any, *, tainted: bool) -> None:
        """Keep every tainted hit; keep an untainted one only when it happened AT the sink
        (that is the "sink ran but the payload was sanitized / parameterized" signal).
        Untainted hits elsewhere are the interpreter's normal business (imports compile
        code, files get opened) and would only drown the record."""
        if not self.active:
            return
        stack = self.repo_stack()
        located = self.at_sink(stack, innermost_only=not tainted)
        if not tainted and not located:
            return
        if len(self.hits) >= MAX_HITS:
            self.truncated = True
            return
        self.hits.append(
            {
                "cwe": cwe,
                "kind": kind,
                "tainted": tainted,
                "at_sink": tainted and located,
                "argument": _preview(argument, self.canary),
                "stack": stack,
            }
        )

    def contains(self, value: Any) -> bool:
        """Does ``value`` (str / bytes / nested list-tuple-dict / anything) carry the canary
        core? The core is alphanumeric, so it survives transport and escaping unchanged."""
        return self._contains(value, self.core, self.canary_bytes)

    def contains_full(self, value: Any) -> bool:
        """Does ``value`` carry the WHOLE canary, metacharacter probe intact? Used by the
        escaping-defended families (XSS/CRLF/LDAP): an escaped or stripped copy fails this."""
        return self._contains(value, self.canary, self.full_bytes)

    def _contains(self, value: Any, needle: str, needle_bytes: bytes) -> bool:
        try:
            if isinstance(value, str):
                return needle in value
            if isinstance(value, (bytes, bytearray, memoryview)):
                return needle_bytes in bytes(value)
            if isinstance(value, (list, tuple, set, frozenset)):
                return any(self._contains(v, needle, needle_bytes) for v in value)
            if isinstance(value, dict):
                return any(self._contains(v, needle, needle_bytes) for v in value.values())
            if hasattr(value, "read") and hasattr(value, "seek"):
                pos = value.tell()
                data = value.read()
                value.seek(pos)
                return self._contains(data, needle, needle_bytes)
            if value is None or isinstance(value, (int, float, bool)):
                return False
            return needle in str(value)
        except Exception:
            return False


def _is_poc(rel: str) -> bool:
    return rel.startswith(".ono/")


def _preview(value: Any, canary: str) -> str:
    try:
        if isinstance(value, (bytes, bytearray)):
            text = value.decode("utf-8", "replace")
        else:
            text = str(value)
    except Exception:
        text = repr(value)
    # Redact the full canary first (it contains the core), then the alphanumeric core.
    text = text.replace(canary, "<PAYLOAD>").replace(canary[:CANARY_CORE_LEN], "<PAYLOAD>")
    return text[:PREVIEW_CHARS]


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


def _audit_hook(state: _State) -> Any:
    def hook(event: str, args: tuple[Any, ...]) -> None:
        if not state.active:
            return
        try:
            if event == "os.system":
                state.record("CWE-78", "os.system", args[0], tainted=state.contains(args[0]))
            elif event == "subprocess.Popen":
                executable, argv = args[0], args[1]
                shell = _is_shell(executable) or (
                    isinstance(argv, (list, tuple)) and argv and _is_shell(argv[0])
                )
                if shell and isinstance(argv, (list, tuple)) and len(argv) >= 3:
                    command = argv[2] if argv[1] == "-c" else " ".join(map(str, argv[1:]))
                    state.record(
                        "CWE-78", "subprocess(shell)", command, tainted=state.contains(command)
                    )
                elif isinstance(argv, str):
                    state.record("CWE-78", "subprocess(str)", argv, tainted=state.contains(argv))
                else:
                    state.record("CWE-78", "subprocess(argv)", argv, tainted=False)
            elif event == "compile":
                source = args[0]
                if source is not None and not hasattr(source, "co_code"):
                    state.record("CWE-94", "compile", source, tainted=state.contains(source))
            elif event == "open":
                path = args[0]
                if isinstance(path, (str, bytes, os.PathLike)):
                    mode = args[1] if len(args) > 1 and isinstance(args[1], str) else "r"
                    _record_path(state, "open", path, mode=mode)
            elif event in ("os.remove", "os.rmdir", "shutil.rmtree", "os.truncate"):
                _record_path(state, event, args[0], mode="w")
            elif event in ("os.rename", "os.link", "os.symlink", "shutil.move", "shutil.copyfile"):
                _record_path(state, event, args[0], mode="w")
                _record_path(state, event, args[1], mode="w")
            elif event == "socket.getaddrinfo":
                host = args[0]
                state.record("CWE-918", "getaddrinfo", host, tainted=state.contains(host))
            elif event == "socket.connect":
                address = args[1]
                host = address[0] if isinstance(address, tuple) and address else address
                state.record("CWE-918", "socket.connect", host, tainted=state.contains(host))
            elif event == "urllib.Request":
                state.record("CWE-918", "urllib.Request", args[0], tainted=state.contains(args[0]))
        except Exception:  # a hook must never break the interpreter
            return

    return hook


def _is_shell(executable: Any) -> bool:
    try:
        return os.path.basename(os.fsdecode(executable)) in SHELLS
    except Exception:
        return False


def _record_path(state: _State, kind: str, path: Any, *, mode: str = "r") -> None:
    try:
        text = os.fsdecode(path) if isinstance(path, (bytes, os.PathLike)) else str(path)
    except Exception:
        return
    if not state.contains(text):
        return
    normalized = text.replace("\\", "/")
    segments = normalized.split("/")
    traversal = ".." in segments
    # CWE-22 (path traversal): the attacker's value walks OUT of the intended dir with ``..``.
    state.record("CWE-22", kind, text, tainted=traversal)
    # CWE-73 (external control of file name/path, read OR write): the attacker's value escapes
    # a confined LEAF - it either traverses with ``..`` or lands in a DIRECTORY component
    # (controls where, not just which file). A safe handler confines to a fixed dir and keeps
    # the attacker value as the final leaf only (``basename`` / allowlist), so core appears in
    # no earlier segment and stays untainted. The open-mode is surfaced in the kind (write/read).
    in_directory = any(state.contains(seg) for seg in segments[:-1])
    writing = any(c in mode for c in ("w", "a", "x", "+"))
    label = f"{kind}({'write' if writing else 'read'})"
    state.record("CWE-73", label, text, tainted=traversal or in_directory)


class _Proxy:
    """Delegates everything to the wrapped object; subclasses intercept a few methods."""

    def __init__(self, target: Any, state: _State) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_state", state)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_target"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_target"), name, value)

    def __enter__(self) -> Any:
        target = object.__getattribute__(self, "_target")
        target.__enter__()
        return self

    def __exit__(self, *exc: Any) -> Any:
        return object.__getattribute__(self, "_target").__exit__(*exc)

    def __iter__(self) -> Any:
        return iter(object.__getattribute__(self, "_target"))


class _CursorProxy(_Proxy):
    def execute(self, sql: Any, *args: Any, **kwargs: Any) -> Any:
        self._state.record("CWE-89", "execute", sql, tainted=self._state.contains(sql))
        return self._target.execute(sql, *args, **kwargs)

    def executemany(self, sql: Any, *args: Any, **kwargs: Any) -> Any:
        self._state.record("CWE-89", "executemany", sql, tainted=self._state.contains(sql))
        return self._target.executemany(sql, *args, **kwargs)

    def executescript(self, sql: Any, *args: Any, **kwargs: Any) -> Any:
        self._state.record("CWE-89", "executescript", sql, tainted=self._state.contains(sql))
        return self._target.executescript(sql, *args, **kwargs)


class _ConnectionProxy(_CursorProxy):
    def cursor(self, *args: Any, **kwargs: Any) -> Any:
        return _CursorProxy(self._target.cursor(*args, **kwargs), self._state)


def _wrap_connect(module: Any, state: _State) -> None:
    original = module.connect

    def connect(*args: Any, **kwargs: Any) -> Any:
        return _ConnectionProxy(original(*args, **kwargs), state)

    module.connect = connect


def _install_hooks(state: _State) -> list[str]:
    """Install every hook that applies; return the names of what was installed."""
    installed: list[str] = []
    sys.addaudithook(_audit_hook(state))
    installed.append("audit")

    for name in ("sqlite3", "psycopg2", "pymysql", "MySQLdb", "psycopg"):
        try:
            module = __import__(name)
        except Exception:
            continue
        try:
            _wrap_connect(module, state)
            installed.append(f"{name}.connect")
        except Exception:
            continue

    try:
        import pickle

        for fn_name in ("loads", "load"):
            original = getattr(pickle, fn_name)

            def make(orig: Any, label: str) -> Any:
                def wrapper(data: Any, *args: Any, **kwargs: Any) -> Any:
                    state.record("CWE-502", label, data, tainted=state.contains(data))
                    return orig(data, *args, **kwargs)

                return wrapper

            setattr(pickle, fn_name, make(original, f"pickle.{fn_name}"))
        installed.append("pickle")
    except Exception:
        pass

    try:
        import marshal

        original_marshal = marshal.loads

        def marshal_loads(data: Any, *args: Any, **kwargs: Any) -> Any:
            state.record("CWE-502", "marshal.loads", data, tainted=state.contains(data))
            return original_marshal(data, *args, **kwargs)

        marshal.loads = marshal_loads
        installed.append("marshal")
    except Exception:
        pass

    try:
        import yaml  # type: ignore[import-not-found, import-untyped, unused-ignore]

        original_load = yaml.load
        safe = {getattr(yaml, n, None) for n in ("SafeLoader", "CSafeLoader", "BaseLoader")}

        def yaml_load(stream: Any, Loader: Any = None, *args: Any, **kwargs: Any) -> Any:  # noqa: N803
            unsafe = Loader is None or Loader not in safe
            state.record("CWE-502", "yaml.load", stream, tainted=unsafe and state.contains(stream))
            if Loader is None:
                return original_load(stream, *args, **kwargs)
            return original_load(stream, Loader, *args, **kwargs)

        yaml.load = yaml_load
        installed.append("yaml")
    except Exception:
        pass

    _install_framework_hooks(state, installed)
    return installed


# ---------------------------------------------------------------------------
# Framework / library sink hooks (the added CWE families)
#
# Each wraps the REAL dangerous call of an optional third-party library and records whether
# the secret canary reached its dangerous argument. All are best-effort and guarded: a
# library that is not importable installs no hook (the finding then stays skipped/unproven,
# never falsely failed). Like the audit hooks they only record while the PoC runs and only
# count when the flagged line is on the call stack.
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^\s*(?:[a-z][a-z0-9+.\-]*:)?//", re.IGNORECASE)
_XML_DTD = ("<!DOCTYPE", "<!ENTITY")
_NOSQL_JS_OPS = ("$where", "$expr", "$function", "$accumulator", "$code")


def _install_framework_hooks(state: _State, installed: list[str]) -> None:
    for installer in (
        _hook_templates,
        _hook_xpath,
        _hook_ldap,
        _hook_nosql,
        _hook_xxe,
        _hook_redirect,
        _hook_response,
    ):
        try:
            installer(state, installed)
        except Exception:  # one library's absence/oddity must never break the others
            continue


def _hook_templates(state: _State, installed: list[str]) -> None:
    """SSTI (CWE-1336): the canary appears in a Jinja2 / Mako template BODY (vs. its context)."""
    try:
        import jinja2

        env_cls = jinja2.Environment
        original = env_cls.from_string

        def from_string(self: Any, source: Any, *args: Any, **kwargs: Any) -> Any:
            state.record("CWE-1336", "jinja2.from_string", source, tainted=state.contains(source))
            return original(self, source, *args, **kwargs)

        env_cls.from_string = from_string  # type: ignore[method-assign]
        installed.append("jinja2")
    except Exception:
        pass
    try:
        import mako.template as mako_template

        original_init = mako_template.Template.__init__

        def init(self: Any, *args: Any, **kwargs: Any) -> None:
            text = kwargs.get("text")
            if text is None and args and isinstance(args[0], str):
                text = args[0]
            if isinstance(text, (str, bytes)):
                state.record("CWE-1336", "mako.Template", text, tainted=state.contains(text))
            original_init(self, *args, **kwargs)

        mako_template.Template.__init__ = init
        installed.append("mako")
    except Exception:
        pass


def _hook_xpath(state: _State, installed: list[str]) -> None:
    """XPath injection (CWE-643): the canary appears in the XPath EXPRESSION text."""
    try:
        from xml.etree import ElementPath

        for name in ("find", "findall", "iterfind", "findtext"):
            original = getattr(ElementPath, name, None)
            if original is None:
                continue
            setattr(ElementPath, name, _xpath_wrapper(state, original, f"ElementTree.{name}"))
        installed.append("xml.xpath")
    except Exception:
        pass
    try:
        from lxml import etree

        for name in ("XPath", "ETXPath"):
            original = getattr(etree, name, None)
            if original is None:
                continue
            setattr(etree, name, _xpath_wrapper(state, original, f"lxml.{name}"))
        installed.append("lxml.xpath")
    except Exception:
        pass


def _xpath_wrapper(state: _State, original: Any, label: str) -> Any:
    def wrapper(first: Any, *args: Any, **kwargs: Any) -> Any:
        # ElementPath.<fn>(elem, path, ...): the expression is the SECOND positional;
        # lxml.XPath(expr, ...): it is the first. Inspect whichever carries the canary.
        expr = args[0] if label.startswith("ElementTree.") and args else first
        state.record("CWE-643", label, expr, tainted=state.contains(expr))
        return original(first, *args, **kwargs)

    return wrapper


def _hook_ldap(state: _State, installed: list[str]) -> None:
    """LDAP injection (CWE-90): the canary (with its ``)(|`` probe INTACT) is in the filter."""
    try:
        import ldap3

        original = ldap3.Connection.search

        def search(self: Any, search_base: Any, search_filter: Any, *a: Any, **k: Any) -> Any:
            state.record(
                "CWE-90", "ldap3.search", search_filter, tainted=state.contains_full(search_filter)
            )
            return original(self, search_base, search_filter, *a, **k)

        ldap3.Connection.search = search
        installed.append("ldap3")
    except Exception:
        pass
    try:
        from ldap import ldapobject

        for name in ("search_s", "search_ext_s", "search_st"):
            original = getattr(ldapobject.LDAPObject, name, None)
            if original is None:
                continue
            setattr(ldapobject.LDAPObject, name, _ldap_wrapper(state, original, f"ldap.{name}"))
        installed.append("python-ldap")
    except Exception:
        pass


def _ldap_wrapper(state: _State, original: Any, label: str) -> Any:
    def wrapper(self: Any, base: Any, scope: Any, filterstr: Any = "", *a: Any, **k: Any) -> Any:
        state.record("CWE-90", label, filterstr, tainted=state.contains_full(filterstr))
        return original(self, base, scope, filterstr, *a, **k)

    return wrapper


def _hook_nosql(state: _State, installed: list[str]) -> None:
    """NoSQL injection (CWE-943): the canary lands in a query OPERATOR (``$where`` JS, a
    ``$``-prefixed key) rather than as a plain field value - operator/query-object injection."""
    try:
        from pymongo import collection

        for name in (
            "find",
            "find_one",
            "count_documents",
            "delete_one",
            "delete_many",
            "update_one",
            "update_many",
        ):
            original = getattr(collection.Collection, name, None)
            if original is None:
                continue
            setattr(collection.Collection, name, _nosql_wrapper(state, original, f"pymongo.{name}"))
        installed.append("pymongo")
    except Exception:
        pass


def _nosql_wrapper(state: _State, original: Any, label: str) -> Any:
    def wrapper(self: Any, query: Any = None, *a: Any, **k: Any) -> Any:
        state.record("CWE-943", label, query, tainted=_nosql_tainted(state, query))
        return original(self, query, *a, **k)

    return wrapper


def _nosql_tainted(state: _State, node: Any) -> bool:
    """True if the canary core reaches a dangerous operator position in a Mongo query:
    inside a JavaScript operator string (``$where`` / ``$expr`` / ...), or AS a ``$``-prefixed
    operator KEY the attacker injected (query-object injection). A plain field value carrying
    the canary - even under an ordinary operator like ``$regex`` / ``$gt`` - is the safe,
    parameterised shape and does NOT count."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key in _NOSQL_JS_OPS and state.contains(value):
                return True
            if isinstance(key, str) and key.startswith("$") and state.contains(key):
                return True
            if _nosql_tainted(state, value):
                return True
        return False
    if isinstance(node, (list, tuple)):
        return any(_nosql_tainted(state, item) for item in node)
    return False


def _hook_xxe(state: _State, installed: list[str]) -> None:
    """XXE (CWE-611): tainted XML carrying a DOCTYPE/ENTITY reaches an entity-resolving parser."""
    try:
        from lxml import etree

        for name in ("fromstring", "XML", "parse"):
            original = getattr(etree, name, None)
            if original is None:
                continue
            setattr(etree, name, _xxe_wrapper(state, original, f"lxml.{name}"))
        installed.append("lxml.xxe")
    except Exception:
        pass
    try:
        from xml.dom import minidom

        original_parse_string = minidom.parseString

        def parse_string(string: Any, *a: Any, **k: Any) -> Any:
            dangerous = _xxe_source_dangerous(state, string)
            state.record("CWE-611", "minidom.parseString", string, tainted=dangerous)
            return original_parse_string(string, *a, **k)

        minidom.parseString = parse_string
        installed.append("minidom.xxe")
    except Exception:
        pass


def _xxe_wrapper(state: _State, original: Any, label: str) -> Any:
    def wrapper(source: Any, *args: Any, **kwargs: Any) -> Any:
        parser = kwargs.get("parser")
        if parser is None and args:
            parser = args[0]
        if _xxe_source_dangerous(state, source) and _parser_resolves_entities(parser):
            state.record("CWE-611", label, source, tainted=True)
        elif state.contains(source):
            state.record("CWE-611", label, source, tainted=False)
        return original(source, *args, **kwargs)

    return wrapper


def _xxe_source_dangerous(state: _State, source: Any) -> bool:
    if not state.contains(source):
        return False
    try:
        text = (
            source.decode("utf-8", "replace")
            if isinstance(source, (bytes, bytearray))
            else str(source)
        )
    except Exception:
        return False
    return any(marker in text for marker in _XML_DTD)


def _parser_resolves_entities(parser: Any) -> bool:
    """A missing parser means the library default (lxml resolves internal entities); a parser
    built with ``resolve_entities=False`` / ``no_network=True`` DTD-forbidding (defusedxml) is
    the safe shape and reports False."""
    if parser is None:
        return True
    return bool(getattr(parser, "resolve_entities", True))


def _hook_redirect(state: _State, installed: list[str]) -> None:
    """Open redirect (CWE-601): the canary forms an EXTERNAL redirect target (off-site URL)."""
    try:
        from werkzeug import utils as werkzeug_utils

        original = werkzeug_utils.redirect

        def redirect(location: Any, *a: Any, **k: Any) -> Any:
            state.record(
                "CWE-601", "werkzeug.redirect", location, tainted=_redirect_tainted(state, location)
            )
            return original(location, *a, **k)

        werkzeug_utils.redirect = redirect
        installed.append("werkzeug.redirect")
        try:
            import flask

            if getattr(flask, "redirect", None) is original:
                flask.redirect = redirect
        except Exception:
            pass
    except Exception:
        pass
    _hook_class_init(
        state, installed, "django.http", "HttpResponseRedirect", "CWE-601", "django.redirect", 0
    )
    _hook_class_init(
        state,
        installed,
        "starlette.responses",
        "RedirectResponse",
        "CWE-601",
        "starlette.redirect",
        0,
        tainted=lambda value: _redirect_tainted(state, value),
    )


def _redirect_tainted(state: _State, location: Any) -> bool:
    return state.contains(location) and _looks_external(location)


def _looks_external(location: Any) -> bool:
    try:
        if isinstance(location, (bytes, os.PathLike)):
            text = os.fsdecode(location)
        else:
            text = str(location)
    except Exception:
        return False
    return bool(_SCHEME_RE.match(text))


def _hook_response(state: _State, installed: list[str]) -> None:
    """Reflected unescaped output (CWE-79): the canary (``<x>`` probe intact) is in the HTTP
    response BODY built at the flagged line (``Response(...)`` / ``make_response(...)``) with an
    HTML content type. This proves tainted input reaches the response UNESCAPED; it does NOT
    prove DOM-based or stored XSS (no browser, no DOM, no persisted sink is involved)."""
    try:
        from werkzeug import wrappers

        original = wrappers.Response.__init__

        def init(self: Any, response: Any = None, *a: Any, **k: Any) -> None:
            mimetype = k.get("mimetype") or k.get("content_type")
            if state.contains_full(response) and not _is_non_html(mimetype):
                state.record("CWE-79", "werkzeug.Response", response, tainted=True)
            elif state.contains(response):
                state.record("CWE-79", "werkzeug.Response", response, tainted=False)
            original(self, response, *a, **k)

        wrappers.Response.__init__ = init  # type: ignore[method-assign]
        installed.append("werkzeug.response")
    except Exception:
        pass


def _is_non_html(mimetype: Any) -> bool:
    if not isinstance(mimetype, str):
        return False
    lowered = mimetype.lower()
    return "html" not in lowered and (
        "json" in lowered or "plain" in lowered or "octet-stream" in lowered
    )


def _hook_class_init(
    state: _State,
    installed: list[str],
    module_name: str,
    class_name: str,
    cwe: str,
    label: str,
    arg_index: int,
    *,
    tainted: Any = None,
) -> None:
    """Wrap ``Class.__init__`` so the ``arg_index``-th positional (the dangerous argument) is
    inspected. ``tainted`` defaults to a plain canary-core check."""
    try:
        module = __import__(module_name, fromlist=[class_name])
        cls = getattr(module, class_name, None)
        if cls is None:
            return
        original = cls.__init__
        predicate = tainted or (lambda value: state.contains(value))

        def init(self: Any, *args: Any, **kwargs: Any) -> None:
            if len(args) > arg_index:
                value = args[arg_index]
                state.record(cwe, label, value, tainted=bool(predicate(value)))
            original(self, *args, **kwargs)

        cls.__init__ = init
        installed.append(label)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Running the PoC
# ---------------------------------------------------------------------------


def run_oracle(config: dict[str, Any], root: str) -> dict[str, Any]:
    """Install hooks, run the PoC, and return the result document."""
    state = _State(config, root)
    os.environ[PAYLOAD_ENV] = state.canary
    if root not in sys.path:
        sys.path.insert(0, root)
    # Provisioned third-party packages (the jail's read-only /deps). The oracle runs under
    # ``python3 -I`` so PYTHONPATH is ignored on purpose; the Executor-controlled directory
    # is appended explicitly - AFTER the workspace and the stdlib, so nothing in it can
    # shadow either. This happens BEFORE hook installation so the framework-library hooks
    # (jinja2 / werkzeug / lxml / ldap3 / ...) can import and wrap the provisioned packages.
    for extra in config.get("sys_path") or []:
        if isinstance(extra, str) and os.path.isdir(extra) and extra not in sys.path:
            sys.path.append(extra)
    installed = _install_hooks(state)
    os.chdir(root)
    out, err = io.StringIO(), io.StringIO()
    real_out, real_err = sys.stdout, sys.stderr
    poc_error = ""
    poc_exit: int | None = 0
    started = time.perf_counter()
    sys.stdout, sys.stderr = out, err
    state.active = True
    try:
        runpy.run_path(state.poc_file, run_name="__main__")
    except SystemExit as exc:
        poc_exit = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    except BaseException:
        poc_exit = 1
        poc_error = "".join(traceback.format_exception(*sys.exc_info()))[-TAIL_CHARS:]
    finally:
        state.active = False
        sys.stdout, sys.stderr = real_out, real_err
    duration_ms = (time.perf_counter() - started) * 1000
    accepted = family_of(str(config.get("cwe", "")))
    relevant = [h for h in state.hits if h["cwe"] in accepted]
    fired = any(h["at_sink"] for h in relevant)
    return {
        "ok": True,
        "fired": fired,
        "reached_elsewhere": [h for h in relevant if h["tainted"] and not h["at_sink"]],
        "untainted_at_sink": not fired and any(not h["tainted"] for h in relevant),
        "hits": state.hits,
        "hits_truncated": state.truncated,
        "hooks": installed,
        "poc_exit": poc_exit,
        "poc_error": poc_error,
        "poc_stdout": out.getvalue()[-TAIL_CHARS:],
        "poc_stderr": err.getvalue()[-TAIL_CHARS:],
        "duration_ms": duration_ms,
    }


def main(argv: list[str], root: str | None = None) -> int:
    if len(argv) < 1:
        sys.stdout.write(RESULT_MARKER + json.dumps({"ok": False, "error": "usage: <json>"}) + "\n")
        return 2
    try:
        config = json.loads(argv[0])
        result = run_oracle(config, root or os.getcwd())
    except Exception as exc:  # the oracle itself failed: report, never hang
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(RESULT_MARKER + json.dumps(result, default=str) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
