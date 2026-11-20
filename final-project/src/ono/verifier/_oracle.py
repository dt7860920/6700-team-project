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
CWE_FAMILIES: dict[str, frozenset[str]] = {
    "CWE-89": frozenset({"CWE-89", "CWE-943"}),
    "CWE-78": frozenset({"CWE-78", "CWE-77", "CWE-88"}),
    "CWE-94": frozenset({"CWE-94", "CWE-95", "CWE-96"}),
    "CWE-502": frozenset({"CWE-502", "CWE-20"}),
    "CWE-22": frozenset({"CWE-22", "CWE-23", "CWE-36", "CWE-73"}),
    "CWE-918": frozenset({"CWE-918"}),
}
SUPPORTED_CWES: frozenset[str] = frozenset().union(*CWE_FAMILIES.values())


def family_of(cwe: str) -> frozenset[str]:
    """Every CWE a hit of ``cwe`` proves (at least ``cwe`` itself)."""
    for members in CWE_FAMILIES.values():
        if cwe in members:
            return members
    return frozenset({cwe})


class _State:
    """Everything a hook needs: the canary, the sink to match, the hits so far."""

    def __init__(self, config: dict[str, Any], root: str) -> None:
        self.canary: str = str(config["canary"])
        self.canary_bytes = self.canary.encode("utf-8")
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
        """Does ``value`` (str / bytes / nested list-tuple-dict / anything) carry the canary?"""
        try:
            if isinstance(value, str):
                return self.canary in value
            if isinstance(value, (bytes, bytearray, memoryview)):
                return self.canary_bytes in bytes(value)
            if isinstance(value, (list, tuple, set, frozenset)):
                return any(self.contains(v) for v in value)
            if isinstance(value, dict):
                return any(self.contains(v) for v in value.values())
            if hasattr(value, "read") and hasattr(value, "seek"):
                pos = value.tell()
                data = value.read()
                value.seek(pos)
                return self.contains(data)
            if value is None or isinstance(value, (int, float, bool)):
                return False
            return self.canary in str(value)
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
    text = text.replace(canary, "<PAYLOAD>")
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
                    _record_path(state, "open", path)
            elif event in ("os.remove", "os.rmdir", "shutil.rmtree", "os.truncate"):
                _record_path(state, event, args[0])
            elif event in ("os.rename", "os.link", "os.symlink", "shutil.move", "shutil.copyfile"):
                _record_path(state, event, args[0])
                _record_path(state, event, args[1])
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


def _record_path(state: _State, kind: str, path: Any) -> None:
    try:
        text = os.fsdecode(path) if isinstance(path, (bytes, os.PathLike)) else str(path)
    except Exception:
        return
    if not state.contains(text):
        return
    parts = text.replace("\\", "/").split("/")
    traversal = ".." in parts
    state.record("CWE-22", kind, text, tainted=traversal)


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
    return installed


# ---------------------------------------------------------------------------
# Running the PoC
# ---------------------------------------------------------------------------


def run_oracle(config: dict[str, Any], root: str) -> dict[str, Any]:
    """Install hooks, run the PoC, and return the result document."""
    state = _State(config, root)
    installed = _install_hooks(state)
    os.environ[PAYLOAD_ENV] = state.canary
    if root not in sys.path:
        sys.path.insert(0, root)
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
