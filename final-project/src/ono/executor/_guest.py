"""In-jail helper: runs INSIDE the sandbox container, as the unprivileged sandbox user.

The Executor ships this module's *source text* on every call::

    python3 -I -S -c "<this file>" <op> [<json-args>]      (stdin: diff for ``apply``)

so nothing in the (hostile) workspace can tamper with it: argv is set by the
Executor, the interpreter lives on the read-only image, ``-I`` ignores all
``PYTHON*`` variables / ``sitecustomize`` / the cwd, and ``-S`` skips ``site``.

Everything here assumes the workspace is adversarial:

* **Path confinement.** Paths are relative to the workspace; absolute paths, ``..``,
  NUL and backslashes are rejected *and* every component is opened with
  ``O_NOFOLLOW`` relative to the previous directory fd, so a planted symlink
  (``evil -> /etc/passwd``) is never followed - not even in a TOCTOU race.
* **Bounded output.** Reads, listings and grep results are capped in bytes / entries.
* **Strict patching.** The unified-diff applier is all-or-nothing, matches context
  exactly, and only ever opens files through the same confined path walk.

Stdlib only, Python >= 3.9 syntax (the sandbox image's interpreter may be older
than ours). Must stay importable on the host: the unit tests exercise it directly.
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import sys
from typing import Any, NoReturn

WORKSPACE = "/workspace"
MAX_FILE_BYTES = 8_000_000  # files above this are never loaded whole (line slicing / grep)
GREP_LINE_CHARS = 400
BINARY_SNIFF = 8192

_O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_O_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


class GuestError(Exception):
    """A user-facing failure (bad path, missing file, ...). Reported as ``{"ok": false}``."""


class MissingPathError(GuestError):
    """A path component does not exist (the one failure ``apply`` treats as "new file")."""


# ---------------------------------------------------------------------------
# Confined path handling
# ---------------------------------------------------------------------------


def split_rel(rel: str) -> list[str]:
    """Normalize a workspace-relative path into components; reject anything that escapes."""
    if "\x00" in rel:
        raise GuestError("path contains a NUL byte")
    if "\\" in rel:
        raise GuestError("backslashes are not allowed in paths")
    if rel.startswith("/"):
        raise GuestError("absolute paths are not allowed; paths are relative to the workspace")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise GuestError("'..' is not allowed in paths")
    if len(parts) > 64:
        raise GuestError("path has too many components")
    return parts


def open_dir(dir_fd: int | None, name: str) -> int:
    """Open a directory *without following symlinks*."""
    try:
        return os.open(name, _O_DIR, dir_fd=dir_fd)
    except OSError as exc:
        _raise_os(exc, name, dir_fd)


def walk_to_parent(root: str, parts: list[str]) -> tuple[int, str | None]:
    """Open ``root/parts[:-1]`` component by component (no symlinks) -> ``(dir_fd, leaf)``.

    ``leaf`` is ``None`` when ``parts`` is empty (the path *is* the root).
    """
    fd = open_dir(None, root)
    try:
        for part in parts[:-1]:
            nxt = open_dir(fd, part)
            os.close(fd)
            fd = nxt
    except Exception:
        os.close(fd)
        raise
    return fd, (parts[-1] if parts else None)


def open_file(dir_fd: int, name: str) -> int:
    """Open a regular file for reading without following symlinks."""
    try:
        fd = os.open(name, _O_FILE, dir_fd=dir_fd)
    except OSError as exc:
        _raise_os(exc, name, dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise GuestError(f"not a regular file: {name!r}")
    except Exception:
        os.close(fd)
        raise
    return fd


def _raise_os(exc: OSError, name: str, dir_fd: int | None = None) -> NoReturn:
    """Map an ``os.open`` failure onto a user-facing :class:`GuestError`.

    ``O_NOFOLLOW`` on a symlink is ELOOP on Linux but ENOTDIR (for ``O_DIRECTORY``) on
    macOS, so the symlink case is confirmed with ``lstat`` and reported uniformly.
    """
    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
        try:
            is_link = stat.S_ISLNK(os.lstat(name, dir_fd=dir_fd).st_mode)
        except OSError:
            is_link = exc.errno == errno.ELOOP
        if is_link:
            raise GuestError(
                f"{name!r} is a symlink; symlinks are not followed inside the workspace"
            ) from None
    if exc.errno == errno.ENOENT:
        raise MissingPathError(f"no such file or directory: {name!r}") from None
    if exc.errno in (errno.EACCES, errno.EPERM):
        raise GuestError(f"permission denied: {name!r}") from None
    if exc.errno == errno.ENOTDIR:
        raise GuestError(f"not a directory: {name!r}") from None
    raise GuestError(f"{exc.strerror or 'os error'}: {name!r}") from None


def read_fd(fd: int, limit: int) -> tuple[bytes, bool]:
    """Read at most ``limit`` bytes; the flag says whether more remained."""
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 1 << 20))
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks), bool(os.read(fd, 1))


def cap_text(text: str, cap_bytes: int) -> tuple[str, bool]:
    raw = text.encode("utf-8", "replace")
    if len(raw) <= cap_bytes:
        return text, False
    return raw[:cap_bytes].decode("utf-8", "ignore"), True


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------


def op_read(root: str, args: dict[str, Any]) -> dict[str, Any]:
    path = str(args["path"])
    start = args.get("start")
    end = args.get("end")
    cap = int(args.get("cap_bytes", 1_000_000))
    parts = split_rel(path)
    if not parts:
        raise GuestError("path must name a file, not the workspace root")
    dir_fd, leaf = walk_to_parent(root, parts)
    try:
        assert leaf is not None
        fd = open_file(dir_fd, leaf)
    finally:
        os.close(dir_fd)
    try:
        size = os.fstat(fd).st_size
        if start is None and end is None:
            data, more = read_fd(fd, cap)
            text = data.decode("utf-8", "replace")
            total = (
                None if more else (text.count("\n") + (0 if text.endswith("\n") or not text else 1))
            )
            return {
                "ok": True,
                "content": text,
                "start_line": 1,
                "end_line": total if total is not None else text.count("\n"),
                "total_lines": total,
                "size_bytes": size,
                "truncated": more,
            }
        if size > MAX_FILE_BYTES:
            raise GuestError(f"file is {size} bytes; line slicing is limited to {MAX_FILE_BYTES}")
        data, _more = read_fd(fd, MAX_FILE_BYTES)
    finally:
        os.close(fd)
    lines = data.decode("utf-8", "replace").splitlines(keepends=True)
    total = len(lines)
    first = int(start or 1)
    last = int(end or total)
    if last < first:
        raise GuestError("end must be >= start")
    chunk = lines[first - 1 : last]
    text, truncated = cap_text("".join(chunk), cap)
    return {
        "ok": True,
        "content": text,
        "start_line": first,
        "end_line": first + len(chunk) - 1 if chunk else 0,
        "total_lines": total,
        "size_bytes": size,
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# tree
# ---------------------------------------------------------------------------


def _kind(entry: os.DirEntry[str]) -> str:
    if entry.is_symlink():
        return "symlink"
    if entry.is_dir(follow_symlinks=False):
        return "dir"
    if entry.is_file(follow_symlinks=False):
        return "file"
    return "other"


def _open_scope(root: str, path: str) -> tuple[int, str]:
    """Open a directory inside the workspace (``"."`` = the root) -> ``(fd, display_prefix)``."""
    parts = split_rel(path)
    dir_fd, leaf = walk_to_parent(root, parts)
    if leaf is None:
        return dir_fd, ""
    try:
        fd = open_dir(dir_fd, leaf)
    finally:
        os.close(dir_fd)
    return fd, "/".join(parts) + "/"


def op_tree(root: str, args: dict[str, Any]) -> dict[str, Any]:
    max_entries = int(args.get("max_entries", 2000))
    max_depth = int(args.get("max_depth", 12))
    fd, prefix = _open_scope(root, str(args.get("path", ".")))
    entries: list[dict[str, Any]] = []
    truncated = False

    def visit(dfd: int, rel: str, depth: int) -> None:
        nonlocal truncated
        if truncated:
            return
        try:
            with os.scandir(dfd) as it:
                children = sorted(it, key=lambda e: e.name)
        except OSError:
            return
        for entry in children:
            if len(entries) >= max_entries:
                truncated = True
                return
            kind = _kind(entry)
            size = 0
            if kind == "file":
                try:
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError:
                    size = 0
            path = f"{rel}{entry.name}"
            entries.append({"path": path, "kind": kind, "size": size})
            if kind == "dir":
                if depth >= max_depth:
                    truncated = True
                    continue
                try:
                    child_fd = open_dir(dfd, entry.name)
                except GuestError:
                    continue
                try:
                    visit(child_fd, path + "/", depth + 1)
                finally:
                    os.close(child_fd)

    try:
        visit(fd, prefix, 1)
    finally:
        os.close(fd)
    return {"ok": True, "entries": entries, "truncated": truncated, "total": len(entries)}


# ---------------------------------------------------------------------------
# grep
# ---------------------------------------------------------------------------


class _GrepState:
    __slots__ = ("scanned", "truncated")

    def __init__(self) -> None:
        self.scanned = 0
        self.truncated = False


def op_grep(root: str, args: dict[str, Any]) -> dict[str, Any]:
    flags = re.IGNORECASE if args.get("ignore_case") else 0
    try:
        pattern = re.compile(str(args["pattern"]), flags)
    except re.error as exc:
        raise GuestError(f"invalid regular expression: {exc}") from None
    max_matches = int(args.get("max_matches", 200))
    scope = str(args.get("path", "."))
    matches: list[dict[str, Any]] = []
    state = _GrepState()

    def scan_file(dfd: int, name: str, display: str) -> None:
        try:
            fd = open_file(dfd, name)
        except GuestError:
            return
        try:
            if os.fstat(fd).st_size > MAX_FILE_BYTES:
                return
            data, _ = read_fd(fd, MAX_FILE_BYTES)
        finally:
            os.close(fd)
        if b"\x00" in data[:BINARY_SNIFF]:
            return
        state.scanned += 1
        for lineno, line in enumerate(data.decode("utf-8", "replace").splitlines(), start=1):
            if pattern.search(line):
                if len(matches) >= max_matches:
                    state.truncated = True
                    return
                matches.append({"file": display, "line": lineno, "text": line[:GREP_LINE_CHARS]})

    def visit(dfd: int, rel: str) -> None:
        try:
            with os.scandir(dfd) as it:
                children = sorted(it, key=lambda e: e.name)
        except OSError:
            return
        for entry in children:
            if state.truncated:  # set by scan_file once max_matches is hit
                return
            kind = _kind(entry)
            if kind == "file":
                scan_file(dfd, entry.name, f"{rel}{entry.name}")
            elif kind == "dir":
                try:
                    child_fd = open_dir(dfd, entry.name)
                except GuestError:
                    continue
                try:
                    visit(child_fd, f"{rel}{entry.name}/")
                finally:
                    os.close(child_fd)

    parts = split_rel(scope)
    dir_fd, leaf = walk_to_parent(root, parts)
    try:
        if leaf is None:
            visit(dir_fd, "")
        else:
            try:
                st = os.stat(leaf, dir_fd=dir_fd, follow_symlinks=False)
            except OSError as exc:
                _raise_os(exc, leaf, dir_fd)
            if stat.S_ISDIR(st.st_mode):
                fd = open_dir(dir_fd, leaf)
                try:
                    visit(fd, "/".join(parts) + "/")
                finally:
                    os.close(fd)
            elif stat.S_ISREG(st.st_mode):
                scan_file(dir_fd, leaf, "/".join(parts))
            else:
                raise GuestError(f"not a file or directory: {scope!r}")
    finally:
        os.close(dir_fd)
    return {
        "ok": True,
        "matches": matches,
        "truncated": state.truncated,
        "files_scanned": state.scanned,
    }


# ---------------------------------------------------------------------------
# apply (unified diff)
# ---------------------------------------------------------------------------

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class Hunk:
    __slots__ = ("lines", "new_start", "old_start")

    def __init__(self, old_start: int, new_start: int) -> None:
        self.old_start = old_start
        self.new_start = new_start
        self.lines: list[tuple[str, str]] = []  # (tag, text-with-newline-or-not)


class FilePatch:
    __slots__ = ("hunks", "is_delete", "is_new", "path")

    def __init__(self, path: str, is_new: bool, is_delete: bool) -> None:
        self.path = path
        self.is_new = is_new
        self.is_delete = is_delete
        self.hunks: list[Hunk] = []


def _strip_prefix(raw: str) -> str:
    """``a/x/y`` -> ``x/y`` (git style); timestamps after a TAB are dropped; quotes removed."""
    path = raw.split("\t", 1)[0].strip()
    if path.startswith('"') and path.endswith('"') and len(path) >= 2:
        path = path[1:-1]
    if path == "/dev/null":
        return path
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path


def parse_unified_diff(text: str) -> list[FilePatch]:
    """Parse a (possibly multi-file) unified diff. Raises :class:`GuestError` when unusable."""
    lines = text.splitlines()
    patches: list[FilePatch] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.startswith(("rename from", "rename to", "copy from", "copy to")):
            raise GuestError("renames and copies are not supported")
        if line.startswith(("Binary files", "GIT binary patch")):
            raise GuestError("binary patches are not supported")
        if not line.startswith("--- "):
            i += 1
            continue
        if i + 1 >= n or not lines[i + 1].startswith("+++ "):
            raise GuestError(f"malformed file header at line {i + 1}")
        old = _strip_prefix(line[4:])
        new = _strip_prefix(lines[i + 1][4:])
        i += 2
        if old == "/dev/null" and new == "/dev/null":
            raise GuestError("file header has /dev/null on both sides")
        patch = FilePatch(
            path=new if new != "/dev/null" else old,
            is_new=old == "/dev/null",
            is_delete=new == "/dev/null",
        )
        while i < n and lines[i].startswith("@@"):
            m = _HUNK_HEADER.match(lines[i])
            if m is None:
                raise GuestError(f"malformed hunk header at line {i + 1}: {lines[i]!r}")
            old_count = int(m.group(2)) if m.group(2) is not None else 1
            new_count = int(m.group(4)) if m.group(4) is not None else 1
            hunk = Hunk(int(m.group(1)), int(m.group(3)))
            i += 1
            while (old_count > 0 or new_count > 0) and i < n:
                body = lines[i]
                if body.startswith("\\"):  # "\ No newline at end of file" -> strip from previous
                    if hunk.lines:
                        tag, txt = hunk.lines[-1]
                        hunk.lines[-1] = (tag, txt.rstrip("\n"))
                    i += 1
                    continue
                tag = body[:1] if body else " "
                content = body[1:] if body else ""
                if tag == " ":
                    old_count -= 1
                    new_count -= 1
                elif tag == "-":
                    old_count -= 1
                elif tag == "+":
                    new_count -= 1
                else:
                    raise GuestError(f"unexpected line in hunk at line {i + 1}: {body!r}")
                hunk.lines.append((tag, content + "\n"))
                i += 1
            if old_count != 0 or new_count != 0:
                raise GuestError(f"hunk at line {hunk.old_start} has a wrong line count")
            # a trailing "\ No newline" marker belongs to the hunk that just ended
            if i < n and lines[i].startswith("\\") and hunk.lines:
                tag, txt = hunk.lines[-1]
                hunk.lines[-1] = (tag, txt.rstrip("\n"))
                i += 1
            patch.hunks.append(hunk)
        if not patch.hunks and not patch.is_delete:
            raise GuestError(f"no hunks for {patch.path!r}")
        patches.append(patch)
    if not patches:
        raise GuestError("no file patches found in the diff")
    return patches


def _find_hunk(src: list[str], old_seg: list[str], guess: int, lo: int) -> int:
    """Locate ``old_seg`` in ``src[lo:]``; start at ``guess`` and search outward. -1 if absent.

    Like ``patch``, an exact context match anywhere at/after the previous hunk is
    accepted (line offsets drift when earlier hunks add or remove lines).
    """
    k = len(old_seg)
    span = len(src) - k
    if k == 0:
        return min(max(guess, lo), len(src))
    if span < lo:
        return -1
    guess = min(max(guess, lo), span)
    for offset in range(span - lo + 1):
        for pos in (guess - offset, guess + offset) if offset else (guess,):
            if lo <= pos <= span and src[pos : pos + k] == old_seg:
                return pos
    return -1


def apply_hunks(original: str, hunks: list[Hunk], path: str) -> str:
    src = original.splitlines(keepends=True)
    out: list[str] = []
    cursor = 0  # index in src already copied into out
    for num, hunk in enumerate(hunks, start=1):
        old_seg = [txt for tag, txt in hunk.lines if tag in " -"]
        new_seg = [txt for tag, txt in hunk.lines if tag in " +"]
        guess = hunk.old_start - 1
        pos = _find_hunk(src, old_seg, guess, cursor)
        if pos < 0:
            raise GuestError(f"hunk #{num} of {path!r} does not apply (context not found)")
        out.extend(src[cursor:pos])
        out.extend(new_seg)
        cursor = pos + len(old_seg)
    out.extend(src[cursor:])
    return "".join(out)


def _read_text_at(root: str, parts: list[str]) -> str | None:
    """Current content of a workspace file (None if absent). Confined, symlink-free."""
    try:
        dir_fd, leaf = walk_to_parent(root, parts)
    except MissingPathError:
        return None  # a missing intermediate directory: the file does not exist either
    try:
        assert leaf is not None
        try:
            fd = open_file(dir_fd, leaf)
        except MissingPathError:
            return None
    finally:
        os.close(dir_fd)
    try:
        if os.fstat(fd).st_size > MAX_FILE_BYTES:
            raise GuestError(f"{'/'.join(parts)!r} is too large to patch")
        data, _ = read_fd(fd, MAX_FILE_BYTES)
    finally:
        os.close(fd)
    return data.decode("utf-8", "surrogateescape")


def _write_text_at(root: str, parts: list[str], text: str, *, create: bool) -> None:
    dir_fd = open_dir(None, root)
    try:
        for part in parts[:-1]:
            try:
                nxt = open_dir(dir_fd, part)
            except GuestError:
                if not create:
                    raise
                os.mkdir(part, 0o755, dir_fd=dir_fd)
                nxt = open_dir(dir_fd, part)
            os.close(dir_fd)
            dir_fd = nxt
        flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        flags |= (os.O_CREAT | os.O_EXCL) if create else os.O_TRUNC
        try:
            fd = os.open(parts[-1], flags, 0o644, dir_fd=dir_fd)
        except FileExistsError:
            raise GuestError(f"{'/'.join(parts)!r} already exists") from None
        except OSError as exc:
            _raise_os(exc, parts[-1], dir_fd)
    finally:
        os.close(dir_fd)
    try:
        data = text.encode("utf-8", "surrogateescape")
        while data:
            written = os.write(fd, data)
            data = data[written:]
    finally:
        os.close(fd)


def _unlink_at(root: str, parts: list[str]) -> None:
    dir_fd, leaf = walk_to_parent(root, parts)
    try:
        assert leaf is not None
        os.unlink(leaf, dir_fd=dir_fd)
    except OSError as exc:
        _raise_os(exc, leaf or "", dir_fd)
    finally:
        os.close(dir_fd)


def apply_patch(root: str, diff: str) -> dict[str, Any]:
    """All-or-nothing: every file is patched in memory first, then all are written."""
    try:
        patches = parse_unified_diff(diff)
        plan: list[tuple[FilePatch, list[str], str | None]] = []
        seen: set[str] = set()
        for patch in patches:
            parts = split_rel(patch.path)
            if not parts:
                raise GuestError("a file patch names the workspace root")
            key = "/".join(parts)
            if key in seen:
                raise GuestError(f"{key!r} is patched twice")
            seen.add(key)
            current = _read_text_at(root, parts)
            if patch.is_new:
                if current is not None:
                    raise GuestError(f"{key!r} already exists (patch creates it)")
                plan.append((patch, parts, apply_hunks("", patch.hunks, key)))
            elif current is None:
                raise GuestError(f"{key!r} does not exist")
            elif patch.is_delete:
                if patch.hunks:
                    expected = apply_hunks(current, patch.hunks, key)
                    if expected.strip():
                        raise GuestError(f"{key!r} does not match the deletion patch")
                plan.append((patch, parts, None))
            else:
                plan.append((patch, parts, apply_hunks(current, patch.hunks, key)))
        for patch, parts, new_text in plan:
            if new_text is None:
                _unlink_at(root, parts)
            else:
                _write_text_at(root, parts, new_text, create=patch.is_new)
    except GuestError as exc:
        return {"ok": True, "applied": False, "reason": str(exc), "files": []}
    return {"ok": True, "applied": True, "reason": "", "files": ["/".join(p) for _, p, _ in plan]}


# ---------------------------------------------------------------------------
# Entry point (argv protocol)
# ---------------------------------------------------------------------------

OPS = {"read": op_read, "tree": op_tree, "grep": op_grep}


def main(argv: list[str], root: str = WORKSPACE, stdin: Any = None) -> int:
    if len(argv) < 1:
        sys.stdout.write(json.dumps({"ok": False, "error": "usage: <op> [json-args]"}))
        return 2
    op = argv[0]
    try:
        args: dict[str, Any] = json.loads(argv[1]) if len(argv) > 1 else {}
        if op == "apply":
            data = (stdin or sys.stdin.buffer).read()
            result = apply_patch(root, data.decode("utf-8", "surrogateescape"))
        elif op in OPS:
            result = OPS[op](root, args)
        else:
            result = {"ok": False, "error": f"unknown op {op!r}"}
    except GuestError as exc:
        result = {"ok": False, "error": str(exc)}
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
