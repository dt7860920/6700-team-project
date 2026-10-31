"""The in-jail helper, exercised on the host against a temp directory (no Docker).

Covers path confinement (the part that must be airtight), the bounded read/tree/grep
operations, and the strict unified-diff applier.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

from ono.executor import _guest
from ono.executor._guest import GuestError, apply_patch, parse_unified_diff, split_rel


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.py").write_text("import os\n\ndef f(x):\n    os.system(x)\n")
    (tmp_path / "app" / "util.py").write_text("A = 1\nB = 2\nC = 3\n")
    (tmp_path / "README.md").write_text("hello\n")
    (tmp_path / "bin.dat").write_bytes(b"\x00\x01os.system\x00")
    with contextlib.suppress(OSError):
        (tmp_path / "evil").symlink_to("/etc/passwd")
        (tmp_path / "evil_dir").symlink_to("/etc")
    return tmp_path


def run_guest(root: Path, op: str, args: dict[str, Any] | None = None, stdin: bytes = b"") -> Any:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = _guest.main([op, json.dumps(args or {})], root=str(root), stdin=io.BytesIO(stdin))
    assert code == 0
    return json.loads(buf.getvalue())


# ---------------------------------------------------------------------------
# Path confinement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "/etc/passwd",
        "../../etc/passwd",
        "app/../../etc/passwd",
        "..",
        "app/..",
        "a\\b",
        "x\x00y",
        "/".join(["d"] * 65),
    ],
)
def test_split_rel_rejects_escapes(bad: str) -> None:
    with pytest.raises(GuestError):
        split_rel(bad)


def test_split_rel_normalizes() -> None:
    assert split_rel("./app//views.py") == ["app", "views.py"]
    assert split_rel(".") == []
    assert split_rel("") == []


def test_read_refuses_symlink_even_though_it_exists(ws: Path) -> None:
    if not (ws / "evil").is_symlink():
        pytest.skip("symlinks unsupported here")
    out = run_guest(ws, "read", {"path": "evil"})
    assert out["ok"] is False
    assert "symlink" in out["error"]


def test_read_refuses_symlinked_directory_component(ws: Path) -> None:
    if not (ws / "evil_dir").is_symlink():
        pytest.skip("symlinks unsupported here")
    out = run_guest(ws, "read", {"path": "evil_dir/passwd"})
    assert out["ok"] is False
    assert "symlink" in out["error"]


def test_read_rejects_escapes_at_op_level(ws: Path) -> None:
    for bad in ("../x", "/etc/passwd", "app/../../x"):
        out = run_guest(ws, "read", {"path": bad})
        assert out["ok"] is False, bad


def test_read_missing_and_directory(ws: Path) -> None:
    assert "no such file" in run_guest(ws, "read", {"path": "nope.py"})["error"]
    assert "not a regular file" in run_guest(ws, "read", {"path": "app"})["error"]
    assert "root" in run_guest(ws, "read", {"path": "."})["error"]


# ---------------------------------------------------------------------------
# read / tree / grep
# ---------------------------------------------------------------------------


def test_read_whole_file_and_cap(ws: Path) -> None:
    out = run_guest(ws, "read", {"path": "app/util.py"})
    assert out["ok"] and out["content"] == "A = 1\nB = 2\nC = 3\n"
    assert out["total_lines"] == 3 and out["truncated"] is False

    out = run_guest(ws, "read", {"path": "app/util.py", "cap_bytes": 7})
    assert out["truncated"] is True
    assert out["content"] == "A = 1\nB"
    assert out["total_lines"] is None


def test_read_lines(ws: Path) -> None:
    out = run_guest(ws, "read", {"path": "app/util.py", "start": 2, "end": 3})
    assert out["content"] == "B = 2\nC = 3\n"
    assert (out["start_line"], out["end_line"], out["total_lines"]) == (2, 3, 3)
    out = run_guest(ws, "read", {"path": "app/util.py", "start": 10, "end": 20})
    assert out["content"] == "" and out["end_line"] == 0
    assert run_guest(ws, "read", {"path": "app/util.py", "start": 3, "end": 2})["ok"] is False


def test_tree_lists_without_following_symlinks(ws: Path) -> None:
    out = run_guest(ws, "tree", {})
    paths = {e["path"]: e["kind"] for e in out["entries"]}
    assert paths["app"] == "dir" and paths["app/views.py"] == "file"
    if (ws / "evil_dir").is_symlink():
        assert paths["evil_dir"] == "symlink"
        assert not any(p.startswith("evil_dir/") for p in paths)
    assert out["truncated"] is False


def test_tree_caps_entries_and_depth(ws: Path) -> None:
    out = run_guest(ws, "tree", {"max_entries": 2})
    assert out["total"] == 2 and out["truncated"] is True
    deep = ws / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "x").write_text("")
    out = run_guest(ws, "tree", {"max_depth": 2})
    assert "a/b" in {e["path"] for e in out["entries"]}
    assert "a/b/c/x" not in {e["path"] for e in out["entries"]}
    assert out["truncated"] is True


def test_grep_skips_binary_and_symlinks_and_caps(ws: Path) -> None:
    out = run_guest(ws, "grep", {"pattern": r"os\.system"})
    files = {m["file"] for m in out["matches"]}
    assert files == {"app/views.py"}
    assert out["matches"][0]["line"] == 4
    out = run_guest(ws, "grep", {"pattern": "=", "max_matches": 2})
    assert len(out["matches"]) == 2 and out["truncated"] is True
    out = run_guest(ws, "grep", {"pattern": "HELLO", "ignore_case": True, "path": "README.md"})
    assert out["matches"][0]["file"] == "README.md"
    assert run_guest(ws, "grep", {"pattern": "("})["ok"] is False
    assert run_guest(ws, "grep", {"pattern": "x", "path": "../"})["ok"] is False


# ---------------------------------------------------------------------------
# Unified diff applier
# ---------------------------------------------------------------------------

PATCH_UTIL = """\
--- a/app/util.py
+++ b/app/util.py
@@ -1,3 +1,3 @@
 A = 1
-B = 2
+B = 20
 C = 3
"""


def test_apply_simple_patch(ws: Path) -> None:
    out = apply_patch(str(ws), PATCH_UTIL)
    assert out["applied"] is True and out["files"] == ["app/util.py"]
    assert (ws / "app" / "util.py").read_text() == "A = 1\nB = 20\nC = 3\n"


def test_apply_via_stdin_protocol(ws: Path) -> None:
    out = run_guest(ws, "apply", stdin=PATCH_UTIL.encode())
    assert out["applied"] is True


def test_apply_context_mismatch_is_rejected_not_partially_applied(ws: Path) -> None:
    multi = PATCH_UTIL + "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-nope\n+yes\n"
    out = apply_patch(str(ws), multi)
    assert out["applied"] is False
    assert "README.md" in out["reason"]
    assert (ws / "app" / "util.py").read_text() == "A = 1\nB = 2\nC = 3\n"  # untouched


def test_apply_offset_tolerant(ws: Path) -> None:
    (ws / "app" / "util.py").write_text("X = 0\nY = 0\nA = 1\nB = 2\nC = 3\n")
    out = apply_patch(str(ws), PATCH_UTIL)  # header says line 1, context is at line 3
    assert out["applied"] is True
    assert (ws / "app" / "util.py").read_text() == "X = 0\nY = 0\nA = 1\nB = 20\nC = 3\n"


def test_apply_new_and_deleted_files(ws: Path) -> None:
    diff = (
        "--- /dev/null\n+++ b/app/new.py\n@@ -0,0 +1,2 @@\n+print(1)\n+print(2)\n"
        "--- a/README.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-hello\n"
    )
    out = apply_patch(str(ws), diff)
    assert out["applied"] is True
    assert (ws / "app" / "new.py").read_text() == "print(1)\nprint(2)\n"
    assert not (ws / "README.md").exists()
    out = apply_patch(str(ws), "--- /dev/null\n+++ b/app/new.py\n@@ -0,0 +1 @@\n+x\n")
    assert out["applied"] is False and "already exists" in out["reason"]


def test_apply_creates_parent_dirs_but_never_escapes(ws: Path) -> None:
    out = apply_patch(str(ws), "--- /dev/null\n+++ b/deep/er/file.txt\n@@ -0,0 +1 @@\n+x\n")
    assert out["applied"] is True and (ws / "deep" / "er" / "file.txt").read_text() == "x\n"
    for bad in ("../escape.txt", "/tmp/escape.txt"):
        out = apply_patch(str(ws), f"--- /dev/null\n+++ b/{bad}\n@@ -0,0 +1 @@\n+x\n")
        assert out["applied"] is False, bad
    assert not (ws.parent / "escape.txt").exists()


def test_apply_refuses_to_write_through_symlink(ws: Path) -> None:
    if not (ws / "evil").is_symlink():
        pytest.skip("symlinks unsupported here")
    out = apply_patch(str(ws), "--- a/evil\n+++ b/evil\n@@ -1 +1 @@\n-root\n+pwned\n")
    assert out["applied"] is False


def test_apply_no_newline_at_eof(ws: Path) -> None:
    (ws / "n.txt").write_text("one\ntwo")
    diff = (
        "--- a/n.txt\n+++ b/n.txt\n@@ -1,2 +1,2 @@\n one\n-two\n"
        "\\ No newline at end of file\n+two!\n"
    )
    out = apply_patch(str(ws), diff)
    assert out["applied"] is True
    assert (ws / "n.txt").read_text() == "one\ntwo!\n"


def test_apply_git_style_headers_and_rejections(ws: Path) -> None:
    git_diff = (
        "diff --git a/app/util.py b/app/util.py\nindex 1111111..2222222 100644\n" + PATCH_UTIL
    )
    assert apply_patch(str(ws), git_diff)["applied"] is True
    for bad, reason in (
        ("diff --git a/x b/y\nrename from x\nrename to y\n", "rename"),
        ("Binary files a/x and b/x differ\n", "binary"),
        ("just prose\n", "no file patches"),
        ("--- a/app/util.py\n+++ b/app/util.py\n@@ -1,3 +1,3 @@\n A = 1\n", "line count"),
        ("--- a/app/util.py\n+++ b/app/util.py\n@@ -1,1 +1,1 @@\n-A = 1\n+A = 2\n" * 2, "twice"),
        ("--- a/missing.py\n+++ b/missing.py\n@@ -1 +1 @@\n-a\n+b\n", "does not exist"),
    ):
        out = apply_patch(str(ws), bad)
        assert out["applied"] is False and reason in out["reason"], (bad, out)


def test_parse_counts_blank_context_lines() -> None:
    patches = parse_unified_diff("--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n\n-x\n+y\n")
    assert [t for t, _ in patches[0].hunks[0].lines] == [" ", "-", "+"]


def test_unknown_op_and_usage() -> None:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert _guest.main(["bogus", "{}"]) == 0
    assert json.loads(buf.getvalue())["ok"] is False
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert _guest.main([]) == 2
