"""Stage 1 - ingest: materialize an authorized target into a per-scan workspace.

The workspace is ``<workspace_dir>/<scan_id>/`` and is removed when the scan ends.

* ``repo`` / ``practice-app`` targets are **shallow-cloned** (``--depth 1``,
  single branch, no tags, no submodules) under a timeout and a size cap. The
  ``.git`` directory is deleted right after the clone: the plan's isolation
  principle is that the origin is contacted exactly once and never again.
  Nothing cloned is ever executed - the workspace is read by SAST and the model.
* ``snippet`` targets are written to ``snippet.py`` so SAST runs over them uniformly.
* A ``source`` that is an existing local directory (a pre-ingested snapshot, or a
  test fixture) is copied instead of cloned - no network involved.

Deliberately NOT here yet (later steps): the egress-blocked sandbox container
around the clone, CVE-string stripping, tree-sitter parsing / call graph.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

from ono.models import ScanOptions
from ono.targets import Target

log = logging.getLogger(__name__)

SNIPPET_FILE = "snippet.py"
_ALLOWED_SCHEMES = ("https://", "http://")


class IngestError(RuntimeError):
    """The target could not be materialized (clone failed, too large, bad source)."""


def workspace_path(workspace_dir: Path, scan_id: str) -> Path:
    """``<workspace_dir>/<scan_id>`` - the scan id is server-generated, never user input."""
    return workspace_dir / scan_id


def ingest_target(
    target: Target,
    options: ScanOptions,
    *,
    workspace: Path,
    clone_timeout_s: float,
    max_clone_mb: int,
) -> Path:
    """Materialize ``target`` into ``workspace`` and return the local snapshot root."""
    if workspace.exists():  # a stale dir from a crashed run must not leak into this scan
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=False)
    try:
        if target.kind == "snippet":
            return write_snippet(options.snippet or "", workspace)
        return fetch_source(
            target.source, workspace, clone_timeout_s=clone_timeout_s, max_clone_mb=max_clone_mb
        )
    except Exception:
        cleanup_workspace(workspace)
        raise


def write_snippet(code: str, workspace: Path) -> Path:
    path = workspace / SNIPPET_FILE
    path.write_text(code, encoding="utf-8")
    log.info("ingest: wrote inline snippet (%d chars) to %s", len(code), path)
    return workspace


def fetch_source(source: str, dest: Path, *, clone_timeout_s: float, max_clone_mb: int) -> Path:
    """Local directory -> copy; https URL -> shallow clone. Anything else is rejected."""
    local = Path(source).expanduser()
    if local.is_dir():
        copy_snapshot(local, dest)
    elif source.startswith(_ALLOWED_SCHEMES):
        clone_repo(source, dest, timeout_s=clone_timeout_s)
    else:
        msg = f"unsupported target source {source!r} (expected an https URL or a local directory)"
        raise IngestError(msg)

    strip_git(dest)
    size_mb = dir_size_bytes(dest) / 1_000_000
    if size_mb > max_clone_mb:
        msg = f"snapshot is {size_mb:.0f} MB, above max_clone_mb={max_clone_mb}; aborting"
        raise IngestError(msg)
    log.info("ingest: snapshot ready at %s (%.1f MB)", dest, size_mb)
    return dest


def copy_snapshot(src: Path, dest: Path) -> None:
    """Copy a local snapshot into the workspace (``.git`` is never copied)."""
    shutil.copytree(
        src, dest, dirs_exist_ok=True, symlinks=False, ignore=shutil.ignore_patterns(".git")
    )
    log.info("ingest: copied local snapshot %s", src)


def clone_repo(source: str, dest: Path, *, timeout_s: float) -> None:
    """``git clone --depth 1 --no-tags --single-branch`` with a hard timeout."""
    cmd = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",  # never run hooks from a template or the clone
        "clone",
        "--quiet",
        "--depth",
        "1",
        "--no-tags",
        "--single-branch",
        "--no-recurse-submodules",
        source,
        str(dest),
    ]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false"}
    log.info("ingest: cloning %s (depth 1, timeout %.0fs)", source, timeout_s)
    try:
        proc = subprocess.run(  # fixed argv, no shell; source comes from the allowlist
            cmd, capture_output=True, text=True, timeout=timeout_s, env=env, check=False
        )
    except FileNotFoundError as exc:
        raise IngestError("git is not installed on this host") from exc
    except subprocess.TimeoutExpired as exc:
        raise IngestError(f"git clone of {source} timed out after {timeout_s:.0f}s") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else f"exit {proc.returncode}"
        raise IngestError(f"git clone of {source} failed: {tail}")


def strip_git(root: Path) -> None:
    """Remove ``.git`` so no later stage can contact the origin (or read its history)."""
    git_dir = root / ".git"
    if git_dir.is_dir():
        shutil.rmtree(git_dir)
    elif git_dir.is_file():  # worktree pointer file
        git_dir.unlink()


def dir_size_bytes(root: Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            try:
                total += os.lstat(Path(dirpath) / name).st_size
            except OSError:
                continue
    return total


def cleanup_workspace(workspace: Path) -> None:
    """Remove the per-scan workspace. Never raises - cleanup must not mask the scan result."""
    shutil.rmtree(workspace, ignore_errors=True)
    log.debug("ingest: removed workspace %s", workspace)
