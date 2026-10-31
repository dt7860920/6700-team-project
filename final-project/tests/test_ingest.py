"""Ingest stage: local fixture copy, snippet file, and a monkeypatched git clone (no network)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from ono import ingest
from ono.models import ScanOptions
from ono.targets import Target

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"


def _target(kind: str, source: str) -> Target:
    return Target(target_id="t", name="t", kind=kind, source=source, snapshot="n/a")  # type: ignore[arg-type]


def _ingest(target: Target, workspace: Path, **overrides: Any) -> Path:
    kwargs: dict[str, Any] = {"clone_timeout_s": 5.0, "max_clone_mb": 50, **overrides}
    return ingest.ingest_target(target, ScanOptions(), workspace=workspace, **kwargs)


def test_local_directory_source_is_copied_and_git_stripped(tmp_path: Path) -> None:
    src = tmp_path / "src"
    ingest.copy_snapshot(FIXTURE_REPO, src)
    (src / ".git").mkdir()
    (src / ".git" / "config").write_text("[remote]\n")

    root = _ingest(_target("repo", str(src)), tmp_path / "ws" / "scn_1")

    assert root == tmp_path / "ws" / "scn_1"
    assert (root / "app" / "views.py").read_text() == (
        FIXTURE_REPO / "app" / "views.py"
    ).read_text()
    assert not (root / ".git").exists()


def test_snippet_is_written_to_a_file(tmp_path: Path) -> None:
    ws = tmp_path / "scn_2"
    root = ingest.ingest_target(
        _target("snippet", "inline"),
        ScanOptions(snippet="x = eval(data)\n"),
        workspace=ws,
        clone_timeout_s=5.0,
        max_clone_mb=50,
    )
    assert root == ws
    assert (ws / ingest.SNIPPET_FILE).read_text() == "x = eval(data)\n"


def test_https_source_is_shallow_cloned_with_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append({"cmd": cmd, **kwargs})
        dest = Path(cmd[-1])  # pretend to be git: materialize a checkout with a .git dir
        (dest / ".git").mkdir(parents=True)
        (dest / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (dest / "main.py").write_text("print('hi')\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(ingest.subprocess, "run", fake_run)
    ws = tmp_path / "scn_3"

    root = _ingest(
        _target("practice-app", "https://github.com/example/app"), ws, clone_timeout_s=42.0
    )

    assert root == ws
    assert len(calls) == 1
    cmd = calls[0]["cmd"]
    assert cmd[0] == "git" and "clone" in cmd
    assert "--depth" in cmd and cmd[cmd.index("--depth") + 1] == "1"
    assert {"--no-tags", "--single-branch", "--no-recurse-submodules"} <= set(cmd)
    assert cmd[-2:] == ["https://github.com/example/app", str(ws)]
    assert calls[0]["timeout"] == 42.0
    assert calls[0]["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert (ws / "main.py").exists()
    assert not (ws / ".git").exists()  # origin is never contacted again


def test_clone_failure_raises_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 128, "", "fatal: repository not found\n")

    monkeypatch.setattr(ingest.subprocess, "run", fake_run)
    ws = tmp_path / "scn_4"
    with pytest.raises(ingest.IngestError, match="repository not found"):
        _ingest(_target("repo", "https://github.com/nope/nope"), ws)
    assert not ws.exists()


def test_clone_timeout_and_missing_git_are_clear_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timeout(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(ingest.subprocess, "run", timeout)
    with pytest.raises(ingest.IngestError, match="timed out"):
        _ingest(_target("repo", "https://github.com/slow/repo"), tmp_path / "a")

    def missing(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("git")

    monkeypatch.setattr(ingest.subprocess, "run", missing)
    with pytest.raises(ingest.IngestError, match="git is not installed"):
        _ingest(_target("repo", "https://github.com/slow/repo"), tmp_path / "b")


def test_unsupported_source_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ingest.IngestError, match="unsupported target source"):
        _ingest(_target("repo", "git@github.com:org/repo.git"), tmp_path / "scn_5")
    with pytest.raises(ingest.IngestError):
        _ingest(_target("repo", "/definitely/not/a/dir"), tmp_path / "scn_6")


def test_size_cap_aborts_the_scan(tmp_path: Path) -> None:
    big = tmp_path / "big"
    big.mkdir()
    (big / "blob.bin").write_bytes(b"\0" * 2_500_000)
    ws = tmp_path / "scn_7"
    with pytest.raises(ingest.IngestError, match="above max_clone_mb=2"):
        _ingest(_target("repo", str(big)), ws, max_clone_mb=2)
    assert not ws.exists()


def test_stale_workspace_is_replaced_and_cleanup_never_raises(tmp_path: Path) -> None:
    ws = tmp_path / "scn_8"
    ws.mkdir()
    (ws / "leftover.py").write_text("eval(x)\n")
    _ingest(_target("repo", str(FIXTURE_REPO)), ws)
    assert not (ws / "leftover.py").exists()
    ingest.cleanup_workspace(ws)
    assert not ws.exists()
    ingest.cleanup_workspace(ws)  # idempotent
