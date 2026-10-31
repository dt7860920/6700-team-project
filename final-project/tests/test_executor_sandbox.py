"""SandboxManager / Sandbox unit tests against the fake Docker client (no daemon needed).

The real-container behaviour (egress, OOM, fork bombs, ...) lives in
``test_executor_docker.py``; here we pin the jail *flags*, the exec protocol, the
error mapping, teardown-on-failure, the sweeper, and the trusted-side validation.
"""

from __future__ import annotations

import io
import struct
import tarfile
import time
from pathlib import Path

import pytest
import requests

from fakedocker import FakeDocker, FakeRaw, api_error, frame
from ono.config import Settings
from ono.executor import archive
from ono.executor.archive import ArchiveError, pack_workspace, validate_archive
from ono.executor.sandbox import (
    KEEPER_UID,
    LABEL_CREATED,
    LABEL_SANDBOX,
    LABEL_SCAN,
    DockerUnavailableError,
    JailConfig,
    Sandbox,
    SandboxError,
    SandboxLimitError,
    SandboxManager,
    SandboxNotRunningError,
    SandboxOperationError,
    SandboxPathError,
    _container_created_epoch,
    _iter_frames,
    _recv_exact,
    jail_kwargs,
    validate_rel_path,
)

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"


@pytest.fixture
def fake(tmp_path: Path) -> FakeDocker:
    return FakeDocker(tmp_path / "jails")


@pytest.fixture
def manager(fake: FakeDocker) -> SandboxManager:
    return SandboxManager(JailConfig(cmd_timeout_s=10, output_cap_bytes=4096, max_active=2), fake)


@pytest.fixture
def sandbox(manager: SandboxManager) -> Sandbox:
    return manager.create("scn_unit", FIXTURE_REPO)


# ---------------------------------------------------------------------------
# The jail flags
# ---------------------------------------------------------------------------


def test_jail_kwargs_are_the_hardened_set() -> None:
    cfg = JailConfig(mem_mb=256, cpus=0.5, pids_limit=64, workspace_mb=128)
    kw = jail_kwargs(cfg, scan_id="scn_1", sandbox_id="sbx_1")
    assert kw["network_mode"] == "none"
    assert kw["read_only"] is True
    assert kw["cap_drop"] == ["ALL"]
    assert kw["security_opt"] == ["no-new-privileges:true"]
    assert kw["privileged"] is False
    assert kw["init"] is True
    assert kw["user"] == f"{KEEPER_UID}:{KEEPER_UID}" and KEEPER_UID != 0
    assert KEEPER_UID != archive.SANDBOX_UID, "PID 1 must not share the untrusted uid"
    assert kw["mem_limit"] == "256m" and kw["memswap_limit"] == "256m"  # no swap
    assert kw["nano_cpus"] == 500_000_000
    assert kw["pids_limit"] == 64
    assert kw["oom_score_adj"] == 1000
    ws = kw["tmpfs"]["/workspace"]
    assert "size=128m" in ws and f"uid={archive.SANDBOX_UID}" in ws and "nosuid" in ws
    assert "nosuid" in kw["tmpfs"]["/tmp"] and "nodev" in kw["tmpfs"]["/tmp"]
    assert kw["labels"][LABEL_SANDBOX] == "1" and kw["labels"][LABEL_SCAN] == "scn_1"
    assert float(kw["labels"][LABEL_CREATED]) == pytest.approx(time.time(), abs=5)
    # Nothing from the host is ever mounted - in particular no Docker socket.
    for forbidden in ("volumes", "mounts", "binds", "devices", "device_requests", "ports"):
        assert forbidden not in kw
    assert "docker.sock" not in repr(kw)


def test_jail_config_from_settings() -> None:
    s = Settings(
        _env_file=None,
        sandbox_image="debian:stable-slim",
        sandbox_mem_mb=512,
        sandbox_cpus=2,
        sandbox_pids_limit=100,
        sandbox_cmd_timeout_s=60,
        sandbox_ttl_s=120,
        sandbox_output_cap_bytes=2048,
        sandbox_workspace_mb=64,
        sandbox_max_active=3,
        max_clone_mb=10,
    )
    cfg = JailConfig.from_settings(s)
    assert cfg == JailConfig(
        image="debian:stable-slim",
        mem_mb=512,
        cpus=2.0,
        pids_limit=100,
        cmd_timeout_s=60.0,
        ttl_s=120.0,
        output_cap_bytes=2048,
        workspace_mb=64,
        max_active=3,
        max_archive_bytes=10_000_000,
    )


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_create_starts_jail_and_ships_workspace(
    manager: SandboxManager, fake: FakeDocker, sandbox: Sandbox
) -> None:
    assert sandbox.status == "running" and sandbox.container_id is not None
    kw = fake.run_calls[0]
    assert kw["network_mode"] == "none" and kw["labels"][LABEL_SCAN] == "scn_unit"
    # the workspace went in via `tar -x` over exec stdin, as the sandbox user
    tar_exec = fake.exec_log[0]
    assert (
        tar_exec.cmd[0] == "tar" and tar_exec.user == f"{archive.SANDBOX_UID}:{archive.SANDBOX_UID}"
    )
    assert (fake.workspace(sandbox.container_id) / "app" / "views.py").is_file()
    assert manager.active() == [sandbox]
    assert sandbox.info().scan_id == "scn_unit"
    assert sandbox.info().expires_at > sandbox.info().created_at


def test_operations_run_the_guest_inside_the_jail(sandbox: Sandbox) -> None:
    content = sandbox.read_file("app/views.py")
    assert "os.system" in content.content and content.total_lines is not None
    lines = sandbox.read_lines("app/views.py", 1, 2)
    assert lines.start_line == 1 and lines.end_line == 2
    tree = sandbox.tree()
    assert {"README.md", "app", "app/views.py", "app/util.py"} <= {e.path for e in tree.entries}
    hits = sandbox.grep(r"os\.system")
    assert "app/views.py" in {m.file for m in hits.matches}
    with pytest.raises(SandboxOperationError, match="no such file"):
        sandbox.read_file("missing.py")


def test_destroy_is_idempotent_and_never_raises(
    manager: SandboxManager, fake: FakeDocker, sandbox: Sandbox
) -> None:
    cid = sandbox.container_id
    sandbox.destroy()
    assert sandbox.status == "destroyed" and cid in fake.removed
    assert manager.active() == []
    fake.remove_error = RuntimeError("daemon exploded")
    sandbox.destroy()  # second time: already gone, and the daemon error is swallowed
    with pytest.raises(SandboxNotRunningError):
        sandbox.read_file("README.md")


def test_create_failure_tears_down_the_container(manager: SandboxManager, fake: FakeDocker) -> None:
    fake.tar_fails = True
    with pytest.raises(SandboxError, match="extraction failed"):
        manager.create("scn_bad", FIXTURE_REPO)
    assert manager.active() == []
    assert len(fake.removed) == 1 and not fake.live  # the half-made jail was removed


def test_create_pulls_missing_image_and_reports_pull_failure(
    manager: SandboxManager, fake: FakeDocker
) -> None:
    fake.missing_images.add("python:3.13-slim")
    manager.create("scn_pull", FIXTURE_REPO)
    assert fake.pulled == ["python:3.13-slim"]
    fake.pull_error = api_error(404, "manifest unknown")
    fresh = SandboxManager(JailConfig(image="nope:latest"), fake)
    fake.missing_images.add("nope:latest")
    with pytest.raises(SandboxError, match="could not pull"):
        fresh.create("scn_pull2", FIXTURE_REPO)
    assert not fake.run_calls[-1:] or fake.run_calls[-1]["image"] != "nope:latest"


def test_max_active_limit(manager: SandboxManager) -> None:
    manager.create("scn_a", FIXTURE_REPO)
    manager.create("scn_b", FIXTURE_REPO)
    with pytest.raises(SandboxLimitError):
        manager.create("scn_c", FIXTURE_REPO)
    manager.destroy_all()
    assert manager.active() == []
    manager.create("scn_d", FIXTURE_REPO)  # room again


def test_create_validates_inputs(manager: SandboxManager, tmp_path: Path) -> None:
    with pytest.raises(SandboxPathError, match="scan_id"):
        manager.create_from_archive("Bad Id", b"")
    with pytest.raises(SandboxPathError, match="not a valid gzipped tar"):
        manager.create_from_archive("scn_x", b"garbage")
    with pytest.raises(SandboxPathError, match="not a directory"):
        manager.create("scn_x", tmp_path / "missing")


def test_docker_unreachable_maps_to_unavailable(manager: SandboxManager, fake: FakeDocker) -> None:
    fake.run_error = requests.exceptions.ConnectionError("socket gone")
    with pytest.raises(DockerUnavailableError):
        manager.create("scn_x", FIXTURE_REPO)
    assert manager.active() == []
    fake.ping_ok = False
    assert manager.ping() is False


# ---------------------------------------------------------------------------
# run(): protocol, timeout, cap, reap, OOM, death
# ---------------------------------------------------------------------------


def test_run_wraps_in_timeout_and_reaps_afterwards(sandbox: Sandbox, fake: FakeDocker) -> None:
    fake.run_handler = lambda cmd: (3, b"out\n", b"err\n")
    before = len(fake.exec_log)
    result = sandbox.run("echo hi; exit 3", timeout_s=4)
    assert (result.exit_code, result.stdout, result.stderr) == (3, "out\n", "err\n")
    assert result.timed_out is False and result.oom_killed is False and result.truncated is False
    wrapped = fake.exec_log[before].cmd
    assert wrapped[:3] == ["timeout", "-s", "KILL"] and wrapped[3] == "4.000"
    assert wrapped[4:] == ["sh", "-c", "echo hi; exit 3"]
    assert fake.reaps_after(before) == 1, "every run() must be followed by kill -9 -1"


def test_run_timeout_is_capped_by_settings(sandbox: Sandbox, fake: FakeDocker) -> None:
    before = len(fake.exec_log)
    sandbox.run("true", timeout_s=999)
    assert fake.exec_log[before].cmd[3] == "10.000"  # JailConfig.cmd_timeout_s
    sandbox.run("true")
    assert fake.exec_log[-2].cmd[3] == "10.000" or fake.exec_log[-3].cmd[3] == "10.000"


def test_run_timed_out_when_stream_deadline_hits(sandbox: Sandbox, fake: FakeDocker) -> None:
    fake.hang_next_exec = True
    result = sandbox.run("sleep 999", timeout_s=1)
    assert result.timed_out is True and result.exit_code is None
    assert sandbox.status == "running"  # the reap ran and succeeded


def test_run_timed_out_when_killed_at_the_deadline(sandbox: Sandbox, fake: FakeDocker) -> None:
    def slow(_cmd: str) -> tuple[int, bytes, bytes]:
        time.sleep(0.5)
        return 137, b"", b""

    fake.run_handler = slow
    result = sandbox.run("sleep 999", timeout_s=0.5)
    assert result.timed_out is True and result.exit_code == 137 and result.oom_killed is False


def test_run_detects_oom_kill(sandbox: Sandbox, fake: FakeDocker) -> None:
    def hog(_cmd: str) -> tuple[int, bytes, bytes]:
        fake.oom_kills += 1
        return 137, b"", b"Killed\n"

    fake.run_handler = hog
    result = sandbox.run("python3 -c 'bytearray(10**10)'", timeout_s=5)
    assert result.oom_killed is True and result.timed_out is False and result.exit_code == 137
    fake.run_handler = lambda cmd: (137, b"", b"")  # a plain 137 later is not an OOM
    assert sandbox.run("kill -9 $$", timeout_s=5).oom_killed is False


def test_run_output_is_capped(sandbox: Sandbox, fake: FakeDocker) -> None:
    fake.run_handler = lambda cmd: (0, b"x" * 100_000, b"y" * 10_000)
    result = sandbox.run("yes", timeout_s=5)
    assert result.truncated is True
    assert len(result.stdout) == 4096 and len(result.stderr) == 4096


def test_run_rejects_bad_input(sandbox: Sandbox) -> None:
    with pytest.raises(SandboxPathError):
        sandbox.run("   ")
    with pytest.raises(SandboxPathError):
        sandbox.run("echo\x00hi")


def test_dead_container_is_reported_and_reset_revives_it(
    sandbox: Sandbox, fake: FakeDocker, manager: SandboxManager
) -> None:
    old = sandbox.container_id
    assert old is not None
    fake.live.pop(old)  # the daemon says: gone (OOM group kill, docker rm, crash ...)
    with pytest.raises(SandboxNotRunningError):
        sandbox.run("true")
    assert sandbox.status == "dead" and sandbox.info().container_id is None
    with pytest.raises(SandboxNotRunningError):
        sandbox.read_file("README.md")
    info = sandbox.reset()
    assert info.status == "running" and info.resets == 1 and info.container_id != old
    assert sandbox.read_file("README.md").content.startswith("#") or sandbox.read_file("README.md")
    assert manager.active() == [sandbox]


def test_failed_reap_marks_sandbox_dead(sandbox: Sandbox, fake: FakeDocker) -> None:
    fake.reap_fails = True
    with pytest.raises(SandboxNotRunningError, match="reset"):
        sandbox.run("true")
    assert sandbox.status == "dead"
    assert sandbox.container_id is None and fake.removed  # torn down immediately


def test_exec_create_api_error_without_death_is_a_sandbox_error(
    sandbox: Sandbox, fake: FakeDocker
) -> None:
    fake.exec_create_error = api_error(
        500, "OCI runtime exec failed: resource temporarily unavailable"
    )
    with pytest.raises(SandboxError, match="exec failed"):
        sandbox.read_file("README.md")
    assert sandbox.status == "running"


def test_reset_after_destroy_is_refused(sandbox: Sandbox) -> None:
    sandbox.destroy()
    with pytest.raises(SandboxNotRunningError):
        sandbox.reset()


# ---------------------------------------------------------------------------
# apply_patch / run_tests
# ---------------------------------------------------------------------------


def test_apply_patch_and_reset_round_trip(sandbox: Sandbox, fake: FakeDocker) -> None:
    before = sandbox.read_lines("app/util.py", 1, 1).content
    diff = f"--- a/app/util.py\n+++ b/app/util.py\n@@ -1 +1,2 @@\n+# patched\n {before}"
    result = sandbox.apply_patch(diff)
    assert result.applied is True and result.files == ["app/util.py"]
    assert sandbox.read_lines("app/util.py", 1, 1).content == "# patched\n"
    bad = sandbox.apply_patch("--- a/nope\n+++ b/nope\n@@ -1 +1 @@\n-a\n+b\n")
    assert bad.applied is False and "does not exist" in bad.reason
    sandbox.reset()
    assert sandbox.read_lines("app/util.py", 1, 1).content == before
    with pytest.raises(SandboxPathError):
        sandbox.apply_patch(" \n")


def test_run_tests_detection(sandbox: Sandbox, fake: FakeDocker, manager: SandboxManager) -> None:
    fake.run_handler = lambda cmd: (1, b"", b"No module named pytest\n")
    assert sandbox.run_tests().runner == "none"  # the fixture repo has no tests
    ws = fake.workspace(sandbox.container_id or "")
    (ws / "tests").mkdir()
    result = sandbox.run_tests(timeout_s=5)
    assert result.runner == "pytest" and result.detected and result.passed is False
    assert "pytest" in result.summary and result.command.startswith("python3 -m pytest")
    fake.run_handler = lambda cmd: (0, b"3 passed in 0.01s\n", b"")
    assert sandbox.run_tests().passed is True
    fake.run_handler = lambda cmd: (5, b"no tests ran\n", b"")
    assert sandbox.run_tests().passed is None
    (ws / "tests").rmdir()
    (ws / "package.json").write_text("{}")
    fake.run_handler = lambda cmd: (127, b"", b"npm is not available in the sandbox image\n")
    result = sandbox.run_tests()
    assert result.runner == "npm" and result.passed is False and "npm" in result.summary


# ---------------------------------------------------------------------------
# Trusted-side validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad", ["/etc/passwd", "../x", "a/../../x", "a\\b", "a\x00b", "a\nb", "x" * 1025]
)
def test_validate_rel_path_rejects(bad: str) -> None:
    with pytest.raises(SandboxPathError):
        validate_rel_path(bad)


def test_validate_rel_path_normalizes() -> None:
    assert validate_rel_path("./a//b.py") == "a/b.py"
    assert validate_rel_path(".", allow_root=True) == "."
    with pytest.raises(SandboxPathError):
        validate_rel_path(".")


def test_grep_rejects_bad_patterns(sandbox: Sandbox) -> None:
    with pytest.raises(SandboxPathError, match="regular expression"):
        sandbox.grep("(")
    with pytest.raises(SandboxPathError):
        sandbox.grep("")
    with pytest.raises(SandboxPathError):
        sandbox.grep("x", path="../")


def test_read_lines_validates_range(sandbox: Sandbox) -> None:
    with pytest.raises(SandboxPathError):
        sandbox.read_lines("README.md", 3, 2)


# ---------------------------------------------------------------------------
# Sweeper
# ---------------------------------------------------------------------------


def test_sweep_removes_expired_tracked_and_orphaned_containers(
    manager: SandboxManager, fake: FakeDocker, sandbox: Sandbox
) -> None:
    old = fake.add_orphan(
        "o" * 64, {LABEL_SANDBOX: "1", LABEL_CREATED: str(time.time() - 7200)}, ""
    )
    young = fake.add_orphan("y" * 64, {LABEL_SANDBOX: "1", LABEL_CREATED: str(time.time())}, "")
    unlabeled_time = fake.add_orphan(
        "u" * 64, {LABEL_SANDBOX: "1"}, "2020-01-01T00:00:00.123456789Z"
    )
    assert manager.sweep() == [old.id, unlabeled_time.id]  # ttl 1800s: tracked one is young
    assert sandbox.status == "running"
    assert young.remove_calls == []
    assert fake.list_calls[-1]["filters"] == {"label": f"{LABEL_SANDBOX}=1"}

    removed = manager.sweep(max_age_s=0)
    assert sandbox.container_id is None and sandbox.status == "destroyed"
    assert manager.active() == [] and young.id in removed


def test_sweep_survives_daemon_errors(manager: SandboxManager, fake: FakeDocker) -> None:
    fake.ping_ok = False
    fake.containers.list = lambda **_: (_ for _ in ()).throw(  # type: ignore[method-assign]
        requests.exceptions.ConnectionError("down")
    )
    assert manager.sweep() == []


def test_sweeper_thread_runs_and_close_destroys_everything(
    manager: SandboxManager, fake: FakeDocker, sandbox: Sandbox
) -> None:
    manager.start_sweeper(interval_s=0.05)
    time.sleep(0.2)
    assert fake.list_calls, "the sweeper thread should have listed containers"
    manager.close()
    assert sandbox.status == "destroyed" and manager.active() == []
    assert manager._sweeper is None


def test_container_created_epoch_parsing(fake: FakeDocker) -> None:
    c = fake.add_orphan("a" * 64, {}, "2026-10-31T13:51:00.123456789Z")
    assert _container_created_epoch(c) == pytest.approx(1793454660.123456, abs=1)
    c = fake.add_orphan("b" * 64, {LABEL_CREATED: "not-a-number"}, "garbage")
    assert _container_created_epoch(c) is None


# ---------------------------------------------------------------------------
# Exec stream protocol
# ---------------------------------------------------------------------------


class _Raw:
    def __init__(self, data: bytes, chunk: int = 3) -> None:
        self.data, self.pos, self.chunk = data, 0, chunk

    def settimeout(self, _t: float) -> None:
        pass

    def recv(self, n: int) -> bytes:
        out = self.data[self.pos : self.pos + min(n, self.chunk)]
        self.pos += len(out)
        return out


def test_iter_frames_reassembles_split_reads() -> None:
    raw = _Raw(frame(1, b"hello ") + frame(2, b"oops") + frame(1, b"world"))
    frames = _iter_frames(raw, time.monotonic() + 5)
    assert frames == [(1, b"hello "), (2, b"oops"), (1, b"world")]


def test_iter_frames_stops_on_truncated_frame() -> None:
    raw = _Raw(frame(1, b"ok") + struct.pack(">BxxxL", 1, 10) + b"short")
    assert _iter_frames(raw, time.monotonic() + 5) == [(1, b"ok")]


def test_recv_exact_enforces_deadline() -> None:
    with pytest.raises(TimeoutError):
        _recv_exact(_Raw(b"abc"), 3, time.monotonic() - 1)


def test_fake_raw_sends_stdin_before_reading(fake: FakeDocker, sandbox: Sandbox) -> None:
    # sanity check of the fake's own protocol: stdin captured, shutdown(SHUT_WR) called
    tar_exec = fake.exec_log[0]
    assert tar_exec.stdin[:2] == b"\x1f\x8b"  # gzip magic
    assert isinstance(FakeRaw(tar_exec, fake), FakeRaw)


# ---------------------------------------------------------------------------
# Archives
# ---------------------------------------------------------------------------


def test_pack_workspace_skips_git_and_symlinks_and_sets_uid(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("print(1)\n")
    (tmp_path / "run.sh").write_text("#!/bin/sh\n")
    (tmp_path / "run.sh").chmod(0o755)
    (tmp_path / "link").symlink_to("/etc/passwd")
    data = pack_workspace(tmp_path, max_bytes=10_000)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = {m.name: m for m in tar.getmembers()}
    assert set(members) == {"src", "src/a.py", "run.sh"}
    assert members["src/a.py"].uid == archive.SANDBOX_UID
    assert members["run.sh"].mode == 0o755 and members["src/a.py"].mode == 0o644
    with pytest.raises(ArchiveError, match="exceeds"):
        pack_workspace(tmp_path, max_bytes=3)


def test_validate_archive_rejects_unsafe_members(tmp_path: Path) -> None:
    def tar_with(name: str, typ: bytes = tarfile.REGTYPE) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name)
            info.type = typ
            info.size = 0
            tar.addfile(info)
        return buf.getvalue()

    assert validate_archive(tar_with("ok.txt"), max_bytes=100) == 0
    for name in ("/abs", "../escape", "a/../../b", "back\\slash"):
        with pytest.raises(ArchiveError, match="unsafe"):
            validate_archive(tar_with(name), max_bytes=100)
    with pytest.raises(ArchiveError, match="not a regular file"):
        validate_archive(tar_with("link", tarfile.SYMTYPE), max_bytes=100)
    with pytest.raises(ArchiveError, match="not a valid"):
        validate_archive(b"\x1f\x8bnot-gzip", max_bytes=100)
    with pytest.raises(ArchiveError, match="more than"):
        validate_archive(tar_with("a"), max_bytes=100, max_members=0)
    big = pack_workspace(FIXTURE_REPO, max_bytes=10**9)
    with pytest.raises(ArchiveError, match="expands"):
        validate_archive(big, max_bytes=10)
