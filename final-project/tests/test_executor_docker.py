"""REAL-DOCKER stress tests for the sandbox jail (``pytest -m docker``).

Everything here spins up genuine containers with the production jail flags and
tries to break out / exhaust / linger. Skipped automatically without a daemon or
in CI (see ``conftest.docker_tests_enabled``). Limits are deliberately tiny so the
failure modes trigger fast: 256 MB RAM, 64 PIDs, 128 MB tmpfs, 200 KB output cap.
"""

from __future__ import annotations

import contextlib
import dataclasses
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import docker
import httpx
import pytest
from pydantic import SecretStr

from conftest import LiveServer, start_live_server
from ono.config import Settings
from ono.executor.app import create_executor_app
from ono.executor.client import ExecutorAuthError, ExecutorClient
from ono.executor.sandbox import (
    KEEPER_UID,
    LABEL_CREATED,
    LABEL_SANDBOX,
    SANDBOX_USER,
    JailConfig,
    Sandbox,
    SandboxError,
    SandboxManager,
    SandboxNotRunningError,
    SandboxOperationError,
    SandboxPathError,
)

pytestmark = pytest.mark.docker

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"
TOKEN = "docker-test-token-0123456789"
CONFIG = JailConfig(
    mem_mb=256,
    cpus=1.0,
    pids_limit=64,
    cmd_timeout_s=30.0,
    ttl_s=600.0,
    output_cap_bytes=200_000,
    workspace_mb=128,
    max_active=8,
)


def labelled_containers(client: Any) -> list[Any]:
    return list(client.containers.list(all=True, filters={"label": f"{LABEL_SANDBOX}=1"}))


@pytest.fixture(scope="module")
def raw_docker() -> Any:
    return docker.from_env()


@pytest.fixture(scope="module")
def manager(raw_docker: Any) -> Iterator[SandboxManager]:
    before = {c.id for c in labelled_containers(raw_docker)}
    m = SandboxManager(CONFIG)
    yield m
    m.close()
    leaked = [c for c in labelled_containers(raw_docker) if c.id not in before]
    for c in leaked:
        c.remove(force=True)
    assert not leaked, f"sandbox containers leaked: {[c.id[:12] for c in leaked]}"


@pytest.fixture
def sandbox(manager: SandboxManager) -> Iterator[Sandbox]:
    sbx = manager.create("scn_dockertest", FIXTURE_REPO)
    try:
        yield sbx
    finally:
        sbx.destroy()


def processes(sbx: Sandbox) -> str:
    """Command lines of every process in the jail (``ps`` is not in the slim image)."""
    out = sbx.run("for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null; echo; done")
    return out.stdout


# ---------------------------------------------------------------------------
# 1. The jail as the daemon and the inmate see it
# ---------------------------------------------------------------------------


def test_jail_flags_as_applied_by_the_daemon(sandbox: Sandbox, raw_docker: Any) -> None:
    attrs = raw_docker.api.inspect_container(sandbox.container_id)
    hc, cfg = attrs["HostConfig"], attrs["Config"]
    assert hc["NetworkMode"] == "none"
    assert hc["ReadonlyRootfs"] is True
    assert hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd")
    assert "no-new-privileges:true" in hc["SecurityOpt"]
    assert hc["Privileged"] is False
    assert hc["Memory"] == 256 * 1024 * 1024 and hc["MemorySwap"] == hc["Memory"]
    assert hc["NanoCpus"] == 1_000_000_000
    assert hc["PidsLimit"] == 64
    assert hc["Init"] is True
    assert not hc.get("Binds") and not hc.get("Devices")
    assert all(m["Type"] == "tmpfs" for m in attrs["Mounts"]) or attrs["Mounts"] == []
    assert "docker.sock" not in str(attrs["Mounts"]) and "docker.sock" not in str(hc.get("Binds"))
    assert cfg["User"] == f"{KEEPER_UID}:{KEEPER_UID}"
    assert attrs["NetworkSettings"]["Networks"].keys() == {"none"}
    assert cfg["Labels"][LABEL_SANDBOX] == "1" and cfg["Labels"]["ono.scan_id"] == "scn_dockertest"


def test_inmate_view_non_root_no_caps_no_socket_no_net(sandbox: Sandbox) -> None:
    r = sandbox.run(
        "id -u; id -g; grep -E 'Cap(Eff|Bnd|Prm)|NoNewPrivs' /proc/self/status; "
        "{ test -e /var/run/docker.sock || test -e /run/docker.sock; } "
        "&& echo SOCKET || echo nosocket; "
        "ls /sys/class/net | tr '\\n' ' '; echo; cat /proc/1/cmdline | tr '\\0' ' '"
    )
    lines = r.stdout.splitlines()
    assert lines[0] == SANDBOX_USER.split(":")[0] and lines[1] == SANDBOX_USER.split(":")[1]
    assert "CapEff:\t0000000000000000" in r.stdout
    assert "CapBnd:\t0000000000000000" in r.stdout
    assert "CapPrm:\t0000000000000000" in r.stdout
    assert "NoNewPrivs:\t1" in r.stdout
    assert "nosocket" in lines and "SOCKET" not in lines
    assert [line for line in lines if line.strip() == "lo"], "only the loopback interface"
    assert "eth0" not in r.stdout
    assert "docker-init" in lines[-1] and "sleep infinity" in lines[-1]


def test_rootfs_is_read_only_and_tmpfs_is_nosuid(sandbox: Sandbox) -> None:
    r = sandbox.run("touch /usr/x; echo x >> /etc/passwd; touch /root/x; echo rc=$?")
    assert "Read-only file system" in r.stderr
    r = sandbox.run("grep -E ' /(workspace|tmp) ' /proc/mounts")
    assert r.stdout.count("nosuid") == 2 and r.stdout.count("nodev") == 2
    r = sandbox.run("echo hi > /workspace/x && echo hi > /tmp/y && cat /workspace/x /tmp/y")
    assert r.stdout == "hi\nhi\n"


# ---------------------------------------------------------------------------
# 2. Egress is actually blocked
# ---------------------------------------------------------------------------


def test_egress_is_blocked(sandbox: Sandbox) -> None:
    py = "python3 -c "
    attempts = {
        "tcp": py
        + '"import socket; s=socket.socket(); s.settimeout(3); '
        + "s.connect(('1.1.1.1', 80))\"",
        "http": py + "\"import urllib.request as u; u.urlopen('http://example.com', timeout=3)\"",
        "https": py + "\"import urllib.request as u; u.urlopen('https://1.1.1.1', timeout=3)\"",
        "dns": py + "\"import socket; socket.getaddrinfo('example.com', 443)\"",
        "udp": py
        + '"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); '
        + "s.sendto(b'x', ('8.8.8.8', 53))\"",
        "gateway": py
        + "\"import socket; s=socket.socket(); s.settimeout(3); s.connect(('172.17.0.1', 2375))\"",
    }
    for name, cmd in attempts.items():
        r = sandbox.run(cmd, timeout_s=10)
        assert r.exit_code not in (0, None), (name, r)
        assert r.timed_out is False, name  # fails fast: there is no route at all
        assert r.duration_ms < 8000, name
        assert any(
            s in r.stderr
            for s in (
                "unreachable",
                "Temporary failure",
                "Name or service",
                "No address",
                "nodename",
                "URLError",
                "gaierror",
                "OSError",
            )
        ), (name, r.stderr)


# ---------------------------------------------------------------------------
# 3. Timeouts and process hygiene
# ---------------------------------------------------------------------------


def test_timeout_is_enforced_and_process_is_killed(sandbox: Sandbox) -> None:
    t0 = time.perf_counter()
    r = sandbox.run("sleep 999", timeout_s=2)
    wall = time.perf_counter() - t0
    assert r.timed_out is True and r.exit_code == 137
    assert 1.8 < wall < 6, wall
    assert "sleep 999" not in processes(sandbox)
    assert sandbox.status == "running"


def test_background_and_setsid_processes_do_not_survive_a_run(sandbox: Sandbox) -> None:
    sandbox.run("nohup sleep 300 >/dev/null 2>&1 & echo started")
    assert "sleep 300" not in processes(sandbox)
    r = sandbox.run("setsid sleep 400 >/dev/null 2>&1 & sleep 5", timeout_s=1)
    assert r.timed_out is True
    assert "sleep 400" not in processes(sandbox), "setsid escaped `timeout` but not the reap"


def test_inmate_cannot_kill_the_container(sandbox: Sandbox) -> None:
    sandbox.run("kill -9 -1; kill -9 1; echo alive")
    assert sandbox.status == "running"
    assert sandbox.run("echo still").stdout == "still\n"


# ---------------------------------------------------------------------------
# 4. Resource limits bite
# ---------------------------------------------------------------------------


def test_memory_hog_is_oom_killed_not_the_host(sandbox: Sandbox) -> None:
    r = sandbox.run(
        "python3 -c \"x = bytearray(400 * 1024 * 1024); print('allocated')\"", timeout_s=20
    )
    assert r.exit_code == 137 and r.oom_killed is True and r.timed_out is False
    assert "allocated" not in r.stdout
    assert sandbox.status == "running"
    assert sandbox.run("echo ok").stdout == "ok\n"  # the jail survived the OOM
    small = sandbox.run(
        "python3 -c \"x = bytearray(50 * 1024 * 1024); print('fine')\"", timeout_s=20
    )
    assert small.exit_code == 0 and small.oom_killed is False


def test_fork_bomb_is_contained(sandbox: Sandbox) -> None:
    t0 = time.perf_counter()
    try:
        r = sandbox.run("bomb() { bomb | bomb & }; bomb; sleep 20", timeout_s=4)
        assert r.timed_out is True or r.exit_code not in (0, None)
        assert "Cannot fork" in r.stderr or r.timed_out
    except SandboxNotRunningError:
        pass  # PID limit saturated so hard that even the reap could not start: torn down
    assert time.perf_counter() - t0 < 25
    if sandbox.status != "running":
        sandbox.reset()
    assert sandbox.run("echo recovered").stdout == "recovered\n"
    assert processes(sandbox).count("\n") < 12


def test_setsid_fork_bomb_cannot_escape_pids_limit(sandbox: Sandbox) -> None:
    with contextlib.suppress(SandboxNotRunningError):  # torn down if even the reap can't start
        sandbox.run("bomb() { setsid sh -c 'bomb' & bomb & }; bomb; sleep 20", timeout_s=4)
    if sandbox.status != "running":
        sandbox.reset()
    r = sandbox.run("echo recovered")
    assert r.stdout == "recovered\n"


def test_disk_fill_hits_the_tmpfs_cap(sandbox: Sandbox) -> None:
    r = sandbox.run(
        "dd if=/dev/zero of=/workspace/big bs=1M count=600 2>&1; echo rc=$?", timeout_s=25
    )
    assert "No space left" in r.stdout or r.oom_killed
    if sandbox.status != "running":
        sandbox.reset()
    r = sandbox.run("df -m /workspace | tail -1")
    assert r.exit_code == 0
    sandbox.reset()
    assert sandbox.run("ls /workspace/big 2>&1").exit_code != 0


def test_cpu_quota_is_applied(sandbox: Sandbox) -> None:
    r = sandbox.run(
        "cat /sys/fs/cgroup/cpu.max 2>/dev/null || cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us"
    )
    assert r.exit_code == 0 and r.stdout.split()[0] == "100000"


def test_output_is_capped_without_hanging(sandbox: Sandbox) -> None:
    t0 = time.perf_counter()
    r = sandbox.run("yes | head -c 20000000", timeout_s=20)
    assert r.truncated is True and len(r.stdout) <= CONFIG.output_cap_bytes
    assert r.exit_code == 0 and time.perf_counter() - t0 < 20


# ---------------------------------------------------------------------------
# 5. Path confinement against a hostile workspace
# ---------------------------------------------------------------------------


def test_path_confinement(sandbox: Sandbox) -> None:
    for bad in ("../../etc/passwd", "/etc/passwd", "app/../../../etc/passwd", "..", "a\\..\\b"):
        with pytest.raises(SandboxPathError):
            sandbox.read_file(bad)
        with pytest.raises(SandboxPathError):
            sandbox.grep("root", path=bad)
    # a symlink planted by the inmate is never followed - file or directory
    sandbox.run(
        "ln -s /etc/passwd /workspace/evil && ln -s /etc /workspace/evil_dir && "
        "mkdir -p /workspace/sub && ln -s .. /workspace/sub/up"
    )
    with pytest.raises(SandboxOperationError, match="symlink"):
        sandbox.read_file("evil")
    with pytest.raises(SandboxOperationError, match="symlink"):
        sandbox.read_file("evil_dir/passwd")
    with pytest.raises(SandboxOperationError, match="symlink"):
        sandbox.read_file("sub/up/sub/up/evil")
    kinds = {e.path: e.kind for e in sandbox.tree().entries}
    assert kinds["evil"] == "symlink" and kinds["evil_dir"] == "symlink"
    assert not any(p.startswith("evil_dir/") for p in kinds)
    assert all("root:" not in m.text for m in sandbox.grep("root:x").matches)
    patch = sandbox.apply_patch("--- a/evil\n+++ b/evil\n@@ -1 +1 @@\n-root:x\n+pwned\n")
    assert patch.applied is False
    assert "root:x:0:0" in sandbox.run("head -1 /etc/passwd").stdout  # the real file is untouched


# ---------------------------------------------------------------------------
# 6. Teardown always happens; the sweeper catches orphans
# ---------------------------------------------------------------------------


def test_teardown_happens_even_when_an_operation_raises(
    manager: SandboxManager, raw_docker: Any
) -> None:
    before = {c.id for c in labelled_containers(raw_docker)}
    sbx = manager.create("scn_teardown", FIXTURE_REPO)
    cid = sbx.container_id
    try:
        with pytest.raises(SandboxPathError):
            sbx.read_file("../../etc/passwd")
        raise RuntimeError("simulated verifier crash")
    except RuntimeError:
        pass
    finally:
        sbx.destroy()
    assert {c.id for c in labelled_containers(raw_docker)} == before
    with pytest.raises(docker.errors.NotFound):
        raw_docker.api.inspect_container(cid)
    sbx.destroy()  # idempotent


def test_failed_create_leaves_no_container(raw_docker: Any) -> None:
    before = {c.id for c in labelled_containers(raw_docker)}
    bad = SandboxManager(dataclasses.replace(CONFIG, image="ono-does-not-exist:never"))
    with pytest.raises(SandboxError):
        bad.create("scn_badimage", FIXTURE_REPO)
    assert bad.active() == []
    assert {c.id for c in labelled_containers(raw_docker)} == before


def test_sweeper_removes_old_labelled_containers(manager: SandboxManager, raw_docker: Any) -> None:
    orphan = raw_docker.containers.run(
        CONFIG.image,
        ["sleep", "infinity"],
        detach=True,
        network_mode="none",
        labels={
            LABEL_SANDBOX: "1",
            LABEL_CREATED: str(time.time() - 24 * 3600),
            "ono.scan_id": "scn_orphan",
        },
    )
    young = raw_docker.containers.run(
        CONFIG.image,
        ["sleep", "infinity"],
        detach=True,
        network_mode="none",
        labels={LABEL_SANDBOX: "1", LABEL_CREATED: str(time.time()), "ono.scan_id": "scn_young"},
    )
    try:
        removed = manager.sweep()
        assert orphan.id in removed and young.id not in removed
        with pytest.raises(docker.errors.NotFound):
            raw_docker.api.inspect_container(orphan.id)
        assert raw_docker.api.inspect_container(young.id)["State"]["Running"]
        tracked = manager.create("scn_ttl", FIXTURE_REPO)
        removed = manager.sweep(max_age_s=0)
        assert tracked.container_id is None and tracked.status == "destroyed"
        assert young.id in removed
    finally:
        for c in (orphan, young):
            with contextlib.suppress(docker.errors.NotFound):
                c.remove(force=True)


# ---------------------------------------------------------------------------
# 7. Concurrency and isolation between scans
# ---------------------------------------------------------------------------


def test_two_sandboxes_do_not_share_state(manager: SandboxManager) -> None:
    a = manager.create("scn_a", FIXTURE_REPO)
    b = manager.create("scn_b", FIXTURE_REPO)
    try:
        a.run("echo secret-a > /workspace/marker && echo a > /tmp/t")
        assert b.run("cat /workspace/marker /tmp/t 2>&1").exit_code != 0
        assert "secret-a" in a.read_file("marker").content
        with pytest.raises(SandboxOperationError):
            b.read_file("marker")
        assert a.container_id != b.container_id
        # the fixed hostname is not shared state either; neither can see the other's processes
        a.run("sleep 30 >/dev/null 2>&1 &")
        assert "sleep 30" not in processes(b)
    finally:
        a.destroy()
        b.destroy()


def test_parallel_create_run_destroy(manager: SandboxManager, raw_docker: Any) -> None:
    before = {c.id for c in labelled_containers(raw_docker)}
    errors: list[BaseException] = []
    results: dict[int, str] = {}

    def worker(i: int) -> None:
        try:
            sbx = manager.create(f"scn_par{i}", FIXTURE_REPO)
            try:
                sbx.run(f"echo {i} > /workspace/who")
                for _ in range(3):
                    assert sbx.read_file("who").content.strip() == str(i)
                    assert sbx.grep("os.system").matches
                sbx.reset()
                results[i] = sbx.run("cat /workspace/who 2>&1; echo rc=$?").stdout
            finally:
                sbx.destroy()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert not errors, errors
    assert len(results) == 6 and all("rc=1" in v for v in results.values())  # reset wiped `who`
    assert manager.active() == []
    assert {c.id for c in labelled_containers(raw_docker)} == before


# ---------------------------------------------------------------------------
# 8. apply_patch + reset round-trip (the fixer <-> verifier loop)
# ---------------------------------------------------------------------------


def test_apply_patch_then_reset_round_trip(sandbox: Sandbox) -> None:
    original = sandbox.read_file("app/views.py").content
    sink = sandbox.grep(r"os\.system\(", path="app/views.py").matches[0]
    ctx = sandbox.read_lines("app/views.py", sink.line - 1, sink.line - 1).content
    diff = (
        "--- a/app/views.py\n+++ b/app/views.py\n"
        f"@@ -{sink.line - 1},2 +{sink.line - 1},3 @@\n"
        f" {ctx}"
        f"-{sink.text}\n"
        "+    import subprocess\n"
        '+    return subprocess.call(["ping", "-c", "1", host])\n'
    )
    result = sandbox.apply_patch(diff)
    assert result.applied is True, result.reason
    patched = sandbox.read_file("app/views.py").content
    assert "subprocess.call" in patched and "os.system(" not in patched
    check = sandbox.run("python3 -c 'import ast; ast.parse(open(\"app/views.py\").read())'")
    assert check.exit_code == 0, check.stderr
    sandbox.run("echo junk > /workspace/junk && echo junk > /tmp/junk")
    before_reset = sandbox.container_id
    info = sandbox.reset()
    assert info.status == "running" and info.resets == 1 and info.container_id != before_reset
    assert sandbox.read_file("app/views.py").content == original
    assert sandbox.run("ls /workspace/junk /tmp/junk 2>&1").exit_code != 0
    # applying the same patch again on the clean tree works; applying twice does not
    assert sandbox.apply_patch(diff).applied is True
    assert sandbox.apply_patch(diff).applied is False


def test_run_tests_detects_and_runs_pytest_shaped_repo(
    manager: SandboxManager, tmp_path: Path
) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_ok():\n    assert True\n")
    sbx = manager.create("scn_tests", tmp_path)
    try:
        result = sbx.run_tests(timeout_s=20)
        assert result.runner == "pytest" and result.detected is True
        # python:3.13-slim has no pytest: detected, ran, failed with a clear summary
        assert result.passed is False and "pytest" in result.summary.lower()
        assert result.run is not None and result.run.exit_code not in (0, None)
    finally:
        sbx.destroy()


def test_large_workspace_round_trip(manager: SandboxManager, tmp_path: Path) -> None:
    for i in range(1500):
        d = tmp_path / f"d{i % 30}"
        d.mkdir(exist_ok=True)
        (d / f"f{i}.py").write_text(f"x = {i}\n")
    sbx = manager.create("scn_big", tmp_path)
    try:
        listing = sbx.tree(max_entries=5000)
        assert sum(1 for e in listing.entries if e.kind == "file") == 1500
        assert sbx.grep("x = 1499").matches[0].file.endswith("f1499.py")
    finally:
        sbx.destroy()


# ---------------------------------------------------------------------------
# 9. The whole stack: service + client + real jail, including auth
# ---------------------------------------------------------------------------


@pytest.fixture
def live_executor(raw_docker: Any) -> Iterator[LiveServer]:
    settings = Settings(
        _env_file=None,
        executor_token=SecretStr(TOKEN),
        sandbox_mem_mb=256,
        sandbox_pids_limit=64,
        sandbox_cmd_timeout_s=30,
        sandbox_workspace_mb=128,
    )
    app = create_executor_app(settings)
    server = start_live_server(app)
    try:
        yield server
    finally:
        server.stop()
        # lifespan shutdown must have destroyed every sandbox the service created
        leftovers = [
            c for c in labelled_containers(raw_docker) if c.labels.get("ono.scan_id") == "scn_e2e"
        ]
        for c in leftovers:
            c.remove(force=True)
        assert not leftovers


def test_service_auth_and_end_to_end(live_executor: LiveServer) -> None:
    with httpx.Client(base_url=live_executor.url, timeout=10) as raw:
        assert raw.get("/health").json()["docker"] is True
        assert raw.get("/sandboxes").status_code == 401
        assert (
            raw.get(
                "/sandboxes", headers={"Authorization": "Bearer nope-nope-nope-nope"}
            ).status_code
            == 401
        )
        assert (
            raw.get("/sandboxes", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
        )
    with pytest.raises(ExecutorAuthError):
        ExecutorClient(live_executor.url, "wrong-token-wrong-token").list_sandboxes()

    with ExecutorClient(live_executor.url, TOKEN, timeout_s=60) as client:
        with client.sandbox("scn_e2e", FIXTURE_REPO) as sbx:
            assert sbx.run("id -u").stdout.strip() == "10001"
            assert (
                sbx.run(
                    'python3 -c "import urllib.request as u; '
                    "u.urlopen('http://example.com', timeout=3)\"",
                    timeout_s=10,
                ).exit_code
                != 0
            )
            assert sbx.run("sleep 50", timeout_s=1).timed_out is True
            hits = sbx.grep(r"os\.system", path="app")
            assert hits.matches and hits.matches[0].file == "app/views.py"
            line = sbx.read_lines(
                "app/views.py", hits.matches[0].line, hits.matches[0].line
            ).content
            assert "os.system" in line
            assert sbx.apply_patch("--- a/nope\n+++ b/nope\n@@ -1 +1 @@\n-a\n+b\n").applied is False
            assert sbx.reset().resets == 1
            assert sbx.run_tests().runner == "none"
            sid = sbx.sandbox_id
        assert all(s.sandbox_id != sid for s in client.list_sandboxes())


def test_destroy_wins_over_an_in_flight_run(manager: SandboxManager, raw_docker: Any) -> None:
    """TTL sweeps / shutdown must not wait behind a long command: teardown interrupts it."""
    sbx = manager.create("scn_midrun", FIXTURE_REPO)
    cid = sbx.container_id
    outcome: dict[str, object] = {}

    def long_run() -> None:
        try:
            outcome["result"] = sbx.run("sleep 25", timeout_s=25)
        except SandboxError as exc:
            outcome["error"] = exc

    t = threading.Thread(target=long_run)
    t.start()
    time.sleep(1.5)
    t0 = time.perf_counter()
    sbx.destroy()
    assert time.perf_counter() - t0 < 10, "destroy must not wait for the command budget"
    t.join(timeout=20)
    assert not t.is_alive(), "the interrupted run() must return promptly"
    assert "error" in outcome or outcome["result"].timed_out  # type: ignore[union-attr]
    with pytest.raises(docker.errors.NotFound):
        raw_docker.api.inspect_container(cid)
    assert manager.active() == []
