"""Sandbox manager: one ephemeral, jailed Docker container per scan.

Threat model: everything inside the container is hostile (it is the target's code,
and later the agents' PoCs and patches run there too). The container is therefore
built so that the worst it can do is burn its own CPU/memory budget until it is
destroyed:

======================  =====================================================================
``network_mode=none``   no egress at all - only ``lo``; cannot reach the internet, the
                        Executor, the ONO app, the model server, or other sandboxes
``user`` (non-root)     PID 1 (``docker-init`` + ``sleep``) runs as uid 10002; every exec
                        runs as uid 10001. The split means ``kill -9 -1`` issued *as the
                        sandbox user* reaps all stray processes without touching PID 1.
``cap_drop=ALL``        no capabilities at all (no mknod/ptrace/net/raw/chown ...)
``no-new-privileges``   setuid binaries cannot raise privileges (mounts are ``nosuid`` too)
``read_only=True``      the image is immutable; only two bounded ``tmpfs`` mounts are writable
                        (``/workspace`` owned by the sandbox uid, ``/tmp`` sticky)
``mem_limit`` (=swap)   memory cgroup, swap disabled; tmpfs pages are charged to it as well
``nano_cpus``           CPU quota
``pids_limit``          fork bombs hit the cgroup wall, not the host
``init=True``           zombies are reaped (otherwise a fork bomb's corpses pin the PID limit)
``oom_score_adj=1000``  if the *host* is short on memory, sandbox processes die first
no Docker socket        the socket is only ever mounted into the Executor, never into a target
labels ``ono.*``        the TTL sweeper finds and removes orphans after a crash
======================  =====================================================================

Files travel in by streaming a tar over ``docker exec`` stdin into ``tar -x`` running
*as the sandbox user* (the archive API cannot write into a tmpfs under a read-only
rootfs). Every operation is a ``docker exec`` with a hard deadline, a byte cap on
output, and - for ``run()`` - a ``kill -9 -1`` sweep afterwards so nothing survives
between operations. ``reset()`` destroys the container and recreates it from the
snapshot kept on the (trusted) Executor side: ~100 ms plus extraction, and it also
recovers a sandbox whose container died.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from importlib import resources
from pathlib import Path
from typing import Any, Self

import docker
import docker.errors
import docker.types
import requests

from ono.config import Settings
from ono.executor._guest import GuestError, split_rel
from ono.executor.archive import SANDBOX_UID, ArchiveError, pack_workspace, validate_archive
from ono.executor.models import (
    SANDBOX_WORKSPACE,
    SCAN_ID_PATTERN,
    FileContent,
    GrepResult,
    PatchResult,
    RunResult,
    SandboxInfo,
    SandboxStatus,
    TestRunner,
    TestRunResult,
    TreeListing,
)

__all__ = [
    "DockerUnavailableError",
    "JailConfig",
    "Sandbox",
    "SandboxError",
    "SandboxLimitError",
    "SandboxManager",
    "SandboxNotRunningError",
    "SandboxOperationError",
    "SandboxPathError",
    "jail_kwargs",
]

log = logging.getLogger(__name__)

KEEPER_UID = 10002
"""Uid of the container's PID 1 / keepalive. Distinct from the sandbox uid on purpose."""
SANDBOX_USER = f"{SANDBOX_UID}:{SANDBOX_UID}"
KEEPER_USER = f"{KEEPER_UID}:{KEEPER_UID}"

LABEL_SANDBOX = "ono.sandbox"
LABEL_SCAN = "ono.scan_id"
LABEL_SANDBOX_ID = "ono.sandbox_id"
LABEL_CREATED = "ono.created_at"  # unix epoch seconds, as a string

_SCAN_ID_RE = re.compile(SCAN_ID_PATTERN)
_EXEC_GRACE_S = 5.0  # host-side slack after the in-jail `timeout` deadline
_EXIT_CODE_WAIT_S = 3.0
_GUEST_TIMEOUT_S = 60.0
_REAP_TIMEOUT_S = 10.0
_EXTRACT_TIMEOUT_S = 180.0
_GUEST_OVERHEAD_BYTES = 256 * 1024
_STDERR_TAIL = 600
_OOM_RE = re.compile(r"oom_kill\s+(\d+)")

# The in-jail helper is shipped by value on every call (see _guest.py's docstring).
GUEST_SOURCE = resources.files("ono.executor").joinpath("_guest.py").read_text(encoding="utf-8")

_CONTAINER_ENV = {
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
    "NO_COLOR": "1",
    "CI": "true",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "PIP_NO_INDEX": "1",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
}

_PYTEST_MARKERS = frozenset({"pytest.ini", "conftest.py", "tests", "test"})
_PYTEST_FILE = re.compile(r"^(test_.*|.*_test)\.py$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SandboxError(RuntimeError):
    """Base class: the sandbox could not perform the operation."""


class DockerUnavailableError(SandboxError):
    """The Docker daemon cannot be reached (socket missing, daemon down, timeout)."""


class SandboxLimitError(SandboxError):
    """Too many live sandboxes on this Executor."""


class SandboxNotRunningError(SandboxError):
    """The container is dead (OOM, fork bomb, ...) or already destroyed; ``reset()`` recreates."""


class SandboxPathError(ValueError):
    """A client-supplied path/pattern/diff was rejected before reaching the jail."""


class SandboxOperationError(SandboxError):
    """The jail performed the operation and reported a user-facing failure (e.g. no such file)."""


# ---------------------------------------------------------------------------
# Jail configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class JailConfig:
    """Everything the jail needs from settings, as plain values (easy to assert on in tests)."""

    image: str = "python:3.13-slim"
    mem_mb: int = 1024
    cpus: float = 1.0
    pids_limit: int = 256
    cmd_timeout_s: float = 300.0
    ttl_s: float = 1800.0
    output_cap_bytes: int = 1_000_000
    workspace_mb: int = 512
    max_active: int = 8
    max_archive_bytes: int = 200_000_000

    @classmethod
    def from_settings(cls, settings: Settings) -> Self:
        return cls(
            image=settings.sandbox_image,
            mem_mb=settings.sandbox_mem_mb,
            cpus=settings.sandbox_cpus,
            pids_limit=settings.sandbox_pids_limit,
            cmd_timeout_s=settings.sandbox_cmd_timeout_s,
            ttl_s=settings.sandbox_ttl_s,
            output_cap_bytes=settings.sandbox_output_cap_bytes,
            workspace_mb=settings.sandbox_workspace_mb,
            max_active=settings.sandbox_max_active,
            max_archive_bytes=settings.max_clone_mb * 1_000_000,
        )


def jail_kwargs(config: JailConfig, *, scan_id: str, sandbox_id: str) -> dict[str, Any]:
    """The exact ``containers.run`` arguments for a target container (the jail flags).

    Kept as one pure function so the unit tests can assert every flag without Docker.
    """
    tmp_mb = max(16, config.workspace_mb // 2)
    return {
        "image": config.image,
        "command": ["sleep", "infinity"],
        "detach": True,
        "name": f"ono-sbx-{sandbox_id}",
        "hostname": "sandbox",
        "user": KEEPER_USER,
        "working_dir": SANDBOX_WORKSPACE,
        "environment": dict(_CONTAINER_ENV),
        # -- isolation ---------------------------------------------------------
        "network_mode": "none",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "privileged": False,
        "tmpfs": {
            SANDBOX_WORKSPACE: (
                f"rw,nosuid,nodev,size={config.workspace_mb}m,"
                f"uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0755"
            ),
            "/tmp": f"rw,nosuid,nodev,size={tmp_mb}m,mode=1777",
        },
        # -- resource limits -------------------------------------------------------
        "mem_limit": f"{config.mem_mb}m",
        "memswap_limit": f"{config.mem_mb}m",  # == mem_limit -> no swap
        "nano_cpus": int(config.cpus * 1_000_000_000),
        "pids_limit": config.pids_limit,
        "oom_score_adj": 1000,
        "ulimits": [
            docker.types.Ulimit(name="core", soft=0, hard=0),
            docker.types.Ulimit(name="nofile", soft=4096, hard=4096),
        ],
        "init": True,
        # -- bookkeeping -----------------------------------------------------------
        "labels": {
            LABEL_SANDBOX: "1",
            LABEL_SCAN: scan_id,
            LABEL_SANDBOX_ID: sandbox_id,
            LABEL_CREATED: f"{time.time():.3f}",
        },
    }


# ---------------------------------------------------------------------------
# Exec stream protocol
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _ExecOutcome:
    stdout: bytes
    stderr: bytes
    exit_code: int | None
    duration_ms: float
    timed_out: bool
    truncated: bool

    def stderr_tail(self) -> str:
        return self.stderr.decode("utf-8", "replace")[-_STDERR_TAIL:].strip()


def _recv_exact(raw: Any, n: int, deadline: float) -> bytes | None:
    """Read exactly ``n`` bytes; ``None`` on EOF; :class:`TimeoutError` past ``deadline``."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("exec stream deadline exceeded")
        raw.settimeout(left)
        chunk: bytes = raw.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _iter_frames(raw: Any, deadline: float) -> list[tuple[int, bytes]]:
    """Docker's multiplexed stream: 8-byte header (type, 3 pad, u32 len) + payload."""
    frames: list[tuple[int, bytes]] = []
    while True:
        header = _recv_exact(raw, 8, deadline)
        if header is None:
            return frames
        stream_type, length = struct.unpack(">BxxxL", header)
        payload = _recv_exact(raw, length, deadline) if length else b""
        if payload is None:
            return frames
        frames.append((int(stream_type), payload))


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class Sandbox:
    """One scan's jailed container plus the clean snapshot it can be reset to.

    All operations are serialized per sandbox (``reset`` while a ``run`` is streaming
    would be chaos); different sandboxes run fully in parallel.
    """

    manager: SandboxManager
    sandbox_id: str
    scan_id: str
    snapshot: bytes = field(repr=False)
    created_at: datetime
    status: SandboxStatus = "dead"
    container_id: str | None = None
    resets: int = 0
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _oom_kills: int = 0
    _destroyed: bool = False

    # -- lifecycle --------------------------------------------------------------
    @property
    def config(self) -> JailConfig:
        return self.manager.config

    @property
    def expires_at(self) -> datetime:
        return self.created_at + timedelta(seconds=self.config.ttl_s)

    def info(self) -> SandboxInfo:
        return SandboxInfo(
            sandbox_id=self.sandbox_id,
            scan_id=self.scan_id,
            status=self.status,
            image=self.config.image,
            container_id=self.container_id,
            created_at=self.created_at,
            expires_at=self.expires_at,
            resets=self.resets,
        )

    def _start_container(self) -> None:
        """Create + start the jail and extract the snapshot into it. Cleans up on failure."""
        client = self.manager.client
        kwargs = jail_kwargs(self.config, scan_id=self.scan_id, sandbox_id=self.sandbox_id)
        self.manager.ensure_image(self.config.image)
        try:
            container = client.containers.run(**kwargs)
        except docker.errors.APIError as exc:
            raise SandboxError(f"could not start sandbox container: {_api_detail(exc)}") from exc
        except requests.exceptions.RequestException as exc:
            raise DockerUnavailableError(f"docker daemon unreachable: {exc}") from exc
        except Exception as exc:  # the SDK can raise OSError/ValueError too; never leak raw
            raise SandboxError(f"could not start sandbox container: {exc}") from exc
        self.container_id = str(container.id)
        self.status = "running"
        try:
            outcome = self._exec(
                [
                    "tar",
                    "-xz",
                    "--no-same-owner",
                    "--no-same-permissions",
                    "-C",
                    SANDBOX_WORKSPACE,
                    "-f",
                    "-",
                ],
                stdin=self.snapshot,
                timeout_s=_EXTRACT_TIMEOUT_S,
                cap_bytes=_GUEST_OVERHEAD_BYTES,
            )
            if outcome.exit_code != 0:
                raise SandboxError(
                    f"workspace extraction failed (exit {outcome.exit_code}): "
                    f"{outcome.stderr_tail()}"
                )
            self._oom_kills = self._read_oom_kills()
        except Exception:
            self._remove_container()
            self.status = "dead"
            raise
        if self._destroyed:  # destroy() raced a reset(): never leave a container behind
            self._remove_container()
            self.status = "destroyed"
            raise SandboxNotRunningError("sandbox was destroyed while (re)starting")
        log.info(
            "sandbox %s: container %s up for scan %s (image=%s)",
            self.sandbox_id,
            self.container_id[:12],
            self.scan_id,
            self.config.image,
        )

    def _remove_container(self) -> None:
        """Force-remove the container. Never raises."""
        cid = self.container_id
        self.container_id = None
        if cid is None:
            return
        try:
            self.manager.client.api.remove_container(cid, v=True, force=True)
        except docker.errors.NotFound:
            pass
        except Exception as exc:  # teardown must never mask the caller's error
            log.warning(
                "sandbox %s: removing container %s failed: %s", self.sandbox_id, cid[:12], exc
            )
        else:
            log.info("sandbox %s: container %s removed", self.sandbox_id, cid[:12])

    def destroy(self) -> None:
        """Tear the jail down. Idempotent, never raises.

        Deliberately does NOT take the operation lock: teardown (TTL sweep, shutdown,
        ``DELETE``) must win over an in-flight ``run()``. Force-removing the container
        ends that exec's stream; the caller of ``run`` gets ``SandboxNotRunningError``.
        """
        self._destroyed = True
        self.status = "destroyed"  # refuses any operation that starts from here on
        self._remove_container()
        self.manager._forget(self)

    def reset(self) -> SandboxInfo:
        """Back to the clean snapshot: destroy + recreate the container (revives a dead one too)."""
        with self._lock:
            if self.status == "destroyed":
                raise SandboxNotRunningError("sandbox has been destroyed")
            self._remove_container()
            self._start_container()
            self.resets += 1
            return self.info()

    def _mark_dead(self, reason: str) -> None:
        log.warning("sandbox %s: marking dead - %s", self.sandbox_id, reason)
        self.status = "dead"
        self._remove_container()

    def _require_running(self) -> str:
        if self.status == "destroyed":
            raise SandboxNotRunningError("sandbox has been destroyed")
        if self.status != "running" or self.container_id is None:
            raise SandboxNotRunningError("sandbox container is not running; reset() recreates it")
        return self.container_id

    # -- exec primitive ---------------------------------------------------------
    def _exec(
        self,
        cmd: list[str],
        *,
        stdin: bytes | None = None,
        timeout_s: float,
        cap_bytes: int,
    ) -> _ExecOutcome:
        """Run ``cmd`` inside the jail as the sandbox user with a hard deadline and output cap."""
        cid = self._require_running()
        api = self.manager.client.api
        deadline = time.monotonic() + timeout_s + _EXEC_GRACE_S
        started = time.perf_counter()
        try:
            created = api.exec_create(
                cid,
                cmd,
                stdin=stdin is not None,
                user=SANDBOX_USER,
                workdir=SANDBOX_WORKSPACE,
            )
            exec_id = str(created["Id"])
            sock = api.exec_start(exec_id, socket=True)
        except docker.errors.APIError as exc:
            raise self._translate_exec_error(exc) from exc
        except requests.exceptions.RequestException as exc:
            raise DockerUnavailableError(f"docker daemon unreachable: {exc}") from exc

        # docker-py hands back a SocketIO wrapper for unix/tcp daemons and a bare
        # (SSL)socket for https ones; the underlying socket is what we drive.
        raw = getattr(sock, "_sock", sock)
        stdout, stderr = bytearray(), bytearray()
        truncated = timed_out = False
        try:
            if stdin is not None:
                raw.settimeout(max(0.1, deadline - time.monotonic()))
                raw.sendall(stdin)
                raw.shutdown(socket.SHUT_WR)
            for stream_type, payload in _iter_frames(raw, deadline):
                buf = stdout if stream_type == 1 else stderr
                room = cap_bytes - len(buf)
                if room <= 0:
                    truncated = True
                    continue
                if len(payload) > room:
                    truncated = True
                    payload = payload[:room]
                buf.extend(payload)
        except TimeoutError:
            timed_out = True
        except OSError as exc:
            raise SandboxError(f"exec stream failed: {exc}") from exc
        finally:
            _close_exec_socket(sock, raw)
        duration_ms = (time.perf_counter() - started) * 1000
        exit_code = None if timed_out else self._exit_code(exec_id)
        return _ExecOutcome(
            bytes(stdout), bytes(stderr), exit_code, duration_ms, timed_out, truncated
        )

    def _exit_code(self, exec_id: str) -> int | None:
        api = self.manager.client.api
        until = time.monotonic() + _EXIT_CODE_WAIT_S
        while True:
            try:
                info = api.exec_inspect(exec_id)
            except (docker.errors.APIError, requests.exceptions.RequestException):
                return None
            code = info.get("ExitCode")
            if code is not None and not info.get("Running", False):
                return int(code)
            if time.monotonic() > until:
                return None
            time.sleep(0.02)

    def _translate_exec_error(self, exc: docker.errors.APIError) -> SandboxError:
        detail = _api_detail(exc)
        if "is not running" in detail or isinstance(exc, docker.errors.NotFound):
            self._mark_dead(f"container gone: {detail}")
            return SandboxNotRunningError("sandbox container died; reset() recreates it")
        if not self._container_running():
            self._mark_dead(f"exec failed and container is not running: {detail}")
            return SandboxNotRunningError("sandbox container died; reset() recreates it")
        return SandboxError(f"exec failed: {detail}")

    def _container_running(self) -> bool:
        if self.container_id is None:
            return False
        try:
            state = self.manager.client.api.inspect_container(self.container_id)["State"]
        except (docker.errors.APIError, requests.exceptions.RequestException):
            return False
        return bool(state.get("Running"))

    def _reap(self) -> None:
        """Kill every process owned by the sandbox user (strays, setsid escapes, bombs).

        PID 1 belongs to a different uid, so this cannot take the container down. If
        even this cannot run (PID limit saturated by a bomb) the container is untrusted
        and is torn down: the caller must ``reset()``.
        """
        try:
            outcome = self._exec(
                ["sh", "-c", "kill -9 -1 2>/dev/null; exit 0"],
                timeout_s=_REAP_TIMEOUT_S,
                cap_bytes=4096,
            )
        except SandboxNotRunningError:
            raise
        except SandboxError as exc:
            self._mark_dead(f"could not reap stray processes: {exc}")
            raise SandboxNotRunningError(
                "sandbox could not be cleaned after the command; reset() recreates it"
            ) from exc
        if outcome.timed_out or outcome.exit_code != 0:
            self._mark_dead("stray-process reap did not complete")
            raise SandboxNotRunningError(
                "sandbox could not be cleaned after the command; reset() recreates it"
            )

    def _read_oom_kills(self) -> int:
        """The cgroup's cumulative OOM-kill counter (v2 ``memory.events``, v1 fallback)."""
        try:
            outcome = self._exec(
                [
                    "sh",
                    "-c",
                    "cat /sys/fs/cgroup/memory.events 2>/dev/null"
                    " || cat /sys/fs/cgroup/memory/memory.oom_control 2>/dev/null; exit 0",
                ],
                timeout_s=_REAP_TIMEOUT_S,
                cap_bytes=4096,
            )
        except SandboxError:
            return self._oom_kills
        match = _OOM_RE.search(outcome.stdout.decode("utf-8", "replace"))
        return int(match.group(1)) if match else self._oom_kills

    # -- guest helper -----------------------------------------------------------
    def _guest(
        self, op: str, args: dict[str, Any], *, stdin: bytes | None = None
    ) -> dict[str, Any]:
        cap = self.config.output_cap_bytes + _GUEST_OVERHEAD_BYTES
        cmd = ["python3", "-I", "-S", "-c", GUEST_SOURCE, op, json.dumps(args)]
        outcome = self._exec(cmd, stdin=stdin, timeout_s=_GUEST_TIMEOUT_S, cap_bytes=cap)
        if outcome.timed_out:
            raise SandboxOperationError(f"{op} timed out inside the sandbox")
        if outcome.exit_code != 0:
            raise SandboxError(
                f"in-jail helper failed for {op} (exit {outcome.exit_code}): "
                f"{outcome.stderr_tail()}"
            )
        try:
            result = json.loads(outcome.stdout.decode("utf-8", "replace"))
        except ValueError as exc:
            raise SandboxError(f"in-jail helper returned invalid JSON for {op}") from exc
        if not isinstance(result, dict):
            raise SandboxError(f"in-jail helper returned a non-object for {op}")
        if not result.get("ok"):
            raise SandboxOperationError(str(result.get("error") or f"{op} failed"))
        return result

    # -- read-only operations ---------------------------------------------------
    def read_file(self, path: str) -> FileContent:
        """Whole file (UTF-8, lossy), capped at ``output_cap_bytes``."""
        return self._read(path, None, None)

    def read_lines(self, path: str, start: int, end: int) -> FileContent:
        """Lines ``start..end`` (1-based, inclusive)."""
        if start < 1 or end < start:
            raise SandboxPathError("need 1 <= start <= end")
        return self._read(path, start, end)

    def _read(self, path: str, start: int | None, end: int | None) -> FileContent:
        rel = validate_rel_path(path)
        with self._lock:
            result = self._guest(
                "read",
                {
                    "path": rel,
                    "start": start,
                    "end": end,
                    "cap_bytes": self.config.output_cap_bytes,
                },
            )
        return FileContent(
            path=rel,
            content=str(result["content"]),
            start_line=int(result["start_line"]),
            end_line=int(result["end_line"]),
            total_lines=None if result.get("total_lines") is None else int(result["total_lines"]),
            size_bytes=int(result["size_bytes"]),
            truncated=bool(result["truncated"]),
        )

    def tree(self, path: str = ".", *, max_entries: int = 2000, max_depth: int = 12) -> TreeListing:
        rel = validate_rel_path(path, allow_root=True)
        with self._lock:
            result = self._guest(
                "tree", {"path": rel, "max_entries": max_entries, "max_depth": max_depth}
            )
        return TreeListing.model_validate(result)

    def grep(
        self, pattern: str, path: str = ".", *, ignore_case: bool = False, max_matches: int = 200
    ) -> GrepResult:
        if not pattern or len(pattern) > 512 or "\x00" in pattern:
            raise SandboxPathError("pattern must be 1-512 characters without NUL")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise SandboxPathError(f"invalid regular expression: {exc}") from exc
        rel = validate_rel_path(path, allow_root=True)
        with self._lock:
            result = self._guest(
                "grep",
                {
                    "pattern": pattern,
                    "path": rel,
                    "ignore_case": ignore_case,
                    "max_matches": max_matches,
                },
            )
        return GrepResult.model_validate(result)

    # -- mutating operations ----------------------------------------------------
    def apply_patch(self, diff: str) -> PatchResult:
        """Apply a unified diff to the workspace (all-or-nothing). Never raises for a bad diff."""
        if not diff.strip():
            raise SandboxPathError("diff is empty")
        if "\x00" in diff:
            raise SandboxPathError("diff contains a NUL byte")
        if len(diff) > 2_000_000:
            raise SandboxPathError("diff is larger than 2 MB")
        with self._lock:
            result = self._guest("apply", {}, stdin=diff.encode("utf-8", "surrogateescape"))
        return PatchResult.model_validate(result)

    def run(self, cmd: str, timeout_s: float | None = None) -> RunResult:
        """``sh -c cmd`` in the jail: hard timeout, bounded output, strays reaped afterwards."""
        if not cmd.strip():
            raise SandboxPathError("cmd is empty")
        if "\x00" in cmd:
            raise SandboxPathError("cmd contains a NUL byte")
        budget = (
            self.config.cmd_timeout_s
            if timeout_s is None
            else min(timeout_s, self.config.cmd_timeout_s)
        )
        budget = max(0.1, budget)
        # `timeout` kills the whole process group on the deadline; the host-side socket
        # deadline (budget + grace) is the backstop if the daemon or a setsid()'d child misbehaves.
        wrapped = ["timeout", "-s", "KILL", f"{budget:.3f}", "sh", "-c", cmd]
        with self._lock:
            outcome = self._exec(wrapped, timeout_s=budget, cap_bytes=self.config.output_cap_bytes)
            self._reap()
            oom = False
            if outcome.exit_code in (137, None) or outcome.timed_out:
                kills = self._read_oom_kills()
                oom = kills > self._oom_kills
                self._oom_kills = kills
        timed_out = outcome.timed_out or (
            outcome.exit_code in (124, 137)
            and not oom
            and outcome.duration_ms >= budget * 1000 * 0.95
        )
        return RunResult(
            cmd=cmd,
            stdout=outcome.stdout.decode("utf-8", "replace"),
            stderr=outcome.stderr.decode("utf-8", "replace"),
            exit_code=outcome.exit_code,
            duration_ms=outcome.duration_ms,
            timed_out=timed_out,
            oom_killed=oom,
            truncated=outcome.truncated,
        )

    def run_tests(self, timeout_s: float | None = None) -> TestRunResult:
        """Best-effort: detect pytest / npm from the top-level listing and run it, bounded."""
        with self._lock:
            listing = self.tree(max_entries=500, max_depth=1)
            names = {e.path for e in listing.entries}
            runner: TestRunner = "none"
            command = ""
            if names & _PYTEST_MARKERS or any(_PYTEST_FILE.match(n) for n in names):
                runner = "pytest"
                command = "python3 -m pytest -q --no-header -p no:cacheprovider --color=no"
            elif "package.json" in names:
                runner = "npm"
                command = (
                    "command -v npm >/dev/null 2>&1 || "
                    "{ echo 'npm is not available in the sandbox image' >&2; exit 127; }; "
                    "npm test --silent"
                )
            if runner == "none":
                return TestRunResult(
                    runner="none", detected=False, passed=None, summary="no test runner detected"
                )
            result = self.run(command, timeout_s)
        passed: bool | None
        if result.timed_out or result.oom_killed:
            passed = None
        elif result.exit_code == 0:
            passed = True
        elif runner == "pytest" and result.exit_code == 5:
            passed = None  # pytest: no tests collected
        else:
            passed = False
        summary = _last_line(result.stdout) or _last_line(result.stderr)
        if result.timed_out:
            summary = f"timed out after {int(result.duration_ms)} ms"
        return TestRunResult(
            runner=runner,
            command=command,
            detected=True,
            passed=passed,
            summary=summary[:300],
            run=result,
        )


def _last_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if line.strip():
            return line.strip()
    return ""


def _close_exec_socket(sock: Any, raw: Any) -> None:
    """Release a hijacked exec connection cleanly.

    docker-py parks the HTTP response on ``sock._response``; closing it *first* lets
    ``http.client`` flush while the file is still open (otherwise Python logs an
    "Exception ignored ... I/O operation on closed file" at garbage-collection time).
    """
    response = getattr(sock, "_response", None)
    for closeable in (response, sock, raw):
        if closeable is not None:
            with contextlib.suppress(OSError, ValueError):
                closeable.close()


def _api_detail(exc: docker.errors.APIError) -> str:
    explanation = getattr(exc, "explanation", None)
    if isinstance(explanation, bytes):
        explanation = explanation.decode("utf-8", "replace")
    return str(explanation or exc)


def validate_rel_path(path: str, *, allow_root: bool = False) -> str:
    """Trusted-side path confinement (the guest re-checks and opens with ``O_NOFOLLOW``)."""
    if len(path) > 1024:
        raise SandboxPathError("path is longer than 1024 characters")
    if any(ord(ch) < 0x20 or ch == "\x7f" for ch in path):
        raise SandboxPathError("path contains control characters")
    try:
        parts = split_rel(path)
    except GuestError as exc:
        raise SandboxPathError(str(exc)) from exc
    if not parts:
        if allow_root:
            return "."
        raise SandboxPathError("path must name a file inside the workspace")
    return "/".join(parts)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class SandboxManager:
    """Creates, tracks, sweeps and destroys sandboxes. One per Executor process."""

    def __init__(self, config: JailConfig, client: Any | None = None) -> None:
        self.config = config
        self._client: Any | None = client
        self._client_lock = threading.Lock()
        self._lock = threading.Lock()
        self._sandboxes: dict[str, Sandbox] = {}
        self._pulled: set[str] = set()
        self._sweeper: threading.Thread | None = None
        self._stop = threading.Event()

    # -- docker client ----------------------------------------------------------
    @property
    def client(self) -> Any:
        """The docker-py client, created lazily from the environment (``DOCKER_HOST`` ...)."""
        with self._client_lock:
            if self._client is None:
                try:
                    # Streaming execs can be silent for the whole command budget: the HTTP
                    # read timeout must outlive it (the socket deadline is enforced by us).
                    self._client = docker.from_env(timeout=int(self.config.cmd_timeout_s) + 60)
                except docker.errors.DockerException as exc:
                    raise DockerUnavailableError(f"cannot create docker client: {exc}") from exc
            return self._client

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except (
            DockerUnavailableError,
            docker.errors.DockerException,
            requests.exceptions.RequestException,
        ):
            return False

    def ensure_image(self, image: str) -> None:
        if image in self._pulled:
            return
        try:
            self.client.images.get(image)
        except docker.errors.ImageNotFound:
            log.info("sandbox image %s not present; pulling", image)
            try:
                self.client.images.pull(image)
            except docker.errors.APIError as exc:
                raise SandboxError(
                    f"could not pull sandbox image {image!r}: {_api_detail(exc)}"
                ) from exc
        except docker.errors.APIError as exc:
            raise SandboxError(
                f"could not inspect sandbox image {image!r}: {_api_detail(exc)}"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise DockerUnavailableError(f"docker daemon unreachable: {exc}") from exc
        self._pulled.add(image)

    # -- lifecycle --------------------------------------------------------------
    def create(self, scan_id: str, workspace_dir: Path) -> Sandbox:
        """Pack a local workspace directory and start a jail holding it."""
        try:
            archive = pack_workspace(workspace_dir, max_bytes=self.config.max_archive_bytes)
        except ArchiveError as exc:
            raise SandboxPathError(str(exc)) from exc
        return self.create_from_archive(scan_id, archive)

    def create_from_archive(self, scan_id: str, archive: bytes) -> Sandbox:
        """Start a jail from a gzipped tar of the workspace (validated first)."""
        if not _SCAN_ID_RE.match(scan_id):
            raise SandboxPathError("scan_id must match " + SCAN_ID_PATTERN)
        if len(archive) > self.config.max_archive_bytes:
            raise SandboxPathError(f"archive is larger than {self.config.max_archive_bytes} bytes")
        try:
            validate_archive(archive, max_bytes=self.config.max_archive_bytes)
        except ArchiveError as exc:
            raise SandboxPathError(str(exc)) from exc

        sandbox = Sandbox(
            manager=self,
            sandbox_id=f"sbx_{uuid.uuid4().hex[:12]}",
            scan_id=scan_id,
            snapshot=archive,
            created_at=datetime.now(tz=UTC),
        )
        with self._lock:  # register first so concurrent creates count against the limit
            if len(self._sandboxes) >= self.config.max_active:
                raise SandboxLimitError(
                    f"too many live sandboxes ({self.config.max_active}); destroy one first"
                )
            self._sandboxes[sandbox.sandbox_id] = sandbox
        try:
            sandbox._start_container()
        except BaseException:
            self._forget(sandbox)
            raise
        return sandbox

    def get(self, sandbox_id: str) -> Sandbox | None:
        with self._lock:
            return self._sandboxes.get(sandbox_id)

    def active(self) -> list[Sandbox]:
        with self._lock:
            return list(self._sandboxes.values())

    def destroy(self, sandbox: Sandbox) -> None:
        """Force-remove the sandbox's container and forget it. Never raises."""
        sandbox.destroy()

    def _forget(self, sandbox: Sandbox) -> None:
        with self._lock:
            self._sandboxes.pop(sandbox.sandbox_id, None)

    def destroy_all(self) -> None:
        for sandbox in self.active():
            sandbox.destroy()

    # -- sweeper ----------------------------------------------------------------
    def sweep(self, max_age_s: float | None = None) -> list[str]:
        """Remove sandboxes past the TTL - tracked ones *and* any ``ono.sandbox`` container
        on the daemon (orphans from a crashed Executor). Returns the removed container ids.
        """
        max_age = self.config.ttl_s if max_age_s is None else max_age_s
        now = time.time()
        removed: list[str] = []
        for sandbox in self.active():
            if now - sandbox.created_at.timestamp() > max_age:
                cid = sandbox.container_id
                log.info("sweeper: sandbox %s exceeded ttl; destroying", sandbox.sandbox_id)
                sandbox.destroy()
                if cid:
                    removed.append(cid)
        try:
            containers = self.client.containers.list(
                all=True, filters={"label": f"{LABEL_SANDBOX}=1"}
            )
        except (
            DockerUnavailableError,
            docker.errors.DockerException,
            requests.exceptions.RequestException,
        ) as exc:
            log.warning("sweeper: cannot list containers: %s", exc)
            return removed
        for container in containers:
            cid = str(container.id)
            if cid in removed:
                continue
            created = _container_created_epoch(container)
            if created is None or now - created <= max_age:
                continue
            try:
                container.remove(v=True, force=True)
            except docker.errors.NotFound:
                continue
            except docker.errors.APIError as exc:
                log.warning("sweeper: could not remove orphan %s: %s", cid[:12], _api_detail(exc))
                continue
            log.warning(
                "sweeper: removed orphaned sandbox container %s (age %.0fs)",
                cid[:12],
                now - created,
            )
            removed.append(cid)
        return removed

    def start_sweeper(self, interval_s: float | None = None) -> None:
        if self._sweeper is not None:
            return
        interval = interval_s if interval_s is not None else max(15.0, self.config.ttl_s / 4)

        def loop() -> None:
            while not self._stop.wait(interval):
                try:
                    self.sweep()
                except Exception:  # the sweeper must survive anything
                    log.exception("sweeper: unexpected failure")

        self._sweeper = threading.Thread(target=loop, name="ono-sandbox-sweeper", daemon=True)
        self._sweeper.start()

    def close(self) -> None:
        """Stop the sweeper and destroy every tracked sandbox (service shutdown)."""
        self._stop.set()
        if self._sweeper is not None:
            self._sweeper.join(timeout=5)
            self._sweeper = None
        self.destroy_all()


def _container_created_epoch(container: Any) -> float | None:
    labels = container.labels or {}
    raw = labels.get(LABEL_CREATED)
    if raw:
        try:
            return float(raw)
        except ValueError:
            pass
    created = container.attrs.get("Created") if isinstance(container.attrs, dict) else None
    if not isinstance(created, str):
        return None
    # "2026-10-31T13:51:00.123456789Z" -> trim nanoseconds for fromisoformat
    text = re.sub(r"(\.\d{6})\d+", r"\1", created).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None
