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
seccomp profile         Docker's default minus ptrace/AIO/SysV-IPC/... and non-INET socket
                        families (``sandbox_seccomp_profile``, see :func:`load_seccomp_profile`)
``/deps`` tmpfs         third-party packages the BUILDER produced, extracted as the keeper uid
                        so the inmate can import but never modify them (``provision()``)
======================  =====================================================================

**The builder** (:func:`builder_kwargs`, :meth:`SandboxManager.build_dependencies`) is the
one deliberate exception to "no network": a target's declared Python dependencies have to
come from an index, so they are installed in a *separate*, ephemeral container that keeps
every other jail property (non-root, ``cap_drop=ALL``, ``no-new-privileges``, seccomp,
read-only rootfs with bounded tmpfs, memory/CPU/PID caps, no host mounts, never the Docker
socket) and additionally has a wall-clock budget and an installed-size cap. Installing an
untrusted repository's dependencies *executes its code* (``setup.py``, build backends), so
that is the only place it ever happens. Its sole output - the installed packages directory
- leaves as a tar that is validated exactly like a workspace archive before being extracted
into the verification jail, which stays ``network_mode=none`` and otherwise unchanged. The
builder is force-removed when the build ends (success, failure, timeout, or the sandbox's
own teardown) and carries a short TTL label for the sweeper in case the Executor dies.

Files travel in by streaming a tar over ``docker exec`` stdin into ``tar -x`` running
*as the sandbox user* (the archive API cannot write into a tmpfs under a read-only
rootfs). The archive is only ever read from a **file** - the upload is spooled to
disk, validated by streaming, and kept there as the :class:`~ono.executor.archive.Snapshot`
``reset()`` restores from - so the Executor's resident memory does not grow with the
size or number of workspaces (see issue #96). Every operation is a ``docker exec``
with a hard deadline, a byte cap on output, and - for ``run()`` - a ``kill -9 -1``
sweep afterwards so nothing survives between operations. ``reset()`` destroys the
container and recreates it from the snapshot: ~100 ms plus extraction, and it also
recovers a sandbox whose container died.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import shutil
import socket
import struct
import tarfile
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from importlib import resources
from pathlib import Path
from typing import IO, Any, Self

import docker
import docker.errors
import docker.types
import requests

from ono.config import Settings
from ono.executor._builder import RESULT_MARKER as BUILD_RESULT_MARKER
from ono.executor._builder import basename_manifest_kind, manifest_kind
from ono.executor._guest import GuestError, split_rel
from ono.executor.archive import (
    SANDBOX_UID,
    SPOOL_CHUNK_BYTES,
    ArchiveError,
    Snapshot,
    pack_workspace,
)
from ono.executor.models import (
    SANDBOX_DEPS,
    SANDBOX_WORKSPACE,
    SCAN_ID_PATTERN,
    FileContent,
    GrepResult,
    PatchResult,
    ProvisionResult,
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
    "builder_kwargs",
    "check_grep_pattern",
    "jail_kwargs",
    "load_seccomp_profile",
    "select_image",
    "snapshot_manifests",
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
LABEL_BUILDER = "ono.builder"
LABEL_TTL = "ono.ttl_s"
"""Per-container TTL the sweeper honours when shorter than the configured one (builders)."""

BUILD_DIR = "/build"
BUILD_SRC = f"{BUILD_DIR}/src"
"""Where the builder gets the workspace snapshot (manifests, setup.py, ...)."""
BUILD_SITE = f"{BUILD_DIR}/site"
"""The builder's ``pip install --target`` directory: its ONLY output."""

_SCAN_ID_RE = re.compile(SCAN_ID_PATTERN)
_EXEC_GRACE_S = 5.0  # host-side slack after the in-jail `timeout` deadline
_EXIT_CODE_WAIT_S = 3.0
_GUEST_TIMEOUT_S = 60.0
_REAP_TIMEOUT_S = 10.0
_EXTRACT_TIMEOUT_S = 180.0
_GUEST_OVERHEAD_BYTES = 256 * 1024
_BUILD_OUTPUT_CAP = 1_000_000
_STDERR_TAIL = 600
_OOM_RE = re.compile(r"oom_kill\s+(\d+)")

# The in-jail helper is shipped by value on every call (see _guest.py's docstring).
GUEST_SOURCE = resources.files("ono.executor").joinpath("_guest.py").read_text(encoding="utf-8")
# The in-builder installer, likewise shipped by value (see _builder.py's docstring).
BUILDER_SOURCE = resources.files("ono.executor").joinpath("_builder.py").read_text(encoding="utf-8")

SECCOMP_DOCKER_DEFAULT = "docker-default"
"""``sandbox_seccomp_profile`` value meaning: add nothing, keep the daemon's default."""
SECCOMP_HARDENED = "hardened"
"""``sandbox_seccomp_profile`` value selecting the profile shipped with the package."""
_SECCOMP_HARDENED_FILE = "seccomp-hardened.json"

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
    # Provisioned packages (read-only, keeper-owned). Honoured by plain `python3` runs such
    # as the target's test suite; ignored by the `-I` oracle/guest, which add it explicitly.
    "PYTHONPATH": SANDBOX_DEPS,
    # Same idea for Node: a plain `node` run (the target's own `npm test`, say) resolves
    # provisioned npm packages through NODE_PATH; the JS oracle adds the directory itself
    # (module.globalPaths) so it works even on an image/exec that does not inherit this var.
    # Harmless on a Python-only (non-combined) jail image: node is never invoked there.
    "NODE_PATH": f"{SANDBOX_DEPS}/node_modules",
}

_BUILDER_ENV = {
    "HOME": "/tmp",
    "TMPDIR": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
    "NO_COLOR": "1",
    "CI": "true",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    # pip: no cache, no self-upgrade, no prompts; the pip that ships with the pinned image
    # is the one that runs (no `--upgrade pip` ever happens in the builder).
    "PIP_NO_CACHE_DIR": "1",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_INPUT": "1",
    "PIP_PROGRESS_BAR": "off",
    "PIP_NO_PYTHON_VERSION_WARNING": "1",
    # npm: cache + config under the writable /tmp (HOME is already /tmp), no audit/funding
    # noise, no update nagging - the installed npm (pinned by the image) is the one that runs.
    "NPM_CONFIG_CACHE": "/tmp/.npm-cache",
    "NPM_CONFIG_AUDIT": "false",
    "NPM_CONFIG_FUND": "false",
    "NPM_CONFIG_UPDATE_NOTIFIER": "false",
    "NPM_CONFIG_LOGLEVEL": "error",
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
    image_node: str = "nikolaik/python-nodejs:python3.13-nodejs20-slim"
    """Selected instead of ``image`` for a scan with any JS/TS finding (``runtime="node"``);
    must have Python (the guest helper always runs ``python3``) PLUS ``node``/``npm``."""
    builder_image: str = "ghcr.io/astral-sh/uv:python3.13-bookworm"
    """Image for the ephemeral dependency builder of a Python scan - a full toolchain + ``uv``,
    NOT the slim jail image (see ``builder_image_for`` / ``sandbox_builder_image``)."""
    builder_image_node: str = "nikolaik/python-nodejs:python3.13-nodejs20"
    """Image for the dependency builder of a JS/TS scan - the non-slim combined image, so
    node-gyp's toolchain is present (``sandbox_builder_image_node``)."""
    mem_mb: int = 1024
    cpus: float = 1.0
    pids_limit: int = 256
    cmd_timeout_s: float = 300.0
    ttl_s: float = 1800.0
    output_cap_bytes: int = 1_000_000
    workspace_mb: int = 512
    max_active: int = 8
    max_archive_bytes: int = 200_000_000
    snapshot_dir: Path | None = None
    """Where validated archives are kept for ``reset()``; ``None`` = a private temp dir."""
    seccomp_profile: str | None = None
    """Seccomp profile JSON handed to the daemon; ``None`` = Docker's default profile."""
    deps_enabled: bool = True
    """Whether ``provision()`` may start a builder at all (``sandbox_deps_enabled``)."""
    deps_timeout_s: float = 300.0
    """Wall-clock cap on one dependency build."""
    deps_mb: int = 256
    """Cap on the installed dependency set; also the size of the jail's ``/deps`` tmpfs."""
    deps_index_url: str | None = None
    """Package index for the builder (``PIP_INDEX_URL``); ``None`` = PyPI."""
    deps_npm_registry: str | None = None
    """Registry for the builder's npm install/ci (``NPM_CONFIG_REGISTRY``); ``None`` = npm's
    default (registry.npmjs.org)."""

    @classmethod
    def from_settings(cls, settings: Settings) -> Self:
        return cls(
            image=settings.sandbox_image,
            image_node=settings.sandbox_image_node,
            builder_image=settings.sandbox_builder_image,
            builder_image_node=settings.sandbox_builder_image_node,
            mem_mb=settings.sandbox_mem_mb,
            cpus=settings.sandbox_cpus,
            pids_limit=settings.sandbox_pids_limit,
            cmd_timeout_s=settings.sandbox_cmd_timeout_s,
            ttl_s=settings.sandbox_ttl_s,
            output_cap_bytes=settings.sandbox_output_cap_bytes,
            workspace_mb=settings.sandbox_workspace_mb,
            max_active=settings.sandbox_max_active,
            max_archive_bytes=settings.max_clone_mb * 1_000_000,
            snapshot_dir=settings.sandbox_snapshot_dir,
            seccomp_profile=load_seccomp_profile(settings.sandbox_seccomp_profile),
            deps_enabled=settings.sandbox_deps_enabled,
            deps_timeout_s=settings.sandbox_deps_timeout_s,
            deps_mb=settings.sandbox_deps_max_mb,
            deps_index_url=settings.sandbox_deps_index_url,
            deps_npm_registry=settings.sandbox_deps_npm_registry,
        )

    @property
    def deps_max_bytes(self) -> int:
        return self.deps_mb * 1_000_000


def load_seccomp_profile(spec: str | None) -> str | None:
    """Resolve the ``sandbox_seccomp_profile`` setting to the JSON the daemon receives.

    ``None`` / ``""`` / ``"docker-default"`` keep Docker's built-in profile (nothing is
    added to ``security_opt``); ``"hardened"`` loads the profile shipped in this package
    (Docker's default minus the syscall groups a test runner never needs - see
    ``seccomp-hardened.json``); anything else is a path to a custom profile. The
    Engine API takes the profile *contents* (the CLI reads the file for you; docker-py
    does not), so the text is returned compacted and must be valid JSON.
    """
    if not spec or spec == SECCOMP_DOCKER_DEFAULT:
        return None
    if spec == SECCOMP_HARDENED:
        text = resources.files("ono.executor").joinpath(_SECCOMP_HARDENED_FILE).read_text("utf-8")
    else:
        try:
            text = Path(spec).read_text("utf-8")
        except OSError as exc:
            raise ValueError(f"sandbox_seccomp_profile {spec!r} cannot be read: {exc}") from exc
    try:
        profile = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"sandbox_seccomp_profile {spec!r} is not valid JSON: {exc}") from exc
    if not isinstance(profile, dict) or "defaultAction" not in profile or "syscalls" not in profile:
        raise ValueError(
            f"sandbox_seccomp_profile {spec!r} is not a seccomp profile "
            "(needs 'defaultAction' and 'syscalls')"
        )
    return json.dumps(profile, separators=(",", ":"))


def select_image(config: JailConfig, runtime: str) -> str:
    """The image for a sandbox's declared ``runtime``: ``"python"`` (default) or ``"node"``.

    This is the ONLY place a client-influenced value selects a Docker image, and it chooses
    between exactly two Executor-configured images (never an arbitrary string from a
    request) - see ``create_sandbox``'s ``runtime`` query parameter in ``app.py``, which
    FastAPI's ``Literal`` validation already restricts to these two values before this runs.
    """
    return config.image_node if runtime == "node" else config.image


def builder_image_for(config: JailConfig, jail_image: str) -> str:
    """The dependency-builder image to pair with a sandbox running ``jail_image``.

    The builder is deliberately a DIFFERENT image from the jail: the jail is slim and
    hardened (it only has to run the already-built code), while the builder needs a full
    compiler toolchain so sdist-only packages build, plus ``uv`` for era-correct Python
    resolution. The pairing follows the jail's runtime - a JS/TS jail (``image_node``) gets
    the Node builder (node-gyp toolchain), everything else the Python builder.
    """
    return config.builder_image_node if jail_image == config.image_node else config.builder_image


def jail_kwargs(
    config: JailConfig, *, scan_id: str, sandbox_id: str, image: str | None = None
) -> dict[str, Any]:
    """The exact ``containers.run`` arguments for a target container (the jail flags).

    ``image`` overrides ``config.image`` (the per-sandbox runtime selection - see
    :func:`select_image`); every other flag is identical regardless of which image is used.
    Kept as one pure function so the unit tests can assert every flag without Docker.
    """
    tmp_mb = max(16, config.workspace_mb // 2)
    return {
        "image": image or config.image,
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
        "security_opt": _security_opt(config),
        "privileged": False,
        "tmpfs": {
            SANDBOX_WORKSPACE: (
                f"rw,nosuid,nodev,size={config.workspace_mb}m,"
                f"uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0755"
            ),
            "/tmp": f"rw,nosuid,nodev,size={tmp_mb}m,mode=1777",
            # Provisioned packages: owned by the keeper uid, so the sandbox user can read
            # (import) them but never write; filled by `tar -x` running as the keeper.
            # `exec` (Docker's tmpfs default is noexec) because native wheels - pydantic-core,
            # numpy, cryptography ... - are shared objects that must be mmap'd executable.
            # Nothing the inmate can write is ever on this mount, so it adds no capability
            # beyond the Python and /usr/bin binaries the jail already runs.
            SANDBOX_DEPS: (
                f"rw,exec,nosuid,nodev,size={config.deps_mb}m,"
                f"uid={KEEPER_UID},gid={KEEPER_UID},mode=0755"
            ),
        },
        # -- resource limits -------------------------------------------------------
        **_resource_limits(config),
        # -- bookkeeping -----------------------------------------------------------
        "labels": {
            LABEL_SANDBOX: "1",
            LABEL_SCAN: scan_id,
            LABEL_SANDBOX_ID: sandbox_id,
            LABEL_CREATED: f"{time.time():.3f}",
        },
    }


def builder_kwargs(
    config: JailConfig, *, scan_id: str, sandbox_id: str, image: str | None = None
) -> dict[str, Any]:
    """The exact ``containers.run`` arguments for a BUILDER container.

    Identical to :func:`jail_kwargs` in every hardening flag except the one it needs to do
    its job: ``network_mode`` is the daemon's default bridge (pip/npm have to reach an
    index/registry). Non-root, ``cap_drop=ALL``, ``no-new-privileges``, the same seccomp
    profile, read-only rootfs with two bounded tmpfs mounts (``/build`` for the snapshot +
    the install target, ``/tmp`` for pip/npm's scratch), the same memory/CPU/PID caps, no
    host bind mounts and - like every target container - never the Docker socket. It is
    labelled with a short TTL so the sweeper removes it if the Executor dies mid-build.
    ``image`` is the dedicated BUILDER image (see :func:`builder_image_for`): a full
    toolchain + ``uv`` for a Python scan, the non-slim combined image for a JS/TS scan - NOT
    the slim jail image, because building (unlike running) needs a compiler.
    """
    env = dict(_BUILDER_ENV)
    if config.deps_index_url:
        env["PIP_INDEX_URL"] = config.deps_index_url
    if config.deps_npm_registry:
        env["NPM_CONFIG_REGISTRY"] = config.deps_npm_registry
    return {
        "image": image or config.image,
        "command": ["sleep", "infinity"],
        "detach": True,
        "name": f"ono-bld-{sandbox_id}",
        "hostname": "builder",
        "user": KEEPER_USER,
        "working_dir": BUILD_DIR,
        "environment": env,
        # -- isolation (network is the ONE difference from the jail) ---------------
        "network_mode": "bridge",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": _security_opt(config),
        "privileged": False,
        "tmpfs": {
            BUILD_DIR: (
                f"rw,nosuid,nodev,size={config.workspace_mb + config.deps_mb}m,"
                f"uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0755"
            ),
            "/tmp": f"rw,nosuid,nodev,size={config.deps_mb}m,mode=1777",
        },
        # -- resource limits -------------------------------------------------------
        **_resource_limits(config),
        # -- bookkeeping -----------------------------------------------------------
        "labels": {
            LABEL_SANDBOX: "1",  # the sweeper's filter: an orphaned builder is swept too
            LABEL_BUILDER: "1",
            LABEL_SCAN: scan_id,
            LABEL_SANDBOX_ID: sandbox_id,
            LABEL_CREATED: f"{time.time():.3f}",
            LABEL_TTL: f"{2 * config.deps_timeout_s + _EXTRACT_TIMEOUT_S:.0f}",
        },
    }


def _security_opt(config: JailConfig) -> list[str]:
    security_opt = ["no-new-privileges:true"]
    if config.seccomp_profile is not None:
        security_opt.append(f"seccomp={config.seccomp_profile}")
    return security_opt


def _resource_limits(config: JailConfig) -> dict[str, Any]:
    return {
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
    return list(_frames(raw, deadline))


def _frames(raw: Any, deadline: float) -> Any:
    """Lazy variant of :func:`_iter_frames` - what the streaming exec consumes."""
    while True:
        header = _recv_exact(raw, 8, deadline)
        if header is None:
            return
        stream_type, length = struct.unpack(">BxxxL", header)
        payload = _recv_exact(raw, length, deadline) if length else b""
        if payload is None:
            return
        yield int(stream_type), payload


def _exec_in(
    api: Any,
    cid: str,
    cmd: list[str],
    *,
    user: str,
    workdir: str,
    stdin: bytes | IO[bytes] | None,
    timeout_s: float,
    cap_bytes: int,
    stdout_sink: IO[bytes] | None = None,
) -> _ExecOutcome:
    """Run ``cmd`` in container ``cid`` with a hard deadline and an output cap.

    The exec primitive shared by the jail and the builder. ``stdin`` may be a byte string
    or an open binary file (streamed in :data:`~ono.executor.archive.SPOOL_CHUNK_BYTES`
    pieces, never loaded whole). With ``stdout_sink`` the command's stdout goes to that
    file instead of memory - how a builder's archive leaves the container - and reading
    stops once ``cap_bytes`` have arrived (``truncated``). Docker API / transport errors
    propagate for the caller to translate.
    """
    deadline = time.monotonic() + timeout_s + _EXEC_GRACE_S
    started = time.perf_counter()
    created = api.exec_create(cid, cmd, stdin=stdin is not None, user=user, workdir=workdir)
    exec_id = str(created["Id"])
    sock = api.exec_start(exec_id, socket=True)
    # docker-py hands back a SocketIO wrapper for unix/tcp daemons and a bare
    # (SSL)socket for https ones; the underlying socket is what we drive.
    raw = getattr(sock, "_sock", sock)
    stdout, stderr = bytearray(), bytearray()
    sunk = 0
    truncated = timed_out = False
    try:
        if stdin is not None:
            _send_stdin(raw, stdin, deadline)
            raw.shutdown(socket.SHUT_WR)
        for stream_type, payload in _frames(raw, deadline):
            if stream_type == 1 and stdout_sink is not None:
                room = cap_bytes - sunk
                if len(payload) > room:
                    truncated = True
                    break
                stdout_sink.write(payload)
                sunk += len(payload)
                continue
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
    exit_code = None if timed_out else _exit_code_of(api, exec_id)
    return _ExecOutcome(bytes(stdout), bytes(stderr), exit_code, duration_ms, timed_out, truncated)


def _exit_code_of(api: Any, exec_id: str) -> int | None:
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


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class Sandbox:
    """One scan's jailed container plus the clean snapshot it can be reset to.

    All operations are serialized per sandbox (``reset`` while a ``run`` is streaming
    would be chaos); different sandboxes run fully in parallel. The snapshot is a
    validated archive **on disk** (:class:`~ono.executor.archive.Snapshot`); it is
    streamed into the jail on every (re)start and deleted with the sandbox.
    """

    manager: SandboxManager
    sandbox_id: str
    scan_id: str
    snapshot: Snapshot = field(repr=False)
    created_at: datetime
    status: SandboxStatus = "dead"
    container_id: str | None = None
    resets: int = 0
    image: str = ""
    """The resolved image this sandbox runs (``select_image``'s result at creation time);
    "" falls back to ``config.image`` (legacy / test-constructed sandboxes)."""
    deps: Snapshot | None = field(default=None, repr=False)
    """The builder's validated packages archive, re-extracted into ``/deps`` on every reset."""
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _oom_kills: int = 0
    _destroyed: bool = False
    _builder_cid: str | None = None  # an in-flight builder container, torn down with us

    # -- lifecycle --------------------------------------------------------------
    @property
    def config(self) -> JailConfig:
        return self.manager.config

    @property
    def expires_at(self) -> datetime:
        return self.created_at + timedelta(seconds=self.config.ttl_s)

    @property
    def effective_image(self) -> str:
        return self.image or self.config.image

    @property
    def builder_image(self) -> str:
        """Toolchain image for this sandbox's dependency builder (never the slim jail image)."""
        return builder_image_for(self.config, self.effective_image)

    def info(self) -> SandboxInfo:
        return SandboxInfo(
            sandbox_id=self.sandbox_id,
            scan_id=self.scan_id,
            status=self.status,
            image=self.effective_image,
            container_id=self.container_id,
            created_at=self.created_at,
            expires_at=self.expires_at,
            resets=self.resets,
            provisioned=self.deps is not None,
        )

    def _start_container(self) -> None:
        """Create + start the jail and extract the snapshot into it. Cleans up on failure."""
        client = self.manager.client
        kwargs = jail_kwargs(
            self.config,
            scan_id=self.scan_id,
            sandbox_id=self.sandbox_id,
            image=self.effective_image,
        )
        self.manager.ensure_image(self.effective_image)
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
            self._extract(self.snapshot, SANDBOX_WORKSPACE, user=SANDBOX_USER, what="workspace")
            if self.deps is not None:
                self._extract(self.deps, SANDBOX_DEPS, user=KEEPER_USER, what="dependencies")
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

    def _extract(self, snapshot: Snapshot, dest: str, *, user: str, what: str) -> None:
        """Stream a validated archive into ``dest`` via ``tar -x`` running as ``user``."""
        try:
            archive = snapshot.open()
        except OSError as exc:
            raise SandboxError(f"{what} snapshot is missing: {exc}") from exc
        with archive:
            outcome = self._exec(
                ["tar", "-xz", "--no-same-owner", "--no-same-permissions", "-C", dest, "-f", "-"],
                stdin=archive,
                timeout_s=_EXTRACT_TIMEOUT_S,
                cap_bytes=_GUEST_OVERHEAD_BYTES,
                user=user,
            )
        if outcome.exit_code != 0:
            raise SandboxError(
                f"{what} extraction failed (exit {outcome.exit_code}): {outcome.stderr_tail()}"
            )

    def _remove_container(self) -> None:
        """Force-remove the container (and an in-flight builder). Never raises."""
        cid = self.container_id
        self.container_id = None
        builder = self._builder_cid
        self._builder_cid = None
        if builder is not None:
            self.manager._remove_quietly(builder, f"sandbox {self.sandbox_id}: builder")
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
        ``DELETE``) must win over an in-flight ``run()`` or ``provision()``. Force-removing
        the container ends that exec's stream; the caller of ``run`` gets
        ``SandboxNotRunningError`` and an in-flight builder is removed as well.
        """
        self._destroyed = True
        self.status = "destroyed"  # refuses any operation that starts from here on
        self._remove_container()
        self.manager._forget(self)
        self.snapshot.remove()
        if self.deps is not None:
            self.deps.remove()

    # -- dependency provisioning (the builder phase) ------------------------------
    def provision(
        self, timeout_s: float | None = None, *, near: list[str] | None = None
    ) -> ProvisionResult:
        """Build the workspace's declared Python dependencies and ship them into ``/deps``.

        ``near`` lists sink files to provision from the NEAREST manifest (walk up to the
        closest one, union with the root); empty = root-manifest behaviour.

        Never raises for a failed build: the result says ``skipped`` (no manifest),
        ``disabled`` (the Executor's switch is off) or ``failed`` (build broke, timed out,
        exceeded a cap, could not be shipped) and the jail keeps running without
        third-party packages - the pre-provisioning behaviour. Only ``provisioned`` means
        the packages are importable in the jail. Re-provisioning replaces the previous set.
        """
        near = near or []
        with self._lock:
            self._require_running()
            if not self.config.deps_enabled:
                return ProvisionResult(
                    status="disabled",
                    detail="dependency provisioning is disabled on this Executor "
                    "(SANDBOX_DEPS_ENABLED=false)",
                )
            # Gate on the union of root manifests and any manifest nearest a sink (which may
            # sit deeper than the root scan reaches), so a nested app with its OWN manifest is
            # still provisioned even when the repository root declares none.
            manifests = snapshot_manifests(self.snapshot, near=near)
            if not manifests:
                return ProvisionResult(
                    status="skipped",
                    detail="no dependency manifest in the workspace (requirements*.txt, "
                    "pyproject.toml, setup.cfg, setup.py, Pipfile)",
                )
            budget = self.config.deps_timeout_s
            if timeout_s is not None:
                budget = min(budget, timeout_s)
            snapshot, result = self.manager.build_dependencies(
                self, manifests, timeout_s=max(1.0, budget), near=near
            )
            if snapshot is None:
                return result
            try:
                self._exec(
                    ["sh", "-c", f"find {SANDBOX_DEPS} -mindepth 1 -delete"],
                    timeout_s=_REAP_TIMEOUT_S,
                    cap_bytes=4096,
                    user=KEEPER_USER,
                )
                self._extract(snapshot, SANDBOX_DEPS, user=KEEPER_USER, what="dependencies")
            except SandboxError as exc:
                snapshot.remove()
                log.warning("sandbox %s: shipping dependencies failed: %s", self.sandbox_id, exc)
                return result.model_copy(
                    update={
                        "status": "failed",
                        "installed": [],
                        "detail": f"could not ship the built dependencies into the jail: {exc}",
                    }
                )
            previous, self.deps = self.deps, snapshot
            if previous is not None:
                previous.remove()
            log.info(
                "sandbox %s: provisioned %d package(s) (%d bytes) from %s",
                self.sandbox_id,
                len(result.installed),
                result.size_bytes,
                ", ".join(result.installed_from),
            )
            return result

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
        stdin: bytes | IO[bytes] | None = None,
        timeout_s: float,
        cap_bytes: int,
        user: str = SANDBOX_USER,
    ) -> _ExecOutcome:
        """Run ``cmd`` inside the jail (as the sandbox user unless told otherwise) with a
        hard deadline and output cap - :func:`_exec_in` plus the jail's error mapping."""
        cid = self._require_running()
        try:
            return _exec_in(
                self.manager.client.api,
                cid,
                cmd,
                user=user,
                workdir=SANDBOX_WORKSPACE,
                stdin=stdin,
                timeout_s=timeout_s,
                cap_bytes=cap_bytes,
            )
        except docker.errors.APIError as exc:
            raise self._translate_exec_error(exc) from exc
        except requests.exceptions.RequestException as exc:
            raise DockerUnavailableError(f"docker daemon unreachable: {exc}") from exc

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
        check_grep_pattern(pattern)
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


def snapshot_manifests(snapshot: Snapshot, *, near: list[str] | None = None) -> list[str]:
    """Dependency manifests among a validated snapshot's members (a header-only scan).

    The root scan (:func:`manifest_kind`) is depth-bounded; ``near`` additionally admits any
    manifest that sits on the path from one of those sink files up to the root (by basename,
    at any depth), so a nested application's own manifest is not missed.
    """
    near = near or []
    ancestors: set[str] = set()
    for sink in near:
        ancestors |= set(_ancestor_dirs(sink))
    found: list[str] = []
    try:
        with tarfile.open(snapshot.path, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                name = member.name.removeprefix("./")
                if manifest_kind(name) is not None:
                    found.append(name)
                    continue
                rel_dir = name.rsplit("/", 1)[0] if "/" in name else ""
                if rel_dir in ancestors and basename_manifest_kind(name.rsplit("/", 1)[-1]):
                    found.append(name)
    except (OSError, tarfile.TarError, EOFError):
        return []
    return sorted(set(found), key=lambda r: (r.count("/"), r != "requirements.txt", r))


def _ancestor_dirs(sink_rel: str) -> list[str]:
    """Every directory from the sink file's own directory up to (and including) the root."""
    parts = [p for p in sink_rel.replace("\\", "/").strip("/").split("/") if p not in ("", ".")]
    dirs = parts[:-1]
    out: list[str] = []
    while True:
        out.append("/".join(dirs))
        if not dirs:
            return out
        dirs = dirs[:-1]


def _send_stdin(raw: Any, stdin: bytes | IO[bytes], deadline: float) -> None:
    """Feed ``stdin`` to the exec socket; files go chunk by chunk under the deadline."""
    if isinstance(stdin, bytes):
        raw.settimeout(max(0.1, deadline - time.monotonic()))
        raw.sendall(stdin)
        return
    while True:
        chunk = stdin.read(SPOOL_CHUNK_BYTES)
        if not chunk:
            return
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("exec stdin deadline exceeded")
        raw.settimeout(left)
        raw.sendall(chunk)


MAX_GREP_PATTERN_CHARS = 512


def check_grep_pattern(pattern: str) -> None:
    """Trusted-side check of a user regex: shape and *syntax* only, never a match.

    This is the one place the Executor process touches the pattern. ``re.compile`` is
    a parse (linear in the pattern, bounded by the 512-character cap) and gives the
    caller a fast 422 for a malformed expression; the compiled object is discarded.
    The pattern is only ever *executed* inside the jail (``_guest.op_grep``), where a
    catastrophic-backtracking regex can burn nothing but that sandbox's own budget:
    the guest timeout, its CPU quota and its serialised operation lock (issue #99).
    """
    if not pattern or len(pattern) > MAX_GREP_PATTERN_CHARS or "\x00" in pattern:
        raise SandboxPathError(f"pattern must be 1-{MAX_GREP_PATTERN_CHARS} characters without NUL")
    try:
        re.compile(pattern)
    except (re.error, OverflowError, RecursionError) as exc:
        raise SandboxPathError(f"invalid regular expression: {exc}") from exc


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
        self._snapshot_dir: Path | None = None
        self._owns_snapshot_dir = False

    # -- snapshots ----------------------------------------------------------------
    @property
    def snapshot_dir(self) -> Path:
        """Directory holding the on-disk snapshots (created on first use, mode 0700).

        Uploads are spooled straight into it so a validated upload becomes a snapshot
        by rename - the archive bytes are never held in memory and never copied.
        """
        with self._lock:
            if self._snapshot_dir is None:
                if self.config.snapshot_dir is not None:
                    self._snapshot_dir = self.config.snapshot_dir
                    self._snapshot_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                else:
                    self._snapshot_dir = Path(tempfile.mkdtemp(prefix="ono-snapshots-"))
                    self._owns_snapshot_dir = True
            return self._snapshot_dir

    def snapshot_bytes(self) -> int:
        """Compressed bytes retained on disk for the live sandboxes (bounded by
        ``max_active * max_archive_bytes``; none of it is resident in this process)."""
        return sum(s.snapshot.size_bytes for s in self.active())

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
    def create(self, scan_id: str, workspace_dir: Path, *, runtime: str = "python") -> Sandbox:
        """Pack a local workspace directory and start a jail holding it."""
        try:
            archive = pack_workspace(workspace_dir, max_bytes=self.config.max_archive_bytes)
        except ArchiveError as exc:
            raise SandboxPathError(str(exc)) from exc
        return self.create_from_archive(scan_id, archive, runtime=runtime)

    def create_from_archive(
        self, scan_id: str, archive: bytes | Path, *, runtime: str = "python"
    ) -> Sandbox:
        """Start a jail from a gzipped tar of the workspace (validated first).

        ``archive`` is either the bytes (small, test/CLI convenience: they are written
        to the snapshot directory first) or - the service path - a file the caller
        has already spooled there. **The manager takes ownership of that file**: it is
        renamed to the sandbox's snapshot on success and deleted on any failure. ``runtime``
        ("python" or "node") picks the base image (see :func:`select_image`) - a scan with
        any JS/TS finding needs "node" for the WHOLE jail that verifies it.
        """
        if not _SCAN_ID_RE.match(scan_id):
            raise SandboxPathError("scan_id must match " + SCAN_ID_PATTERN)
        sandbox_id = f"sbx_{uuid.uuid4().hex[:12]}"
        path = self.snapshot_dir / f"{sandbox_id}.tar.gz"
        try:
            if isinstance(archive, bytes):
                if len(archive) > self.config.max_archive_bytes:
                    raise ArchiveError(
                        f"archive is larger than {self.config.max_archive_bytes} bytes"
                    )
                path.write_bytes(archive)
            else:
                shutil.move(archive, path)  # a rename when spooled into snapshot_dir
            # Validation is the only way to obtain a Snapshot: nothing below extracts
            # anything that did not pass it (issue #97).
            snapshot = Snapshot.validate(path, max_bytes=self.config.max_archive_bytes)
        except ArchiveError as exc:
            _unlink_quietly(path)
            raise SandboxPathError(str(exc)) from exc
        except OSError as exc:
            _unlink_quietly(path)
            raise SandboxError(f"cannot store workspace snapshot: {exc}") from exc

        sandbox = Sandbox(
            manager=self,
            sandbox_id=sandbox_id,
            scan_id=scan_id,
            snapshot=snapshot,
            created_at=datetime.now(tz=UTC),
            image=select_image(self.config, runtime),
        )
        try:
            with self._lock:  # register first so concurrent creates count against the limit
                if len(self._sandboxes) >= self.config.max_active:
                    raise SandboxLimitError(
                        f"too many live sandboxes ({self.config.max_active}); destroy one first"
                    )
                self._sandboxes[sandbox.sandbox_id] = sandbox
            sandbox._start_container()
        except BaseException:
            self._forget(sandbox)
            snapshot.remove()
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

    def _remove_quietly(self, cid: str, who: str) -> None:
        """Force-remove any container by id. Never raises."""
        try:
            self.client.api.remove_container(cid, v=True, force=True)
        except docker.errors.NotFound:
            pass
        except Exception as exc:
            log.warning("%s: removing container %s failed: %s", who, cid[:12], exc)
        else:
            log.info("%s: container %s removed", who, cid[:12])

    # -- the builder --------------------------------------------------------------
    def build_dependencies(
        self,
        sandbox: Sandbox,
        manifests: list[str],
        *,
        timeout_s: float,
        near: list[str] | None = None,
    ) -> tuple[Snapshot | None, ProvisionResult]:
        """Install ``sandbox``'s declared dependencies in an ephemeral builder container.

        Returns ``(validated packages archive or None, what happened)``. The builder is
        created with :func:`builder_kwargs`, receives the workspace snapshot under
        ``/build/src``, runs the shipped installer (:mod:`ono.executor._builder`) under
        ``timeout -s KILL`` and a host-side deadline, and its ``/build/site`` is tarred out
        to a spool file under the size cap and validated with the same rules as any
        workspace archive. The container is force-removed on every path.
        """
        config = self.config
        max_bytes = config.deps_max_bytes
        started = time.perf_counter()

        def failed(detail: str, **extra: Any) -> tuple[None, ProvisionResult]:
            log.warning("sandbox %s: dependency build failed: %s", sandbox.sandbox_id, detail)
            return None, ProvisionResult(
                status="failed",
                manifests=manifests,
                detail=detail,
                duration_ms=(time.perf_counter() - started) * 1000,
                **extra,
            )

        builder_image = sandbox.builder_image
        kwargs = builder_kwargs(
            config,
            scan_id=sandbox.scan_id,
            sandbox_id=sandbox.sandbox_id,
            image=builder_image,
        )
        try:
            self.ensure_image(builder_image)
            container = self.client.containers.run(**kwargs)
        except SandboxError as exc:
            return failed(f"could not start the builder container: {exc}")
        except docker.errors.APIError as exc:
            return failed(f"could not start the builder container: {_api_detail(exc)}")
        except requests.exceptions.RequestException as exc:
            raise DockerUnavailableError(f"docker daemon unreachable: {exc}") from exc
        except Exception as exc:
            return failed(f"could not start the builder container: {exc}")
        cid = str(container.id)
        sandbox._builder_cid = cid
        if sandbox._destroyed:  # destroy() raced us: never leave a builder behind
            sandbox._builder_cid = None
            self._remove_quietly(cid, f"sandbox {sandbox.sandbox_id}: builder")
            return failed("sandbox was destroyed while the build was starting")
        log.info(
            "sandbox %s: builder %s up (manifests: %s, budget %.0fs, cap %d MB)",
            sandbox.sandbox_id,
            cid[:12],
            ", ".join(manifests),
            timeout_s,
            config.deps_mb,
        )
        spool = self.snapshot_dir / f"{sandbox.sandbox_id}-deps-{uuid.uuid4().hex[:8]}.tar.gz"
        api = self.client.api
        keep = False  # the spool file survives only as a validated snapshot handed back
        try:
            # 1. the workspace snapshot goes in (the builder reads manifests / setup.py from it)
            with sandbox.snapshot.open() as archive:
                outcome = _exec_in(
                    api,
                    cid,
                    [
                        "sh",
                        "-c",
                        f"mkdir -p {BUILD_SRC} {BUILD_SITE} && exec tar -xz --no-same-owner "
                        f"--no-same-permissions -C {BUILD_SRC} -f -",
                    ],
                    user=SANDBOX_USER,
                    workdir=BUILD_DIR,
                    stdin=archive,
                    timeout_s=_EXTRACT_TIMEOUT_S,
                    cap_bytes=_GUEST_OVERHEAD_BYTES,
                )
            if outcome.exit_code != 0:
                return failed(
                    f"could not extract the workspace into the builder "
                    f"(exit {outcome.exit_code}): {outcome.stderr_tail()}"
                )
            # 2. the installer, under a hard in-container deadline and a host-side one
            build_config = {
                "src": BUILD_SRC,
                "site": BUILD_SITE,
                "max_bytes": max_bytes,
                "timeout_s": timeout_s,
                "near": list(near or []),
            }
            outcome = _exec_in(
                api,
                cid,
                [
                    "timeout",
                    "-s",
                    "KILL",
                    f"{timeout_s + _EXEC_GRACE_S:.0f}",
                    "python3",
                    "-I",
                    "-c",
                    BUILDER_SOURCE,
                    json.dumps(build_config),
                ],
                user=SANDBOX_USER,
                workdir=BUILD_SRC,
                stdin=None,
                timeout_s=timeout_s + _EXEC_GRACE_S,
                cap_bytes=_BUILD_OUTPUT_CAP,
            )
            if outcome.timed_out or outcome.exit_code in (124, 137):
                return failed(f"dependency build exceeded its {timeout_s:.0f}s budget")
            data = _parse_build_result(outcome)
            if data is None:
                tail = outcome.stderr_tail() or _last_line(
                    outcome.stdout.decode("utf-8", "replace")
                )
                return failed(f"the builder produced no result (exit {outcome.exit_code}): {tail}")
            result = ProvisionResult(
                status="provisioned" if data.get("status") == "provisioned" else "failed",
                manifests=[str(m) for m in data.get("manifests", [])] or manifests,
                installed=[str(p) for p in data.get("installed", [])],
                installed_from=[str(s) for s in data.get("installed_from", [])],
                failed=[str(f) for f in data.get("failed", [])],
                relaxed=[str(r) for r in data.get("relaxed", [])],
                warnings=[str(w) for w in data.get("warnings", [])],
                size_bytes=max(0, int(data.get("size_bytes", 0) or 0)),
                duration_ms=(time.perf_counter() - started) * 1000,
                detail=str(data.get("error") or ""),
            )
            if result.status != "provisioned":
                if data.get("status") == "skipped":
                    result = result.model_copy(
                        update={"status": "skipped", "detail": "no dependency manifest found"}
                    )
                else:
                    log.warning(
                        "sandbox %s: dependency build failed: %s", sandbox.sandbox_id, result.detail
                    )
                return None, result
            # 3. the ONLY output leaves: the install target, as a bounded tar on disk
            with spool.open("wb") as sink:
                outcome = _exec_in(
                    api,
                    cid,
                    ["tar", "-cz", "-C", BUILD_SITE, "."],
                    user=SANDBOX_USER,
                    workdir=BUILD_DIR,
                    stdin=None,
                    timeout_s=_EXTRACT_TIMEOUT_S,
                    cap_bytes=max_bytes,
                    stdout_sink=sink,
                )
            if outcome.truncated:
                return failed(
                    f"built dependencies are larger than the cap of {max_bytes} bytes",
                    installed=result.installed,
                )
            if outcome.exit_code != 0:
                return failed(
                    f"could not archive the built dependencies (exit {outcome.exit_code}): "
                    f"{outcome.stderr_tail()}"
                )
            try:
                snapshot = Snapshot.validate(spool, max_bytes=max_bytes)
            except ArchiveError as exc:
                return failed(f"the built dependencies archive was rejected: {exc}")
            keep = True
            return snapshot, result.model_copy(
                update={"duration_ms": (time.perf_counter() - started) * 1000}
            )
        except docker.errors.APIError as exc:
            return failed(f"builder exec failed: {_api_detail(exc)}")
        except requests.exceptions.RequestException as exc:
            raise DockerUnavailableError(f"docker daemon unreachable: {exc}") from exc
        except SandboxError as exc:
            return failed(f"builder failed: {exc}")
        except OSError as exc:
            return failed(f"cannot spool the built dependencies: {exc}")
        finally:
            sandbox._builder_cid = None
            self._remove_quietly(cid, f"sandbox {sandbox.sandbox_id}: builder")
            if not keep:
                _unlink_quietly(spool)

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
            limit = min(max_age, _container_ttl(container, max_age))
            if created is None or now - created <= limit:
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
        with self._lock:
            snapshot_dir, owned = self._snapshot_dir, self._owns_snapshot_dir
            self._snapshot_dir, self._owns_snapshot_dir = None, False
        if snapshot_dir is not None and owned:
            shutil.rmtree(snapshot_dir, ignore_errors=True)


def _unlink_quietly(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()


def _parse_build_result(outcome: _ExecOutcome) -> dict[str, Any] | None:
    text = outcome.stdout.decode("utf-8", "replace")
    line = next(
        (ln for ln in reversed(text.splitlines()) if ln.startswith(BUILD_RESULT_MARKER)), None
    )
    if line is None:
        return None
    try:
        data = json.loads(line[len(BUILD_RESULT_MARKER) :])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _container_ttl(container: Any, default: float) -> float:
    labels = container.labels or {}
    raw = labels.get(LABEL_TTL)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


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
