"""A fake docker-py client for the unit tests (CI has no Docker).

It mimics exactly the surface :mod:`ono.executor.sandbox` uses - ``containers.run``,
``containers.list``, ``images.get/pull``, ``api.exec_create/exec_start/exec_inspect/
inspect_container/remove_container``, ``ping`` - and is realistic where it matters:

* the ``tar -x`` exec really extracts the uploaded archive into a temp "workspace"
  (``-C /workspace``, ``-C /deps`` and ``-C /build/src`` map to per-container directories);
* ``python3 -I -S -c <guest> ...`` execs run the real in-jail helper against it;
* ``timeout ... sh -c <cmd>`` execs are routed to a programmable handler;
* the BUILDER's execs run the real :mod:`ono.executor._builder` installer against the
  extracted snapshot with a *fake pip* (``pip_handler``) that lays down ``<name>/`` +
  ``<name>.dist-info`` for every requirement, then ``tar -cz`` the fake site dir out;
* the exec socket speaks Docker's multiplexed frame protocol, lazily, so stdin
  written by the sandbox layer is seen by the fake "process".
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import struct
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

import docker.errors
import requests

from ono.executor import _builder, _guest

RunHandler = Callable[[str], tuple[int, bytes, bytes]]
PipHandler = Callable[[list[str], Path], tuple[int, str]]
"""``(pip args after 'install', site dir) -> (exit code, output)`` - the fake pip."""


def frame(stream: int, payload: bytes) -> bytes:
    return struct.pack(">BxxxL", stream, len(payload)) + payload


def api_error(code: int, message: str) -> docker.errors.APIError:
    response = requests.Response()
    response.status_code = code
    response._content = json.dumps({"message": message}).encode()
    return docker.errors.APIError(message, response=response, explanation=message)


class FakeResponse:
    closed = False

    def close(self) -> None:
        self.closed = True


class FakeRaw:
    """The ``_sock`` underneath docker-py's SocketIO: frames are produced on first recv.

    Stdin written by the sandbox layer is spooled to a temp *file*, not kept in memory,
    so a test measuring the Executor's own memory footprint is not polluted by the fake.
    """

    def __init__(self, exec_: FakeExec, docker_: FakeDocker) -> None:
        self.exec = exec_
        self.docker = docker_
        self.sent: IO[bytes] = tempfile.TemporaryFile()  # noqa: SIM115 - closed in recv()
        self.sent_bytes = 0
        self.buf = b""
        self.pos = 0
        self.produced = False
        self.timeout: float | None = None
        self.closed = False
        self.shutdown_called = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent.write(data)
        self.sent_bytes += len(data)

    def shutdown(self, _how: int) -> None:
        self.shutdown_called = True

    def recv(self, n: int) -> bytes:
        if not self.produced:
            self.produced = True
            self.sent.seek(0)
            code, out, err = self.docker.perform(self.exec, self.sent)
            self.sent.close()
            self.exec.exit_code = code
            self.exec.running = False
            self.buf = b"".join(
                [frame(1, out[i : i + 4096]) for i in range(0, len(out), 4096)]
                + [frame(2, err[i : i + 4096]) for i in range(0, len(err), 4096)]
            )
        if self.exec.hang:
            raise TimeoutError("fake socket timeout")
        chunk = self.buf[self.pos : self.pos + n]
        self.pos += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeSock:
    def __init__(self, raw: FakeRaw) -> None:
        self._sock = raw
        self._response = FakeResponse()
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeExec:
    def __init__(self, exec_id: str, container_id: str, cmd: list[str], user: str) -> None:
        self.id = exec_id
        self.container_id = container_id
        self.cmd = cmd
        self.user = user
        self.exit_code: int | None = None
        self.running = True
        self.hang = False
        self.stdin = b""
        """The first 64 KiB of what the sandbox layer wrote to stdin (for assertions)."""
        self.stdin_bytes = 0
        self.stdin_sha256 = ""


class FakeContainer:
    def __init__(self, docker_: FakeDocker, cid: str, labels: dict[str, str], created: str) -> None:
        self.docker = docker_
        self.id = cid
        self.labels = labels
        self.attrs = {"Created": created, "HostConfig": {}}
        self.remove_calls: list[dict[str, Any]] = []

    def remove(self, v: bool = False, force: bool = False) -> None:
        self.remove_calls.append({"v": v, "force": force})
        self.docker.removed.append(self.id)
        if self.docker.remove_error is not None:
            raise self.docker.remove_error
        self.docker.live.pop(self.id, None)


class _Containers:
    def __init__(self, docker_: FakeDocker) -> None:
        self.docker = docker_

    def run(self, **kwargs: Any) -> FakeContainer:
        self.docker.run_calls.append(kwargs)
        if self.docker.run_error is not None:
            raise self.docker.run_error
        self.docker.counter += 1
        cid = f"{self.docker.counter:02d}" + "c" * 62
        container = FakeContainer(
            self.docker, cid, dict(kwargs.get("labels", {})), "2026-10-31T00:00:00.123456789Z"
        )
        self.docker.live[cid] = container
        self.docker.workspaces[cid] = self.docker.new_workspace(cid)
        if kwargs.get("labels", {}).get("ono.builder") == "1":
            self.docker.builders.append(cid)
        return container

    def list(self, all: bool = False, filters: dict[str, str] | None = None) -> list[FakeContainer]:
        self.docker.list_calls.append({"all": all, "filters": filters})
        return list(self.docker.live.values()) + list(self.docker.orphans)


class _Images:
    def __init__(self, docker_: FakeDocker) -> None:
        self.docker = docker_

    def get(self, name: str) -> dict[str, str]:
        if name in self.docker.missing_images:
            raise docker.errors.ImageNotFound(f"no such image: {name}")
        return {"Id": name}

    def pull(self, name: str) -> dict[str, str]:
        self.docker.pulled.append(name)
        if self.docker.pull_error is not None:
            raise self.docker.pull_error
        self.docker.missing_images.discard(name)
        return {"Id": name}


class _Api:
    def __init__(self, docker_: FakeDocker) -> None:
        self.docker = docker_

    def exec_create(
        self,
        container_id: str,
        cmd: list[str],
        stdin: bool = False,
        user: str | None = None,
        workdir: str | None = None,
    ) -> dict[str, str]:
        d = self.docker
        if d.exec_create_error is not None:
            raise d.exec_create_error
        if container_id not in d.live:
            raise api_error(409, f"container {container_id} is not running")
        d.counter += 1
        exec_id = f"exec{d.counter}"
        exec_ = FakeExec(exec_id, container_id, list(cmd), user or "")
        exec_.hang = d.hang_next_exec and cmd[0] == "timeout"
        d.execs[exec_id] = exec_
        d.exec_log.append(exec_)
        return {"Id": exec_id}

    def exec_start(self, exec_id: str, socket: bool = False) -> FakeSock:
        return FakeSock(FakeRaw(self.docker.execs[exec_id], self.docker))

    def exec_inspect(self, exec_id: str) -> dict[str, Any]:
        exec_ = self.docker.execs[exec_id]
        return {"ExitCode": exec_.exit_code, "Running": exec_.running}

    def inspect_container(self, container_id: str) -> dict[str, Any]:
        return {"State": {"Running": container_id in self.docker.live}}

    def remove_container(self, container_id: str, v: bool = False, force: bool = False) -> None:
        self.docker.removed.append(container_id)
        if self.docker.remove_error is not None:
            raise self.docker.remove_error
        if container_id not in self.docker.live:
            raise docker.errors.NotFound(f"no such container: {container_id}")
        self.docker.live.pop(container_id)


class FakeDocker:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.counter = 0
        self.live: dict[str, FakeContainer] = {}
        self.orphans: list[FakeContainer] = []
        self.workspaces: dict[str, Path] = {}
        self.execs: dict[str, FakeExec] = {}
        self.exec_log: list[FakeExec] = []
        self.run_calls: list[dict[str, Any]] = []
        self.list_calls: list[dict[str, Any]] = []
        self.removed: list[str] = []
        self.pulled: list[str] = []
        self.missing_images: set[str] = set()
        self.builders: list[str] = []  # ids of every builder container ever started
        self.oom_kills = 0
        # knobs
        self.run_handler: RunHandler = lambda cmd: (0, f"ran: {cmd}\n".encode(), b"")
        self.pip_handler: PipHandler = self.fake_pip
        self.pip_fail: set[str] = set()  # requirement names the fake pip refuses
        self.pip_fail_all = False
        self.pip_package_bytes = 64  # size of each fake package's __init__.py
        self.build_result_override: str | None = None  # raw stdout of the builder exec
        self.run_error: Exception | None = None
        self.pull_error: Exception | None = None
        self.remove_error: Exception | None = None
        self.exec_create_error: Exception | None = None
        self.reap_fails = False
        self.tar_fails = False
        self.hang_next_exec = False
        self.ping_ok = True
        self.containers = _Containers(self)
        self.images = _Images(self)
        self.api = _Api(self)

    def ping(self) -> bool:
        if not self.ping_ok:
            raise requests.exceptions.ConnectionError("no daemon")
        return True

    def new_workspace(self, cid: str) -> Path:
        ws = self.root / cid[:4] / "workspace"
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    def workspace(self, container_id: str) -> Path:
        return self.workspaces[container_id]

    def container_dir(self, container_id: str, path: str) -> Path:
        """The host directory standing in for ``path`` inside the fake container."""
        return self.workspaces[container_id].parent / path.strip("/")

    def deps_dir(self, container_id: str) -> Path:
        return self.container_dir(container_id, "/deps")

    # -- the fake pip -----------------------------------------------------------
    def fake_pip(self, args: list[str], site: Path) -> tuple[int, str]:
        """Lay down a fake package per requirement; refuse the ones in ``pip_fail``."""
        if self.pip_fail_all:
            return 1, "ERROR: fake pip refuses everything\n"
        reqs: list[str] = []
        i = 0
        while i < len(args):
            if args[i] == "-r":
                reqs.extend(_builder.requirement_lines(args[i + 1]))
                i += 2
                continue
            reqs.append(args[i])
            i += 1
        for req in reqs:
            name = _builder.requirement_name(req)
            if name is None:
                return 1, f"ERROR: fake pip cannot install {req!r}\n"
            bare = name.split("[", 1)[0].lower().replace("-", "_")
            if bare in self.pip_fail or (
                _builder.is_pinned(req) and f"{bare}{_spec_of(req)}" in self.pip_fail
            ):
                return 1, f"ERROR: No matching distribution found for {req}\n"
            pkg = site / bare
            pkg.mkdir(parents=True, exist_ok=True)
            (pkg / "__init__.py").write_text(
                f"NAME = {bare!r}\nPAD = {'x' * self.pip_package_bytes!r}\n"
            )
            info = site / f"{bare}-1.0.dist-info"
            info.mkdir(exist_ok=True)
            (info / "METADATA").write_text(f"Name: {bare}\nVersion: 1.0\n")
        return 0, "Successfully installed " + " ".join(reqs) + "\n"

    def add_orphan(self, cid: str, labels: dict[str, str], created: str) -> FakeContainer:
        container = FakeContainer(self, cid, labels, created)
        self.orphans.append(container)
        return container

    # -- the fake "process" ---------------------------------------------------
    def perform(self, exec_: FakeExec, stdin: IO[bytes]) -> tuple[int, bytes, bytes]:
        digest = hashlib.sha256()
        exec_.stdin = b""
        while chunk := stdin.read(64 * 1024):  # small buffers: keep the fake out of RAM tests
            if not exec_.stdin:
                exec_.stdin = chunk
            exec_.stdin_bytes += len(chunk)
            digest.update(chunk)
        exec_.stdin_sha256 = digest.hexdigest()
        stdin.seek(0)
        cmd = exec_.cmd
        cid = exec_.container_id
        ws = self.workspaces[cid]
        if cmd[0] == "tar" and "-xz" in cmd:
            if self.tar_fails:
                return 2, b"", b"tar: boom\n"
            dest = self.container_dir(cid, cmd[cmd.index("-C") + 1])
            dest.mkdir(parents=True, exist_ok=True)
            with tarfile.open(fileobj=stdin, mode="r:gz") as tar:
                tar.extractall(dest, filter="data")
            return 0, b"", b""
        if cmd[0] == "tar" and "-cz" in cmd:  # the builder's output leaves as a tar
            src = self.container_dir(cid, cmd[cmd.index("-C") + 1])
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                tar.add(src, arcname=".")
            return 0, buf.getvalue(), b""
        if cmd[0] == "sh" and cmd[2].startswith("mkdir -p /build/src"):  # into the builder
            for sub in ("/build/src", "/build/site"):
                self.container_dir(cid, sub).mkdir(parents=True, exist_ok=True)
            with tarfile.open(fileobj=stdin, mode="r:gz") as tar:
                tar.extractall(self.container_dir(cid, "/build/src"), filter="data")
            return 0, b"", b""
        if cmd[0] == "sh" and cmd[2].startswith("find /deps -mindepth 1 -delete"):
            deps = self.deps_dir(cid)
            if deps.exists():
                shutil.rmtree(deps)
            deps.mkdir(parents=True)
            return 0, b"", b""
        if cmd[0] == "python3" and cmd[1:4] == ["-I", "-S", "-c"]:
            assert cmd[4] == _guest_source(), "guest source must be shipped verbatim"
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = _guest.main(cmd[5:], root=str(ws), stdin=stdin)
            return code, out.getvalue().encode(), b""
        if cmd[0] == "sh" and "kill -9 -1" in cmd[2]:
            return (1, b"", b"nope\n") if self.reap_fails else (0, b"", b"")
        if cmd[0] == "sh" and "memory.events" in cmd[2]:
            return 0, f"low 0\nhigh 0\nmax 0\noom 0\noom_kill {self.oom_kills}\n".encode(), b""
        if cmd[0] == "timeout" and cmd[4:7] == ["python3", "-I", "-c"]:  # the builder
            assert cmd[7] == _builder_source(), "builder source must be shipped verbatim"
            return self.perform_build(cid, json.loads(cmd[8]))
        if cmd[0] == "timeout":
            assert cmd[1:3] == ["-s", "KILL"] and cmd[4:6] == ["sh", "-c"]
            return self.run_handler(cmd[6])
        raise AssertionError(f"unexpected exec: {cmd}")

    def perform_build(self, cid: str, config: dict[str, Any]) -> tuple[int, bytes, bytes]:
        """Run the real installer against the fake builder dirs, pip replaced by the fake."""
        if self.build_result_override is not None:
            return 0, self.build_result_override.encode(), b""
        site = self.container_dir(cid, str(config["site"]))
        config = {
            **config,
            "src": str(self.container_dir(cid, str(config["src"]))),
            "site": str(site),
        }

        def pip(args: list[str], _timeout_s: float) -> tuple[int, str]:
            return self.pip_handler(args, site)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = _builder.main([json.dumps(config)], pip=pip)
        return code, out.getvalue().encode(), b""

    # -- assertions -------------------------------------------------------------
    def user_commands(self) -> list[str]:
        return [e.cmd[6] for e in self.exec_log if e.cmd[0] == "timeout"]

    def reaps_after(self, index: int) -> int:
        return sum(
            1 for e in self.exec_log[index:] if e.cmd[0] == "sh" and "kill -9 -1" in e.cmd[2]
        )


def _guest_source() -> str:
    from ono.executor.sandbox import GUEST_SOURCE

    return GUEST_SOURCE


def _builder_source() -> str:
    from ono.executor.sandbox import BUILDER_SOURCE

    return BUILDER_SOURCE


def _spec_of(req: str) -> str:
    """``flask==1.0`` -> ``==1.0`` (what ``pip_fail`` entries like ``flask==1.0`` match on)."""
    match = _builder._NAME_RE.match(req.split(";", 1)[0])
    return match.group(3).strip().replace(" ", "") if match and match.group(3) else ""


def read_build_result(stdout: bytes) -> dict[str, Any]:
    line = next(
        ln for ln in reversed(stdout.decode().splitlines()) if ln.startswith(_builder.RESULT_MARKER)
    )
    data: dict[str, Any] = json.loads(line[len(_builder.RESULT_MARKER) :])
    return data
