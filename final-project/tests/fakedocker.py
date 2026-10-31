"""A fake docker-py client for the unit tests (CI has no Docker).

It mimics exactly the surface :mod:`ono.executor.sandbox` uses - ``containers.run``,
``containers.list``, ``images.get/pull``, ``api.exec_create/exec_start/exec_inspect/
inspect_container/remove_container``, ``ping`` - and is realistic where it matters:

* the ``tar -x`` exec really extracts the uploaded archive into a temp "workspace";
* ``python3 -I -S -c <guest> ...`` execs run the real in-jail helper against it;
* ``timeout ... sh -c <cmd>`` execs are routed to a programmable handler;
* the exec socket speaks Docker's multiplexed frame protocol, lazily, so stdin
  written by the sandbox layer is seen by the fake "process".
"""

from __future__ import annotations

import contextlib
import io
import json
import struct
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import docker.errors
import requests

from ono.executor import _guest

RunHandler = Callable[[str], tuple[int, bytes, bytes]]


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
    """The ``_sock`` underneath docker-py's SocketIO: frames are produced on first recv."""

    def __init__(self, exec_: FakeExec, docker_: FakeDocker) -> None:
        self.exec = exec_
        self.docker = docker_
        self.sent = bytearray()
        self.buf = b""
        self.pos = 0
        self.produced = False
        self.timeout: float | None = None
        self.closed = False
        self.shutdown_called = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def shutdown(self, _how: int) -> None:
        self.shutdown_called = True

    def recv(self, n: int) -> bytes:
        if not self.produced:
            self.produced = True
            code, out, err = self.docker.perform(self.exec, bytes(self.sent))
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
        self.oom_kills = 0
        # knobs
        self.run_handler: RunHandler = lambda cmd: (0, f"ran: {cmd}\n".encode(), b"")
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
        ws = self.root / cid[:4]
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    def workspace(self, container_id: str) -> Path:
        return self.workspaces[container_id]

    def add_orphan(self, cid: str, labels: dict[str, str], created: str) -> FakeContainer:
        container = FakeContainer(self, cid, labels, created)
        self.orphans.append(container)
        return container

    # -- the fake "process" ---------------------------------------------------
    def perform(self, exec_: FakeExec, stdin: bytes) -> tuple[int, bytes, bytes]:
        exec_.stdin = stdin
        cmd = exec_.cmd
        ws = self.workspaces[exec_.container_id]
        if cmd[0] == "tar":
            if self.tar_fails:
                return 2, b"", b"tar: boom\n"
            with tarfile.open(fileobj=io.BytesIO(stdin), mode="r:gz") as tar:
                tar.extractall(ws, filter="data")
            return 0, b"", b""
        if cmd[0] == "python3" and cmd[1:4] == ["-I", "-S", "-c"]:
            assert cmd[4] == _guest_source(), "guest source must be shipped verbatim"
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = _guest.main(cmd[5:], root=str(ws), stdin=io.BytesIO(stdin))
            return code, out.getvalue().encode(), b""
        if cmd[0] == "sh" and "kill -9 -1" in cmd[2]:
            return (1, b"", b"nope\n") if self.reap_fails else (0, b"", b"")
        if cmd[0] == "sh" and "memory.events" in cmd[2]:
            return 0, f"low 0\nhigh 0\nmax 0\noom 0\noom_kill {self.oom_kills}\n".encode(), b""
        if cmd[0] == "timeout":
            assert cmd[1:3] == ["-s", "KILL"] and cmd[4:6] == ["sh", "-c"]
            return self.run_handler(cmd[6])
        raise AssertionError(f"unexpected exec: {cmd}")

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
