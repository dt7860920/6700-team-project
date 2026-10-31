"""Typed client for the Executor service - what the orchestrator (step 3b) will use.

Nothing here touches Docker. The client packs a local workspace into a gzipped tar,
uploads it, and then mirrors the sandbox operations one-to-one, returning the same
pydantic models the service emits. Every call has a timeout; every failure is a
subclass of :class:`ExecutorError`.

    client = ExecutorClient("http://executor:8081", token)
    with client.sandbox("scn_123", Path(".ono-workspace/scn_123")) as sbx:
        sbx.grep("execute\\(")
        sbx.apply_patch(diff)
        sbx.run_tests()
        sbx.reset()
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

import httpx

from ono.executor.archive import ArchiveError, pack_workspace
from ono.executor.models import (
    ExecutorHealth,
    FileContent,
    GrepResult,
    PatchResult,
    RunResult,
    SandboxInfo,
    TestRunResult,
    TreeListing,
)

__all__ = [
    "ExecutorAuthError",
    "ExecutorClient",
    "ExecutorError",
    "ExecutorRequestError",
    "ExecutorUnavailableError",
    "SandboxHandle",
    "SandboxNotFoundError",
    "SandboxNotRunningError",
]

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_S = 30.0
_RUN_SLACK_S = 30.0  # request timeout for run() = command budget + this


class ExecutorError(RuntimeError):
    """Base class for every client failure."""


class ExecutorUnavailableError(ExecutorError):
    """The Executor could not be reached (connection refused, DNS, read timeout)."""


class ExecutorAuthError(ExecutorError):
    """401: missing or wrong token."""


class SandboxNotFoundError(ExecutorError):
    """404: the sandbox id is unknown (destroyed, swept, or never existed)."""


class SandboxNotRunningError(ExecutorError):
    """409: the jail died (OOM / fork bomb / ...); ``reset()`` recreates it."""


class ExecutorRequestError(ExecutorError):
    """Any other non-2xx answer; ``status_code`` and ``detail`` carry the specifics."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"executor returned {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class ExecutorClient:
    """Thin, typed HTTP client. Safe to share across threads (httpx.Client is)."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        max_archive_bytes: int = 200_000_000,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not token:
            msg = "ExecutorClient needs the executor token"
            raise ValueError(msg)
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.max_archive_bytes = max_archive_bytes
        self._http = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {token}", "User-Agent": "ono-executor-client"},
            timeout=timeout_s,
            transport=transport,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- transport ----------------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        content: bytes | None = None,
        params: dict[str, str] | None = None,
        timeout_s: float | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        try:
            response = self._http.request(
                method,
                path,
                json=json,
                content=content,
                params=params,
                headers=headers,
                timeout=timeout_s if timeout_s is not None else self.timeout_s,
            )
        except httpx.TimeoutException as exc:
            raise ExecutorUnavailableError(f"executor timed out on {method} {path}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise ExecutorUnavailableError(
                f"executor unreachable on {method} {path}: {exc}"
            ) from exc
        if response.is_success:
            return response
        detail = _detail(response)
        if response.status_code == 401:
            raise ExecutorAuthError(f"executor rejected the token: {detail}")
        if response.status_code == 404:
            raise SandboxNotFoundError(detail)
        if response.status_code == 409:
            raise SandboxNotRunningError(detail)
        raise ExecutorRequestError(response.status_code, detail)

    # -- service ------------------------------------------------------------------
    def health(self) -> ExecutorHealth:
        return ExecutorHealth.model_validate(self._request("GET", "/health").json())

    def list_sandboxes(self) -> list[SandboxInfo]:
        data = self._request("GET", "/sandboxes").json()
        return [SandboxInfo.model_validate(item) for item in data]

    # -- lifecycle ----------------------------------------------------------------
    def create(self, scan_id: str, workspace_dir: Path) -> SandboxInfo:
        """Pack ``workspace_dir`` and create a sandbox holding it."""
        try:
            archive = pack_workspace(workspace_dir, max_bytes=self.max_archive_bytes)
        except ArchiveError as exc:
            raise ExecutorRequestError(413, str(exc)) from exc
        return self.create_from_archive(scan_id, archive)

    def create_from_archive(self, scan_id: str, archive: bytes) -> SandboxInfo:
        response = self._request(
            "POST",
            "/sandboxes",
            content=archive,
            params={"scan_id": scan_id},
            headers={"Content-Type": "application/gzip"},
            timeout_s=max(self.timeout_s, 300.0),  # image pull + extraction can be slow
        )
        return SandboxInfo.model_validate(response.json())

    def get(self, sandbox_id: str) -> SandboxInfo:
        return SandboxInfo.model_validate(self._request("GET", f"/sandboxes/{sandbox_id}").json())

    def destroy(self, sandbox_id: str) -> None:
        """Tear the sandbox down. Idempotent from the caller's view: an unknown id is fine."""
        with contextlib.suppress(SandboxNotFoundError):
            self._request("DELETE", f"/sandboxes/{sandbox_id}")

    def reset(self, sandbox_id: str) -> SandboxInfo:
        response = self._request(
            "POST", f"/sandboxes/{sandbox_id}/reset", timeout_s=max(self.timeout_s, 300.0)
        )
        return SandboxInfo.model_validate(response.json())

    # -- operations ---------------------------------------------------------------
    def read_file(self, sandbox_id: str, path: str) -> FileContent:
        response = self._request("POST", f"/sandboxes/{sandbox_id}/read", json={"path": path})
        return FileContent.model_validate(response.json())

    def read_lines(self, sandbox_id: str, path: str, start: int, end: int) -> FileContent:
        response = self._request(
            "POST",
            f"/sandboxes/{sandbox_id}/read",
            json={"path": path, "start": start, "end": end},
        )
        return FileContent.model_validate(response.json())

    def tree(
        self, sandbox_id: str, path: str = ".", *, max_entries: int = 2000, max_depth: int = 12
    ) -> TreeListing:
        response = self._request(
            "POST",
            f"/sandboxes/{sandbox_id}/tree",
            json={"path": path, "max_entries": max_entries, "max_depth": max_depth},
            timeout_s=max(self.timeout_s, 90.0),
        )
        return TreeListing.model_validate(response.json())

    def grep(
        self,
        sandbox_id: str,
        pattern: str,
        path: str = ".",
        *,
        ignore_case: bool = False,
        max_matches: int = 200,
    ) -> GrepResult:
        response = self._request(
            "POST",
            f"/sandboxes/{sandbox_id}/grep",
            json={
                "pattern": pattern,
                "path": path,
                "ignore_case": ignore_case,
                "max_matches": max_matches,
            },
            timeout_s=max(self.timeout_s, 90.0),
        )
        return GrepResult.model_validate(response.json())

    def apply_patch(self, sandbox_id: str, diff: str) -> PatchResult:
        response = self._request(
            "POST",
            f"/sandboxes/{sandbox_id}/apply_patch",
            json={"diff": diff},
            timeout_s=max(self.timeout_s, 90.0),
        )
        return PatchResult.model_validate(response.json())

    def run(self, sandbox_id: str, cmd: str, timeout_s: float | None = None) -> RunResult:
        body: dict[str, Any] = {"cmd": cmd}
        if timeout_s is not None:
            body["timeout_s"] = timeout_s
        response = self._request(
            "POST",
            f"/sandboxes/{sandbox_id}/run",
            json=body,
            timeout_s=(timeout_s or self.timeout_s) + _RUN_SLACK_S,
        )
        return RunResult.model_validate(response.json())

    def run_tests(self, sandbox_id: str, timeout_s: float | None = None) -> TestRunResult:
        body: dict[str, Any] = {}
        if timeout_s is not None:
            body["timeout_s"] = timeout_s
        response = self._request(
            "POST",
            f"/sandboxes/{sandbox_id}/run_tests",
            json=body,
            timeout_s=(timeout_s or self.timeout_s) + _RUN_SLACK_S,
        )
        return TestRunResult.model_validate(response.json())

    # -- convenience ----------------------------------------------------------------
    @contextmanager
    def sandbox(self, scan_id: str, workspace_dir: Path) -> Iterator[SandboxHandle]:
        """``with client.sandbox(...) as sbx:`` - destroyed on exit, even on error."""
        info = self.create(scan_id, workspace_dir)
        handle = SandboxHandle(client=self, info=info)
        try:
            yield handle
        finally:
            self.destroy(info.sandbox_id)


@dataclass(slots=True)
class SandboxHandle:
    """A bound view of one sandbox: the client methods minus the ``sandbox_id`` argument."""

    client: ExecutorClient
    info: SandboxInfo

    @property
    def sandbox_id(self) -> str:
        return self.info.sandbox_id

    def read_file(self, path: str) -> FileContent:
        return self.client.read_file(self.sandbox_id, path)

    def read_lines(self, path: str, start: int, end: int) -> FileContent:
        return self.client.read_lines(self.sandbox_id, path, start, end)

    def tree(self, path: str = ".", *, max_entries: int = 2000, max_depth: int = 12) -> TreeListing:
        return self.client.tree(self.sandbox_id, path, max_entries=max_entries, max_depth=max_depth)

    def grep(
        self, pattern: str, path: str = ".", *, ignore_case: bool = False, max_matches: int = 200
    ) -> GrepResult:
        return self.client.grep(
            self.sandbox_id, pattern, path, ignore_case=ignore_case, max_matches=max_matches
        )

    def apply_patch(self, diff: str) -> PatchResult:
        return self.client.apply_patch(self.sandbox_id, diff)

    def run(self, cmd: str, timeout_s: float | None = None) -> RunResult:
        return self.client.run(self.sandbox_id, cmd, timeout_s)

    def run_tests(self, timeout_s: float | None = None) -> TestRunResult:
        return self.client.run_tests(self.sandbox_id, timeout_s)

    def reset(self) -> SandboxInfo:
        self.info = self.client.reset(self.sandbox_id)
        return self.info

    def destroy(self) -> None:
        self.client.destroy(self.sandbox_id)


def _detail(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return response.text[:300]
    if isinstance(data, dict) and "detail" in data:
        return str(data["detail"])[:1000]
    return response.text[:300]
