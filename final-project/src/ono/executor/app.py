"""The Executor service: a small, privileged, internal-only FastAPI app.

It is the *only* process that holds the Docker socket, so it is kept deliberately
tiny: validate input, hand it to :class:`~ono.executor.sandbox.SandboxManager`, map
errors. It must never be published to the internet - Compose puts it on an internal
network with no ``ports:`` block - and every endpoint except ``/health`` requires
``Authorization: Bearer <executor_token>``. The service refuses to start without a token.

    GET    /health                          liveness (no auth; reports Docker reachability)
    GET    /sandboxes                       list live sandboxes
    POST   /sandboxes?scan_id=...           create: body = gzipped tar of the workspace
    GET    /sandboxes/{id}                  metadata
    DELETE /sandboxes/{id}                  destroy (teardown always succeeds)
    POST   /sandboxes/{id}/read             read a file / line range
    POST   /sandboxes/{id}/tree             list the workspace
    POST   /sandboxes/{id}/grep             regex search
    POST   /sandboxes/{id}/apply_patch      apply a unified diff
    POST   /sandboxes/{id}/run              run a shell command (hard timeout, capped output)
    POST   /sandboxes/{id}/run_tests        detect + run the repo's test command
    POST   /sandboxes/{id}/reset            back to the clean snapshot (also revives a dead jail)
"""

from __future__ import annotations

import contextlib
import hmac
import logging
import os
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ono import __version__
from ono.config import Settings, configure_logging, get_settings
from ono.executor.models import (
    SCAN_ID_PATTERN,
    ExecutorHealth,
    FileContent,
    GrepRequest,
    GrepResult,
    PatchRequest,
    PatchResult,
    ReadRequest,
    RunRequest,
    RunResult,
    SandboxInfo,
    TestRunRequest,
    TestRunResult,
    TreeListing,
    TreeRequest,
)
from ono.executor.sandbox import (
    DockerUnavailableError,
    JailConfig,
    Sandbox,
    SandboxError,
    SandboxLimitError,
    SandboxManager,
    SandboxNotRunningError,
    SandboxOperationError,
    SandboxPathError,
)
from ono.models import ErrorResponse

log = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False, description="The shared executor_token.")


def _manager(request: Request) -> SandboxManager:
    manager: SandboxManager = request.app.state.manager
    return manager


def _expected_token(request: Request) -> str:
    token: str = request.app.state.token
    return token


def _require_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    """Constant-time bearer check. Missing, malformed and wrong tokens all get a bare 401."""
    expected = _expected_token(request)
    presented = credentials.credentials if credentials is not None else ""
    if credentials is None or credentials.scheme.lower() != "bearer" or not presented:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        log.warning("executor: rejected request with a wrong token from %s", request.client)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _sandbox(sandbox_id: str, manager: Annotated[SandboxManager, Depends(_manager)]) -> Sandbox:
    sandbox = manager.get(sandbox_id)
    if sandbox is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"sandbox {sandbox_id!r} not found")
    return sandbox


ManagerDep = Annotated[SandboxManager, Depends(_manager)]
SandboxDep = Annotated[Sandbox, Depends(_sandbox)]
AUTH = [Depends(_require_token)]
_UNPROCESSABLE = 422  # starlette renamed the constant; the literal is stable
_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse, "description": "missing or invalid bearer token"},
    404: {"model": ErrorResponse, "description": "unknown sandbox"},
    409: {"model": ErrorResponse, "description": "sandbox container is not running (reset it)"},
    413: {"model": ErrorResponse, "description": "request body larger than executor_max_body_mb"},
}

_Scope = MutableMapping[str, Any]
_Message = MutableMapping[str, Any]
_Receive = Callable[[], Awaitable[_Message]]
_Send = Callable[[_Message], Awaitable[None]]
_ASGIApp = Callable[[_Scope, _Receive, _Send], Awaitable[None]]


class BodyTooLargeError(Exception):
    """Raised inside ``receive()`` by :class:`BodyLimitMiddleware` once the cap is crossed."""

    def __init__(self, max_bytes: int) -> None:
        super().__init__(f"request body is larger than {max_bytes} bytes")
        self.max_bytes = max_bytes


class BodyLimitMiddleware:
    """Pure-ASGI request-body cap for the JSON operation routes (issue #98).

    The archive upload (``POST /sandboxes``) is exempt: it streams its body to disk
    under its own cap (``max_clone_mb``). Every other request is bounded by
    ``max_bytes`` - a declared ``Content-Length`` above it is refused before a byte is
    read, and a chunked body is cut off as soon as the running total crosses the cap
    (the bytes received so far are the most it can ever cost). Pydantic's
    ``max_length`` limits still apply afterwards; this is the outer, byte-level wall.

    The 413 is produced *here*: FastAPI turns any exception raised while it reads the
    body into a generic 400, so the middleware swaps that response for its own.
    """

    def __init__(self, app: _ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    @staticmethod
    def exempt(scope: _Scope) -> bool:
        return bool(scope.get("method") == "POST" and scope.get("path") == "/sandboxes")

    async def __call__(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] != "http" or self.exempt(scope):
            await self.app(scope, receive, send)
            return
        too_large = _error(
            status.HTTP_413_CONTENT_TOO_LARGE, str(BodyTooLargeError(self.max_bytes))
        )
        declared = _content_length(scope)
        if declared is not None and declared > self.max_bytes:
            await too_large(scope, receive, send)
            return
        received = 0
        exceeded = False
        response_started = False

        async def capped_receive() -> _Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise BodyTooLargeError(self.max_bytes)
            return message

        async def guarded_send(message: _Message) -> None:
            nonlocal response_started
            if not exceeded:
                await send(message)
                return
            if message["type"] == "http.response.start" and not response_started:
                response_started = True
                await too_large(scope, receive, send)
            # the app's own (400) body for the cut-off read is dropped

        try:
            await self.app(scope, capped_receive, guarded_send)
        except BodyTooLargeError:
            if not response_started:
                response_started = True
                await too_large(scope, receive, send)


def _content_length(scope: _Scope) -> int | None:
    for name, value in scope.get("headers", ()):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


def create_executor_app(
    settings: Settings | None = None, manager: SandboxManager | None = None
) -> FastAPI:
    """Build the Executor app. Tests pass explicit settings and a (fake) manager."""
    settings = settings or get_settings()
    configure_logging(settings)
    if settings.executor_token is None or not settings.executor_token.get_secret_value():
        msg = "EXECUTOR_TOKEN must be set: the Executor never runs unauthenticated"
        raise RuntimeError(msg)
    token = settings.executor_token.get_secret_value()
    if len(token) < 16:
        msg = "EXECUTOR_TOKEN must be at least 16 characters"
        raise RuntimeError(msg)
    manager = manager or SandboxManager(JailConfig.from_settings(settings))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        manager.start_sweeper()
        log.info(
            "executor ready (bind=%s:%d, image=%s, ttl=%.0fs, mem=%dMB, cpus=%.1f, pids=%d)",
            settings.executor_host,
            settings.executor_port,
            manager.config.image,
            manager.config.ttl_s,
            manager.config.mem_mb,
            manager.config.cpus,
            manager.config.pids_limit,
        )
        try:
            yield
        finally:
            # Teardown on shutdown: no jail outlives the Executor that made it.
            await run_in_threadpool(manager.close)

    app = FastAPI(
        title="ONO Executor",
        version=__version__,
        summary="Internal sandbox executor - spawns and drives jailed target containers.",
        description=(
            "**Internal service, never published.** Every endpoint except `/health` needs "
            "`Authorization: Bearer <executor_token>`. One ephemeral, egress-blocked, "
            "capability-less container per scan; destroyed on `DELETE` or after the TTL."
        ),
        docs_url="/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.manager = manager
    app.state.token = token
    max_upload = manager.config.max_archive_bytes
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.executor_max_body_mb * 1_000_000)

    # -- error mapping ----------------------------------------------------------
    @app.exception_handler(SandboxPathError)
    async def _bad_input(_: Request, exc: SandboxPathError) -> JSONResponse:
        return _error(_UNPROCESSABLE, str(exc))

    @app.exception_handler(SandboxOperationError)
    async def _op_failed(_: Request, exc: SandboxOperationError) -> JSONResponse:
        return _error(status.HTTP_400_BAD_REQUEST, str(exc))

    @app.exception_handler(SandboxNotRunningError)
    async def _not_running(_: Request, exc: SandboxNotRunningError) -> JSONResponse:
        return _error(status.HTTP_409_CONFLICT, str(exc))

    @app.exception_handler(SandboxLimitError)
    async def _too_many(_: Request, exc: SandboxLimitError) -> JSONResponse:
        return _error(status.HTTP_429_TOO_MANY_REQUESTS, str(exc))

    @app.exception_handler(DockerUnavailableError)
    async def _no_docker(_: Request, exc: DockerUnavailableError) -> JSONResponse:
        log.error("executor: docker unavailable: %s", exc)
        return _error(status.HTTP_503_SERVICE_UNAVAILABLE, "docker daemon unavailable")

    @app.exception_handler(SandboxError)
    async def _sandbox_failed(_: Request, exc: SandboxError) -> JSONResponse:
        log.error("executor: sandbox error: %s", exc)
        return _error(status.HTTP_500_INTERNAL_SERVER_ERROR, "sandbox operation failed")

    # -- ops --------------------------------------------------------------------
    @app.get("/health", response_model=ExecutorHealth, tags=["ops"])
    async def health(manager: ManagerDep) -> ExecutorHealth:
        docker_ok = await run_in_threadpool(manager.ping)
        return ExecutorHealth(
            status="ok" if docker_ok else "degraded",
            docker=docker_ok,
            active_sandboxes=len(manager.active()),
            snapshot_bytes=manager.snapshot_bytes(),
        )

    # -- sandboxes --------------------------------------------------------------
    @app.get(
        "/sandboxes",
        response_model=list[SandboxInfo],
        dependencies=AUTH,
        tags=["sandboxes"],
        responses=_ERRORS,
    )
    def list_sandboxes(manager: ManagerDep) -> list[SandboxInfo]:
        return [s.info() for s in manager.active()]

    @app.post(
        "/sandboxes",
        response_model=SandboxInfo,
        status_code=status.HTTP_201_CREATED,
        dependencies=AUTH,
        tags=["sandboxes"],
        responses={**_ERRORS, 413: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
        summary="Create a jailed sandbox for a scan",
        description=(
            "Request body: a **gzipped tar** of the workspace (`Content-Type: application/gzip`), "
            "streamed to disk (never buffered in memory), validated, and extracted inside the "
            "jail as the sandbox user. The file is kept on disk as the clean snapshot that "
            "`reset` restores, and deleted with the sandbox."
        ),
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/gzip": {"schema": {"type": "string", "format": "binary"}}},
            }
        },
    )
    async def create_sandbox(
        request: Request,
        manager: ManagerDep,
        scan_id: Annotated[str, Query(pattern=SCAN_ID_PATTERN, max_length=64)],
    ) -> SandboxInfo:
        # The body goes straight to a file in the snapshot directory, one chunk at a
        # time, with the byte cap enforced as it streams: the Executor's RAM never holds
        # the archive (issue #96). The manager takes the file over from here (it becomes
        # the reset snapshot) and removes it on any failure.
        spool = await run_in_threadpool(_new_spool_file, manager.snapshot_dir)
        total = 0
        try:
            with spool.open("wb") as fh:
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > max_upload:
                        raise HTTPException(
                            status.HTTP_413_CONTENT_TOO_LARGE,
                            f"workspace archive is larger than {max_upload} bytes",
                        )
                    fh.write(chunk)
            if total == 0:
                raise HTTPException(_UNPROCESSABLE, "empty request body")
        except BaseException:
            with contextlib.suppress(OSError):
                spool.unlink()
            raise
        sandbox = await run_in_threadpool(manager.create_from_archive, scan_id, spool)
        return sandbox.info()

    @app.get(
        "/sandboxes/{sandbox_id}",
        response_model=SandboxInfo,
        dependencies=AUTH,
        tags=["sandboxes"],
        responses=_ERRORS,
    )
    def get_sandbox(sandbox: SandboxDep) -> SandboxInfo:
        return sandbox.info()

    @app.delete(
        "/sandboxes/{sandbox_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=AUTH,
        tags=["sandboxes"],
        responses=_ERRORS,
    )
    def destroy_sandbox(sandbox: SandboxDep, manager: ManagerDep) -> Response:
        manager.destroy(sandbox)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post(
        "/sandboxes/{sandbox_id}/reset",
        response_model=SandboxInfo,
        dependencies=AUTH,
        tags=["sandboxes"],
        responses=_ERRORS,
    )
    def reset_sandbox(sandbox: SandboxDep) -> SandboxInfo:
        return sandbox.reset()

    # -- operations -------------------------------------------------------------
    @app.post(
        "/sandboxes/{sandbox_id}/read",
        response_model=FileContent,
        dependencies=AUTH,
        tags=["operations"],
        responses=_ERRORS,
    )
    def read(sandbox: SandboxDep, body: ReadRequest) -> FileContent:
        if body.start is None and body.end is None:
            return sandbox.read_file(body.path)
        start = body.start or 1
        end = body.end if body.end is not None else 10**9
        return sandbox.read_lines(body.path, start, end)

    @app.post(
        "/sandboxes/{sandbox_id}/tree",
        response_model=TreeListing,
        dependencies=AUTH,
        tags=["operations"],
        responses=_ERRORS,
    )
    def tree(sandbox: SandboxDep, body: TreeRequest | None = None) -> TreeListing:
        body = body or TreeRequest()
        return sandbox.tree(body.path, max_entries=body.max_entries, max_depth=body.max_depth)

    @app.post(
        "/sandboxes/{sandbox_id}/grep",
        response_model=GrepResult,
        dependencies=AUTH,
        tags=["operations"],
        responses=_ERRORS,
    )
    def grep(sandbox: SandboxDep, body: GrepRequest) -> GrepResult:
        return sandbox.grep(
            body.pattern, body.path, ignore_case=body.ignore_case, max_matches=body.max_matches
        )

    @app.post(
        "/sandboxes/{sandbox_id}/apply_patch",
        response_model=PatchResult,
        dependencies=AUTH,
        tags=["operations"],
        responses=_ERRORS,
    )
    def apply_patch(sandbox: SandboxDep, body: PatchRequest) -> PatchResult:
        return sandbox.apply_patch(body.diff)

    @app.post(
        "/sandboxes/{sandbox_id}/run",
        response_model=RunResult,
        dependencies=AUTH,
        tags=["operations"],
        responses=_ERRORS,
    )
    def run(sandbox: SandboxDep, body: RunRequest) -> RunResult:
        return sandbox.run(body.cmd, body.timeout_s)

    @app.post(
        "/sandboxes/{sandbox_id}/run_tests",
        response_model=TestRunResult,
        dependencies=AUTH,
        tags=["operations"],
        responses=_ERRORS,
    )
    def run_tests(sandbox: SandboxDep, body: TestRunRequest | None = None) -> TestRunResult:
        body = body or TestRunRequest()
        return sandbox.run_tests(body.timeout_s)

    return app


def _error(code: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=code, content=ErrorResponse(detail=detail).model_dump())


def _new_spool_file(directory: Path) -> Path:
    """An empty, private (0600) file in the snapshot directory for an incoming upload."""
    fd, name = tempfile.mkstemp(prefix="upload-", suffix=".tar.gz", dir=directory)
    os.close(fd)
    return Path(name)


def get_app() -> FastAPI:
    """Module-level factory for ``uvicorn --factory ono.executor.app:get_app``."""
    return create_executor_app()
