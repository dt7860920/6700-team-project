"""FastAPI application: the documented HTTP API plus the mounted Gradio UI.

One process, one published port (8080). OpenAPI docs live at ``/docs``.

    GET  /health                     liveness
    GET  /info                       app / version / environment / backend (no secrets)
    GET  /targets                    the allowlist
    POST /scans                      start a scan (403 if target_id is not allowlisted)
    GET  /scans/{scan_id}            scan metadata
    GET  /scans/{scan_id}/findings   findings for a scan
    GET  /findings/{finding_id}      one finding
    GET  /ui                         Gradio analyst UI  (``/`` redirects here)
"""

from __future__ import annotations

import logging
from typing import Annotated

import gradio as gr
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from ono import __version__
from ono.analyzer import build_analyzer
from ono.config import Settings, configure_logging, get_settings
from ono.models import (
    ErrorResponse,
    Finding,
    HealthResponse,
    InfoResponse,
    Scan,
    ScanRequest,
    ScanResponse,
    TargetsResponse,
    TargetSummary,
)
from ono.service import ScanService
from ono.store import InMemoryScanStore
from ono.targets import TargetRegistry, UnauthorizedTargetError, get_registry
from ono.ui import UI_CSS, build_ui

log = logging.getLogger(__name__)

UI_PATH = "/ui"


def _service(request: Request) -> ScanService:
    service: ScanService = request.app.state.service
    return service


ServiceDep = Annotated[ScanService, Depends(_service)]


def create_app(
    settings: Settings | None = None,
    registry: TargetRegistry | None = None,
    *,
    mount_ui: bool = True,
) -> FastAPI:
    """Build the application. Tests call this with explicit settings."""
    settings = settings or get_settings()
    registry = registry or get_registry()
    configure_logging(settings)

    service = ScanService(
        settings=settings,
        registry=registry,
        analyzer=build_analyzer(settings),
        store=InMemoryScanStore(),
    )

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        summary="Agentic vulnerability analysis of authorized code targets.",
        description=(
            "ONO ingests an **authorized** code target, finds vulnerabilities, proves they are "
            "reachable, and proposes verified fixes. Scans are addressed by `target_id` from "
            "the allowlist (`GET /targets`) - never by URL. "
            f"Current analyzer backend: `{settings.model_backend}`."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_tags=[
            {"name": "ops", "description": "Health and runtime info."},
            {"name": "targets", "description": "The authorized-target allowlist."},
            {"name": "scans", "description": "Start scans and read results."},
        ],
    )
    app.state.settings = settings
    app.state.service = service

    # -- Error mapping ----------------------------------------------------
    @app.exception_handler(UnauthorizedTargetError)
    async def _unauthorized_target(_: Request, exc: UnauthorizedTargetError) -> JSONResponse:
        log.warning("rejected scan for unauthorized target_id=%r", exc.target_id)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=ErrorResponse(
                detail=f"{exc}. See GET /targets for the allowlist."
            ).model_dump(),
        )

    # -- ops --------------------------------------------------------------
    @app.get("/health", response_model=HealthResponse, tags=["ops"])
    async def health() -> HealthResponse:
        return HealthResponse()

    @app.get("/info", response_model=InfoResponse, tags=["ops"])
    async def info(svc: ServiceDep) -> InfoResponse:
        s = svc.settings
        return InfoResponse(
            app_name=s.app_name,
            version=__version__,
            environment=s.environment,
            model_backend=s.model_backend,
            model_name=s.model_name,
            targets_registered=len(svc.registry),
        )

    # -- targets ----------------------------------------------------------
    @app.get("/targets", response_model=TargetsResponse, tags=["targets"])
    async def list_targets(svc: ServiceDep) -> TargetsResponse:
        return TargetsResponse(
            targets=[TargetSummary(**t.model_dump()) for t in svc.registry.all()]
        )

    # -- scans ------------------------------------------------------------
    @app.post(
        "/scans",
        response_model=ScanResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["scans"],
        responses={403: {"model": ErrorResponse, "description": "target_id not allowlisted"}},
        summary="Start a scan of an authorized target",
    )
    async def create_scan(body: ScanRequest, svc: ServiceDep) -> ScanResponse:
        # Synchronous in the prototype: the response carries the findings.
        # Future: enqueue, return 202 + status="queued", poll GET /scans/{scan_id}.
        return svc.start_scan(body)

    @app.get(
        "/scans/{scan_id}",
        response_model=Scan,
        tags=["scans"],
        responses={404: {"model": ErrorResponse}},
    )
    async def get_scan(scan_id: str, svc: ServiceDep) -> Scan:
        scan = svc.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"scan {scan_id!r} not found")
        return scan

    @app.get(
        "/scans/{scan_id}/findings",
        response_model=list[Finding],
        tags=["scans"],
        responses={404: {"model": ErrorResponse}},
    )
    async def get_scan_findings(scan_id: str, svc: ServiceDep) -> list[Finding]:
        findings = svc.get_findings(scan_id)
        if findings is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"scan {scan_id!r} not found")
        return findings

    @app.get(
        "/findings/{finding_id}",
        response_model=Finding,
        tags=["scans"],
        responses={404: {"model": ErrorResponse}},
    )
    async def get_finding(finding_id: str, svc: ServiceDep) -> Finding:
        finding = svc.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"finding {finding_id!r} not found")
        return finding

    # -- UI ---------------------------------------------------------------
    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse(url=UI_PATH if mount_ui else "/docs")

    if mount_ui:
        gr.mount_gradio_app(
            app,
            build_ui(service),
            path=UI_PATH,
            theme=gr.themes.Soft(),
            css=UI_CSS,
            footer_links=[],
        )

    log.info(
        "ONO %s ready (environment=%s, model_backend=%s, targets=%d)",
        __version__,
        settings.environment,
        settings.model_backend,
        len(registry),
    )
    return app


# Module-level ASGI app for `uvicorn ono.api:app` (used by the Dockerfile).
app = create_app()
