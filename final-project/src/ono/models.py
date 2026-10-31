"""API and domain schemas (pydantic).

The :class:`Finding` schema is the product: it encodes the *output-strength
ladder* (``rung`` 1-5) and the deterministic verifier's verdict (``verified``).
Everything the UI renders and the API returns is one of these models, so the
OpenAPI document at ``/docs`` is the authoritative contract.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high", "critical"]
ScanStatus = Literal["queued", "running", "done", "failed"]
StageName = Literal["ingest", "sast", "plan", "analyze", "verify"]

Rung = Annotated[
    int,
    Field(
        ge=1,
        le=5,
        description=(
            "Output-strength rung. 1=bare flag, 2=+CWE+patch, 3=+proof it is reachable, "
            "4=+proof the fix works (target floor), 5=+detection rule (stretch)."
        ),
    ),
]


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


def finding_id_for(target_id: str, file: str, line: int, cwe: str) -> str:
    """Stable id so the same (target, sink) yields the same finding across runs."""
    digest = hashlib.sha1(f"{target_id}|{file}|{line}|{cwe}".encode()).hexdigest()
    return f"fnd_{digest[:10]}"


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


class ScanOptions(BaseModel):
    """Optional per-scan knobs. All fields have safe defaults."""

    model_config = ConfigDict(extra="forbid")

    snippet: str | None = Field(
        default=None,
        max_length=20_000,
        description="Source code to analyze when target_id == 'snippet'. Ignored otherwise.",
    )
    max_findings: int = Field(default=10, ge=1, le=50, description="Cap on findings returned.")
    min_rung: Rung = Field(default=1, description="Drop findings below this output rung.")


class ScanRequest(BaseModel):
    """Body of ``POST /scans``. The target is named by id, never by URL."""

    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
        description=(
            "Key in the target allowlist (see GET /targets). Unknown ids are rejected (403)."
        ),
        examples=["pygoat"],
    )
    options: ScanOptions = Field(default_factory=ScanOptions)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class TraceStep(BaseModel):
    """One hop of the source->sink data-flow trace."""

    file: str
    line: int = Field(ge=1)
    symbol: str = Field(description="Function/variable at this hop.")
    note: str = Field(default="", description="Why this hop matters (e.g. 'attacker-controlled').")


class Finding(BaseModel):
    """A single vulnerability finding, shaped by the output-strength ladder."""

    finding_id: str = Field(examples=["fnd_3a9f1c2b7e"])
    scan_id: str
    target_id: str
    title: str
    cwe: str = Field(pattern=r"^CWE-\d+$", examples=["CWE-89"])
    severity: Severity
    file: str = Field(description="Path of the sink, relative to the target snapshot root.")
    line_range: tuple[int, int] = Field(description="[start, end] lines of the sink (1-based).")
    trace: list[TraceStep] = Field(default_factory=list, description="Source->sink data-flow.")
    confidence: float = Field(ge=0.0, le=1.0)
    rung: Rung
    verified: bool = Field(
        description="True only if the deterministic verifier passed (line exists, PoC reaches "
        "sink, patch applies, PoC no longer fires, tests pass)."
    )
    description: str = ""
    patch_diff: str = Field(description="Unified diff that closes the flaw.")
    detection_rule: str | None = Field(
        default=None,
        description="Rung-5 extra: a detection rule (e.g. Semgrep YAML) to catch exploitation.",
    )

    @property
    def location(self) -> str:
        start, end = self.line_range
        return f"{self.file}:{start}" if start == end else f"{self.file}:{start}-{end}"


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


class StageResult(BaseModel):
    """Outcome of one pipeline stage - makes the pipeline shape visible in responses."""

    stage: StageName
    status: Literal["ok", "skipped", "failed"] = "ok"
    duration_ms: float = Field(ge=0)
    summary: str = ""


class ProgressEvent(BaseModel):
    """One line of the scan's live activity log (what the pipeline is doing right now)."""

    at: datetime
    message: str


class Scan(BaseModel):
    """Scan metadata as returned by ``GET /scans/{scan_id}`` - a *live* record.

    ``POST /scans`` returns it with ``status="queued"`` (202 Accepted); the background
    worker then moves it through ``running`` to ``done`` or ``failed``, updating
    ``progress`` / ``events`` / ``pipeline`` as the stages complete. Poll this resource.
    """

    scan_id: str = Field(examples=["scn_6f1d9c0a2b4e"])
    target_id: str
    status: ScanStatus
    model_backend: str
    created_at: datetime
    started_at: datetime | None = Field(
        default=None, description="When a worker picked the scan up (None while queued)."
    )
    completed_at: datetime | None = None
    findings_count: int = Field(ge=0, default=0)
    pipeline: list[StageResult] = Field(default_factory=list)
    progress: str = Field(
        default="",
        description=(
            "What the pipeline is doing right now, e.g. 'Cloning the target repository' or "
            "'Analyzing candidate 2 of 3 - app/views.py:16'. Empty once the scan has ended."
        ),
    )
    events: list[ProgressEvent] = Field(
        default_factory=list,
        description="Bounded activity log (most recent last): every progress step so far.",
    )
    message: str = Field(default="", description="Human-readable status / failure detail.")


class ScanResponse(Scan):
    """A scan plus its findings inline (the synchronous ``ScanService.run_scan`` result)."""

    findings: list[Finding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Misc API responses
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"


class InfoResponse(BaseModel):
    """Non-secret runtime information."""

    app_name: str
    version: str
    environment: str
    model_backend: str
    model_name: str
    targets_registered: int


class TargetsResponse(BaseModel):
    """The allowlist, as exposed by ``GET /targets``."""

    targets: list[TargetSummary]


class TargetSummary(BaseModel):
    target_id: str
    name: str
    kind: str
    languages: list[str]
    description: str
    source: str
    snapshot: str
    authorized: bool = True


class ErrorResponse(BaseModel):
    detail: str
