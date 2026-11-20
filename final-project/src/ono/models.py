"""API and domain schemas (pydantic).

The :class:`Finding` schema is the product: it encodes the *output-strength
ladder* (``rung`` 1-5) and the deterministic verifier's verdict (``verified``).
Everything the UI renders and the API returns is one of these models, so the
OpenAPI document at ``/docs`` is the authoritative contract.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


def fingerprint_for(target_id: str, file: str, line: int, cwe: str) -> str:
    """Stable across runs: the same (target, sink, CWE) always gets the same fingerprint.

    Use it to match one weakness between scans (e.g. "was this fixed since last week?").
    It is *not* an address - two scans of one target share it - so lookups use
    :func:`finding_id_for`.
    """
    return hashlib.sha1(f"{target_id}|{file}|{line}|{cwe}".encode()).hexdigest()[:16]


def finding_id_for(scan_id: str, target_id: str, file: str, line: int, cwe: str) -> str:
    """Unique per scan, so re-scanning a target never overwrites an earlier scan's finding."""
    fingerprint = fingerprint_for(target_id, file, line, cwe)
    digest = hashlib.sha1(f"{scan_id}|{fingerprint}".encode()).hexdigest()
    return f"fnd_{digest[:12]}"


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
    """Body of ``POST /scans`` for a configured target or checked public repo."""

    model_config = ConfigDict(extra="forbid")

    target_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
        description=(
            "Key in the target allowlist (see GET /targets). Unknown ids are rejected (403)."
        ),
        examples=["pygoat"],
    )
    repo_url: str | None = Field(
        default=None,
        max_length=2048,
        description="HTTPS URL of a public github.com repository; private repos are not accepted.",
    )
    authorized_to_scan: bool = Field(
        default=False,
        description="User confirmation required when repo_url is supplied.",
    )
    options: ScanOptions = Field(default_factory=ScanOptions)

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if (self.target_id is None) == (self.repo_url is None):
            raise ValueError("provide exactly one of target_id or repo_url")
        if self.repo_url is not None:
            if not self.authorized_to_scan:
                raise ValueError("confirm that you are allowed to scan this public repository")
            if self.options.snippet is not None:
                raise ValueError("snippet code cannot be combined with a repository URL")
        return self


class SourceCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_url: str = Field(min_length=1, max_length=2048)


class SourceCheckResponse(BaseModel):
    repository: str
    canonical_url: str
    default_branch: str
    size_mb: float
    languages: list[str]
    supported_languages: list[str]
    unsupported_languages: list[str]
    scan_ready: bool
    message: str


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class TraceStep(BaseModel):
    """One hop of the source->sink data-flow trace."""

    file: str
    line: int = Field(ge=1)
    symbol: str = Field(description="Function/variable at this hop.")
    note: str = Field(default="", description="Why this hop matters (e.g. 'attacker-controlled').")


CheckName = Literal[
    "anchor", "poc_reaches_sink", "patch_applies", "poc_no_longer_fires", "tests_pass"
]
CheckStatus = Literal["passed", "failed", "skipped"]


class VerificationCheck(BaseModel):
    """One deterministic check of the graded verifier and what it saw."""

    name: CheckName
    status: CheckStatus
    detail: str = Field(default="", description="Why it passed / failed / was skipped.")


class Verification(BaseModel):
    """The verifier's record for a finding: every check, the PoC that proved it, the cost.

    The checks are the plan's ladder, in order: ``anchor`` (the flagged file:line exists
    and is not blank), ``poc_reaches_sink`` (a read-only PoC run in the jail carried a
    verifier-chosen canary into the dangerous argument of the flagged call -> rung 3),
    ``patch_applies``, ``poc_no_longer_fires`` and ``tests_pass`` (-> rung 4). A check that
    could not be attempted (no dynamic oracle for the language or CWE, no PoC to re-run)
    is ``skipped`` with the reason, never silently passed.
    """

    attempts: int = Field(default=0, ge=0, description="Self-correction rounds used.")
    poc_attempts: int = Field(
        default=0,
        ge=0,
        description="Prover attempts until the PoC fired (0 if it never did). The learning "
        "loop's headline metric: it trends down as the knowledge memory seeds later scans.",
    )
    seeded: bool = Field(
        default=False, description="Whether a knowledge-memory hint was seeded into the prover."
    )
    checks: list[VerificationCheck] = Field(default_factory=list)
    poc: str = Field(default="", description="The read-only PoC script that proved rung 3.")
    evidence: str = Field(
        default="", description="What the oracle saw when the PoC fired (sink kind, argument)."
    )
    tests: str = Field(default="", description="Test runner and summary after the patch.")
    model_calls: int = Field(default=0, ge=0)

    def check(self, name: CheckName) -> VerificationCheck | None:
        return next((c for c in self.checks if c.name == name), None)

    @property
    def summary(self) -> str:
        parts = [f"{c.name}={c.status}" for c in self.checks]
        return f"{self.attempts} attempt(s): " + ", ".join(parts)


class Finding(BaseModel):
    """A single vulnerability finding, shaped by the output-strength ladder."""

    finding_id: str = Field(
        examples=["fnd_3a9f1c2b7e04"],
        description="Unique per scan; the key for GET /findings/{finding_id}.",
    )
    fingerprint: str = Field(
        default="",
        examples=["5d2c0a9e1f3b7c44"],
        description=(
            "Same value for the same (target, file, line, CWE) in every scan: use it to "
            "match a finding across scans. Not unique - do not use it to look findings up."
        ),
    )
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
        description=(
            "True only if the deterministic verifier PROVED the finding in the sandbox: a "
            "read-only PoC carried a canary into the flagged sink (rung 3); at rung 4 the "
            "patch also applied, the PoC no longer fired and the tests passed. False = "
            "model-asserted only (rung 1-2); see `verification` for which check stopped it."
        )
    )
    description: str = ""
    patch_diff: str = Field(
        description=(
            "Unified diff that closes the flaw. At rung 4 it is proven (applies, PoC no "
            "longer fires, tests pass); below that it is a proposal that at least applies "
            "cleanly, or empty when no patch could be produced."
        )
    )
    detection_rule: str | None = Field(
        default=None,
        description="Rung-5 extra: a detection rule (e.g. Semgrep YAML) to catch exploitation.",
    )
    verification: Verification | None = Field(
        default=None,
        description="The graded verifier's record (None when the verifier did not run).",
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
    target_name: str | None = Field(
        default=None, description="Display name for the selected source."
    )
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
    auth_required: bool = False
    """Whether POST /scans and POST /sources/check need a session or bearer (so a UI can
    decide to show "Sign in with GitHub"). Not a secret."""


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
