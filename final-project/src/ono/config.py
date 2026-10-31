"""Application settings.

All runtime configuration flows through :class:`Settings` (pydantic-settings),
which reads environment variables and an optional ``.env`` file. Nothing else in
the codebase reads ``os.environ`` directly - this is the single source of truth
that the Docker image, Compose file, and CI all configure through.

Secrets (``model_service_api_key``, ``executor_token``) are ``SecretStr`` and are never
rendered by ``repr``/``str``, so they cannot leak through logs or the ``/info`` endpoint.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "staging", "production"]
"""Deployment environment. Controls defaults such as log verbosity and docs exposure."""

ModelBackend = Literal["mock", "local", "service"]
"""Which analyzer backend to run.

* ``mock``    - deterministic, GPU-free findings (Deliverable 2 path; also what CI runs).
* ``local``   - the frozen Qwen2.5-Coder agent served by an in-box vLLM (Deliverable 3).
* ``service`` - the same agent, but calling a remote OpenAI-compatible endpoint.
"""

AgentToolProtocol = Literal["auto", "native", "text"]
"""How agent tools are presented to the model (see ``Settings.agent_tool_protocol``)."""


class Settings(BaseSettings):
    """Runtime settings, loaded from the environment / ``.env``.

    Environment variable names are the upper-cased field names (``ENVIRONMENT``,
    ``MODEL_BACKEND``, ...). See ``.env.example.local`` and
    ``.env.example.production`` for the two supported profiles.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Our fields legitimately start with ``model_``; silence pydantic's namespace warning.
        protected_namespaces=(),
    )

    app_name: str = Field(default="Operation: Negative One", description="Human-readable app name.")
    environment: Environment = Field(default="local", description="Deployment environment.")
    log_level: str = Field(default="INFO", description="Python logging level name.")

    host: str = Field(default="0.0.0.0", description="Bind address for uvicorn.")
    port: int = Field(default=8080, ge=1, le=65535, description="The ONE published port.")

    model_backend: ModelBackend = Field(
        default="mock",
        description="Analyzer backend. 'mock' is the Deliverable-2 path and what CI runs.",
    )
    model_name: str = Field(
        default="Qwen/Qwen2.5-Coder-7B-Instruct",
        description="Model identifier used by the local/service backends (informational for mock).",
    )
    model_service_url: str | None = Field(
        default=None,
        description="Base URL of the OpenAI-compatible model endpoint (required for 'service').",
    )
    model_service_api_key: SecretStr | None = Field(
        default=None,
        description="API key for the model endpoint. Never logged or returned by the API.",
    )

    max_verifier_retries: int = Field(
        default=3,
        ge=1,
        le=5,
        description="Hard cap on the verifier-in-the-loop self-correction cycle (prevents thrash).",
    )

    # -- Ingest + SAST (service / local backends; the mock backend ignores these) ----
    workspace_dir: Path = Field(
        default=Path(".ono-workspace"),
        description=(
            "Directory holding per-scan workspaces (<workspace_dir>/<scan_id>/). Each clone "
            "is removed when its scan ends. Must be writable (the container uses /tmp)."
        ),
    )
    sast_ruleset: str = Field(
        default="p/owasp-top-ten",
        description=(
            "Comma-separated Semgrep --config values (registry packs or local rule files). "
            "A language pack (p/python, p/javascript, ...) is appended per target language. "
            "Empty string = skip Semgrep and use the built-in regex scanner."
        ),
    )
    max_candidates: int = Field(
        default=20,
        ge=1,
        le=200,
        description="Cap on SAST candidates kept per scan - and therefore on model calls.",
    )
    context_lines: int = Field(
        default=25,
        ge=5,
        le=200,
        description="Lines of code shown to the model on each side of a candidate sink.",
    )
    clone_timeout_s: float = Field(
        default=120.0,
        ge=5.0,
        le=1800.0,
        description="Hard timeout for the shallow git clone during ingest.",
    )
    max_clone_mb: int = Field(
        default=200,
        ge=1,
        le=5000,
        description="Snapshots larger than this (after .git is stripped) abort the scan.",
    )

    # -- Agentic detection core (Deliverable 3, step 3b-1) ---------------------------
    # The planner and analyst are *definitions* (role prompt + tools + budget) on the one
    # pinned model; the orchestrator is deterministic code that enforces these budgets.
    # Upper bound on model calls per scan: max_candidates * (1 + analyst_max_steps).
    planner_enabled: bool = Field(
        default=True,
        description=(
            "Run the planner agent (one model call per candidate) to emit an investigation "
            "plan for the analyst. False = a fixed default plan, no planner call."
        ),
    )
    analyst_max_steps: int = Field(
        default=8,
        ge=1,
        le=32,
        description=(
            "Hard cap on model calls in the analyst's ReAct loop per candidate (tool calls, "
            "retries after malformed replies and the final verdict all count)."
        ),
    )
    agent_temperature: float = Field(
        default=0.0,
        ge=0.0,
        le=2.0,
        description="Sampling temperature for every agent call (0 = deterministic).",
    )
    agent_tool_protocol: AgentToolProtocol = Field(
        default="auto",
        description=(
            "How the analyst's tools are exposed to the model: 'native' = OpenAI "
            "function-calling, 'text' = one strict JSON action per reply, 'auto' = native "
            "first, fall back to text (for the rest of the process) if the endpoint rejects "
            "the tools field."
        ),
    )
    agent_tool_output_chars: int = Field(
        default=6000,
        ge=500,
        le=100_000,
        description="Max characters of any single tool result fed back to the model (truncated).",
    )
    agent_candidate_timeout_s: float = Field(
        default=300.0,
        ge=10.0,
        le=3600.0,
        description=(
            "Wall-clock budget per candidate (planner + analyst loop). Checked between steps; "
            "an in-flight model call is additionally bounded by the model request timeout."
        ),
    )
    agent_trajectory_dir: Path | None = Field(
        default=None,
        description=(
            "If set, every agent trajectory (each model call, tool call and result) is "
            "appended as JSON lines to <dir>/<scan_id>.jsonl - observability / learning data."
        ),
    )

    # -- Executor service + sandbox jail (Deliverable 3, step 3a) ----------------------
    # The Executor is a separate, internal-only, token-authenticated service that owns
    # the Docker socket and spawns one jailed container per scan. ``executor_*`` is how
    # the two processes find and trust each other; ``sandbox_*`` are the jail's limits.
    executor_url: str = Field(
        default="http://127.0.0.1:8081",
        description="Base URL the ONO app uses to reach the Executor (never published).",
    )
    executor_token: SecretStr | None = Field(
        default=None,
        description=(
            "Shared secret for the Executor API (Authorization: Bearer). The Executor refuses "
            "to start without one. Never logged or returned by any endpoint."
        ),
    )
    executor_host: str = Field(
        default="127.0.0.1",
        description="Bind address of the Executor service. Loopback by default; 0.0.0.0 only "
        "inside the Compose internal network.",
    )
    executor_port: int = Field(default=8081, ge=1, le=65535, description="Executor bind port.")
    sandbox_image: str = Field(
        default="python:3.13-slim",
        description="Image the jailed target containers start from (pulled if missing).",
    )
    sandbox_mem_mb: int = Field(
        default=1024,
        ge=64,
        le=65536,
        description="Memory limit per sandbox (no swap). Includes the tmpfs workspace contents.",
    )
    sandbox_cpus: float = Field(
        default=1.0, ge=0.1, le=64.0, description="CPU quota per sandbox (nano_cpus)."
    )
    sandbox_pids_limit: int = Field(
        default=256, ge=16, le=8192, description="PID limit per sandbox (fork bombs)."
    )
    sandbox_cmd_timeout_s: float = Field(
        default=300.0,
        ge=1.0,
        le=3600.0,
        description="Hard cap on any single run()/run_tests() inside a sandbox.",
    )
    sandbox_ttl_s: float = Field(
        default=1800.0,
        ge=30.0,
        le=86400.0,
        description="Max sandbox age; the sweeper force-removes older (orphaned) containers.",
    )
    sandbox_output_cap_bytes: int = Field(
        default=1_000_000,
        ge=1024,
        le=50_000_000,
        description="Per-stream cap on captured stdout/stderr (and on file reads).",
    )
    sandbox_workspace_mb: int = Field(
        default=512,
        ge=16,
        le=16384,
        description="Size of the writable tmpfs holding the workspace (/tmp gets half of it).",
    )
    sandbox_max_active: int = Field(
        default=8, ge=1, le=64, description="Max concurrently live sandboxes on this Executor."
    )

    @model_validator(mode="after")
    def _service_backend_requires_url(self) -> Self:
        if self.model_backend == "service" and not self.model_service_url:
            msg = "model_service_url is required when model_backend == 'service'"
            raise ValueError(msg)
        if self.model_backend == "service" and not (
            self.executor_token and self.executor_token.get_secret_value()
        ):
            # Every read of target code goes through the jailed Executor (step 3b-1);
            # without its token the agents would have no hands at all.
            msg = (
                "executor_token is required when model_backend == 'service': the agents read "
                "target code only through the Executor sandbox (set EXECUTOR_TOKEN)"
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _normalize_log_level(self) -> Self:
        level = self.log_level.upper()
        if level not in logging.getLevelNamesMapping():
            msg = f"log_level must be a Python logging level name, got {self.log_level!r}"
            raise ValueError(msg)
        self.log_level = level
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached after first load)."""
    return Settings()


def configure_logging(settings: Settings) -> None:
    """Configure root logging once, from settings. Idempotent."""
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)-8s %(name)s - %(message)s",
        force=False,
    )
