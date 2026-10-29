"""Application settings.

All runtime configuration flows through :class:`Settings` (pydantic-settings),
which reads environment variables and an optional ``.env`` file. Nothing else in
the codebase reads ``os.environ`` directly - this is the single source of truth
that the Docker image, Compose file, and CI all configure through.

Secrets (``model_service_api_key``) are ``SecretStr`` and are never rendered by
``repr``/``str``, so they cannot leak through logs or the ``/info`` endpoint.
"""

from __future__ import annotations

import logging
from functools import lru_cache
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

    @model_validator(mode="after")
    def _service_backend_requires_url(self) -> Self:
        if self.model_backend == "service" and not self.model_service_url:
            msg = "model_service_url is required when model_backend == 'service'"
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
