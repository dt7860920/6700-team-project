"""Settings validation - the 'config / boot' smoke layer."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from ono.config import Settings


def test_defaults_are_the_mock_path() -> None:
    s = Settings(_env_file=None)
    assert s.environment == "local"
    assert s.model_backend == "mock"
    assert s.port == 8080


def test_invalid_environment_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, environment="prod")  # type: ignore[arg-type]


def test_invalid_model_backend_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, model_backend="gpt")  # type: ignore[arg-type]


def test_service_backend_requires_url() -> None:
    with pytest.raises(ValidationError, match="model_service_url is required"):
        Settings(_env_file=None, model_backend="service")


def test_service_backend_accepts_url() -> None:
    s = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://vllm:8000/v1",
        executor_token=SecretStr("unit-test-token-0123456789"),
    )
    assert s.model_service_url == "http://vllm:8000/v1"


def test_service_backend_requires_executor_token() -> None:
    with pytest.raises(ValidationError, match="executor_token is required"):
        Settings(_env_file=None, model_backend="service", model_service_url="http://vllm:8000/v1")


def test_agent_settings_have_safe_defaults_and_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    s = Settings(_env_file=None)
    assert (s.planner_enabled, s.analyst_max_steps, s.agent_temperature) == (True, 8, 0.0)
    assert s.agent_tool_protocol == "auto"
    assert (s.agent_tool_output_chars, s.agent_candidate_timeout_s) == (6000, 300.0)
    assert s.agent_trajectory_dir is None

    monkeypatch.setenv("PLANNER_ENABLED", "false")
    monkeypatch.setenv("ANALYST_MAX_STEPS", "4")
    monkeypatch.setenv("AGENT_TOOL_PROTOCOL", "text")
    monkeypatch.setenv("AGENT_TRAJECTORY_DIR", "/tmp/ono-traj")
    s = Settings(_env_file=None)
    assert (s.planner_enabled, s.analyst_max_steps, s.agent_tool_protocol) == (False, 4, "text")
    assert s.agent_trajectory_dir == Path("/tmp/ono-traj")

    with pytest.raises(ValidationError, match="analyst_max_steps"):
        Settings(_env_file=None, analyst_max_steps=0)
    with pytest.raises(ValidationError, match="agent_tool_protocol"):
        Settings(_env_file=None, agent_tool_protocol="grpc")  # type: ignore[arg-type]


def test_api_key_is_secret_and_never_rendered() -> None:
    s = Settings(_env_file=None, model_service_api_key=SecretStr("sk-super-secret"))
    assert "sk-super-secret" not in repr(s)
    assert "sk-super-secret" not in str(s)
    assert "sk-super-secret" not in s.model_dump_json()
    assert s.model_service_api_key is not None
    assert s.model_service_api_key.get_secret_value() == "sk-super-secret"


def test_env_vars_are_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("MODEL_BACKEND", "mock")
    monkeypatch.setenv("LOG_LEVEL", "warning")
    s = Settings(_env_file=None)
    assert s.is_production
    assert s.log_level == "WARNING"


def test_invalid_log_level_rejected() -> None:
    with pytest.raises(ValidationError, match="log_level"):
        Settings(_env_file=None, log_level="loud")


_OAUTH = {
    "github_oauth_client_id": "Iv1.test",
    "github_oauth_client_secret": SecretStr("app-secret"),
    "github_oauth_callback_url": "https://ono.example.org/auth/github/callback",
}


def test_auth_defaults_are_off_and_rate_limited() -> None:
    s = Settings(_env_file=None)
    assert s.auth_required is False
    assert s.auth_session_secret is None and s.auth_api_token is None
    assert s.cookie_secure is True and s.trusted_proxy is False
    assert (s.rate_limit_max, s.rate_limit_window_s) == (30, 60.0)


def test_auth_required_fails_fast_without_session_secret() -> None:
    with pytest.raises(ValidationError, match="auth_session_secret is required"):
        Settings(_env_file=None, auth_required=True, **_OAUTH)


def test_auth_required_fails_fast_without_oauth_app() -> None:
    with pytest.raises(ValidationError, match="GITHUB_OAUTH_CLIENT_ID"):
        Settings(_env_file=None, auth_required=True, auth_session_secret=SecretStr("s" * 32))


def test_auth_required_rejects_the_ungated_gradio_ui() -> None:
    with pytest.raises(ValidationError, match="ui_backend='gradio'"):
        Settings(
            _env_file=None,
            auth_required=True,
            auth_session_secret=SecretStr("s" * 32),
            ui_backend="gradio",
            **_OAUTH,
        )


def test_auth_secret_lengths_and_callback_shape_are_validated() -> None:
    with pytest.raises(ValidationError, match="at least 32"):
        Settings(_env_file=None, auth_session_secret=SecretStr("short"))
    with pytest.raises(ValidationError, match="at least 16"):
        Settings(_env_file=None, auth_api_token=SecretStr("short"))
    with pytest.raises(ValidationError, match="/auth/github/callback"):
        Settings(
            _env_file=None, github_oauth_callback_url="https://ono.example.org/github/callback"
        )
    with pytest.raises(ValidationError, match="/auth/github/callback"):
        Settings(_env_file=None, github_oauth_callback_url="ono.example.org/auth/github/callback")


def test_auth_required_accepts_a_complete_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    monkeypatch.setenv("AUTH_SESSION_SECRET", "s" * 32)
    monkeypatch.setenv("AUTH_API_TOKEN", "t" * 16)
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "app-secret")
    monkeypatch.setenv("GITHUB_OAUTH_CALLBACK_URL", "https://ono.example.org/auth/github/callback")
    monkeypatch.setenv("TRUSTED_PROXY", "true")
    monkeypatch.setenv("RATE_LIMIT_MAX", "10")
    s = Settings(_env_file=None)
    assert s.auth_required and s.trusted_proxy and s.rate_limit_max == 10
    for secret in ("s" * 32, "t" * 16, "app-secret"):
        assert secret not in repr(s) and secret not in s.model_dump_json()


def test_ingest_and_sast_settings_have_safe_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    s = Settings(_env_file=None)
    assert s.workspace_dir == Path(".ono-workspace")
    assert s.sast_ruleset == "p/owasp-top-ten"
    assert (s.max_candidates, s.context_lines) == (20, 25)
    assert (s.clone_timeout_s, s.max_clone_mb) == (120.0, 200)

    monkeypatch.setenv("WORKSPACE_DIR", "/tmp/ono-workspace")
    monkeypatch.setenv("SAST_RULESET", "p/owasp-top-ten,rules/custom.yml")
    monkeypatch.setenv("MAX_CANDIDATES", "5")
    s = Settings(_env_file=None)
    assert s.workspace_dir == Path("/tmp/ono-workspace")
    assert s.sast_ruleset.split(",") == ["p/owasp-top-ten", "rules/custom.yml"]
    assert s.max_candidates == 5

    with pytest.raises(ValidationError, match="max_candidates"):
        Settings(_env_file=None, max_candidates=0)
    with pytest.raises(ValidationError, match="clone_timeout_s"):
        Settings(_env_file=None, clone_timeout_s=1)
