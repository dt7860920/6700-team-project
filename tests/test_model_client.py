from unittest.mock import patch

import pytest

from team_project.config import Settings
from team_project.model_client import ModelClient


def test_local_backend_is_selected() -> None:
    app_settings = Settings(
        model_backend="local",
        model_path="./test-model",
        model_device="cpu",
    )

    with patch("team_project.model_client.LocalModel") as mock_local:
        mock_local.return_value.predict.return_value = ["reading"]
        client = ModelClient(app_settings)

        assert client.predict(["reading"]) == ["reading"]
        mock_local.assert_called_once_with(path="./test-model", device="cpu")


def test_service_backend_is_selected_without_exposing_api_key() -> None:
    app_settings = Settings(
        model_backend="service",
        model_service_url="https://model.example.test",
        model_service_api_key="secret-value",
    )

    assert "secret-value" not in repr(app_settings)

    with patch("team_project.model_client.RemoteModel") as mock_remote:
        mock_remote.return_value.predict.return_value = ["reading"]
        client = ModelClient(app_settings)

        assert client.predict(["reading"]) == ["reading"]
        mock_remote.assert_called_once_with(
            base_url="https://model.example.test",
            api_key="secret-value",
        )


def test_service_backend_requires_url() -> None:
    with pytest.raises(ValueError, match="model_service_url is required"):
        Settings(model_backend="service")


def test_invalid_model_backend_is_rejected() -> None:
    with pytest.raises(ValueError, match="model_backend must be one of"):
        Settings(model_backend="unknown")
