from typing import Protocol

import httpx

from team_project.config import Settings, settings
from team_project.fakemodel import FakeModel


class ModelBackend(Protocol):
    def predict(self, inputs: list[str]) -> list[str]: ...


class LocalModel:
    """In-process backend; wraps the stub model until a real one replaces it."""

    def __init__(self, path: str, device: str) -> None:
        self.path = path
        self.device = device
        self._model = FakeModel()

    def predict(self, inputs: list[str]) -> list[str]:
        return self._model.predict(inputs)


class RemoteModel:
    """Client for a model served by a separate HTTP service."""

    def __init__(self, base_url: str, api_key: str | None = None) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
        self._client = httpx.Client(base_url=base_url, headers=headers, timeout=30.0)

    def predict(self, inputs: list[str]) -> list[str]:
        response = self._client.post("/predict", json={"inputs": inputs})
        response.raise_for_status()
        predictions = response.json().get("predictions")
        if not isinstance(predictions, list) or not all(
            isinstance(item, str) for item in predictions
        ):
            raise ValueError("model service returned invalid predictions")
        return predictions


class ModelClient:
    """Select and use the model backend configured through environment settings."""

    def __init__(self, app_settings: Settings = settings) -> None:
        if app_settings.model_backend == "local":
            self._backend: ModelBackend = LocalModel(
                path=app_settings.model_path,
                device=app_settings.model_device,
            )
        else:
            assert app_settings.model_service_url is not None
            api_key = (
                app_settings.model_service_api_key.get_secret_value()
                if app_settings.model_service_api_key
                else None
            )
            self._backend = RemoteModel(
                base_url=app_settings.model_service_url,
                api_key=api_key,
            )

    def predict(self, inputs: list[str]) -> list[str]:
        return self._backend.predict(inputs)


model_client = ModelClient()
