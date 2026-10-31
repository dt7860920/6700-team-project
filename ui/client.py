"""HTTP client for the backend job API. See the README for the API contract."""

from typing import Any, Protocol

import httpx

FINAL_STATUSES = {"done", "license_rejected", "failed"}

# The order a successful job moves through (used for the progress bar)
PIPELINE_STEPS = [
    "queued",
    "extracting",
    "checking_license",
    "hunting",
    "verifying",
    "patching",
    "done",
]

STATUS_LABELS = {
    "queued": "Waiting in line",
    "extracting": "Unpacking your code",
    "checking_license": "Checking for an MIT license",
    "license_rejected": "Rejected: no MIT license",
    "hunting": "Hunter model is scanning for exploits",
    "verifying": "Double-checking each finding",
    "patching": "Patch model is writing fixes",
    "done": "Done",
    "failed": "Failed",
}


class BackendError(Exception):
    """The backend could not be reached or returned an error."""


class Client(Protocol):
    def health(self) -> bool: ...
    def submit(self, filename: str, data: bytes) -> str: ...
    def status(self, job_id: str) -> dict[str, Any]: ...
    def results(self, job_id: str) -> dict[str, Any]: ...
    def delete(self, job_id: str) -> None: ...


class ApiClient:
    def __init__(self, base_url: str, http: httpx.Client | None = None) -> None:
        self.http = http or httpx.Client(base_url=base_url, timeout=30.0)

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self.http.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            raise BackendError(f"Could not reach the backend: {e}") from e
        if response.is_error:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            raise BackendError(f"Backend error {response.status_code}: {detail}")
        return response

    def health(self) -> bool:
        try:
            return self._request("GET", "/health").json().get("status") == "ok"
        except BackendError:
            return False

    def submit(self, filename: str, data: bytes) -> str:
        files = {"file": (filename, data, "application/zip")}
        return self._request("POST", "/jobs", files=files).json()["job_id"]

    def status(self, job_id: str) -> dict[str, Any]:
        return self._request("GET", f"/jobs/{job_id}").json()

    def results(self, job_id: str) -> dict[str, Any]:
        return self._request("GET", f"/jobs/{job_id}/results").json()

    def delete(self, job_id: str) -> None:
        self._request("DELETE", f"/jobs/{job_id}")
