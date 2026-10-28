import httpx
import pytest
from client import ApiClient, BackendError
from fake_backend import MockClient


def test_mock_client_walks_through_pipeline():
    """
    A mock job should finish and return findings with the fields the UI shows.
    """
    client = MockClient(step_seconds=0)
    job_id = client.submit("repo.zip", b"data")

    assert client.status(job_id)["status"] == "done"
    results = client.results(job_id)
    assert results["findings"]
    for finding in results["findings"]:
        assert {"id", "file", "line", "cwe", "title", "explanation", "trigger"} <= (
            finding.keys()
        )


def test_mock_client_results_wait_until_done():
    """
    Results should not be available while the job is still running.
    """
    client = MockClient(step_seconds=60)
    job_id = client.submit("repo.zip", b"data")
    with pytest.raises(BackendError):
        client.results(job_id)


def test_mock_client_delete_removes_job():
    client = MockClient(step_seconds=0)
    job_id = client.submit("repo.zip", b"data")
    client.delete(job_id)
    with pytest.raises(BackendError):
        client.status(job_id)


def test_api_client_uses_job_endpoints():
    """
    The real client should call the documented endpoints and parse the JSON.
    """
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            return httpx.Response(200, json={"job_id": "abc"})
        if request.url.path == "/jobs/abc":
            return httpx.Response(200, json={"job_id": "abc", "status": "hunting"})
        return httpx.Response(200)

    http = httpx.Client(base_url="http://api", transport=httpx.MockTransport(handler))
    client = ApiClient("http://api", http=http)

    assert client.submit("repo.zip", b"data") == "abc"
    assert client.status("abc")["status"] == "hunting"
    client.delete("abc")
    assert calls == [("POST", "/jobs"), ("GET", "/jobs/abc"), ("DELETE", "/jobs/abc")]


def test_api_client_reports_backend_errors():
    """
    HTTP errors should surface as BackendError with the backend's detail message.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(413, json={"detail": "Upload too large"})

    http = httpx.Client(base_url="http://api", transport=httpx.MockTransport(handler))
    client = ApiClient("http://api", http=http)

    with pytest.raises(BackendError, match="Upload too large"):
        client.submit("repo.zip", b"data")
    assert client.health() is False
