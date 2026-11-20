"""Prometheus metrics: the ``/metrics`` endpoint, its gate, and the collectors moving.

Each app owns its own registry (``app.state.metrics.registry``), so the tests below
build apps freely and never see each other's counters.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from ono.agents.model import ModelClient, ModelError
from ono.analyzer import MockAnalyzer
from ono.api import create_app
from ono.config import Settings
from ono.metrics import Metrics
from ono.models import ScanRequest
from ono.service import ScanService
from ono.store import InMemoryScanStore
from ono.targets import get_registry
from test_api import start_and_wait

EXPECTED_FAMILIES = {
    "ono_build_info",
    "ono_scans_total",
    "ono_scan_duration_seconds",
    "ono_findings_total",
    "ono_verifier_results_total",
    "ono_active_scans",
    "ono_queued_scans",
    "ono_model_requests_total",
    "ono_model_latency_seconds",
    "ono_model_tokens_total",
}

Sample = tuple[str, dict[str, str], float]
"""One exposition sample: ``(sample_name, labels, value)``."""


def samples(text: str) -> list[Sample]:
    """Flatten the exposition text into ``(sample_name, labels, value)`` rows."""
    return [
        (s.name, dict(s.labels), s.value)
        for family in text_string_to_metric_families(text)
        for s in family.samples
    ]


def value(table: list[Sample], name: str, **labels: str) -> float:
    """The one sample called ``name`` whose labels include ``labels`` (0.0 if absent)."""
    hits = [v for n, lbl, v in table if n == name and labels.items() <= lbl.items()]
    assert len(hits) <= 1, hits
    return hits[0] if hits else 0.0


def family_names(text: str) -> set[str]:
    names: set[str] = set()
    for family in text_string_to_metric_families(text):
        # The parser strips the _total suffix of counters; add it back for readability.
        names.add(family.name + ("_total" if family.type == "counter" else ""))
    return names


# ---------------------------------------------------------------------------
# The endpoint and its gate
# ---------------------------------------------------------------------------


def test_metrics_endpoint_is_on_by_default(client: TestClient) -> None:
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
    assert family_names(r.text) >= EXPECTED_FAMILIES, family_names(r.text)
    table = samples(r.text)
    assert value(table, "ono_build_info", model_backend="mock") == 1.0
    assert value(table, "ono_active_scans") == 0.0
    assert value(table, "ono_queued_scans") == 0.0


def test_metrics_endpoint_is_internal(client: TestClient) -> None:
    """Not part of the documented API surface."""
    assert "/metrics" not in client.get("/openapi.json").json()["paths"]


def test_metrics_disabled_is_404_and_collects_nothing() -> None:
    app = create_app(Settings(_env_file=None, metrics_enabled=False), mount_ui=False)
    assert app.state.metrics is None
    with TestClient(app) as c:
        assert c.get("/metrics").status_code == 404
        done = start_and_wait(c, {"target_id": "pygoat"})  # the app itself is unaffected
        assert done["status"] == "done" and done["findings_count"] >= 1
        assert c.get("/metrics").status_code == 404


def test_each_app_has_its_own_registry(settings: Settings) -> None:
    a = create_app(settings, mount_ui=False)
    b = create_app(settings, mount_ui=False)
    assert a.state.metrics is not b.state.metrics
    assert a.state.metrics.registry is not b.state.metrics.registry
    with TestClient(a) as ca, TestClient(b) as cb:
        start_and_wait(ca, {"target_id": "pygoat"})
        assert value(samples(ca.get("/metrics").text), "ono_scans_total", status="done") == 1.0
        assert value(samples(cb.get("/metrics").text), "ono_scans_total", status="done") == 0.0


# ---------------------------------------------------------------------------
# The scan lifecycle moves the collectors
# ---------------------------------------------------------------------------


def test_scan_through_the_mock_backend_populates_the_metrics(client: TestClient) -> None:
    start_and_wait(client, {"target_id": "pygoat"})
    start_and_wait(client, {"target_id": "juice-shop"})
    table = samples(client.get("/metrics").text)

    assert value(table, "ono_scans_total", target="pygoat", status="done") == 1.0
    assert value(table, "ono_scans_total", target="juice-shop", status="done") == 1.0
    assert value(table, "ono_scans_total", status="failed") == 0.0
    assert value(table, "ono_scan_duration_seconds_count") == 2.0
    assert value(table, "ono_scan_duration_seconds_sum") >= 0.0

    # The mock's findings are all verified; juice-shop's is rung 5, pygoat's are high/critical.
    findings = [(n, lbl, v) for n, lbl, v in table if n == "ono_findings_total"]
    assert sum(v for _, _, v in findings) >= 2
    assert all(lbl["verified"] == "true" for _, lbl, _ in findings)
    assert value(table, "ono_findings_total", rung="5", severity="critical") >= 1.0
    assert {lbl["severity"] for _, lbl, _ in findings} <= {"low", "medium", "high", "critical"}

    # The mock verifier drops nothing and never passes a finding through without a verdict.
    assert value(table, "ono_verifier_results_total", result="pass") >= 2.0
    assert value(table, "ono_verifier_results_total", result="fail") == 0.0
    assert value(table, "ono_verifier_results_total", result="skip") == 0.0

    # The pool is idle again.
    assert value(table, "ono_active_scans") == 0.0
    assert value(table, "ono_queued_scans") == 0.0

    # The mock backend makes no model calls.
    assert value(table, "ono_model_requests_total", outcome="ok") == 0.0
    assert value(table, "ono_model_latency_seconds_count") == 0.0


def test_failed_scan_is_counted_as_failed(settings: Settings) -> None:
    class Boom(MockAnalyzer):
        def analyze(self, *args: Any, **kwargs: Any) -> Any:
            msg = "kaboom"
            raise RuntimeError(msg)

    metrics = Metrics(process_collectors=False)
    service = ScanService(settings, get_registry(), Boom(settings), InMemoryScanStore(), metrics)
    try:
        scan = service.submit_scan(ScanRequest(target_id="pygoat"))
        final = service.wait(scan.scan_id, timeout=10)
    finally:
        service.close()
    assert final is not None and final.status == "failed"
    table = samples(metrics.render().decode())
    assert value(table, "ono_scans_total", target="pygoat", status="failed") == 1.0
    assert value(table, "ono_scans_total", status="done") == 0.0
    assert value(table, "ono_scan_duration_seconds_count") == 1.0  # it did start
    assert value(table, "ono_verifier_results_total", result="pass") == 0.0  # never reached


def test_queued_scan_failed_at_shutdown_has_no_duration(settings: Settings) -> None:
    metrics = Metrics(process_collectors=False)
    service = ScanService(
        settings, get_registry(), MockAnalyzer(settings), InMemoryScanStore(), metrics
    )
    service.close()  # nothing ran; close() is what marks the (empty) queue failed
    assert value(samples(metrics.render().decode()), "ono_scan_duration_seconds_count") == 0.0
    assert service.active_scans == 0 and service.queued_scans == 0


def test_run_scan_synchronous_path_is_counted_too(settings: Settings) -> None:
    metrics = Metrics(process_collectors=False)
    service = ScanService(
        settings, get_registry(), MockAnalyzer(settings), InMemoryScanStore(), metrics=metrics
    )
    service.run_scan(ScanRequest(target_id="vulpy"))
    table = samples(metrics.render().decode())
    assert value(table, "ono_scans_total", target="vulpy", status="done") == 1.0


def test_service_without_metrics_is_unchanged(settings: Settings) -> None:
    """The hooks are additive: no metrics object, same behaviour."""
    service = ScanService(settings, get_registry(), MockAnalyzer(settings), InMemoryScanStore())
    response = service.run_scan(ScanRequest(target_id="pygoat"))
    assert response.status == "done" and response.findings


# ---------------------------------------------------------------------------
# The model client reports latency, outcome and tokens (never content)
# ---------------------------------------------------------------------------


REPLY_CONTENT = "MODEL-REPLY-TEXT-4242"  # distinctive, so "not in /metrics" is meaningful


def _model_settings() -> Settings:
    return Settings(_env_file=None, model_service_url="http://model/v1", model_name="m")


def _chat_transport(status: int = 200, usage: dict[str, int] | None = None) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        if status != 200:
            return httpx.Response(status, text="nope")
        body: dict[str, Any] = {
            "choices": [{"message": {"role": "assistant", "content": REPLY_CONTENT}}]
        }
        if usage is not None:
            body["usage"] = usage
        return httpx.Response(200, json=body)

    return httpx.MockTransport(handle)


def test_model_client_records_latency_and_tokens() -> None:
    metrics = Metrics(process_collectors=False)
    client = ModelClient(
        _model_settings(),
        transport=_chat_transport(usage={"prompt_tokens": 120, "completion_tokens": 30}),
        metrics=metrics,
    )
    reply = client.chat([{"role": "user", "content": "x"}])
    client.chat([{"role": "user", "content": "y"}])
    assert reply.prompt_tokens == 120 and reply.completion_tokens == 30

    table = samples(metrics.render().decode())
    assert value(table, "ono_model_requests_total", outcome="ok") == 2.0
    assert value(table, "ono_model_requests_total", outcome="error") == 0.0
    assert value(table, "ono_model_latency_seconds_count") == 2.0
    assert value(table, "ono_model_tokens_total", kind="prompt") == 240.0
    assert value(table, "ono_model_tokens_total", kind="completion") == 60.0
    assert REPLY_CONTENT not in metrics.render().decode()  # content never reaches the registry


def test_model_client_counts_failures_and_tolerates_missing_usage() -> None:
    metrics = Metrics(process_collectors=False)
    failing = ModelClient(_model_settings(), transport=_chat_transport(503), metrics=metrics)
    try:
        failing.chat([{"role": "user", "content": "x"}])
    except ModelError:
        pass
    else:
        raise AssertionError("expected ModelError")
    silent = ModelClient(_model_settings(), transport=_chat_transport(usage=None), metrics=metrics)
    silent.chat([{"role": "user", "content": "x"}])

    table = samples(metrics.render().decode())
    assert value(table, "ono_model_requests_total", outcome="error") == 1.0
    assert value(table, "ono_model_requests_total", outcome="ok") == 1.0
    assert value(table, "ono_model_latency_seconds_count") == 2.0  # failures are timed too
    assert value(table, "ono_model_tokens_total", kind="prompt") == 0.0  # not fabricated


def test_model_client_without_metrics_still_works() -> None:
    client = ModelClient(_model_settings(), transport=_chat_transport(usage={"prompt_tokens": 1}))
    assert client.chat([{"role": "user", "content": "x"}]).text == REPLY_CONTENT
