"""Prometheus metrics - plan §8.6, layer 2 ("is it healthy *now*").

One :class:`Metrics` object per application, holding its own
:class:`~prometheus_client.CollectorRegistry` (never the process-global one, so a
test can build several apps without "duplicated timeseries" errors and nothing bleeds
between them). The service, the analyzer and the model client receive the object and
call its small helpers; when ``Settings.metrics_enabled`` is false :func:`build_metrics`
returns ``None`` and every caller skips the call - nothing is collected and
``GET /metrics`` does not exist.

Label cardinality is deliberately tiny: ``target`` is a key of the allowlist, the rest
are closed enums (``status``, ``severity``, ``rung``, ``verified``, ``result``, ``kind``,
``outcome``). Nothing here ever records a scan id, a file path, code or a prompt.

Metric                               Type       Labels
------------------------------------ ---------- ------------------------------------
ono_build_info                       Info       version, model_backend
ono_scans_total                      Counter    target, status (done | failed)
ono_scan_duration_seconds            Histogram  -
ono_findings_total                   Counter    severity, rung, verified
ono_verifier_results_total           Counter    result (pass | fail | skip)
ono_active_scans / ono_queued_scans  Gauge      -
ono_model_requests_total             Counter    outcome (ok | error)
ono_model_latency_seconds            Histogram  -
ono_model_tokens_total               Counter    kind (prompt | completion)

TODO(metrics): ``ono_model_ttft_seconds`` (time to first token) needs a *streaming*
model call - :class:`~ono.agents.model.ModelClient` posts ``stream: false`` and gets
one body back, so there is no first-token instant to observe and the metric is not
defined rather than faked. Until the client streams, take TTFT from the model
server's own ``/metrics`` (vLLM exposes ``vllm:time_to_first_token_seconds``; see
``observability/prometheus.yml``).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    disable_created_metrics,
    generate_latest,
)
from prometheus_client.gc_collector import GCCollector
from prometheus_client.platform_collector import PlatformCollector
from prometheus_client.process_collector import ProcessCollector

from ono.config import Settings
from ono.models import Finding, Scan

__all__ = ["TEXT_CONTENT_TYPE", "Metrics", "VerifierResult", "build_metrics"]

TEXT_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
"""Content type of ``GET /metrics``: the Prometheus text exposition format."""

VerifierResult = Literal["pass", "fail", "skip"]
"""``pass`` = verdict true, ``fail`` = dropped by the verifier, ``skip`` = passed through
without a verdict (the service backend's verifier is still a pass-through, step 3b-2)."""

SCAN_DURATION_BUCKETS: tuple[float, ...] = (
    0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1200, 1800, 3600,
)  # fmt: skip
"""Mock scans end in milliseconds; a service scan is minutes (clone + Semgrep + agents)."""

MODEL_LATENCY_BUCKETS: tuple[float, ...] = (
    0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 120,
)  # fmt: skip
"""One ``/chat/completions`` round-trip; the request timeout is 120 s."""


class Metrics:
    """The application's collectors plus the helpers that move them.

    Every helper is cheap (a counter increment, a histogram observation) and
    thread-safe: prometheus-client guards each value with its own lock, so the scan
    workers and the event loop can call them without coordination.
    """

    def __init__(
        self, *, registry: CollectorRegistry | None = None, process_collectors: bool = True
    ) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        # No ``*_created`` companion series: they double the sample count and carry
        # nothing a dashboard uses. (A process-wide prometheus-client switch.)
        disable_created_metrics()  # type: ignore[no-untyped-call]  # unannotated upstream
        if process_collectors:  # process_* (Linux only), python_info, python_gc_*
            ProcessCollector(registry=self.registry)
            PlatformCollector(registry=self.registry)
            GCCollector(registry=self.registry)

        self.build_info = Info(
            "ono_build", "Version and analyzer backend of this process.", registry=self.registry
        )
        # -- scans ---------------------------------------------------------------------
        self.scans_total = Counter(
            "ono_scans",
            "Scans that ended, by allowlisted target and final status.",
            ["target", "status"],
            registry=self.registry,
        )
        self.scan_duration = Histogram(
            "ono_scan_duration_seconds",
            "Wall-clock time from a worker picking a scan up to its end.",
            buckets=SCAN_DURATION_BUCKETS,
            registry=self.registry,
        )
        self.findings_total = Counter(
            "ono_findings",
            "Findings persisted by completed scans, by severity, output rung and verdict.",
            ["severity", "rung", "verified"],
            registry=self.registry,
        )
        self.verifier_results_total = Counter(
            "ono_verifier_results",
            "Raw findings seen by the verify stage: pass (verdict true), fail (dropped), "
            "skip (passed through without a verdict).",
            ["result"],
            registry=self.registry,
        )
        self.active_scans = Gauge(
            "ono_active_scans", "Scans running on a worker right now.", registry=self.registry
        )
        self.queued_scans = Gauge(
            "ono_queued_scans", "Scans waiting for a free worker.", registry=self.registry
        )
        # -- model client --------------------------------------------------------------
        self.model_requests_total = Counter(
            "ono_model_requests",
            "Chat-completion requests made by the shared model client, by outcome.",
            ["outcome"],
            registry=self.registry,
        )
        self.model_latency = Histogram(
            "ono_model_latency_seconds",
            "Wall-clock latency of one chat-completion request (success or failure).",
            buckets=MODEL_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.model_tokens_total = Counter(
            "ono_model_tokens",
            "Tokens reported in the model's usage block, by kind.",
            ["kind"],
            registry=self.registry,
        )
        # Pre-create the closed-enum series so rate()/increase() have a zero to start from.
        for result in ("pass", "fail", "skip"):
            self.verifier_results_total.labels(result=result)
        for outcome in ("ok", "error"):
            self.model_requests_total.labels(outcome=outcome)
        for kind in ("prompt", "completion"):
            self.model_tokens_total.labels(kind=kind)
        self.set_inflight(active=0, queued=0)

    # -- helpers -----------------------------------------------------------------------
    def describe_build(self, *, version: str, model_backend: str) -> None:
        self.build_info.info({"version": version, "model_backend": model_backend})

    def set_inflight(self, *, active: int, queued: int) -> None:
        """Publish the worker pool's state (the service calls this on every transition)."""
        self.active_scans.set(active)
        self.queued_scans.set(queued)

    def scan_finished(self, scan: Scan, findings: Sequence[Finding]) -> None:
        """Count an ended scan (``done`` or ``failed``), its duration and its findings."""
        self.scans_total.labels(target=scan.target_id, status=scan.status).inc()
        if scan.started_at is not None and scan.completed_at is not None:
            # A scan failed at shutdown never started: no duration to observe.
            self.scan_duration.observe((scan.completed_at - scan.started_at).total_seconds())
        for finding in findings:
            self.findings_total.labels(
                severity=finding.severity,
                rung=str(finding.rung),
                verified="true" if finding.verified else "false",
            ).inc()

    def verifier_results(self, *, passed: int, failed: int, skipped: int) -> None:
        self.verifier_results_total.labels(result="pass").inc(passed)
        self.verifier_results_total.labels(result="fail").inc(failed)
        self.verifier_results_total.labels(result="skip").inc(skipped)

    def model_request(
        self,
        *,
        latency_s: float,
        ok: bool,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
    ) -> None:
        """Record one chat-completion round-trip (token counts only when the reply had them)."""
        self.model_requests_total.labels(outcome="ok" if ok else "error").inc()
        self.model_latency.observe(max(0.0, latency_s))
        if prompt_tokens:
            self.model_tokens_total.labels(kind="prompt").inc(prompt_tokens)
        if completion_tokens:
            self.model_tokens_total.labels(kind="completion").inc(completion_tokens)

    def render(self) -> bytes:
        """The registry in the Prometheus text exposition format (the ``/metrics`` body)."""
        return generate_latest(self.registry)


def build_metrics(settings: Settings) -> Metrics | None:
    """A fresh :class:`Metrics` when ``settings.metrics_enabled``; otherwise ``None``."""
    return Metrics() if settings.metrics_enabled else None
