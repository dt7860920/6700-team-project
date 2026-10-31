"""Service backend (stock-Qwen baseline). The model endpoint is always mocked here."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from ono.analyzer import ServiceAnalyzer, build_analyzer
from ono.config import Settings
from ono.models import ScanOptions
from ono.targets import Target, TargetRegistry, get_registry

SNIPPET = 'import os\nos.system("ping " + host)\n'

MODEL_FINDING = {
    "cwe": "CWE-78",
    "title": "OS command injection via os.system",
    "severity": "high",
    "file": "snippet.py",
    "line_start": 2,
    "line_end": 2,
    "description": "host is concatenated into a shell command.",
    "suggested_patch": "-os.system('ping ' + host)\n+subprocess.run(['ping', host])",
    "confidence": 0.9,
}


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "model_backend": "service",
        "model_service_url": "http://localhost:11434/v1/",  # trailing slash on purpose
        "model_name": "qwen2.5-coder:7b",
    }
    return Settings(_env_file=None, **{**base, **overrides})


def _chat_body(content: str) -> dict[str, Any]:
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def _mock_endpoint(analyzer: ServiceAnalyzer, content: str) -> list[httpx.Request]:
    """Point the analyzer's HTTP client at an in-memory endpoint; return captured requests."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_chat_body(content))

    analyzer._http = httpx.Client(transport=httpx.MockTransport(handler))
    return seen


@pytest.fixture
def registry() -> TargetRegistry:
    return get_registry()


@pytest.fixture
def snippet(registry: TargetRegistry) -> Target:
    return registry["snippet"]


def test_build_analyzer_selects_service() -> None:
    analyzer = build_analyzer(_settings())
    assert isinstance(analyzer, ServiceAnalyzer)
    assert analyzer.backend == "service"
    assert analyzer.base_url == "http://localhost:11434/v1"


def test_local_backend_still_unimplemented() -> None:
    with pytest.raises(NotImplementedError, match="MODEL_BACKEND=service"):
        build_analyzer(Settings(_env_file=None, model_backend="local"))


def test_json_response_becomes_rung2_unverified_finding(snippet: Target) -> None:
    analyzer = ServiceAnalyzer(_settings())
    _mock_endpoint(analyzer, json.dumps([MODEL_FINDING]))

    result = analyzer.run("scn_svc", snippet, ScanOptions(snippet=SNIPPET))

    assert [s.stage for s in result.stages] == ["ingest", "sast", "plan", "analyze", "verify"]
    assert all(s.status == "ok" for s in result.stages)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.scan_id == "scn_svc"
    assert f.target_id == "snippet"
    assert f.cwe == "CWE-78"
    assert f.severity == "high"
    assert f.line_range == (2, 2)
    assert f.rung == 2
    assert f.verified is False
    assert f.confidence == 0.9
    assert f.patch_diff.startswith("-os.system")
    assert f.finding_id.startswith("fnd_")


def test_fenced_object_response_with_prose_is_tolerated(snippet: Target) -> None:
    analyzer = ServiceAnalyzer(_settings())
    content = (
        "Here is my analysis:\n```json\n"
        + json.dumps({"findings": [{**MODEL_FINDING, "cwe": "78", "severity": "Critical"}]})
        + "\n```\nLet me know if you need more."
    )
    _mock_endpoint(analyzer, content)

    findings = analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET)).findings
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-78"  # bare number normalized
    assert findings[0].severity == "critical"  # case-insensitive


def test_garbage_response_yields_no_findings_without_crashing(snippet: Target) -> None:
    analyzer = ServiceAnalyzer(_settings())
    _mock_endpoint(analyzer, "I think line 2 looks dangerous but I am not sure {oops")

    result = analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET))
    assert result.findings == []
    assert all(s.status == "ok" for s in result.stages)


def test_items_without_cwe_or_patch_are_handled(snippet: Target) -> None:
    analyzer = ServiceAnalyzer(_settings())
    items = [
        {**MODEL_FINDING, "cwe": "unknown"},  # dropped: Finding.cwe must match CWE-\d+
        {**MODEL_FINDING, "suggested_patch": "", "confidence": 7},  # kept, but only rung 1
    ]
    _mock_endpoint(analyzer, json.dumps(items))

    findings = analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET)).findings
    assert len(findings) == 1
    assert findings[0].rung == 1
    assert findings[0].confidence == 1.0  # clamped


def test_request_uses_configured_model_and_bearer_header(snippet: Target) -> None:
    analyzer = ServiceAnalyzer(_settings(model_service_api_key=SecretStr("sk-test")))
    seen = _mock_endpoint(analyzer, "[]")

    analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET))

    assert len(seen) == 1
    request = seen[0]
    assert str(request.url) == "http://localhost:11434/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer sk-test"
    body = json.loads(request.content)
    assert body["model"] == "qwen2.5-coder:7b"
    assert body["temperature"] == 0
    assert body["stream"] is False
    assert body["messages"][0]["role"] == "system"
    assert 'os.system("ping " + host)' in body["messages"][1]["content"]


def test_request_omits_authorization_when_no_key(snippet: Target) -> None:
    analyzer = ServiceAnalyzer(_settings())
    seen = _mock_endpoint(analyzer, "[]")

    analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET))
    assert "authorization" not in seen[0].headers


def test_non_snippet_targets_skip_the_model(registry: TargetRegistry) -> None:
    analyzer = ServiceAnalyzer(_settings())
    seen = _mock_endpoint(analyzer, json.dumps([MODEL_FINDING]))

    result = analyzer.run("s", registry["pygoat"], ScanOptions())
    assert result.findings == []
    assert seen == []  # real ingest is a later step; nothing to send yet
    assert result.stages[0].summary == "snapshot sandbox/pygoat@pinned"


def test_endpoint_failure_marks_the_scan_failed(snippet: Target) -> None:
    analyzer = ServiceAnalyzer(_settings())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="model loading")

    analyzer._http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET))
