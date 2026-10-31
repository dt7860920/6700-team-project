"""Service backend. The model endpoint is always mocked and Semgrep never runs here.

Repo targets point at ``tests/fixtures/vuln_repo`` (a local directory, copied not
cloned), so the ingest -> SAST -> analyze chain is exercised end to end offline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from ono import sast
from ono.analyzer import ServiceAnalyzer, build_analyzer
from ono.config import Settings
from ono.models import ScanOptions
from ono.targets import Target, TargetRegistry, get_registry

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"

SNIPPET = 'import os\nos.system("ping " + host)\n'

MODEL_FINDING = {
    "vulnerable": True,
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


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never run the Semgrep binary in the suite: the regex fallback is deterministic."""

    def unavailable(root: Path, rulesets: Any) -> dict[str, object]:
        raise sast.SemgrepUnavailableError("semgrep disabled in tests")

    monkeypatch.setattr(sast, "run_semgrep", unavailable)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return tmp_path / "ws"


def _settings(workspace: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "model_backend": "service",
        "model_service_url": "http://localhost:11434/v1/",  # trailing slash on purpose
        "model_name": "qwen2.5-coder:7b",
        "workspace_dir": workspace,
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


def _prompt(request: httpx.Request) -> str:
    content: str = json.loads(request.content)["messages"][1]["content"]
    return content


@pytest.fixture
def registry() -> TargetRegistry:
    return get_registry()


@pytest.fixture
def snippet(registry: TargetRegistry) -> Target:
    return registry["snippet"]


@pytest.fixture
def repo() -> Target:
    """A ``repo`` target whose source is the local fixture directory (no network)."""
    return Target(
        target_id="fixture-repo",
        name="fixture",
        kind="repo",
        languages=["python"],
        source=str(FIXTURE_REPO),
        snapshot="fixture",
    )


# -- Construction --------------------------------------------------------------


def test_build_analyzer_selects_service(workspace: Path) -> None:
    analyzer = build_analyzer(_settings(workspace))
    assert isinstance(analyzer, ServiceAnalyzer)
    assert analyzer.backend == "service"
    assert analyzer.base_url == "http://localhost:11434/v1"


def test_local_backend_still_unimplemented() -> None:
    with pytest.raises(NotImplementedError, match="MODEL_BACKEND=service"):
        build_analyzer(Settings(_env_file=None, model_backend="local"))


# -- Snippet target (ingest writes a file; SAST shortlists it; model confirms) ---


def test_json_response_becomes_rung2_unverified_finding(snippet: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))
    _mock_endpoint(analyzer, json.dumps(MODEL_FINDING))

    result = analyzer.run("scn_svc", snippet, ScanOptions(snippet=SNIPPET))

    assert [s.stage for s in result.stages] == ["ingest", "sast", "plan", "analyze", "verify"]
    assert all(s.status == "ok" for s in result.stages)
    assert result.stages[1].summary == "1 candidate(s)"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.scan_id == "scn_svc"
    assert f.target_id == "snippet"
    assert f.cwe == "CWE-78"
    assert f.severity == "high"
    assert f.file == "snippet.py"
    assert f.line_range == (2, 2)
    assert f.rung == 2
    assert f.verified is False
    assert f.confidence == 0.9
    assert f.patch_diff.startswith("-os.system")
    assert f.finding_id.startswith("fnd_")
    assert f.trace[0].line == 2 and "shell-command-from-string" in f.trace[0].note
    assert not (workspace / "scn_svc").exists()  # workspace cleaned up


def test_fenced_object_response_with_prose_is_tolerated(snippet: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))
    content = (
        "Here is my analysis:\n```json\n"
        + json.dumps({**MODEL_FINDING, "cwe": "78", "severity": "Critical"})
        + "\n```\nLet me know if you need more."
    )
    _mock_endpoint(analyzer, content)

    findings = analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET)).findings
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-78"  # bare number normalized
    assert findings[0].severity == "critical"  # case-insensitive


def test_garbage_response_yields_no_findings_without_crashing(
    snippet: Target, workspace: Path
) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))
    _mock_endpoint(analyzer, "I think line 2 looks dangerous but I am not sure {oops")

    result = analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET))
    assert result.findings == []
    assert all(s.status == "ok" for s in result.stages)


def test_items_without_cwe_or_patch_are_handled(snippet: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))
    items = [
        {**MODEL_FINDING, "cwe": "unknown"},  # dropped: Finding.cwe must match CWE-\d+
        {**MODEL_FINDING, "suggested_patch": "", "confidence": 7},  # kept, but only rung 1
    ]
    _mock_endpoint(analyzer, json.dumps(items))

    findings = analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET)).findings
    assert len(findings) == 1
    assert findings[0].rung == 1
    assert findings[0].confidence == 1.0  # clamped


def test_request_uses_configured_model_and_bearer_header(snippet: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace, model_service_api_key=SecretStr("sk-test")))
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
    assert "suspected CWE: CWE-78" in body["messages"][1]["content"]


def test_request_omits_authorization_when_no_key(snippet: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))
    seen = _mock_endpoint(analyzer, "[]")

    analyzer.run("s", snippet, ScanOptions(snippet=SNIPPET))
    assert "authorization" not in seen[0].headers


def test_clean_snippet_makes_no_model_call(snippet: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))
    seen = _mock_endpoint(analyzer, json.dumps(MODEL_FINDING))
    result = analyzer.run("s", snippet, ScanOptions(snippet="print('hello')\n"))
    assert result.findings == []
    assert seen == []
    assert result.stages[2].summary.startswith("REPORT none")


def test_endpoint_failure_marks_the_scan_failed_and_cleans_up(
    snippet: Target, workspace: Path
) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="model loading")

    analyzer._http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        analyzer.run("scn_fail", snippet, ScanOptions(snippet=SNIPPET))
    assert not (workspace / "scn_fail").exists()


# -- Repo target: real files in, real file:line out --------------------------------


def test_repo_target_sends_real_context_per_candidate(repo: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace, context_lines=5))
    reply = {**MODEL_FINDING, "file": "ignored-by-anchor.py", "line_start": 0, "line_end": 0}
    seen = _mock_endpoint(analyzer, json.dumps(reply))

    result = analyzer.run("scn_repo", repo, ScanOptions())

    assert all(s.status == "ok" for s in result.stages), result.stages
    assert result.stages[0].summary == f"snapshot {workspace / 'scn_repo'}"
    assert result.stages[1].summary == "3 candidate(s)"
    assert len(seen) == 3  # one model call per candidate, no more

    prompts = [_prompt(r) for r in seen]
    assert "file: app/util.py" in prompts[0] and "pickle.loads(blob)" in prompts[0]
    assert "file: app/views.py" in prompts[1] and ">>   16 |" in prompts[1]
    assert 'cur.execute(f"SELECT * FROM users WHERE id = {uid}")' in prompts[1]
    assert "import os" not in prompts[1]  # only +-5 lines around the sink are sent
    assert "suspected CWE: CWE-78" in prompts[2]

    # Findings are anchored to the candidate's real file:line (the model's 0/0 is out of window).
    assert [(f.file, f.line_range) for f in result.findings] == [
        ("app/util.py", (5, 5)),
        ("app/views.py", (16, 16)),
        ("app/views.py", (23, 23)),
    ]
    assert all(f.verified is False and f.rung == 2 for f in result.findings)
    assert result.findings[1].trace[0].symbol.startswith("cur.execute(")
    assert not (workspace / "scn_repo").exists()


def test_model_lines_inside_the_window_are_kept(repo: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace, max_candidates=1))
    _mock_endpoint(analyzer, json.dumps({**MODEL_FINDING, "line_start": 4, "line_end": 5}))

    findings = analyzer.run("s", repo, ScanOptions()).findings
    assert [(f.file, f.line_range) for f in findings] == [("app/util.py", (4, 5))]


def test_dismissed_candidates_produce_no_finding(repo: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))
    seen = _mock_endpoint(
        analyzer, json.dumps({**MODEL_FINDING, "vulnerable": False, "suggested_patch": ""})
    )
    result = analyzer.run("s", repo, ScanOptions())
    assert len(seen) == 3
    assert result.findings == []
    assert result.stages[3].summary == "0 raw finding(s)"


def test_max_candidates_bounds_model_calls(repo: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace, max_candidates=2))
    seen = _mock_endpoint(analyzer, json.dumps(MODEL_FINDING))
    result = analyzer.run("s", repo, ScanOptions())
    assert len(seen) == 2
    assert len(result.findings) == 2


def test_semgrep_results_feed_the_model_when_available(
    repo: Target, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canned = json.loads((FIXTURE_REPO.parent / "semgrep_output.json").read_text())
    monkeypatch.setattr(sast, "run_semgrep", lambda root, rulesets: canned)
    analyzer = ServiceAnalyzer(_settings(workspace))
    seen = _mock_endpoint(analyzer, json.dumps(MODEL_FINDING))

    result = analyzer.run("s", repo, ScanOptions())

    assert len(seen) == 4  # 5 Semgrep results -> 4 unique sinks (one no-CWE rule dropped)
    assert "python.flask.security.injection.tainted-sql-string" in _prompt(seen[0])
    assert "python.django.security.injection.sql" in _prompt(seen[3])  # WARNING ranks last
    assert {f.file for f in result.findings} == {"app/views.py"}


def test_ingest_failure_fails_the_scan_cleanly(workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))
    seen = _mock_endpoint(analyzer, json.dumps(MODEL_FINDING))
    missing = Target(
        target_id="gone", name="gone", kind="repo", source="/no/such/dir", snapshot="n/a"
    )
    with pytest.raises(Exception, match="unsupported target source"):
        analyzer.run("scn_gone", missing, ScanOptions())
    assert seen == []
    assert not (workspace / "scn_gone").exists()


def test_stages_outside_run_fail_loudly(repo: Target, workspace: Path) -> None:
    analyzer = ServiceAnalyzer(_settings(workspace))
    with pytest.raises(RuntimeError, match="must run via run"):
        analyzer.sast_shortlist(repo, ScanOptions())
