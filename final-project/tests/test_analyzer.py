"""Mock analyzer: the Deliverable-2 'Analyzer E2E' smoke layer."""

from __future__ import annotations

import pytest

from ono.analyzer import MockAnalyzer, build_analyzer
from ono.config import Settings
from ono.models import ScanOptions
from ono.targets import TargetRegistry, UnauthorizedTargetError, get_registry


@pytest.fixture
def analyzer(settings: Settings) -> MockAnalyzer:
    return MockAnalyzer(settings)


@pytest.fixture
def registry() -> TargetRegistry:
    return get_registry()


def test_build_analyzer_selects_mock(settings: Settings) -> None:
    assert isinstance(build_analyzer(settings), MockAnalyzer)


def test_unimplemented_backends_fail_loudly() -> None:
    s = Settings(_env_file=None, model_backend="local")
    with pytest.raises(NotImplementedError, match="MODEL_BACKEND=mock"):
        build_analyzer(s)


def test_pygoat_golden_path(analyzer: MockAnalyzer, registry: TargetRegistry) -> None:
    result = analyzer.run("scn_test", registry["pygoat"], ScanOptions())
    assert len(result.findings) >= 1
    assert [s.stage for s in result.stages] == ["ingest", "sast", "plan", "analyze", "verify"]
    assert all(s.status == "ok" for s in result.stages)

    sqli = next(f for f in result.findings if f.cwe == "CWE-89")
    assert sqli.scan_id == "scn_test"
    assert sqli.target_id == "pygoat"
    assert sqli.file.endswith(".py")
    assert sqli.line_range[0] >= 1 and sqli.line_range[0] <= sqli.line_range[1]
    assert sqli.location == "introduction/views.py:210-211"
    assert len(sqli.trace) >= 2
    assert 0.0 <= sqli.confidence <= 1.0
    assert sqli.rung == 4
    assert sqli.verified is True
    assert "+++ b/introduction/views.py" in sqli.patch_diff


def test_finding_ids_are_deterministic(analyzer: MockAnalyzer, registry: TargetRegistry) -> None:
    a = analyzer.run("scn_a", registry["pygoat"], ScanOptions()).findings
    b = analyzer.run("scn_b", registry["pygoat"], ScanOptions()).findings
    assert [f.finding_id for f in a] == [f.finding_id for f in b]


def test_options_filter_findings(analyzer: MockAnalyzer, registry: TargetRegistry) -> None:
    only_rung4 = analyzer.run("s", registry["pygoat"], ScanOptions(min_rung=4)).findings
    assert all(f.rung >= 4 for f in only_rung4)
    capped = analyzer.run("s", registry["pygoat"], ScanOptions(max_findings=1)).findings
    assert len(capped) == 1


def test_every_registered_target_runs_cleanly(
    analyzer: MockAnalyzer, registry: TargetRegistry
) -> None:
    for target in registry.all():
        result = analyzer.run("s", target, ScanOptions(snippet="x = eval(user_input)"))
        assert all(s.status == "ok" for s in result.stages), target.target_id


def test_snippet_sast_detects_shell_true_and_eval(
    analyzer: MockAnalyzer, registry: TargetRegistry
) -> None:
    code = "import subprocess\nsubprocess.run(cmd, shell=True)\nresult = eval(expr)\nx = 1\n"
    result = analyzer.run("s", registry["snippet"], ScanOptions(snippet=code))
    cwes = {f.cwe: f.line_range[0] for f in result.findings}
    assert cwes == {"CWE-78": 2, "CWE-95": 3}


def test_snippet_without_issues_returns_no_findings(
    analyzer: MockAnalyzer, registry: TargetRegistry
) -> None:
    result = analyzer.run("s", registry["snippet"], ScanOptions(snippet="print('hello')\n"))
    assert result.findings == []


def test_registry_is_an_exact_allowlist(registry: TargetRegistry) -> None:
    assert registry.is_authorized("pygoat")
    assert not registry.is_authorized("PyGoat")  # exact match, no normalization
    assert not registry.is_authorized("pygoat ")
    with pytest.raises(UnauthorizedTargetError):
        registry.require("nodegoat")
