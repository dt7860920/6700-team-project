"""SAST stage: Semgrep JSON parsing (canned output, no binary) and the regex fallback."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ono import sast

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_REPO = FIXTURES / "vuln_repo"


@pytest.fixture
def semgrep_json() -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES / "semgrep_output.json").read_text())
    return data


@pytest.fixture
def no_semgrep(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(root: Path, rulesets: Any) -> dict[str, object]:
        raise sast.SemgrepUnavailableError("semgrep is not installed")

    monkeypatch.setattr(sast, "run_semgrep", unavailable)


# -- Semgrep JSON -> Candidate -----------------------------------------------


def test_parse_semgrep_results_maps_fields_and_drops_rules_without_cwe(
    semgrep_json: dict[str, object],
) -> None:
    candidates, dropped = sast.parse_semgrep_results(semgrep_json, FIXTURE_REPO)

    assert dropped == ["python.lang.best-practice.open-never-closed.open-never-closed"]
    assert [(c.file, c.line, c.cwe_hint) for c in candidates] == [
        ("app/views.py", 13, "CWE-89"),
        ("app/views.py", 16, "CWE-704"),
        ("app/views.py", 22, "CWE-78"),
        ("app/views.py", 23, "CWE-78"),
        ("app/views.py", 23, "CWE-78"),  # two rules on one sink: dedupe() collapses them
    ]
    sqli = candidates[0]
    assert sqli.rule.startswith("python.django.security.injection.sql")
    # The excerpt is read from disk, not from Semgrep CE's "requires login" placeholder.
    # (Taint rules anchor start.line at the *source*; the model sees the whole window.)
    assert sqli.excerpt.strip() == 'uid = request.args.get("id", "")'
    assert 'os.system("ping -c 1 " + host)' in candidates[3].excerpt


def test_dedupe_collapses_same_sink_and_ranks() -> None:
    a = sast.Candidate("b.py", 2, "CWE-78", "r1", severity="WARNING")
    b = sast.Candidate("a.py", 9, "CWE-89", "r2", severity="WARNING")
    c = sast.Candidate("b.py", 2, "CWE-78", "r3", severity="ERROR")  # same sink as ``a``
    d = sast.Candidate("c.py", 1, "CWE-319", "x.audit.http", severity="ERROR")
    assert sast.dedupe([a, b, c, d]) == [c, d, b]  # ERROR first, non-audit before audit
    assert sast.regex_scan(FIXTURE_REPO)[0].severity == "ERROR"  # regex rules rank as ERROR


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CWE-89: Improper Neutralization", "CWE-89"),
        (["CWE-78: OS Command Injection", "CWE-77"], "CWE-78"),
        ("cwe_502", "CWE-502"),
        (89, "CWE-89"),
        ("89", "CWE-89"),
        ([], None),
        ("best-practice", None),
        (None, None),
    ],
)
def test_normalize_cwe(raw: object, expected: str | None) -> None:
    assert sast.normalize_cwe(raw) == expected


def test_absolute_and_dot_relative_paths_become_root_relative(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "m.py").write_text("eval(x)\n")
    data = {
        "results": [
            {
                "check_id": "r",
                "path": str(tmp_path / "pkg" / "m.py"),
                "start": {"line": 1},
                "extra": {"metadata": {"cwe": "CWE-95"}},
            },
            {
                "check_id": "r",
                "path": "./pkg/m.py",
                "start": {"line": 1},
                "extra": {"metadata": {"cwe": "CWE-95"}},
            },
        ]
    }
    candidates, _ = sast.parse_semgrep_results(data, tmp_path)
    assert {c.file for c in candidates} == {"pkg/m.py"}
    assert all(c.excerpt == "eval(x)" for c in candidates)


# -- The shortlist entry point ------------------------------------------------


def test_shortlist_uses_semgrep_when_it_works(
    monkeypatch: pytest.MonkeyPatch, semgrep_json: dict[str, object]
) -> None:
    seen: list[list[str]] = []

    def fake_run(root: Path, rulesets: Any) -> dict[str, object]:
        seen.append(list(rulesets))
        return semgrep_json

    monkeypatch.setattr(sast, "run_semgrep", fake_run)
    result = sast.shortlist(
        FIXTURE_REPO, rulesets=["p/owasp-top-ten"], languages=["python", "cobol"], max_candidates=20
    )
    assert result.engine == "semgrep"
    assert seen == [["p/owasp-top-ten", "p/python"]]  # language pack appended, unknown skipped
    # Ranked: the three ERROR-severity sinks first, the WARNING one last; 23 deduped to one.
    assert [(c.file, c.line, c.cwe_hint, c.severity) for c in result.candidates] == [
        ("app/views.py", 16, "CWE-704", "ERROR"),
        ("app/views.py", 22, "CWE-78", "ERROR"),
        ("app/views.py", 23, "CWE-78", "ERROR"),
        ("app/views.py", 13, "CWE-89", "WARNING"),
    ]


def test_shortlist_falls_back_to_regex_when_semgrep_is_unavailable(no_semgrep: None) -> None:
    result = sast.shortlist(FIXTURE_REPO, rulesets=["p/owasp-top-ten"], max_candidates=20)
    assert result.engine == "regex"
    assert [(c.file, c.line, c.cwe_hint, c.rule) for c in result.candidates] == [
        ("app/util.py", 5, "CWE-502", "unsafe-deserialization"),
        ("app/views.py", 16, "CWE-89", "sql-string-built-from-input"),
        ("app/views.py", 23, "CWE-78", "shell-command-from-string"),
    ]
    assert result.candidates[1].excerpt.strip().startswith("cur.execute(f")


def test_empty_ruleset_means_regex_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(root: Path, rulesets: Any) -> dict[str, object]:
        raise AssertionError("semgrep must not run with no rulesets")

    monkeypatch.setattr(sast, "run_semgrep", boom)
    result = sast.shortlist(FIXTURE_REPO, rulesets=[""], max_candidates=20)
    assert result.engine == "regex"
    assert len(result.candidates) == 3


def test_max_candidates_bounds_the_queue(no_semgrep: None) -> None:
    result = sast.shortlist(FIXTURE_REPO, rulesets=["x"], max_candidates=1)
    assert len(result.candidates) == 1


def test_regex_scan_skips_vendored_dirs_and_non_python(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.py").write_text("eval(a)\n")
    (tmp_path / "notes.txt").write_text("eval(a)\n")
    (tmp_path / "ok.py").write_text("print('x')\nos.system('ls ' + d)\n")
    hits = sast.regex_scan(tmp_path)
    assert [(c.file, c.line) for c in hits] == [("ok.py", 2)]


# -- Running the binary (subprocess monkeypatched) ----------------------------


def test_semgrep_command_is_bounded_and_offline() -> None:
    cmd = sast.semgrep_command(Path("/ws"), ["p/owasp-top-ten", "rules.yml"], "/venv/bin/semgrep")
    assert cmd[:3] == ["/venv/bin/semgrep", "scan", "--json"]
    assert {"--quiet", "--metrics=off", "--disable-version-check", "--no-git-ignore"} <= set(cmd)
    assert any(arg.startswith("--timeout=") for arg in cmd)
    assert cmd[cmd.index("--config") + 1] == "p/owasp-top-ten"
    assert "rules.yml" in cmd
    assert cmd[-1] == "."


def test_run_semgrep_accepts_json_despite_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sast, "semgrep_executable", lambda: "/fake/semgrep")
    doc = {"results": [], "errors": [{"message": "parse error in x.py"}]}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert kwargs["cwd"] == tmp_path
        return subprocess.CompletedProcess(cmd, 2, json.dumps(doc), "warning\n")

    monkeypatch.setattr(sast.subprocess, "run", fake_run)
    assert sast.run_semgrep(tmp_path, ["p/x"]) == doc


@pytest.mark.parametrize(
    "failure",
    ["not-installed", "timeout", "bad-json", "no-executable"],
)
def test_run_semgrep_failure_modes_raise_unavailable(
    failure: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        sast, "semgrep_executable", lambda: None if failure == "no-executable" else "/fake/semgrep"
    )

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if failure == "not-installed":
            raise FileNotFoundError(cmd[0])
        if failure == "timeout":
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
        return subprocess.CompletedProcess(cmd, 2, "", "semgrep: error: invalid config\n")

    monkeypatch.setattr(sast.subprocess, "run", fake_run)
    with pytest.raises(sast.SemgrepUnavailableError):
        sast.run_semgrep(tmp_path, ["p/x"])
