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
    """Exit 3 = some files did not parse: a partial run, zero results still mean "clean"."""
    monkeypatch.setattr(sast, "semgrep_executable", lambda: "/fake/semgrep")
    partial = {"code": 3, "level": "warn", "type": "PartialParsing", "message": "x.py:1 syntax"}
    doc = {"results": [], "errors": [partial]}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert kwargs["cwd"] == tmp_path
        return subprocess.CompletedProcess(cmd, 3, json.dumps(doc), "warning\n")

    monkeypatch.setattr(sast.subprocess, "run", fake_run)
    assert sast.run_semgrep(tmp_path, ["p/x"]) == doc


def test_run_semgrep_keeps_partial_results_after_a_failing_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Non-zero exit *with* results: the document is the better evidence, keep it."""
    monkeypatch.setattr(sast, "semgrep_executable", lambda: "/fake/semgrep")
    doc = {"results": [{"check_id": "r"}], "errors": [{"level": "error", "type": "Fatal error"}]}
    monkeypatch.setattr(
        sast.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 2, json.dumps(doc), ""),
    )
    assert sast.run_semgrep(tmp_path, ["p/x"]) == doc


@pytest.mark.parametrize(
    ("returncode", "errors"),
    [
        (2, []),  # fatal exit code, nothing in the structured array explains it
        (7, [{"level": "error", "type": "Invalid rule schema", "message": "bad pack"}]),
        (0, [{"level": "error", "type": "Fatal error", "message": "stack trace ..."}]),
        (0, [{"level": "error", "type": "Out of memory", "message": "killed"}]),
        (0, [{"message": "semgrep-core exited with code -11"}]),  # prose marker, old versions
    ],
)
def test_run_semgrep_zero_results_from_an_incomplete_run_is_unavailable(
    returncode: int, errors: list[object], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Issue #104: exit code and structured errors, not just prose, decide the fallback."""
    monkeypatch.setattr(sast, "semgrep_executable", lambda: "/fake/semgrep")
    doc = {"results": [], "errors": errors}
    monkeypatch.setattr(
        sast.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, returncode, json.dumps(doc), ""),
    )
    with pytest.raises(sast.SemgrepUnavailableError, match="produced no results"):
        sast.run_semgrep(tmp_path, ["p/x"])
    # ... and shortlist() turns that into the regex fallback instead of a clean queue.
    (tmp_path / "a.py").write_text("eval(x)\n")
    result = sast.shortlist(tmp_path, rulesets=["p/x"], max_candidates=5)
    assert result.engine == "regex" and [c.file for c in result.candidates] == ["a.py"]


def test_semgrep_failure_reason_accepts_completed_runs() -> None:
    assert sast.semgrep_failure_reason(0, []) is None
    assert sast.semgrep_failure_reason(3, [{"level": "warn", "type": "PartialParsing"}]) is None
    assert sast.semgrep_failure_reason(0, ["not a dict", 42]) is None
    assert sast.semgrep_failure_reason(2, []) == "exited with code 2"


# -- Hardening: symlinks, bounds, environment (issues #100, #102, #103, #106) -----------


def test_regex_scan_never_follows_symlinks(tmp_path: Path) -> None:
    """Issue #100: a planted ``evil.py -> /etc/passwd`` is skipped, not read off the host."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("eval(host_secret)\n")
    (outside / "pkg").mkdir()
    (outside / "pkg" / "m.py").write_text("eval(host_secret)\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "real.py").write_text("eval(user_input)\n")
    (repo / "evil.py").symlink_to(outside / "secret.py")
    (repo / "linked_dir").symlink_to(outside / "pkg", target_is_directory=True)
    (repo / "dangling.py").symlink_to(tmp_path / "does-not-exist.py")

    assert [p.name for p in sast.iter_source_files(repo)] == ["real.py"]
    assert [(c.file, c.line) for c in sast.regex_scan(repo)] == [("real.py", 1)]
    assert sast.read_source_file(repo / "evil.py") is None
    assert sast.read_source_file(outside / "secret.py") is not None  # the real file reads fine


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="needs /dev/zero")
def test_regex_scan_skips_device_files_and_symlinks_to_them(tmp_path: Path) -> None:
    """Issue #100: ``x.py -> /dev/zero`` has st_size 0 and would otherwise be read forever."""
    (tmp_path / "zero.py").symlink_to("/dev/zero")
    (tmp_path / "ok.py").write_text("os.system('ls ' + d)\n")
    assert sast.read_source_file(Path("/dev/zero")) is None  # not a regular file, even direct
    assert [(c.file, c.line) for c in sast.regex_scan(tmp_path)] == [("ok.py", 1)]


def test_read_source_file_is_bounded_by_size(tmp_path: Path) -> None:
    big = tmp_path / "big.py"
    big.write_text("eval(x)\n" * 10)
    assert sast.read_source_file(big, max_bytes=16) is None
    assert sast.read_source_file(big, max_bytes=80) == "eval(x)\n" * 10
    assert sast.read_source_file(tmp_path / "missing.py") is None
    assert sast.read_source_file(tmp_path) is None  # a directory


def test_scan_text_skips_overlong_lines() -> None:
    """Issue #103: minified / generated lines are not matched (the patterns are quadratic)."""
    long_line = "x = 1; " * 2000 + "eval(payload)"
    assert len(long_line) > sast._MAX_LINE_CHARS
    code = f"{long_line}\neval(payload)\n"
    assert [c.line for c in sast.scan_text(code, "m.py")] == [2]


def test_regex_scan_report_stops_at_its_wall_clock_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """Issue #103: the walk is bounded and the report says the result is incomplete."""
    ticks = iter([0.0, 0.0, 1000.0])  # deadline, first file in budget, second file over it
    monkeypatch.setattr(sast.time, "monotonic", lambda: next(ticks, 1000.0))
    report = sast.regex_scan_report(FIXTURE_REPO, budget_s=60.0)
    assert report.timed_out and report.files_scanned == 1
    assert len(report.candidates) < len(sast.regex_scan(FIXTURE_REPO))

    full = sast.regex_scan_report(FIXTURE_REPO)  # the monkeypatched clock never advances now
    assert not full.timed_out and full.files_scanned == 2 and full.uncovered_languages == set()


def test_run_semgrep_rejects_oversized_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Issue #102: a document over the cap is never handed to json.loads."""
    monkeypatch.setattr(sast, "semgrep_executable", lambda: "/fake/semgrep")
    monkeypatch.setattr(sast, "_SEMGREP_MAX_STDOUT_BYTES", 64)
    doc = json.dumps({"results": [], "errors": [], "padding": "x" * 100})
    monkeypatch.setattr(
        sast.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, doc, "")
    )
    monkeypatch.setattr(sast.json, "loads", lambda *_a, **_k: pytest.fail("must not parse"))
    with pytest.raises(sast.SemgrepUnavailableError, match="too large"):
        sast.run_semgrep(tmp_path, ["p/x"])


def test_parse_semgrep_results_caps_the_number_of_results(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Issue #102: only the first N results are iterated (and each file is read once)."""
    (tmp_path / "m.py").write_text("eval(x)\n" * 10)
    monkeypatch.setattr(sast, "_SEMGREP_MAX_RESULTS", 3)
    reads: list[str] = []
    original = sast.read_source_file

    def counting(path: Path, max_bytes: int = sast._MAX_FILE_BYTES) -> str | None:
        reads.append(path.name)
        return original(path, max_bytes)

    monkeypatch.setattr(sast, "read_source_file", counting)
    results = [
        {
            "check_id": "r",
            "path": "m.py",
            "start": {"line": i},
            "extra": {"metadata": {"cwe": "CWE-95"}},
        }
        for i in range(1, 11)
    ]
    candidates, _ = sast.parse_semgrep_results({"results": results}, tmp_path)
    assert [c.line for c in candidates] == [1, 2, 3]
    assert reads == ["m.py"]


def test_excerpt_is_never_read_through_a_symlink_or_outside_the_root(tmp_path: Path) -> None:
    """Issue #106: ``_line_at`` applies the same symlink / in-tree guard as the walk."""
    outside = tmp_path / "outside.py"
    outside.write_text("host_secret = 1\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / "evil.py").symlink_to(outside)
    (root / "real.py").write_text("eval(x)\n")

    def result(path: str) -> dict[str, object]:
        return {
            "check_id": "r",
            "path": path,
            "start": {"line": 1},
            "extra": {"metadata": {"cwe": "CWE-95"}},
        }

    data = {"results": [result("evil.py"), result("../outside.py"), result("real.py")]}
    candidates, _ = sast.parse_semgrep_results(data, root)
    assert [(c.file, c.excerpt) for c in candidates] == [("evil.py", ""), ("real.py", "eval(x)")]
    assert sast._line_at(root, "evil.py", 1) == ""
    assert sast._line_at(root, "../outside.py", 1) == ""


def test_semgrep_env_is_scrubbed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Issue #106: the subprocess sees PATH / HOME / proxy / SEMGREP_* - not host secrets."""
    host = {
        "PATH": "/usr/bin",
        "HOME": "/home/ono",
        "HTTPS_PROXY": "http://proxy:3128",
        "SEMGREP_APP_TOKEN": "tool-config",
        "OPENAI_API_KEY": "sk-secret",
        "EXECUTOR_TOKEN": "bearer-secret",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "PYTHONPATH": "/evil",
    }
    env = sast.semgrep_env(host)
    assert env["PATH"] == "/usr/bin" and env["HOME"] == "/home/ono"
    assert env["HTTPS_PROXY"] == "http://proxy:3128" and env["SEMGREP_APP_TOKEN"] == "tool-config"
    assert env["SEMGREP_SEND_METRICS"] == "off"
    assert not {"OPENAI_API_KEY", "EXECUTOR_TOKEN", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH"} & set(
        env
    )

    # run_semgrep passes exactly that environment (derived from os.environ) to the process.
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    monkeypatch.setattr(sast, "semgrep_executable", lambda: "/fake/semgrep")
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"results": [], "errors": []}), "")

    monkeypatch.setattr(sast.subprocess, "run", fake_run)
    sast.run_semgrep(tmp_path, ["p/x"])
    assert "OPENAI_API_KEY" not in seen["env"] and "PATH" in seen["env"]


# -- Degraded fallback on non-Python targets (issue #101) -------------------------------


def test_fallback_on_a_non_python_target_is_flagged_degraded(
    no_semgrep: None, tmp_path: Path
) -> None:
    (tmp_path / "server.js").write_text("eval(req.query.q)\n")
    (tmp_path / "Main.java").write_text("Runtime.getRuntime().exec(cmd);\n")
    result = sast.shortlist(
        tmp_path, rulesets=["p/owasp-top-ten"], languages=["JavaScript", "java"], max_candidates=20
    )
    assert result.engine == "regex" and result.candidates == []
    assert result.degraded.startswith("Semgrep unavailable (semgrep is not installed)")
    assert "covers Python only; java, javascript source was not analyzed" in result.degraded
    assert result.degraded.endswith("results are incomplete")


def test_fallback_detects_uncovered_languages_on_disk_even_if_undeclared(
    no_semgrep: None, tmp_path: Path
) -> None:
    (tmp_path / "ok.py").write_text("print('x')\n")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "handler.go").write_text("exec.Command(input)\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("eval(x)\n")  # vendored: not counted
    result = sast.shortlist(tmp_path, rulesets=["p/x"], languages=[], max_candidates=20)
    assert "go source was not analyzed" in result.degraded
    assert "javascript" not in result.degraded


def test_fallback_on_a_python_target_is_not_degraded(no_semgrep: None) -> None:
    result = sast.shortlist(
        FIXTURE_REPO, rulesets=["p/x"], languages=["python", "html", "cobol"], max_candidates=20
    )
    assert result.engine == "regex" and len(result.candidates) == 3
    assert result.degraded == ""  # html/cobol: Semgrep would not have covered them either


def test_semgrep_success_is_never_degraded(
    monkeypatch: pytest.MonkeyPatch, semgrep_json: dict[str, object]
) -> None:
    monkeypatch.setattr(sast, "run_semgrep", lambda root, rulesets: semgrep_json)
    result = sast.shortlist(
        FIXTURE_REPO, rulesets=["p/x"], languages=["javascript"], max_candidates=20
    )
    assert result.engine == "semgrep" and result.degraded == ""


def test_fallback_time_budget_exhaustion_is_degraded(
    no_semgrep: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter([0.0, 1000.0])
    monkeypatch.setattr(sast.time, "monotonic", lambda: next(ticks, 1000.0))
    result = sast.shortlist(FIXTURE_REPO, rulesets=["p/x"], languages=["python"], max_candidates=20)
    assert result.candidates == []
    assert "stopped at its 60s budget after 0 file(s)" in result.degraded


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
