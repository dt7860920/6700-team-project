"""Benchmark scorer: matching, recall math, and the shipped ground truth loads."""

from __future__ import annotations

from ono.benchmark import load_ground_truth, score_repo, score_sweep
from ono.benchmark.model import ExpectedVuln, RepoGroundTruth
from ono.benchmark.score import _canon_cwe, _matches


def _f(cwe: str, file: str, *, rung: int = 1, verified: bool = False) -> dict:
    return {"cwe": cwe, "file": file, "rung": rung, "verified": verified}


def test_canon_cwe_normalises() -> None:
    assert _canon_cwe("cwe-89") == "CWE-89"
    assert _canon_cwe("CWE_078") == "CWE-078"
    assert _canon_cwe(89) == "CWE-89"
    assert _canon_cwe("not a cwe") == ""


def test_matches_requires_cwe_and_location_substring() -> None:
    ev = ExpectedVuln(cwe="CWE-78", location="command_injection_lab")
    assert _matches(_f("CWE-78", "dockerized_labs/command_injection_lab/app.py"), ev)
    assert not _matches(_f("CWE-89", "dockerized_labs/command_injection_lab/app.py"), ev)  # cwe
    assert not _matches(_f("CWE-78", "dockerized_labs/sql_injection_lab/app.py"), ev)  # location


def test_score_repo_detection_vs_verification_recall() -> None:
    gt = RepoGroundTruth(
        key="demo",
        expected=[
            ExpectedVuln(cwe="CWE-78", location="cmd"),  # will be verified
            ExpectedVuln(cwe="CWE-89", location="sqli"),  # detected only
            ExpectedVuln(cwe="CWE-79", location="xss"),  # missed
        ],
    )
    findings = [
        _f("CWE-78", "app/cmd.py", rung=3, verified=True),  # proves the cmd vuln
        _f("CWE-89", "app/sqli.py", rung=2),  # detects but does not prove sqli
        _f("CWE-502", "app/other.py", rung=2),  # unmatched (extra)
    ]
    card = score_repo(gt, findings)
    assert card.expected_total == 3
    assert card.detected == 2 and card.verified == 1
    assert card.detection_recall == 2 / 3
    assert card.verification_recall == 1 / 3
    assert card.findings_matched == 2 and card.findings_unmatched == 1
    missed = [o for o in card.outcomes if not o.detected]
    assert len(missed) == 1 and missed[0].cwe == "CWE-79"


def test_verified_by_rung_or_flag() -> None:
    gt = RepoGroundTruth(key="d", expected=[ExpectedVuln(cwe="CWE-78", location="x")])
    assert score_repo(gt, [_f("CWE-78", "x.py", rung=4)]).verified == 1  # rung>=3
    assert score_repo(gt, [_f("CWE-78", "x.py", rung=1, verified=True)]).verified == 1  # flag
    assert score_repo(gt, [_f("CWE-78", "x.py", rung=2)]).verified == 0


def test_score_sweep_handles_repo_without_ground_truth() -> None:
    gt = RepoGroundTruth(key="known", expected=[ExpectedVuln(cwe="CWE-78", location="x")])
    from ono.benchmark.model import GroundTruth

    agg = score_sweep(
        {"known": [_f("CWE-78", "x.py", rung=3, verified=True)], "mystery": [_f("CWE-1", "y")]},
        GroundTruth(repos=[gt]),
    )
    assert agg.repos_scored == 1 and agg.verified == 1 and agg.expected_total == 1
    mystery = next(c for c in agg.cards if c.key == "mystery")
    assert mystery.expected_total == 0 and "no ground truth" in mystery.note


def test_shipped_ground_truth_is_valid_and_covers_the_core_repos() -> None:
    gt = load_ground_truth()
    keys = {r.key for r in gt.repos}
    assert {"pygoat", "DVWA", "NodeGoat", "dvna"} <= keys
    for repo in gt.repos:
        assert repo.expected, f"{repo.key} has no expected vulns"
        for ev in repo.expected:
            assert ev.cwe.startswith("CWE-") and ev.location
