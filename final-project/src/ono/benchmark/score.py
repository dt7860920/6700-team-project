"""Match scan findings to curated ground truth and compute recall scorecards.

A finding is any mapping with at least ``cwe``, ``file``, ``rung`` and ``verified`` keys -
exactly the shape of ``GET /scans/{id}/findings`` JSON and of :class:`ono.models.Finding`,
so the scorer runs equally on live API output or a saved sweep.
"""

from __future__ import annotations

import importlib.resources
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from ono.benchmark.model import (
    AggregateScore,
    CweTally,
    ExpectedOutcome,
    ExpectedVuln,
    GroundTruth,
    RepoGroundTruth,
    Scorecard,
)

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)

RUNG_REACHABLE = 3  # findings at or above this rung are "verified" (proven reachable)


def _canon_cwe(value: Any) -> str:
    """``'cwe-89'`` / ``'CWE_89'`` / ``89`` -> ``'CWE-89'``; ``''`` if unparseable."""
    text = str(value).strip()
    match = _CWE_RE.search(text)
    if match:
        return f"CWE-{match.group(1)}"
    return f"CWE-{text}" if text.isdigit() else ""


def _finding_is_verified(finding: Mapping[str, Any]) -> bool:
    if bool(finding.get("verified")):
        return True
    try:
        return int(finding.get("rung", 0)) >= RUNG_REACHABLE
    except (TypeError, ValueError):
        return False


def _matches(finding: Mapping[str, Any], expected: ExpectedVuln) -> bool:
    """A finding counts for an expected vuln when the CWE matches and the sink file path
    contains the expected location substring (case-insensitive)."""
    if _canon_cwe(finding.get("cwe")) != expected.cwe:
        return False
    return expected.location.lower() in str(finding.get("file", "")).lower()


def load_ground_truth(path: str | None = None) -> GroundTruth:
    """Load the curated ground truth (the shipped YAML by default, or a caller's file)."""
    if path is None:
        text = (
            importlib.resources.files("ono.benchmark.data")
            .joinpath("ground_truth.yaml")
            .read_text(encoding="utf-8")
        )
    else:
        text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    return GroundTruth.model_validate(data)


def score_repo(gt: RepoGroundTruth, findings: Sequence[Mapping[str, Any]]) -> Scorecard:
    """Score one scan's findings against one repo's ground truth."""
    outcomes: list[ExpectedOutcome] = []
    matched_finding_idx: set[int] = set()
    cwe_tally: dict[str, CweTally] = {}

    for expected in gt.expected:
        tally = cwe_tally.setdefault(expected.cwe, CweTally(cwe=expected.cwe))
        tally.expected += 1
        hits = [i for i, f in enumerate(findings) if _matches(f, expected)]
        matched_finding_idx.update(hits)
        detected = bool(hits)
        verified = any(_finding_is_verified(findings[i]) for i in hits)
        tally.detected += int(detected)
        tally.verified += int(verified)
        outcomes.append(
            ExpectedOutcome(
                cwe=expected.cwe,
                location=expected.location,
                note=expected.note,
                detected=detected,
                verified=verified,
                matched_findings=len(hits),
            )
        )

    return Scorecard(
        key=gt.key,
        name=gt.name,
        language=gt.language,
        expected_total=len(gt.expected),
        detected=sum(1 for o in outcomes if o.detected),
        verified=sum(1 for o in outcomes if o.verified),
        findings_total=len(findings),
        findings_matched=len(matched_finding_idx),
        findings_unmatched=len(findings) - len(matched_finding_idx),
        outcomes=outcomes,
        by_cwe=sorted(cwe_tally.values(), key=lambda t: t.cwe),
    )


def score_sweep(
    results: Mapping[str, Sequence[Mapping[str, Any]]],
    ground_truth: GroundTruth | None = None,
) -> AggregateScore:
    """Score a whole sweep: ``{repo_key: [findings...]}`` -> per-repo cards + totals.

    A repo with no ground truth still gets a card (so its findings are visible) but does not
    count toward recall - the card's ``note`` says so.
    """
    gt = ground_truth or load_ground_truth()
    cards: list[Scorecard] = []
    for key, findings in results.items():
        repo_gt = gt.by_key(key)
        if repo_gt is None:
            cards.append(
                Scorecard(
                    key=key,
                    findings_total=len(findings),
                    findings_unmatched=len(findings),
                    note="no ground truth curated for this repo",
                )
            )
            continue
        cards.append(score_repo(repo_gt, findings))

    scored = [c for c in cards if c.expected_total]
    return AggregateScore(
        repos_scored=len(scored),
        expected_total=sum(c.expected_total for c in scored),
        detected=sum(c.detected for c in scored),
        verified=sum(c.verified for c in scored),
        findings_total=sum(c.findings_total for c in cards),
        findings_matched=sum(c.findings_matched for c in cards),
        cards=cards,
    )
