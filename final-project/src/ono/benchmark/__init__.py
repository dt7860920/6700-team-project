"""Offline scoring of ONO's results against a curated ground truth of known vulnerabilities.

This package is an EVALUATION harness, not part of the scan pipeline: it compares the
findings a scan produced against a hand-curated list of the vulnerabilities each benchmark
repository is *known* to contain, and reports how many ONO detected and how many it proved
(rung >= 3). It answers "how well are we capturing the vulnerabilities that are really there?"

Critically, the ground truth here is read ONLY by the scorer, AFTER a scan has run. It is
never imported by the analyzer, prover, verifier or oracle, so it can never leak an answer
key into the agents (the prover still earns every rung-3 proof with no knowledge of what the
vulnerability is). Keeping the eval data in its own package, which the pipeline does not
import, is what guarantees that.
"""

from __future__ import annotations

from ono.benchmark.model import ExpectedVuln, GroundTruth, RepoGroundTruth, Scorecard
from ono.benchmark.score import load_ground_truth, score_repo, score_sweep

__all__ = [
    "ExpectedVuln",
    "GroundTruth",
    "RepoGroundTruth",
    "Scorecard",
    "load_ground_truth",
    "score_repo",
    "score_sweep",
]
