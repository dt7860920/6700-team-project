"""Pydantic models for the benchmark: the curated ground truth and the scorecards."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ExpectedVuln(BaseModel):
    """One vulnerability a benchmark repo is known to contain (the ground-truth unit).

    A scan finding is counted against this entry when its CWE matches and its sink file path
    CONTAINS :attr:`location` (a path substring, case-insensitive) - deliberately coarse, so
    the ground truth does not have to track exact line numbers that drift between commits.
    """

    cwe: str = Field(pattern=r"^CWE-\d+$", examples=["CWE-89"])
    location: str = Field(
        description="Path substring a matching finding's sink file must contain, "
        "e.g. 'vulnerabilities/sqli' or 'command_injection_lab'."
    )
    note: str = Field(default="", description="What the vulnerability is (for the report).")


class RepoGroundTruth(BaseModel):
    """The known vulnerabilities of one benchmark repository."""

    key: str = Field(description="Stable key used to look this repo up when scoring a scan.")
    name: str = ""
    language: str = ""
    source: str = Field(default="", description="Where the ground truth was curated from.")
    expected: list[ExpectedVuln] = Field(default_factory=list)


class GroundTruth(BaseModel):
    """The whole curated ground-truth set, loaded from the shipped YAML."""

    repos: list[RepoGroundTruth] = Field(default_factory=list)

    def by_key(self, key: str) -> RepoGroundTruth | None:
        return next((r for r in self.repos if r.key == key), None)


class ExpectedOutcome(BaseModel):
    """What happened to one expected vulnerability in a scan."""

    cwe: str
    location: str
    note: str = ""
    detected: bool = False  # at least one finding matched it (any rung)
    verified: bool = False  # at least one matching finding reached rung >= 3
    matched_findings: int = 0


class CweTally(BaseModel):
    cwe: str
    expected: int = 0
    detected: int = 0
    verified: int = 0


class Scorecard(BaseModel):
    """How a scan scored against one repo's ground truth."""

    key: str
    name: str = ""
    language: str = ""
    expected_total: int = 0
    detected: int = 0
    verified: int = 0
    findings_total: int = 0
    findings_matched: int = 0  # findings that line up with a known vulnerability
    findings_unmatched: int = 0  # findings with no ground-truth match (extra / review)
    outcomes: list[ExpectedOutcome] = Field(default_factory=list)
    by_cwe: list[CweTally] = Field(default_factory=list)
    note: str = ""  # e.g. "no ground truth for this repo"

    @property
    def detection_recall(self) -> float:
        return self.detected / self.expected_total if self.expected_total else 0.0

    @property
    def verification_recall(self) -> float:
        return self.verified / self.expected_total if self.expected_total else 0.0


class AggregateScore(BaseModel):
    """Totals across every scored repo."""

    repos_scored: int = 0
    expected_total: int = 0
    detected: int = 0
    verified: int = 0
    findings_total: int = 0
    findings_matched: int = 0
    cards: list[Scorecard] = Field(default_factory=list)

    @property
    def detection_recall(self) -> float:
        return self.detected / self.expected_total if self.expected_total else 0.0

    @property
    def verification_recall(self) -> float:
        return self.verified / self.expected_total if self.expected_total else 0.0
