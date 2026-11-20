"""Measuring the learning loop: does seeding the prover with verifier-passed PoCs make
later rounds converge faster?

The plan (section 1.5, section 8.6) asks for a real metric that trends across rounds, not a
hand-wave. The headline metric here is **mean prover attempts-to-fire** over the findings
that were proven reachable in a round: with an empty memory the prover may need a correction
round or two; once the memory holds a verified PoC for that sink class, a later round is
seeded with it and fires on the first attempt. A second metric is the **verified rate**
(share of findings reaching rung >= 3).

:func:`round_metrics` reduces one :class:`~ono.verifier.VerifyReport` (duck-typed) to these
numbers; :func:`improvement` compares the first and last round. The reproducible
demonstration lives in ``scripts/learning_demo.py`` and is asserted in
``tests/test_learning.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["RoundMetrics", "improvement", "round_metrics"]


@dataclass(slots=True)
class RoundMetrics:
    round_index: int
    findings: int
    reachable: int
    mean_poc_attempts: float  # over reachable findings; lower is better
    seeded: int  # how many findings were seeded from memory this round
    verified_rate: float
    memory_entries: int

    def as_row(self) -> str:
        return (
            f"round {self.round_index}: findings={self.findings} reachable={self.reachable} "
            f"mean_poc_attempts={self.mean_poc_attempts:.2f} seeded={self.seeded} "
            f"verified_rate={self.verified_rate:.2f} memory={self.memory_entries}"
        )


def round_metrics(report: object, round_index: int, memory_entries: int) -> RoundMetrics:
    """Reduce a VerifyReport to the per-round learning metrics (duck-typed on ``findings``)."""
    findings = list(getattr(report, "findings", []))
    reachable = [f for f in findings if f.rung >= 3 and f.verification is not None]
    attempts = [
        f.verification.poc_attempts
        for f in reachable
        if f.verification is not None and f.verification.poc_attempts > 0
    ]
    seeded = sum(1 for f in findings if f.verification is not None and f.verification.seeded)
    mean = sum(attempts) / len(attempts) if attempts else 0.0
    return RoundMetrics(
        round_index=round_index,
        findings=len(findings),
        reachable=len(reachable),
        mean_poc_attempts=mean,
        seeded=seeded,
        verified_rate=len(reachable) / len(findings) if findings else 0.0,
        memory_entries=memory_entries,
    )


@dataclass(slots=True)
class Improvement:
    first: RoundMetrics
    last: RoundMetrics

    @property
    def attempts_delta(self) -> float:
        """Negative when later rounds need fewer prover attempts (improvement)."""
        return self.last.mean_poc_attempts - self.first.mean_poc_attempts

    @property
    def improved(self) -> bool:
        return self.attempts_delta < 0

    def summary(self) -> str:
        arrow = "down" if self.improved else ("flat" if self.attempts_delta == 0 else "up")
        return (
            f"mean prover attempts-to-fire: {self.first.mean_poc_attempts:.2f} -> "
            f"{self.last.mean_poc_attempts:.2f} ({arrow} {abs(self.attempts_delta):.2f}); "
            f"seeded last round: {self.last.seeded}/{self.last.findings}"
        )


def improvement(rounds: list[RoundMetrics]) -> Improvement:
    if not rounds:
        raise ValueError("no rounds to compare")
    return Improvement(first=rounds[0], last=rounds[-1])
