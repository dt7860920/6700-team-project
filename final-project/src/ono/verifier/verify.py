"""The graded verifier (step 3b-2): plain code, no LLM of its own.

It takes the analyst's model-asserted findings and tries to PROVE them, climbing the
output-strength ladder (plan section 1):

    anchor            the flagged file:line still exists and is not blank         (gate)
    poc_reaches_sink  a read-only PoC carried a canary into the flagged sink      -> rung 3
    patch_applies     the fixer's diff applies cleanly in the jail
    poc_no_longer_fires  the same PoC no longer reaches the sink after the patch
    tests_pass        the project's test suite still passes                        -> rung 4

The prover and the fixer are the only LLM calls; everything that decides *true/false* is
deterministic. On a failed check the specific reason is fed back and the agent revises, a
**bounded** loop (``settings.max_verifier_retries``) - the verifier-in-the-loop
self-correction cycle. A finding that never reaches rung 3 keeps its analyst rung (<= 2)
with ``verified=False`` and a :class:`~ono.models.Verification` record saying which check
stopped it; it is never silently dropped and never falsely marked verified.

One jail is opened for the whole verify stage and reset between findings so a patch from
one never leaks into the next.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ono.agents.definitions import FIXER, PROVER, AgentDefinition
from ono.agents.fixer import Patch, run_fixer
from ono.agents.model import BudgetExhaustedError, CallBudget, ChatModel, ModelError, ToolCall
from ono.agents.prover import Poc, run_prover
from ono.agents.tools import SandboxExecutor, ToolBox
from ono.agents.trajectory import Trajectory, TrajectoryWriter
from ono.config import Settings
from ono.errors import PipelineError
from ono.executor.client import ExecutorAuthError, ExecutorError, ExecutorUnavailableError
from ono.learning.harvest import harvest_report
from ono.learning.memory import KnowledgeMemory
from ono.models import Finding, Verification, VerificationCheck
from ono.progress import ProgressCallback
from ono.verifier.oracle import OracleResult, SinkOracle, explain, new_canary, oracle_supports

__all__ = ["ExecutorProvider", "GradedVerifier", "VerifyReport", "verify_anchor"]

log = logging.getLogger(__name__)

RUNG_REACHABLE = 3
RUNG_FIXED = 4


class ExecutorProvider(Protocol):
    """The slice of the Executor the verifier needs: one resettable sandbox per stage."""

    def sandbox(
        self, scan_id: str, workspace_dir: Path
    ) -> AbstractContextManager[SandboxExecutor]: ...


def _no_progress(message: str) -> None:
    return None


@dataclass(slots=True)
class VerifyReport:
    """What the verify stage did across all findings."""

    findings: list[Finding] = field(default_factory=list)
    reachable: int = 0  # reached rung 3
    fixed: int = 0  # reached rung 4
    model_calls: int = 0
    budget_limit: int = 0
    stopped_early: str = ""
    harvested: int = 0  # verified solutions written into the knowledge memory

    @property
    def summary(self) -> str:
        n = len(self.findings)
        text = (
            f"{self.reachable}/{n} proven reachable (rung 3), {self.fixed} fixed (rung 4); "
            f"{self.model_calls}/{self.budget_limit} model call(s)"
        )
        if self.harvested:
            text += f"; harvested {self.harvested} into knowledge memory"
        if self.stopped_early:
            text += f"; stopped early: {self.stopped_early}"
        return text


def verify_anchor(finding: Finding, sandbox: SandboxExecutor) -> VerificationCheck:
    """The flagged sink line still exists in the workspace and is not blank/comment."""
    try:
        content = sandbox.read_lines(finding.file, finding.line_range[0], finding.line_range[1])
    except ExecutorError as exc:
        return VerificationCheck(name="anchor", status="failed", detail=f"cannot read sink: {exc}")
    body = content.content.strip()
    if not body:
        return VerificationCheck(
            name="anchor", status="failed", detail=f"{finding.location} is blank or out of range"
        )
    comment = all(
        ln.strip().startswith("#") or not ln.strip() for ln in content.content.splitlines()
    )
    if comment:
        return VerificationCheck(
            name="anchor", status="failed", detail=f"{finding.location} is only a comment"
        )
    return VerificationCheck(name="anchor", status="passed", detail=f"{finding.location} present")


class GradedVerifier:
    """Proves findings in one jail. Re-entrant; one instance per scan is fine."""

    def __init__(
        self,
        settings: Settings,
        *,
        model: ChatModel,
        executor: ExecutorProvider,
        trajectories: TrajectoryWriter | None = None,
        memory: KnowledgeMemory | None = None,
    ) -> None:
        self.settings = settings
        self.model = model
        self.executor = executor
        self.trajectories = trajectories or TrajectoryWriter(settings.agent_trajectory_dir)
        # The knowledge memory (learning loop): seeds the prover with prior verified PoCs and
        # harvests new ones. None = no learning (the default; behaviour unchanged).
        self.memory = memory
        self.prover: AgentDefinition = PROVER.with_budget(
            max_steps=settings.prover_max_steps, temperature=settings.agent_temperature
        )
        self.fixer: AgentDefinition = FIXER.with_budget(
            max_steps=settings.fixer_max_steps, temperature=settings.agent_temperature
        )

    def verify(
        self,
        scan_id: str,
        workspace: Path,
        findings: Sequence[Finding],
        *,
        progress: ProgressCallback | None = None,
    ) -> VerifyReport:
        """Prove each finding in turn, resetting the jail between them."""
        report_progress: ProgressCallback = progress if progress is not None else _no_progress
        items = list(findings)
        # Budget: each finding may spend (prover + fixer) model calls per attempt.
        per_finding = (
            self.prover.max_steps + self.fixer.max_steps
        ) * self.settings.max_verifier_retries
        budget = CallBudget(limit=len(items) * per_finding)
        report = VerifyReport(findings=list(items), budget_limit=budget.limit)
        if not items:
            return report
        total = len(items)
        report_progress(f"Opening the verifier sandbox for {total} finding(s)")
        try:
            with self.executor.sandbox(scan_id, workspace) as sandbox:
                for index, finding in enumerate(items):
                    if index:
                        sandbox.reset()  # a fresh copy: no patch leaks between findings
                    report_progress(
                        f"Verifying finding {index + 1} of {total} - {finding.location} "
                        f"({finding.cwe})"
                    )
                    try:
                        proven = self._verify_one(scan_id, sandbox, finding, budget)
                    except BudgetExhaustedError as exc:
                        report.stopped_early = str(exc)
                        break
                    items[index] = proven
                    if proven.rung >= RUNG_REACHABLE:
                        report.reachable += 1
                    if proven.rung >= RUNG_FIXED:
                        report.fixed += 1
                    report_progress(
                        f"Finding {index + 1} of {total}: "
                        + (
                            f"PROVEN rung {proven.rung}"
                            if proven.verified
                            else f"unproven (rung {proven.rung})"
                        )
                    )
        except ExecutorAuthError as exc:
            raise PipelineError(f"executor rejected EXECUTOR_TOKEN during verify: {exc}") from exc
        except ExecutorUnavailableError as exc:
            raise PipelineError(f"executor became unreachable during verify: {exc}") from exc
        except ExecutorError as exc:
            raise PipelineError(f"verifier sandbox failure: {exc}") from exc
        except ModelError as exc:
            raise PipelineError(f"the model service failed during verify ({exc})") from exc
        report.findings = items
        report.model_calls = budget.used
        if self.memory is not None:
            report.harvested = harvest_report(report, self.memory)
        log.info("verifier[%s]: %s", scan_id, report.summary)
        return report

    # -- one finding ------------------------------------------------------------------
    def _verify_one(
        self, scan_id: str, sandbox: SandboxExecutor, finding: Finding, budget: CallBudget
    ) -> Finding:
        v = Verification()
        deadline = time.monotonic() + self.settings.verifier_finding_timeout_s
        toolbox = ToolBox(sandbox, max_output_chars=self.settings.agent_tool_output_chars)

        anchor = verify_anchor(finding, sandbox)
        v.checks.append(anchor)
        if anchor.status != "passed":
            return _apply(finding, finding.rung, verified=False, verification=v)

        window = self._window(toolbox, finding)
        unsupported = oracle_supports(finding)
        if unsupported:
            v.checks.append(
                VerificationCheck(name="poc_reaches_sink", status="skipped", detail=unsupported)
            )
            return _apply(finding, finding.rung, verified=False, verification=v)

        # Rung 3: prove the sink is reachable with a read-only PoC. The learning loop seeds the
        # prover with a prior verified PoC for this sink class, when the memory has one.
        memory_hint = self.memory.seed_for(finding) if self.memory is not None else ""
        v.seeded = bool(memory_hint)
        oracle = SinkOracle(sandbox, timeout_s=self.settings.verifier_poc_timeout_s)
        canary = new_canary()
        poc, poc_check = self._prove_reachable(
            scan_id, finding, window, toolbox, oracle, canary, budget, deadline, v, memory_hint
        )
        v.checks.append(poc_check)
        if poc is None or poc_check.status != "passed":
            oracle.cleanup()
            return _apply(finding, finding.rung, verified=False, verification=v)
        v.poc = poc.code
        rung = RUNG_REACHABLE

        # Rung 4: prove a fix works (applies, PoC no longer fires, tests pass).
        fixed = self._prove_fixed(
            scan_id, finding, window, poc, toolbox, oracle, canary, budget, deadline, v
        )
        oracle.cleanup()
        if fixed is not None:
            patch_diff, rung = fixed, RUNG_FIXED
            return _apply(finding, rung, verified=True, verification=v, patch_diff=patch_diff)
        return _apply(finding, rung, verified=True, verification=v)

    def _prove_reachable(
        self,
        scan_id: str,
        finding: Finding,
        window: str,
        toolbox: ToolBox,
        oracle: SinkOracle,
        canary: str,
        budget: CallBudget,
        deadline: float,
        v: Verification,
        memory_hint: str = "",
    ) -> tuple[Poc | None, VerificationCheck]:
        previous: Poc | None = None
        failure = ""
        for attempt in range(1, self.settings.max_verifier_retries + 1):
            if time.monotonic() > deadline:
                return None, VerificationCheck(
                    name="poc_reaches_sink", status="failed", detail="time budget exhausted"
                )
            v.attempts = max(v.attempts, attempt)
            traj = Trajectory(scan_id=scan_id, role="prover", candidate=finding.location)
            outcome = run_prover(
                self.model,
                self.prover,
                finding=finding,
                window_text=window,
                toolbox=toolbox,
                budget=budget,
                deadline=deadline,
                trajectory=traj,
                previous=previous,
                failure=failure,
                memory_hint=memory_hint,
            )
            v.model_calls += traj.model_calls
            self.trajectories.write(traj)
            if outcome.answer is None:
                failure = f"no PoC was produced ({outcome.reason})"
                continue
            previous = outcome.answer
            result = oracle.run(finding, outcome.answer.code, canary)
            if result.fired:
                v.evidence = result.evidence
                v.poc_attempts = attempt
                return outcome.answer, VerificationCheck(
                    name="poc_reaches_sink",
                    status="passed",
                    detail=result.evidence or "payload reached the flagged sink",
                )
            failure = explain(result, finding)
            log.info(
                "verifier[%s]: PoC attempt %d did not fire: %s", scan_id, attempt, failure[:200]
            )
        return previous, VerificationCheck(
            name="poc_reaches_sink",
            status="failed",
            detail=f"no read-only PoC reached {finding.location} in "
            f"{self.settings.max_verifier_retries} attempt(s): {failure[:400]}",
        )

    def _prove_fixed(
        self,
        scan_id: str,
        finding: Finding,
        window: str,
        poc: Poc,
        toolbox: ToolBox,
        oracle: SinkOracle,
        canary: str,
        budget: CallBudget,
        deadline: float,
        v: Verification,
    ) -> str | None:
        """Return the proven patch diff, or None (leaving rung-3 checks on ``v``)."""
        previous: Patch | None = None
        failure = ""
        applied_check: VerificationCheck | None = None
        poc_check: VerificationCheck | None = None
        tests_check: VerificationCheck | None = None
        for attempt in range(1, self.settings.max_verifier_retries + 1):
            if time.monotonic() > deadline:
                break
            v.attempts = max(v.attempts, attempt)
            traj = Trajectory(scan_id=scan_id, role="fixer", candidate=finding.location)
            outcome = run_fixer(
                self.model,
                self.fixer,
                finding=finding,
                window_text=window,
                poc=poc.code,
                toolbox=toolbox,
                budget=budget,
                deadline=deadline,
                trajectory=traj,
                previous=previous,
                failure=failure,
            )
            v.model_calls += traj.model_calls
            self.trajectories.write(traj)
            if outcome.answer is None:
                failure = f"no patch was produced ({outcome.reason})"
                continue
            previous = outcome.answer
            applied_check, poc_check, tests_check, ok = self._check_patch(
                finding, outcome.answer, poc, oracle, canary
            )
            if ok:
                v.checks += [applied_check, poc_check, tests_check]
                v.tests = tests_check.detail
                return outcome.answer.diff
            failure = _patch_failure(applied_check, poc_check, tests_check)
            log.info("verifier[%s]: patch attempt %d rejected: %s", scan_id, attempt, failure[:200])
            try:
                oracle.sandbox.reset()  # undo a partially-useful patch before the next try
            except ExecutorError:
                break
        # Record the best (last) attempt's checks so the report explains what was missing.
        v.checks += [c for c in (applied_check, poc_check, tests_check) if c is not None]
        return None

    def _check_patch(
        self, finding: Finding, patch: Patch, poc: Poc, oracle: SinkOracle, canary: str
    ) -> tuple[VerificationCheck, VerificationCheck, VerificationCheck, bool]:
        """Re-stage the PoC, apply the diff, re-run that SAME PoC, run the tests. Re-running
        the exact PoC that fired at rung 3 against the patched code is the honest
        "same exploit no longer works" check."""
        stage_error = oracle.stage(poc.code)
        if stage_error:
            return (
                VerificationCheck(name="patch_applies", status="skipped", detail=stage_error),
                VerificationCheck(name="poc_no_longer_fires", status="skipped", detail=stage_error),
                VerificationCheck(name="tests_pass", status="skipped", detail=stage_error),
                False,
            )
        applied = oracle.sandbox.apply_patch(patch.diff)
        if not applied.applied:
            return (
                VerificationCheck(name="patch_applies", status="failed", detail=applied.reason),
                VerificationCheck(
                    name="poc_no_longer_fires", status="skipped", detail="patch did not apply"
                ),
                VerificationCheck(
                    name="tests_pass", status="skipped", detail="patch did not apply"
                ),
                False,
            )
        applied_check = VerificationCheck(
            name="patch_applies", status="passed", detail=f"changed {', '.join(applied.files)}"
        )
        rerun = _rerun_staged_poc(oracle, finding, canary)
        if not rerun.ok:
            return (
                applied_check,
                VerificationCheck(
                    name="poc_no_longer_fires",
                    status="skipped",
                    detail=f"could not re-run the PoC after the patch: {rerun.error}",
                ),
                VerificationCheck(name="tests_pass", status="skipped", detail="PoC re-run failed"),
                False,
            )
        if rerun.fired:
            return (
                applied_check,
                VerificationCheck(
                    name="poc_no_longer_fires",
                    status="failed",
                    detail="the PoC still reaches the sink after the patch",
                ),
                VerificationCheck(name="tests_pass", status="skipped", detail="PoC still fires"),
                False,
            )
        poc_check = VerificationCheck(
            name="poc_no_longer_fires",
            status="passed",
            detail="the PoC no longer reaches the sink",
        )
        tests_check = self._run_tests(oracle.sandbox)
        return applied_check, poc_check, tests_check, tests_check.status != "failed"

    def _run_tests(self, sandbox: SandboxExecutor) -> VerificationCheck:
        result = sandbox.run_tests(timeout_s=self.settings.verifier_tests_timeout_s)
        if not result.detected:
            return VerificationCheck(
                name="tests_pass", status="skipped", detail="no test suite found in the target"
            )
        if result.passed is True:
            return VerificationCheck(
                name="tests_pass", status="passed", detail=f"{result.runner}: {result.summary}"
            )
        if result.passed is None:
            return VerificationCheck(
                name="tests_pass",
                status="skipped",
                detail=f"{result.runner}: inconclusive ({result.summary})",
            )
        return VerificationCheck(
            name="tests_pass", status="failed", detail=f"{result.runner}: {result.summary}"
        )

    def _window(self, toolbox: ToolBox, finding: Finding) -> str:
        span = self.settings.context_lines
        start = max(1, finding.line_range[0] - span)
        end = finding.line_range[1] + span
        result = toolbox.dispatch(
            ToolCall("read_lines", {"path": finding.file, "start": start, "end": end})
        )
        return result.text


def _rerun_staged_poc(oracle: SinkOracle, finding: Finding, canary: str) -> OracleResult:
    """Re-run the PoC staged in ``.ono/poc.py`` against the (patched) workspace."""
    return oracle.run_staged(finding, canary)


def _patch_failure(
    applied: VerificationCheck, poc: VerificationCheck, tests: VerificationCheck
) -> str:
    if applied.status == "failed":
        return f"the patch did not apply: {applied.detail}"
    if poc.status == "failed":
        return poc.detail
    if tests.status == "failed":
        return f"the patch applied and closed the hole, but tests failed: {tests.detail}"
    return "unknown"


def _apply(
    finding: Finding,
    rung: int,
    *,
    verified: bool,
    verification: Verification,
    patch_diff: str | None = None,
) -> Finding:
    update: dict[str, object] = {
        "rung": rung,
        "verified": verified,
        "verification": verification,
    }
    if patch_diff is not None:
        update["patch_diff"] = patch_diff
    return finding.model_copy(update=update)
