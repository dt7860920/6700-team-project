"""The detection orchestrator (step 3b-1): deterministic code, not an LLM.

It is the state machine around the two agent definitions::

    SANDBOX_OPEN -> [ WINDOW -> PLAN -> ANALYZE -> COLLECT ]* per candidate -> SANDBOX_CLOSE

* One jailed sandbox per scan (``executor.sandbox(scan_id, workspace)``), opened only if
  there is at least one candidate and torn down by the context manager - on success,
  on error, on budget exhaustion.
* Every read of target code happens inside the jail through
  :class:`~ono.agents.tools.ToolBox`; the orchestrator itself reads the sink window the
  same way (that read seeds the analyst's ledger).
* Budgets are enforced here, not trusted to the model: ``max_candidates`` on the queue,
  ``analyst_max_steps`` per candidate, a per-candidate wall-clock budget, and one
  :class:`~ono.agents.model.CallBudget` for the whole scan
  (``len(queue) * (analyst_max_steps + planner)``) that no agent can exceed.

The LLM lives only inside :func:`~ono.agents.planner.run_planner` and
:func:`~ono.agents.analyst.run_analyst`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from ono.agents.analyst import AnalystOutcome, run_analyst
from ono.agents.definitions import ANALYST, PLANNER, AgentDefinition
from ono.agents.model import BudgetExhaustedError, CallBudget, ChatModel, ToolCall
from ono.agents.planner import InvestigationPlan, default_plan, run_planner
from ono.agents.tools import SandboxReader, ToolBox
from ono.agents.trajectory import Trajectory, TrajectoryWriter
from ono.config import Settings
from ono.errors import PipelineError
from ono.executor.client import ExecutorAuthError, ExecutorError, ExecutorUnavailableError
from ono.executor.models import ExecutorHealth
from ono.models import Finding
from ono.sast import Candidate

__all__ = ["CandidateOutcome", "DetectionOrchestrator", "DetectionReport", "ExecutorProvider"]

log = logging.getLogger(__name__)

CandidateState = Literal["confirmed", "dismissed", "exhausted", "timeout", "skipped"]


class ExecutorProvider(Protocol):
    """The slice of :class:`~ono.executor.client.ExecutorClient` the orchestrator uses."""

    def health(self) -> ExecutorHealth: ...

    def sandbox(
        self, scan_id: str, workspace_dir: Path
    ) -> AbstractContextManager[SandboxReader]: ...


@dataclass(slots=True)
class CandidateOutcome:
    candidate: Candidate
    state: CandidateState
    reason: str = ""
    finding: Finding | None = None
    plan: InvestigationPlan | None = None
    trajectories: list[Trajectory] = field(default_factory=list)

    @property
    def model_calls(self) -> int:
        return sum(t.model_calls for t in self.trajectories)


@dataclass(slots=True)
class DetectionReport:
    """Everything one ``detect`` run did - findings plus the per-candidate record."""

    scan_id: str
    outcomes: list[CandidateOutcome] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    budget_limit: int = 0
    model_calls: int = 0
    sandbox_id: str = ""
    stopped_early: str = ""  # why the queue was not finished ("" = it was)

    @property
    def summary(self) -> str:
        counts: dict[str, int] = {}
        for o in self.outcomes:
            counts[o.state] = counts.get(o.state, 0) + 1
        parts = [f"{n} {state}" for state, n in sorted(counts.items())]
        text = f"{len(self.findings)} raw finding(s) from {len(self.outcomes)} candidate(s)"
        if parts:
            text += f" ({', '.join(parts)})"
        text += f"; {self.model_calls}/{self.budget_limit} model call(s)"
        if self.stopped_early:
            text += f"; stopped early: {self.stopped_early}"
        return text


class DetectionOrchestrator:
    """Runs planner + analyst over a candidate queue inside one sandbox. Re-entrant."""

    def __init__(
        self,
        settings: Settings,
        *,
        model: ChatModel,
        executor: ExecutorProvider,
        trajectories: TrajectoryWriter | None = None,
    ) -> None:
        self.settings = settings
        self.model = model
        self.executor = executor
        self.trajectories = trajectories or TrajectoryWriter(settings.agent_trajectory_dir)
        self.planner: AgentDefinition = PLANNER.with_budget(temperature=settings.agent_temperature)
        self.analyst: AgentDefinition = ANALYST.with_budget(
            max_steps=settings.analyst_max_steps, temperature=settings.agent_temperature
        )

    # -- preflight ------------------------------------------------------------------
    def preflight(self) -> ExecutorHealth:
        """Fail fast, with an actionable message, if the Executor cannot serve this scan."""
        url = self.settings.executor_url
        try:
            health = self.executor.health()
        except ExecutorUnavailableError as exc:
            msg = (
                f"executor unreachable at {url} ({exc}); start it with `make executor` "
                "(EXECUTOR_TOKEN set) or fix EXECUTOR_URL - the agents read target code "
                "only through the sandbox"
            )
            raise PipelineError(msg) from exc
        except ExecutorError as exc:
            raise PipelineError(f"executor at {url} failed its health check: {exc}") from exc
        if not health.docker:
            msg = (
                f"executor at {url} is up but its Docker daemon is unavailable; "
                "sandboxes cannot be created"
            )
            raise PipelineError(msg)
        return health

    # -- the state machine ------------------------------------------------------------
    def detect(
        self, scan_id: str, target_id: str, workspace: Path, candidates: Sequence[Candidate]
    ) -> DetectionReport:
        queue = list(candidates[: self.settings.max_candidates])
        per_candidate = self.analyst.max_steps + (1 if self.settings.planner_enabled else 0)
        budget = CallBudget(limit=len(queue) * per_candidate)
        report = DetectionReport(scan_id=scan_id, budget_limit=budget.limit)
        if not queue:
            log.info("orchestrator[%s]: no candidates; no sandbox opened", scan_id)
            return report
        log.info(
            "orchestrator[%s]: %d candidate(s), budget %d model call(s), analyst steps %d, "
            "planner %s",
            scan_id,
            len(queue),
            budget.limit,
            self.analyst.max_steps,
            "on" if self.settings.planner_enabled else "off",
        )
        seen: set[str] = set()
        try:
            with self.executor.sandbox(scan_id, workspace) as sandbox:
                report.sandbox_id = str(getattr(sandbox, "sandbox_id", ""))
                for index, candidate in enumerate(queue, start=1):
                    if budget.remaining == 0:
                        report.stopped_early = f"model-call budget spent before candidate {index}"
                        break
                    try:
                        outcome = self._investigate(sandbox, scan_id, target_id, candidate, budget)
                    except BudgetExhaustedError as exc:
                        report.stopped_early = str(exc)
                        break
                    report.outcomes.append(outcome)
                    report.model_calls = budget.used
                    if outcome.finding is not None and outcome.finding.finding_id not in seen:
                        seen.add(outcome.finding.finding_id)
                        report.findings.append(outcome.finding)
        except ExecutorAuthError as exc:
            raise PipelineError(f"executor rejected EXECUTOR_TOKEN: {exc}") from exc
        except ExecutorUnavailableError as exc:
            raise PipelineError(f"executor became unreachable mid-scan: {exc}") from exc
        except ExecutorError as exc:
            raise PipelineError(f"sandbox failure: {exc}") from exc
        report.model_calls = budget.used
        if report.stopped_early:
            log.warning("orchestrator[%s]: %s", scan_id, report.stopped_early)
        log.info("orchestrator[%s]: %s", scan_id, report.summary)
        return report

    def _investigate(
        self,
        sandbox: SandboxReader,
        scan_id: str,
        target_id: str,
        c: Candidate,
        budget: CallBudget,
    ) -> CandidateOutcome:
        """WINDOW -> PLAN -> ANALYZE for one candidate, inside the open sandbox."""
        label = f"{c.file}:{c.line} ({c.rule})"
        deadline = time.monotonic() + self.settings.agent_candidate_timeout_s
        toolbox = ToolBox(sandbox, max_output_chars=self.settings.agent_tool_output_chars)

        # WINDOW: the sink and its surroundings, read through the jail. Seeds the ledger.
        span = self.settings.context_lines
        window = toolbox.dispatch(
            ToolCall(
                "read_lines", {"path": c.file, "start": max(1, c.line - span), "end": c.line + span}
            )
        )
        if not window.ok or not toolbox.ledger.has_line(c.file, c.line):
            reason = f"cannot read the flagged line through the sandbox: {window.text[:200]}"
            log.warning("orchestrator[%s]: skipping %s - %s", scan_id, label, reason)
            return CandidateOutcome(c, "skipped", reason)
        window_text = _mark_flagged_line(window.text, c.line)

        # PLAN
        outcome = CandidateOutcome(c, "skipped")
        if self.settings.planner_enabled:
            plan_traj = Trajectory(scan_id=scan_id, role=self.planner.role, candidate=label)
            plan = run_planner(
                self.model,
                self.planner,
                candidate=c,
                window_text=window_text,
                budget=budget,
                trajectory=plan_traj,
            )
            outcome.trajectories.append(plan_traj)
            self.trajectories.write(plan_traj)
        else:
            plan = default_plan(c)
        outcome.plan = plan

        # ANALYZE
        traj = Trajectory(scan_id=scan_id, role=self.analyst.role, candidate=label)
        result: AnalystOutcome = run_analyst(
            self.model,
            self.analyst,
            scan_id=scan_id,
            target_id=target_id,
            candidate=c,
            plan=plan,
            window_text=window_text,
            toolbox=toolbox,
            budget=budget,
            deadline=deadline,
            trajectory=traj,
        )
        outcome.trajectories.append(traj)
        self.trajectories.write(traj)

        # COLLECT
        outcome.reason = result.reason
        outcome.finding = result.finding
        outcome.state = _STATE_FOR_VERDICT[result.verdict]
        log.info(
            "orchestrator[%s]: %s -> %s (%s)", scan_id, label, outcome.state, result.reason[:120]
        )
        return outcome


_STATE_FOR_VERDICT: dict[str, CandidateState] = {
    "confirm": "confirmed",
    "dismiss": "dismissed",
    "exhausted": "exhausted",
    "timeout": "timeout",
}


FLAG_MARK = "   # <-- FLAGGED"


def _mark_flagged_line(window_text: str, line: int) -> str:
    """Tag the flagged row so both agents can find it at a glance (any line-number width)."""
    prefix = f"{line:5d} | "
    return "\n".join(
        row + FLAG_MARK if row.startswith(prefix) else row for row in window_text.splitlines()
    )
