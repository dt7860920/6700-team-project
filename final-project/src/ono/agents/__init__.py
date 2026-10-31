"""Agent definitions for the detection core (Deliverable 3, step 3b-1).

An *agent* here is a definition - role prompt, allowed tools, step budget, temperature -
that the deterministic orchestrator (:mod:`ono.orchestrator`) runs on the one pinned
model. Nothing in this package decides *when* to run; it only knows *how*.

* :mod:`ono.agents.definitions` - :data:`PLANNER` and :data:`ANALYST`
* :mod:`ono.agents.model`       - the shared OpenAI-compatible client + call budget
* :mod:`ono.agents.tools`       - read-only sandbox tools, output truncation, read ledger
* :mod:`ono.agents.protocol`    - tolerant parsing of model replies into tool calls
* :mod:`ono.agents.planner`     - one call -> :class:`InvestigationPlan`
* :mod:`ono.agents.analyst`     - the bounded ReAct loop -> anchored :class:`Finding`
* :mod:`ono.agents.trajectory`  - per-run step log (observability / learning data)
"""

from ono.agents.analyst import AnalystOutcome, run_analyst
from ono.agents.definitions import ANALYST, PLANNER, AgentDefinition
from ono.agents.model import CallBudget, ChatModel, ModelClient, ModelError, ModelReply, ToolCall
from ono.agents.planner import InvestigationPlan, default_plan, run_planner
from ono.agents.tools import ReadLedger, SandboxReader, ToolBox
from ono.agents.trajectory import Trajectory, TrajectoryWriter

__all__ = [
    "ANALYST",
    "PLANNER",
    "AgentDefinition",
    "AnalystOutcome",
    "CallBudget",
    "ChatModel",
    "InvestigationPlan",
    "ModelClient",
    "ModelError",
    "ModelReply",
    "ReadLedger",
    "SandboxReader",
    "ToolBox",
    "ToolCall",
    "Trajectory",
    "TrajectoryWriter",
    "default_plan",
    "run_analyst",
    "run_planner",
]
