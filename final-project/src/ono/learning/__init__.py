"""The learning loop (plan section 1.5): frontier-free Level-1 self-distillation.

ONO does not update the model's weights. It learns at the orchestration layer, exactly as
the plan specifies: keep only the trajectories the deterministic verifier *passed*, store
them in a persistent :class:`~ono.learning.memory.KnowledgeMemory`, and seed the prover /
planner with them on later scans so the frozen model reaches the proof in fewer steps.

* :mod:`ono.learning.memory`  - the durable, signature-keyed store + the seed text.
* :mod:`ono.learning.harvest` - distil verifier-passed findings into the memory.
* :mod:`ono.learning.measure` - the per-round metrics that show the loop moving a number.

``KnowledgeMemory`` is off by default (``settings.learning_enabled``); when on it only ever
makes the harness faster, never less correct - every seeded attempt is re-proven from
scratch by the verifier.
"""

from ono.learning.harvest import harvest_findings
from ono.learning.measure import RoundMetrics, improvement, round_metrics
from ono.learning.memory import KnowledgeMemory, MemoryEntry, signature_for

__all__ = [
    "KnowledgeMemory",
    "MemoryEntry",
    "RoundMetrics",
    "harvest_findings",
    "improvement",
    "round_metrics",
    "signature_for",
]
