"""Planning / threat-mapping: the per-target stage between SAST and the per-candidate agents.

Public surface:

* :func:`threat_map` - entry points + (one-hop) data flow + sinks -> a ranked, unioned,
  capped candidate queue (:class:`ThreatMap`). This is the ``plan`` stage's engine.
* :mod:`ono.planning.evaluate` - the corpus scoring used by ``scripts/coverage_eval.py``.

Internals: :mod:`ono.planning.ir` (the shared IR), :mod:`ono.planning.python_frontend`
(stdlib ``ast``), :mod:`ono.planning.js_frontend` (tree-sitter), :mod:`ono.planning.taint`
(the flow engine), :mod:`ono.planning.catalog` (sources / sinks / sanitizers / markers).
"""

from ono.planning.ir import EntryPoint
from ono.planning.taint import SinkHit
from ono.planning.threatmap import TIER_ORDER, Link, ThreatMap, threat_map

__all__ = ["TIER_ORDER", "EntryPoint", "Link", "SinkHit", "ThreatMap", "threat_map"]
