"""The graded verifier (Deliverable 3, step 3b-2): prove findings, don't just assert them.

Deterministic code that turns a model-asserted finding into a proven one by climbing the
output-strength ladder in the egress-blocked jail:

* :mod:`ono.verifier.verify`  - :class:`GradedVerifier`, the bounded self-correction loop
  (prover -> run PoC under the oracle -> rung 3; fixer -> apply, re-run, test -> rung 4).
* :mod:`ono.verifier.oracle`  - the host side of the sink oracle (stage, run, parse, explain).
* :mod:`ono.verifier._oracle` - the in-jail oracle shipped into the sandbox (stdlib only).

The LLM only ever *proposes* (a PoC script, a patch diff); every true/false verdict is
plain code running in the sandbox.
"""

from ono.verifier.oracle import OracleResult, SinkOracle, new_canary, oracle_supports
from ono.verifier.verify import ExecutorProvider, GradedVerifier, VerifyReport, verify_anchor

__all__ = [
    "ExecutorProvider",
    "GradedVerifier",
    "OracleResult",
    "SinkOracle",
    "VerifyReport",
    "new_canary",
    "oracle_supports",
    "verify_anchor",
]
