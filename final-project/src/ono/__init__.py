"""Operation: Negative One (ONO).

An agentic system that analyzes *authorized* code targets for security
vulnerabilities, proves each one is reachable, and proposes a verified fix.

This package is the Deliverable 2 (midpoint) prototype: the API, configuration,
container, and UI are real and deployable; the analyzer is a structured mock
(``model_backend="mock"``) that will be replaced by the frozen Qwen2.5-Coder
planner/analyst agent plus the deterministic verifier.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ono")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
