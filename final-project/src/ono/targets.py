"""Target registry - the exact allowlist of authorized analysis targets.

ONO never analyzes an arbitrary URL or host. Every scan names a ``target_id``
that must resolve through this registry to a snapshot we host ourselves. This
is the enforcement point for the "authorized targets only" guardrail: an unknown
``target_id`` is rejected (HTTP 403) before any pipeline stage runs.

The registry is a plain mapping loaded from ``targets.yaml`` shipped inside the
package - an *exact* allowlist, deliberately not a probabilistic structure.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from importlib import resources
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

TargetKind = Literal["practice-app", "repo", "snippet"]


class Target(BaseModel):
    """One authorized target as exposed by ``GET /targets``."""

    model_config = ConfigDict(frozen=True)

    target_id: str = Field(description="Registry key; the only identifier a scan may use.")
    name: str
    kind: TargetKind
    languages: list[str] = Field(default_factory=list)
    description: str = ""
    source: str = Field(
        description=(
            "Where ingest materializes the snapshot from: an https git URL (shallow-cloned "
            "once per scan) or a local directory (copied). 'inline' for the snippet target."
        )
    )
    snapshot: str = Field(description="Pinned snapshot reference inside the sandbox.")
    authorized: Literal[True] = Field(
        default=True,
        description="Always true: presence in the registry *is* the authorization.",
    )


class UnauthorizedTargetError(LookupError):
    """Raised when a ``target_id`` is not in the allowlist."""

    def __init__(self, target_id: str) -> None:
        super().__init__(f"target_id {target_id!r} is not an authorized target")
        self.target_id = target_id


class TargetRegistry(Mapping[str, Target]):
    """Read-only mapping ``target_id -> Target`` backed by the YAML allowlist."""

    def __init__(self, targets: Mapping[str, Target]) -> None:
        self._targets: dict[str, Target] = dict(targets)

    # -- Mapping protocol -------------------------------------------------
    def __getitem__(self, target_id: str) -> Target:
        return self._targets[target_id]

    def __iter__(self) -> Iterator[str]:
        return iter(self._targets)

    def __len__(self) -> int:
        return len(self._targets)

    # -- Domain helpers ---------------------------------------------------
    def is_authorized(self, target_id: str) -> bool:
        """Exact-match membership test. This is the allowlist check."""
        return target_id in self._targets

    def require(self, target_id: str) -> Target:
        """Return the target or raise :class:`UnauthorizedTargetError`."""
        try:
            return self._targets[target_id]
        except KeyError:
            raise UnauthorizedTargetError(target_id) from None

    def all(self) -> list[Target]:
        return list(self._targets.values())

    # -- Construction -----------------------------------------------------
    @classmethod
    def from_yaml(cls, path: Path | None = None) -> TargetRegistry:
        """Load the registry from ``targets.yaml`` (packaged copy by default)."""
        if path is None:
            text = resources.files("ono").joinpath("targets.yaml").read_text(encoding="utf-8")
        else:
            text = path.read_text(encoding="utf-8")
        raw = yaml.safe_load(text) or {}
        entries: dict[str, dict[str, object]] = raw.get("targets", {})
        for target_id, body in entries.items():
            body.setdefault("target_id", target_id)
        validated = TypeAdapter(dict[str, Target]).validate_python(entries)
        return cls(validated)


_DEFAULT_REGISTRY: TargetRegistry | None = None


def get_registry() -> TargetRegistry:
    """Return the packaged allowlist, loading it once per process."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = TargetRegistry.from_yaml()
    return _DEFAULT_REGISTRY
