"""Lightweight taint reasoning over the IR: *does attacker input plausibly reach this sink?*

Depth, stated exactly so nobody mistakes this for a real data-flow engine:

* **Intra-procedural, flow-insensitive.** Within one function, assignments are iterated to
  a fixpoint regardless of control flow: ``x = request.args["q"]`` anywhere in the body
  taints ``x`` everywhere in the body. Branch conditions and ordering are ignored (so a
  value validated on one path and used raw on another is still reported - a recall choice).
* **Propagation** through attribute/subscript access, string building (f-strings, template
  literals, ``+``, ``%``, ``.format``, ``.join``), collections, ternaries, ``or``/``??``
  defaults and *unknown* calls (``helper(tainted)`` stays tainted). A call to a known
  sanitizer (``int()``, ``shlex.quote()``, ``parseInt()``, ...) stops propagation.
* **Closures** inherit the enclosing function's final taint (callbacks inside a handler).
* **Parameters** are tracked as *potential* taint: a sink fed by a parameter is a
  ``param``-state hit that :mod:`ono.planning.threatmap` tries to resolve **one hop** up -
  a caller passing attacker data in that argument position. There is no second hop, no
  return-value flow, no field-sensitivity, no inter-file alias analysis.

Every hit carries evidence (source expression + assignment hops + sink) so the analyst
agent gets a concrete trace to verify, not a verdict to trust.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

from ono.planning.catalog import (
    ASSIGNMENT_SINKS,
    GLOBAL_REQUEST_NAMES,
    GLOBAL_SOURCES,
    REQUEST_PROPS,
    SANITIZERS,
    SOURCE_METHODS,
    SinkRule,
    excerpt_of,
    rules_for,
    select_arg,
)
from ono.planning.ir import Assign, Expr, Function, Module, chain, is_constant, last_segment

log = logging.getLogger(__name__)

__all__ = ["Evidence", "FunctionTaint", "Hop", "SinkHit", "SinkState", "analyze_module"]

EvidenceKind = Literal["source", "entry-param", "param", "request-object"]
SinkState = Literal["tainted", "param", "dynamic", "constant"]

_PRIORITY: dict[str, int] = {"source": 0, "entry-param": 0, "param": 2, "request-object": 3}
_MAX_HOPS = 10
_MAX_DEPTH = 60
_FIXPOINT_ROUNDS = 6


@dataclass(frozen=True, slots=True)
class Hop:
    """One step of a source->sink trace (mirrors :class:`ono.models.TraceStep`)."""

    file: str
    line: int
    symbol: str
    note: str

    def render(self) -> str:
        return f"{self.file}:{self.line} {self.symbol} - {self.note}"


@dataclass(frozen=True, slots=True)
class Evidence:
    """Why a name / expression is considered attacker-controlled."""

    kind: EvidenceKind
    origin: str  # the source expression, or "parameter <p> of <fn>()"
    hops: tuple[Hop, ...]
    param: str = ""  # kind == "param": the parameter name
    param_fn: str = ""  # kind == "param": the function that owns it

    @property
    def priority(self) -> int:
        return _PRIORITY[self.kind]

    def extend(self, hop: Hop) -> Evidence:
        if self.hops and self.hops[-1] == hop:
            return self
        hops = (*self.hops, hop)[-_MAX_HOPS:]
        return Evidence(self.kind, self.origin, hops, self.param, self.param_fn)


@dataclass(slots=True)
class SinkHit:
    """A dangerous call whose inspected argument is not a constant."""

    file: str
    line: int
    cwe: str
    rule: str
    severity: str
    excerpt: str
    function: Function
    language: str
    state: SinkState
    evidence: tuple[Evidence, ...]
    taint_gated: bool  # rule.require_taint: drop unless direct / one-hop taint is found

    @property
    def best(self) -> Evidence | None:
        return min(self.evidence, key=lambda e: e.priority) if self.evidence else None

    @property
    def params(self) -> tuple[Evidence, ...]:
        return tuple(e for e in self.evidence if e.kind == "param")

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.file, self.line, self.cwe)


class _NotInputError(Exception):
    """Internal: a request-object member that is *not* input (``request.user``)."""


class FunctionTaint:
    """The taint state of one function after the fixpoint; also the expression evaluator."""

    def __init__(
        self,
        fn: Function,
        module: Module,
        *,
        parent: FunctionTaint | None,
        module_constants: set[str],
    ) -> None:
        self.fn = fn
        self.module = module
        self.language = module.language
        self.tainted: dict[str, Evidence] = dict(parent.tainted) if parent else {}
        self.request_names: dict[str, tuple[str, ...] | None] = (
            dict(parent.request_names) if parent else {}
        )
        if not parent:
            props = tuple(sorted(REQUEST_PROPS[self.language]))
            for name in GLOBAL_REQUEST_NAMES[self.language]:
                self.request_names[name] = props
        self.constants: set[str] = set(module_constants)
        self.hits: list[SinkHit] = []
        self.constant_sinks: set[tuple[str, int, str]] = set()  # sink calls on constant input
        self._seed_params()
        self._fixpoint()
        self._sinks()

    # -- setup ------------------------------------------------------------------------
    def _seed_params(self) -> None:
        entry = self.fn.entry
        for p in self.fn.params:
            self.constants.discard(p)
            if p in ("self", "cls", "this"):
                continue
            if entry is not None and p in entry.request_params:
                self.request_names[p] = entry.request_props
                continue
            if entry is not None and p in entry.tainted_params:
                self.tainted[p] = Evidence(
                    "entry-param",
                    origin=f"parameter {p!r} of {entry.kind} {entry.detail}",
                    hops=(
                        Hop(
                            self.fn.file,
                            self.fn.start,
                            p,
                            f"attacker-controlled parameter ({entry.detail})",
                        ),
                    ),
                )
                continue
            self.tainted[p] = Evidence(
                "param",
                origin=f"parameter {p!r} of {self.fn.name}()",
                hops=(Hop(self.fn.file, self.fn.start, p, f"parameter of {self.fn.name}()"),),
                param=p,
                param_fn=self.fn.name,
            )

    def _fixpoint(self) -> None:
        assigned: set[str] = set()
        for a in self.fn.assigns:
            for t in a.targets:
                assigned.add(t)
                if is_constant(a.value) and t not in self.fn.params:
                    self.constants.add(t)
                else:
                    self.constants.discard(t)
        # a name assigned both a constant and something else is not a constant
        for a in self.fn.assigns:
            if not is_constant(a.value):
                for t in a.targets:
                    self.constants.discard(t)
        for _ in range(_FIXPOINT_ROUNDS):
            if not any(self._apply(a) for a in self.fn.assigns):
                break

    def _apply(self, a: Assign) -> bool:
        evidence = self.evaluate(a.value)
        if not evidence:
            return False
        best = min(evidence, key=lambda e: e.priority)
        changed = False
        if best.kind == "request-object":  # ``r = request`` aliases the request object
            props = self.request_names.get(best.origin)
            for t in a.targets:
                if t not in self.request_names:
                    self.request_names[t] = props
                    changed = True
            return changed
        for t in a.targets:
            current = self.tainted.get(t)
            if current is None or best.priority < current.priority:
                note = f"{t} = {a.value.text[:80]}" if a.value.text else f"{t} assigned"
                self.tainted[t] = best.extend(Hop(self.fn.file, a.line, t, note))
                changed = True
        return changed

    # -- evaluation -------------------------------------------------------------------
    def evaluate(self, e: Expr, depth: int = 0) -> list[Evidence]:
        """All evidence that ``e`` carries attacker-controlled data (empty = none found)."""
        if depth > _MAX_DEPTH or e.kind in ("literal", "function"):
            return []
        if e.kind == "name":
            found = self.tainted.get(e.name)
            if found is not None:
                return [found]
            if e.name in self.request_names:
                return [
                    Evidence(
                        "request-object",
                        origin=e.name,
                        hops=(Hop(self.fn.file, e.line, e.name, "the request object itself"),),
                    )
                ]
            return []
        if e.kind in ("member", "subscript", "call", "new"):
            try:
                source = self._source_of(e)
            except _NotInputError:
                return []
            if source is not None:
                return [source]
            if e.kind == "call" and last_segment(chain(e)) in SANITIZERS:
                return []
        return self._propagate(e, depth)

    def _propagate(self, e: Expr, depth: int) -> list[Evidence]:
        found: list[Evidence] = []
        seen: set[tuple[str, str, str]] = set()
        # ``d[key]``: the *index* never taints the value read (``ALLOWED[request.args["x"]]``)
        children = e.children[:1] if e.kind == "subscript" else e.children
        for child in (*children, *(v for _k, v in e.kwargs)):
            for ev in self.evaluate(child, depth + 1):
                key = (ev.kind, ev.origin, ev.param)
                if key not in seen:
                    seen.add(key)
                    found.append(ev)
        return found

    def _source_of(self, e: Expr) -> Evidence | None:
        path = chain(e)
        if not path:
            return None
        segments = path.split(".")
        if self.language == "python" and segments[:2] == ["flask", "request"]:
            segments = segments[1:]
            path = ".".join(segments)
        for name, props in self.request_names.items():
            head = name.split(".")
            if segments[: len(head)] != head:
                continue
            rest = segments[len(head) :]
            if not rest:
                return None  # bare request object: handled by the "name" branch
            if props is None or rest[0] in props:
                shown = ".".join(segments[: len(head) + 1])
                return Evidence(
                    "source",
                    origin=e.text or path,
                    hops=(Hop(self.fn.file, e.line, shown, "attacker-controlled request data"),),
                )
            raise _NotInputError
        resolved = self.module.resolve(path)
        for source, label in GLOBAL_SOURCES[self.language]:
            if resolved == source or resolved.startswith(source + "."):
                return Evidence(
                    "source",
                    origin=e.text or path,
                    hops=(Hop(self.fn.file, e.line, source, label),),
                )
        if e.kind == "call" and last_segment(resolved) in SOURCE_METHODS[self.language]:
            return Evidence(
                "source",
                origin=e.text or path,
                hops=(Hop(self.fn.file, e.line, resolved, "parsed external input"),),
            )
        return None

    def classify(self, args: list[Expr]) -> tuple[SinkState, tuple[Evidence, ...]]:
        """What state the inspected argument(s) of a sink are in, with the evidence."""
        evidence: list[Evidence] = []
        constant = bool(args)
        for arg in args:
            evidence.extend(self.evaluate(arg))
            if not (is_constant(arg) or (arg.kind == "name" and arg.name in self.constants)):
                constant = False
        real = tuple(e for e in evidence if e.kind != "request-object")
        if any(e.kind in ("source", "entry-param") for e in real):
            return "tainted", tuple(sorted(real, key=lambda e: e.priority))
        if any(e.kind == "param" for e in real):
            return "param", tuple(sorted(real, key=lambda e: e.priority))
        if constant:
            return "constant", ()
        return "dynamic", ()

    # -- sinks ------------------------------------------------------------------------
    def _sinks(self) -> None:
        for call in self.fn.calls:
            path = self.module.resolve(chain(call))
            for rule in rules_for(path, self.language):
                self._check(call, rule)
        for a in self.fn.assigns:
            for target in a.targets:
                sink = ASSIGNMENT_SINKS.get(last_segment(target))
                if sink is None:
                    continue
                state, evidence = self.classify([a.value])
                if state in ("tainted", "param"):
                    cwe, rule_name, severity = sink
                    self._emit(
                        a.line,
                        cwe,
                        rule_name,
                        severity,
                        f"{target} = {a.value.text}",
                        state,
                        evidence,
                        True,
                    )

    def _check(self, call: Expr, rule: SinkRule) -> None:
        if rule.condition is not None and not rule.condition(call):
            return
        args = select_arg(call, rule.arg)
        if not args:
            return
        state, evidence = self.classify(args)
        if state == "constant":
            self.constant_sinks.add((self.fn.file, call.line, rule.cwe))
            return
        if rule.require_taint and state not in ("tainted", "param"):
            return
        self._emit(
            call.line,
            rule.cwe,
            rule.rule,
            rule.severity,
            excerpt_of(call),
            state,
            evidence,
            rule.require_taint,
        )

    def _emit(
        self,
        line: int,
        cwe: str,
        rule: str,
        severity: str,
        excerpt: str,
        state: SinkState,
        evidence: tuple[Evidence, ...],
        taint_gated: bool,
    ) -> None:
        hit = SinkHit(
            file=self.fn.file,
            line=line,
            cwe=cwe,
            rule=rule,
            severity=severity,
            excerpt=excerpt,
            function=self.fn,
            language=self.language,
            state=state,
            evidence=evidence,
            taint_gated=taint_gated,
        )
        for existing in self.hits:  # one hit per (line, cwe); keep the stronger state
            if existing.key == hit.key:
                if _STATE_RANK[hit.state] < _STATE_RANK[existing.state]:
                    existing.state, existing.evidence, existing.rule = (
                        hit.state,
                        hit.evidence,
                        hit.rule,
                    )
                return
        self.hits.append(hit)


_STATE_RANK: dict[str, int] = {"tainted": 0, "param": 1, "dynamic": 2, "constant": 3}


def analyze_module(module: Module) -> dict[int, FunctionTaint]:
    """Run the taint pass over every function of ``module`` (parents before closures)."""
    contexts: dict[int, FunctionTaint] = {}
    module_constants: set[str] = set()
    for fn in module.functions:
        parent = contexts.get(id(fn.parent)) if fn.parent is not None else None
        ctx = FunctionTaint(fn, module, parent=parent, module_constants=module_constants)
        contexts[id(fn)] = ctx
        if fn.is_module:
            module_constants = set(ctx.constants)
    return contexts
