"""The threat-mapping stage: entry points -> (one-hop) data flow -> sinks -> a ranked queue.

Runs once per scan, after SAST and before the per-candidate agents, as the ``plan``
stage of the pipeline. It is deterministic code (no model call) and does three things:

1. **Entry-point discovery** - web routes/handlers, URL maps, class-based views, CLI and
   event handlers, exported serverless handlers, plus every read of a global input
   (``os.environ``, ``sys.argv``, ``process.env`` ...), across Python and JS/TS.
2. **Data-flow linking** - :mod:`ono.planning.taint` (intra-procedural + one hop through a
   caller) connects those entry points to the sinks it finds itself *and* to the SAST
   candidates it is given.
3. **Prioritisation + union** - the SAST queue is re-ranked so sinks reachable from a real
   entry point come first, reachable sinks the pattern scanners missed are added, and the
   result is capped at ``max_candidates`` so the model budget is unchanged.

Nothing here can fail a scan: unreadable or unparsable files are counted and skipped,
and a wall-clock budget stops file discovery early with a note.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ono.planning.catalog import (
    HTTP_VERBS,
    PHP_NONINPUT_PARAMS,
    PHP_REQUEST_PARAM_NAMES,
    PY_REQUEST_PARAM_NAMES,
    REQUEST_PROPS,
)
from ono.planning.ir import EntryPoint, Expr, Function, Language, Module, chain, last_segment
from ono.planning.js_frontend import EXTENSIONS as JS_EXTENSIONS
from ono.planning.js_frontend import parse_js
from ono.planning.php_frontend import EXTENSIONS as PHP_EXTENSIONS
from ono.planning.php_frontend import parse_php
from ono.planning.python_frontend import parse_python
from ono.planning.taint import Evidence, FunctionTaint, Hop, SinkHit, analyze_module
from ono.sast import Candidate, rank

log = logging.getLogger(__name__)

__all__ = ["TIER_ORDER", "Link", "ThreatMap", "threat_map"]

_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "site-packages",
        ".tox",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "coverage",
        "vendor",
        "bower_components",
        ".cache",
    }
)
_MAX_FILE_BYTES = 1_000_000
_MAX_FILES = 4000
_PY_EXTENSIONS = frozenset({".py"})

TIER_ORDER: dict[str, int] = {
    "direct": 0,  # source and sink in one function (or a closure of it)
    "one-hop": 1,  # caller passes attacker data into the parameter that reaches the sink
    "param": 2,  # sink fed by a parameter; no tainted caller found (reachability unknown)
    "in-entry": 2,  # SAST candidate inside an entry-point function, sink not modelled here
    "dynamic": 3,  # sink argument is non-constant but no input dependency was found
    "unmapped": 4,  # SAST candidate the threat map knows nothing about
    "constant": 5,  # SAST candidate whose sink argument the threat map found to be constant
}
_UNION_TIERS = frozenset({"direct", "one-hop", "param"})


@dataclass(slots=True)
class Link:
    """One entry/source -> sink connection with its evidence trace."""

    sink: SinkHit
    tier: str
    evidence: Evidence
    entry: EntryPoint | None
    hops: tuple[Hop, ...]

    @property
    def entry_label(self) -> str:
        if self.entry is not None:
            return self.entry.label
        return f"input read in {self.sink.function.label}"

    def render(self) -> str:
        path = " -> ".join(f"{h.file}:{h.line} {h.symbol}" for h in self.hops)
        sink = f"{self.sink.cwe} {self.sink.file}:{self.sink.line}"
        return f"[{self.tier}] {self.entry_label} => {sink} | {path}"


@dataclass(slots=True)
class ThreatMap:
    """What the stage found, and the queue it hands to the orchestrator."""

    entry_points: list[EntryPoint] = field(default_factory=list)
    sinks: list[SinkHit] = field(default_factory=list)  # every non-constant sink, after resolution
    links: list[Link] = field(default_factory=list)  # direct / one-hop connections
    tiers: dict[tuple[str, int, str], str] = field(default_factory=dict)  # sink key -> tier
    constant_sinks: set[tuple[str, int, str]] = field(default_factory=set)
    queue: list[Candidate] = field(default_factory=list)
    sast_count: int = 0
    matched: int = 0  # SAST candidates the map could place (tier better than unmapped)
    added: int = 0
    cut: int = 0
    files: int = 0
    parse_errors: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    notes: list[str] = field(default_factory=list)

    @property
    def reachable(self) -> list[SinkHit]:
        return [s for s in self.sinks if self.tiers.get(s.key) in ("direct", "one-hop")]

    def summary(self) -> str:
        direct = sum(1 for link in self.links if link.tier == "direct")
        one_hop = len(self.links) - direct
        langs = (
            ", ".join(f"{n} {lang}" for lang, n in sorted(self.languages.items()))
            or "no source files"
        )
        text = (
            f"threat map: {len(self.entry_points)} entry point(s) in {self.files} file(s) "
            f"({langs}); "
            f"{len(self.sinks)} sink(s), {len(self.reachable)} reachable "
            f"({direct} direct, {one_hop} one-hop); queue {len(self.queue)} = "
            f"{self.sast_count} from SAST ({self.matched} mapped) + {self.added} added"
        )
        if self.cut:
            text += f", {self.cut} cut by max_candidates"
        if self.parse_errors:
            text += f"; {self.parse_errors} file(s) with parse errors"
        if self.notes:
            text += "; " + "; ".join(self.notes)
        return text

    def steps(self) -> list[str]:
        """The per-target scaffold as plan steps (what the orchestrator will walk)."""
        out = [
            f"MAP {e.kind} {e.detail} -> {e.file}:{e.line} {e.function}"
            for e in self.entry_points[:12]
        ]
        if len(self.entry_points) > 12:
            out.append(f"MAP ... {len(self.entry_points) - 12} more entry point(s)")
        for c in self.queue:
            out.append(f"ANALYZE {c.file}:{c.line} ({c.cwe_hint}, {c.reach or 'unmapped'})")
        return out


# ---------------------------------------------------------------------------
# File discovery + parsing
# ---------------------------------------------------------------------------


def _iter_sources(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if (
            suffix not in _PY_EXTENSIONS
            and suffix not in JS_EXTENSIONS
            and suffix not in PHP_EXTENSIONS
        ):
            continue
        if _SKIP_DIRS.intersection(path.relative_to(root).parts[:-1]):
            continue
        name = path.name.lower()
        if name.endswith((".min.js", ".d.ts", ".bundle.js")):
            continue
        yield path


def parse_tree(root: Path, *, deadline_s: float, notes: list[str]) -> list[Module]:
    modules: list[Module] = []
    started = time.monotonic()
    for index, path in enumerate(_iter_sources(root)):
        if index >= _MAX_FILES:
            notes.append(f"stopped after {_MAX_FILES} files")
            break
        if time.monotonic() - started > deadline_s:
            notes.append(f"stopped after {deadline_s:.0f}s wall clock ({index} files parsed)")
            break
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        language: Language = (
            "python"
            if suffix in _PY_EXTENSIONS
            else "php"
            if suffix in PHP_EXTENSIONS
            else "javascript"
        )
        try:
            if suffix in _PY_EXTENSIONS:
                module = parse_python(path, rel)
            elif suffix in PHP_EXTENSIONS:
                module = parse_php(path, rel)
            else:
                module = parse_js(path, rel)
        except Exception as exc:  # a front-end bug on one odd file must not fail the scan
            log.warning("threat map: failed to lower %s: %s", rel, exc)
            module = Module(file=rel, language=language, parse_error=str(exc))
        modules.append(module)
    return modules


# ---------------------------------------------------------------------------
# Cross-module entry points (URL maps / route registrations by name)
# ---------------------------------------------------------------------------


def _apply_handler_refs(modules: list[Module]) -> None:
    by_name: dict[str, list[Function]] = {}
    by_owner: dict[str, list[Function]] = {}
    for module in modules:
        for fn in module.functions:
            if fn.is_module:
                continue
            by_name.setdefault(fn.name, []).append(fn)
            if fn.owner:
                by_owner.setdefault(fn.owner, []).append(fn)
    for module in modules:
        for ref in module.handler_refs:
            if ref.kind == "class-view":
                targets = [
                    fn
                    for fn in by_owner.get(ref.name, [])
                    if fn.name in HTTP_VERBS or fn.name == "dispatch"
                ]
            else:
                targets = by_name.get(ref.name, [])
            for fn in targets:
                if fn.entry is not None and fn.entry.kind != "request-param":
                    continue
                fn.entry = _ref_entry(fn, ref.kind, ref.detail)


def _ref_entry(fn: Function, kind: str, detail: str) -> EntryPoint:
    if fn.language == "python":
        request = tuple(p for p in fn.params if p in PY_REQUEST_PARAM_NAMES)
        data = tuple(
            p for p in fn.params if p not in ("self", "cls") and p not in PY_REQUEST_PARAM_NAMES
        )
        props: tuple[str, ...] | None = tuple(sorted(REQUEST_PROPS["python"]))
    elif fn.language == "php":
        request = tuple(p for p in fn.params if p in PHP_REQUEST_PARAM_NAMES)
        data = tuple(
            p
            for p in fn.params
            if p not in PHP_REQUEST_PARAM_NAMES and p not in PHP_NONINPUT_PARAMS
        )
        props = tuple(sorted(REQUEST_PROPS["php"]))
    else:
        request = fn.params[:1]
        data = ()
        props = tuple(sorted(REQUEST_PROPS["javascript"]))
    return EntryPoint(
        file=fn.file,
        line=fn.start,
        function=fn.name if not fn.owner else f"{fn.owner}.{fn.name}",
        kind=kind,
        detail=detail,
        tainted_params=data,
        request_params=request,
        request_props=props,
    )


# ---------------------------------------------------------------------------
# One-hop resolution
# ---------------------------------------------------------------------------


class _Callers:
    """Index: function name -> (caller context, call expression) for every call in the tree."""

    def __init__(self, contexts: Iterable[FunctionTaint]) -> None:
        self.by_name: dict[str, list[tuple[FunctionTaint, Expr]]] = {}
        for ctx in contexts:
            for call in ctx.fn.calls:
                name = last_segment(chain(call))
                if name:
                    self.by_name.setdefault(name, []).append((ctx, call))

    def resolve(self, hit: SinkHit, owners: dict[str, list[Function]]) -> Link | None:
        for param_ev in hit.params:
            fns = owners.get(param_ev.param_fn, [])
            for fn in fns:
                if param_ev.param not in fn.params:
                    continue
                position = fn.params.index(param_ev.param)
                if fn.params and fn.params[0] in ("self", "cls", "this"):
                    position -= 1
                for ctx, call in self.by_name.get(fn.name, []):
                    if ctx.fn is fn or ctx.fn is hit.function:
                        continue
                    arg = call.kwarg(param_ev.param)
                    if arg is None and 0 <= position < len(call.args):
                        arg = call.args[position]
                    if arg is None:
                        continue
                    evidence = [
                        e
                        for e in ctx.evaluate(arg)
                        if e.kind in ("source", "entry-param", "request-object")
                    ]
                    if not evidence:
                        continue
                    caller_ev = min(evidence, key=lambda e: e.priority)
                    hops = (
                        *caller_ev.hops,
                        Hop(
                            ctx.fn.file,
                            call.line,
                            f"{fn.name}({param_ev.param}=...)",
                            f"call from {ctx.fn.name}() passes attacker data",
                        ),
                        *param_ev.hops,
                        Hop(hit.file, hit.line, hit.excerpt[:80], f"sink ({hit.cwe})"),
                    )
                    entry = ctx.fn.nearest_entry()
                    return Link(
                        sink=hit, tier="one-hop", evidence=caller_ev, entry=entry, hops=hops
                    )
        return None


# ---------------------------------------------------------------------------
# The stage
# ---------------------------------------------------------------------------


def threat_map(
    root: Path,
    candidates: Sequence[Candidate],
    *,
    max_candidates: int,
    deadline_s: float = 120.0,
) -> ThreatMap:
    """Build the threat map of ``root`` and merge it with the SAST ``candidates``."""
    started = time.perf_counter()
    result = ThreatMap(sast_count=len(candidates))
    modules = parse_tree(root, deadline_s=deadline_s, notes=result.notes)
    result.files = len(modules)
    result.parse_errors = sum(1 for m in modules if m.parse_error)
    for m in modules:
        result.languages[m.language] = result.languages.get(m.language, 0) + 1

    _apply_handler_refs(modules)
    contexts: list[FunctionTaint] = []
    by_module: dict[str, Module] = {}
    owners: dict[str, list[Function]] = {}
    for module in modules:
        by_module[module.file] = module
        try:
            analyzed = analyze_module(module)
        except Exception as exc:  # an engine bug on one file must not fail the scan
            log.warning("threat map: taint analysis failed on %s: %s", module.file, exc)
            module.parse_error = f"taint analysis failed: {exc}"
            result.parse_errors += 1
            continue
        for ctx in analyzed.values():
            contexts.append(ctx)
            if not ctx.fn.is_module:
                owners.setdefault(ctx.fn.name, []).append(ctx.fn)
    callers = _Callers(contexts)

    # -- resolve every sink hit to a tier --------------------------------------------
    links_by_key: dict[tuple[str, int, str], Link] = {}
    for ctx in contexts:
        result.constant_sinks.update(ctx.constant_sinks)
        for hit in ctx.hits:
            tier, link = _resolve(hit, callers, owners)
            if tier is None:
                continue
            result.sinks.append(hit)
            result.tiers[hit.key] = tier
            if link is not None:
                result.links.append(link)
                links_by_key[hit.key] = link

    # -- entry points ------------------------------------------------------------------
    seen_entries: set[tuple[str, int, str]] = set()
    for module in modules:
        for fn in module.functions:
            if fn.entry is not None and (fn.file, fn.start, fn.entry.detail) not in seen_entries:
                seen_entries.add((fn.file, fn.start, fn.entry.detail))
                result.entry_points.append(fn.entry)
    for link in result.links:  # global inputs read by functions that are not routes
        if link.entry is None and link.hops:
            first = link.hops[0]
            key = (first.file, first.line, first.note)
            if key not in seen_entries:
                seen_entries.add(key)
                result.entry_points.append(
                    EntryPoint(
                        file=first.file,
                        line=first.line,
                        function=link.sink.function.name,
                        kind="input",
                        detail=f"{first.note}: {first.symbol}",
                    )
                )
    result.entry_points.sort(key=lambda e: (e.file, e.line, e.detail))

    # -- the queue: re-rank SAST candidates, union reachable sinks, cap -----------------
    hits_at: dict[tuple[str, int], list[SinkHit]] = {}
    for hit in result.sinks:
        hits_at.setdefault((hit.file, hit.line), []).append(hit)
    covered: set[tuple[str, int, str]] = set()
    queue: list[tuple[int, Candidate]] = []
    for c in candidates:
        covered.add((c.file, c.line, c.cwe_hint))
        here = hits_at.get((c.file, c.line), [])
        same_cwe = [h for h in here if h.cwe == c.cwe_hint]
        best = min(same_cwe or here, key=lambda h: TIER_ORDER[result.tiers[h.key]], default=None)
        if best is not None:
            tier = result.tiers[best.key]
            enriched = _enrich(c, tier, links_by_key.get(best.key), best)
        elif (c.file, c.line, c.cwe_hint) in result.constant_sinks:
            tier = "constant"
            enriched = _enrich(c, tier, None, None)
        else:
            tier = _tier_for_unmapped(c, by_module, contexts)
            enriched = _enrich(c, tier, None, None)
        if tier != "unmapped":
            result.matched += 1
        queue.append((TIER_ORDER[tier], enriched))
    for hit in result.sinks:
        tier = result.tiers[hit.key]
        if tier not in _UNION_TIERS or hit.key in covered:
            continue
        covered.add(hit.key)
        base = Candidate(
            file=hit.file,
            line=hit.line,
            cwe_hint=hit.cwe,
            rule=f"ono.threatmap.{hit.rule}",
            excerpt=hit.excerpt,
            severity=hit.severity,
        )
        queue.append((TIER_ORDER[tier], _enrich(base, tier, links_by_key.get(hit.key), hit)))
        result.added += 1
    queue.sort(
        key=lambda item: (item[0], *rank(item[1]), item[1].file, item[1].line, item[1].cwe_hint)
    )
    ordered = [c for _tier, c in queue]
    if len(ordered) > max_candidates:
        result.cut = len(ordered) - max_candidates
        ordered = ordered[:max_candidates]
    result.queue = ordered
    result.elapsed_ms = (time.perf_counter() - started) * 1000
    log.info("planning: %s (%.0f ms)", result.summary(), result.elapsed_ms)
    return result


def _resolve(
    hit: SinkHit, callers: _Callers, owners: dict[str, list[Function]]
) -> tuple[str | None, Link | None]:
    best = hit.best
    if best is not None and best.kind in ("source", "entry-param"):
        hops = (*best.hops, Hop(hit.file, hit.line, hit.excerpt[:80], f"sink ({hit.cwe})"))
        return "direct", Link(
            sink=hit, tier="direct", evidence=best, entry=hit.function.nearest_entry(), hops=hops
        )
    if hit.state == "param":
        link = callers.resolve(hit, owners)
        if link is not None:
            return "one-hop", link
        return (None, None) if hit.taint_gated else ("param", None)
    return (None, None) if hit.taint_gated else ("dynamic", None)


def _tier_for_unmapped(
    c: Candidate, by_module: dict[str, Module], contexts: list[FunctionTaint]
) -> str:
    module = by_module.get(c.file)
    if module is None:
        return "unmapped"
    fn = module.function_at(c.line)
    if fn is None:
        return "unmapped"
    if fn.nearest_entry() is not None:
        return "in-entry"
    for ctx in contexts:
        if ctx.fn is fn and any(e.kind == "source" for e in ctx.tainted.values()):
            return "in-entry"
    return "unmapped"


def _enrich(c: Candidate, tier: str, link: Link | None, hit: SinkHit | None) -> Candidate:
    entry = ""
    source = ""
    path: tuple[str, ...] = ()
    if link is not None:
        entry = link.entry_label
        source = (
            f"{link.evidence.origin} at {link.hops[0].file}:{link.hops[0].line}"
            if link.hops
            else link.evidence.origin
        )
        path = tuple(h.render() for h in link.hops)
    elif hit is not None and hit.params:
        p = hit.params[0]
        source = f"{p.origin} (no tainted caller found)"
    elif tier == "in-entry":
        entry = "inside an entry-point function"
    elif tier == "constant":
        source = "the sink argument is a constant (no input dependency found)"
    return Candidate(
        file=c.file,
        line=c.line,
        cwe_hint=c.cwe_hint,
        rule=c.rule,
        excerpt=c.excerpt or (hit.excerpt if hit is not None else ""),
        severity=c.severity,
        reach=tier,
        entry=entry,
        source=source,
        path=path,
    )
