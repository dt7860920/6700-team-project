#!/usr/bin/env python
"""Measure static coverage on the planted corpus: recall / precision before vs. after.

Engines (``--engines`` to pick a subset):

* ``regex``             - the pre-existing Python-only regex fallback (:func:`ono.sast.regex_scan`)
* ``threat-map``        - the AST / tree-sitter threat-mapping engine on its own
* ``regex+threat-map``  - what the pipeline ships offline: regex shortlist, then the threat
                          map re-ranks it and unions in the sinks it found reachable
* ``semgrep`` / ``semgrep+threat-map`` - with ``--semgrep``: the real Semgrep engine (needs the
                          binary and network access to the registry packs)

Usage::

    uv run scripts/coverage_eval.py                # Markdown tables + movement report
    uv run scripts/coverage_eval.py --json out.json
    uv run scripts/coverage_eval.py --corpus path/to/dir --semgrep --tolerance 2
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ono import sast
from ono.planning import threat_map
from ono.planning.evaluate import (
    Movement,
    Planted,
    Score,
    compare,
    planted_vulns,
    render_table,
    score,
)

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "tests" / "corpus"
_BIG = 10_000


def run_engine(name: str, root: Path, *, languages: Sequence[str]) -> list[sast.Candidate]:
    if name == "regex":
        return sast.dedupe(sast.regex_scan(root))
    if name == "threat-map":
        return threat_map(root, [], max_candidates=_BIG).queue
    if name == "regex+threat-map":
        return threat_map(root, sast.dedupe(sast.regex_scan(root)), max_candidates=_BIG).queue
    if name in ("semgrep", "semgrep+threat-map"):
        result = sast.shortlist(
            root, rulesets=["p/owasp-top-ten"], languages=languages, max_candidates=_BIG
        )
        if result.engine != "semgrep":
            raise RuntimeError(f"semgrep did not run: {result.note}")
        if name == "semgrep":
            return result.candidates
        return threat_map(root, result.candidates, max_candidates=_BIG).queue
    raise ValueError(f"unknown engine {name!r}")


def evaluate(
    root: Path, engines: Sequence[str], *, tolerance: int
) -> tuple[list[Planted], list[Score]]:
    planted = planted_vulns(root)
    scores = [
        score(
            name,
            planted,
            run_engine(name, root, languages=("python", "javascript", "typescript")),
            tolerance=tolerance,
        )
        for name in engines
    ]
    return planted, scores


def render_movement(before: Score, after: Score, movement: Movement) -> str:
    lines = [f"## {before.engine} -> {after.engine}", ""]
    lines.append(f"Fixed (missed before, caught after): {len(movement.fixed)}")
    lines.extend(f"  + {p.label}  [{' '.join(sorted(p.tags))}]" for p in movement.fixed)
    lines.append(f"Regressed (caught before, missed after): {len(movement.regressed)}")
    lines.extend(f"  - {p.label}" for p in movement.regressed)
    lines.append(f"False positives removed: {len(movement.removed_false_positives)}")
    lines.extend(
        f"  - {c.file}:{c.line} {c.cwe_hint} ({c.rule})" for c in movement.removed_false_positives
    )
    lines.append(f"False positives added: {len(movement.new_false_positives)}")
    lines.extend(
        f"  + {c.file}:{c.line} {c.cwe_hint} ({c.rule})" for c in movement.new_false_positives
    )
    return "\n".join(lines)


def render_details(s: Score) -> str:
    lines = [f"## {s.engine}: per CWE (tp / fn / fp)", ""]
    for cwe, (tp, fn, fp) in s.by_cwe().items():
        lines.append(f"  {cwe}: {tp} / {fn} / {fp}")
    reach = s.by_reach()
    if any(tier != "(none)" for tier in reach):
        lines.append("")
        lines.append("  by reach tier (tp / fp) - the queue is sorted in this order:")
        lines.extend(f"    {tier}: {tp} / {fp}" for tier, (tp, fp) in reach.items())
    if s.missed:
        lines.append("")
        lines.append("  still missed:")
        lines.extend(f"    {p.label}  [{' '.join(sorted(p.tags))}]" for p in s.missed)
    if s.false_positives:
        lines.append("")
        lines.append("  false positives:")
        lines.extend(f"    {c.file}:{c.line} {c.cwe_hint} ({c.rule})" for c in s.false_positives)
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--engines", nargs="*", default=["regex", "threat-map", "regex+threat-map"])
    parser.add_argument(
        "--semgrep", action="store_true", help="also run semgrep and semgrep+threat-map"
    )
    parser.add_argument(
        "--tolerance", type=int, default=0, help="line tolerance when matching planted sinks"
    )
    parser.add_argument("--json", type=Path, help="write the scores as JSON to this file")
    args = parser.parse_args(argv)

    engines = list(args.engines)
    if args.semgrep:
        engines += ["semgrep", "semgrep+threat-map"]
    planted, scores = evaluate(args.corpus, engines, tolerance=args.tolerance)

    print(f"corpus: {args.corpus} - {len(planted)} planted vulnerabilities")
    print()
    print(render_table(scores))
    print()
    by_name = {s.engine: s for s in scores}
    pairs = [("regex", "regex+threat-map"), ("semgrep", "semgrep+threat-map")]
    for before, after in pairs:
        if before in by_name and after in by_name:
            print(
                render_movement(
                    by_name[before], by_name[after], compare(by_name[before], by_name[after])
                )
            )
            print()
    for s in scores:
        print(render_details(s))
        print()

    if args.json:
        payload = {
            "corpus": str(args.corpus),
            "planted": len(planted),
            "engines": {
                s.engine: {
                    "tp": s.tp,
                    "fp": s.fp,
                    "fn": s.fn,
                    "recall": round(s.recall, 4),
                    "precision": round(s.precision, 4),
                    "f1": round(s.f1, 4),
                    "missed": [p.label for p in s.missed],
                    "false_positives": [
                        f"{c.file}:{c.line} {c.cwe_hint}" for c in s.false_positives
                    ],
                }
                for s in scores
            },
        }
        args.json.write_text(json.dumps(payload, indent=2))
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
