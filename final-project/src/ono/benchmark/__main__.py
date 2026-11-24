"""CLI: score a scan (or a whole sweep) against the curated ground truth.

    python -m ono.benchmark --results results.json [--ground-truth gt.yaml] [--verbose]

``results.json`` maps each repo key (matching a ``key`` in the ground truth) to the list of
finding objects that scan produced - i.e. ``{ "pygoat": [ {cwe, file, rung, verified}, ... ] }``,
the shape of ``GET /scans/{id}/findings``. Prints a per-repo scorecard and the totals.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ono.benchmark.model import AggregateScore, Scorecard
from ono.benchmark.score import load_ground_truth, score_sweep


def _pct(numerator: int, denominator: int) -> str:
    return f"{(100 * numerator / denominator):.0f}%" if denominator else "n/a"


def _render_card(card: Scorecard, *, verbose: bool) -> str:
    if card.note and not card.expected_total:
        return f"  {card.key:16} {card.findings_total:3} findings  ({card.note})"
    head = (
        f"  {card.key:16} detect {card.detected}/{card.expected_total} "
        f"({_pct(card.detected, card.expected_total)})  "
        f"verify {card.verified}/{card.expected_total} "
        f"({_pct(card.verified, card.expected_total)})  "
        f"[{card.findings_matched}/{card.findings_total} findings matched]"
    )
    if not verbose:
        return head
    lines = [head]
    for outcome in card.outcomes:
        mark = "PROVEN" if outcome.verified else ("found " if outcome.detected else "MISSED")
        lines.append(f"        {mark:7} {outcome.cwe:10} {outcome.location}  - {outcome.note}")
    return "\n".join(lines)


def render(score: AggregateScore, *, verbose: bool) -> str:
    lines = ["ONO benchmark scorecard", "=" * 60]
    for card in score.cards:
        lines.append(_render_card(card, verbose=verbose))
    lines.append("-" * 60)
    lines.append(
        f"  TOTAL ({score.repos_scored} repos w/ ground truth): "
        f"detection recall {score.detected}/{score.expected_total} "
        f"({_pct(score.detected, score.expected_total)}), "
        f"verification recall {score.verified}/{score.expected_total} "
        f"({_pct(score.verified, score.expected_total)})"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ono.benchmark", description=__doc__)
    parser.add_argument("--results", required=True, help="JSON: {repo_key: [findings...]}")
    parser.add_argument("--ground-truth", default=None, help="override the shipped ground truth")
    parser.add_argument("--verbose", action="store_true", help="list every expected vuln")
    parser.add_argument("--json", action="store_true", help="emit the scorecard as JSON")
    args = parser.parse_args(argv)

    results: dict[str, list[dict[str, Any]]] = json.loads(
        Path(args.results).read_text(encoding="utf-8")
    )
    score = score_sweep(results, load_ground_truth(args.ground_truth))
    output = score.model_dump_json(indent=2) if args.json else render(score, verbose=args.verbose)
    print(output)  # noqa: T201 - this is a CLI; stdout is the product
    return 0


if __name__ == "__main__":
    sys.exit(main())
