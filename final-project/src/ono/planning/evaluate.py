"""Coverage measurement against a corpus with *planted* vulnerabilities.

A corpus is a directory of source files in which every intended true positive is marked
in-line on the sink line::

    cur.execute(query)                       # VULN: CWE-89
    exec(`ls ${req.query.dir}`)              // VULN: CWE-78 regex-miss

The marker names the CWE and optional free-form tags (``regex-miss`` tags a case the
pre-existing regex fallback is known to miss, so a test can assert it moves miss->catch).
Files without markers are *clean*: every flag on them is a false positive. Within a marked
file, a flag on an unmarked line - or with the wrong CWE - is a false positive too.

:func:`score` turns an engine's candidate list into recall / precision / F1 plus the
concrete caught / missed / false-positive lists, and :func:`compare` reports which planted
cases moved between two engines. ``scripts/coverage_eval.py`` is the CLI around this.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ono.sast import Candidate

__all__ = ["Movement", "Planted", "Score", "compare", "planted_vulns", "render_table", "score"]

MARKER = re.compile(r"(?:#|//)\s*VULN:\s*(CWE-\d+)((?:\s+[\w-]+)*)\s*$")
_EXTENSIONS = (".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")


@dataclass(frozen=True, slots=True)
class Planted:
    file: str
    line: int
    cwe: str
    tags: frozenset[str] = frozenset()

    @property
    def language(self) -> str:
        return _language_of(self.file)

    @property
    def label(self) -> str:
        return f"{self.file}:{self.line} {self.cwe}"


def _language_of(file: str) -> str:
    suffix = Path(file).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in (".ts", ".tsx", ".mts", ".cts"):
        return "typescript"
    return "javascript"


def planted_vulns(root: Path) -> list[Planted]:
    """Every ``VULN:`` marker under ``root`` (sorted by file, line)."""
    found: list[Planted] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _EXTENSIONS:
            continue
        rel = path.relative_to(root).as_posix()
        for lineno, text in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            match = MARKER.search(text)
            if match is None:
                continue
            tags = frozenset(match.group(2).split())
            found.append(Planted(rel, lineno, match.group(1), tags))
    return found


@dataclass(slots=True)
class Score:
    engine: str
    caught: list[Planted] = field(default_factory=list)
    missed: list[Planted] = field(default_factory=list)
    false_positives: list[Candidate] = field(default_factory=list)
    caught_candidates: list[Candidate] = field(default_factory=list)  # parallel to ``caught``

    @property
    def tp(self) -> int:
        return len(self.caught)

    @property
    def fp(self) -> int:
        return len(self.false_positives)

    @property
    def fn(self) -> int:
        return len(self.missed)

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return self.tp / total if total else 0.0

    @property
    def precision(self) -> float:
        total = self.tp + self.fp
        return self.tp / total if total else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def restricted(self, predicate: str) -> Score:
        """The same score over one language (``"python"`` / ``"javascript"`` / ``"typescript"``)."""
        return Score(
            engine=self.engine,
            caught=[p for p in self.caught if p.language == predicate],
            missed=[p for p in self.missed if p.language == predicate],
            false_positives=[c for c in self.false_positives if _language_of(c.file) == predicate],
        )

    def by_reach(self) -> dict[str, tuple[int, int]]:
        """``reach tier -> (tp, fp)`` - how the threat map ranked true vs. false positives."""
        table: dict[str, list[int]] = {}
        for c in self.caught_candidates:
            table.setdefault(c.reach or "(none)", [0, 0])[0] += 1
        for c in self.false_positives:
            table.setdefault(c.reach or "(none)", [0, 0])[1] += 1
        order = {
            "direct": 0,
            "one-hop": 1,
            "param": 2,
            "in-entry": 2,
            "dynamic": 3,
            "unmapped": 4,
            "constant": 5,
        }
        return {
            tier: (v[0], v[1])
            for tier, v in sorted(table.items(), key=lambda kv: order.get(kv[0], 9))
        }

    def by_cwe(self) -> dict[str, tuple[int, int, int]]:
        """``cwe -> (tp, fn, fp)``."""
        table: dict[str, list[int]] = {}
        for p in self.caught:
            table.setdefault(p.cwe, [0, 0, 0])[0] += 1
        for p in self.missed:
            table.setdefault(p.cwe, [0, 0, 0])[1] += 1
        for c in self.false_positives:
            table.setdefault(c.cwe_hint, [0, 0, 0])[2] += 1
        return {cwe: (v[0], v[1], v[2]) for cwe, v in sorted(table.items())}


def score(
    engine: str, planted: Sequence[Planted], candidates: Iterable[Candidate], *, tolerance: int = 0
) -> Score:
    """Match ``candidates`` to ``planted`` by (file, CWE, line within ``tolerance``).

    Each planted case is matched at most once; every unmatched candidate is a false
    positive, every unmatched planted case a false negative.
    """
    result = Score(engine=engine)
    remaining = list(planted)
    for c in sorted(candidates, key=lambda c: (c.file, c.line, c.cwe_hint)):
        match = next(
            (
                p
                for p in remaining
                if p.file == c.file and p.cwe == c.cwe_hint and abs(p.line - c.line) <= tolerance
            ),
            None,
        )
        if match is None:
            result.false_positives.append(c)
        else:
            remaining.remove(match)
            result.caught.append(match)
            result.caught_candidates.append(c)
    result.missed = remaining
    result.caught_candidates.sort(key=lambda c: (c.file, c.line))
    result.caught.sort(key=lambda p: (p.file, p.line))
    result.missed.sort(key=lambda p: (p.file, p.line))
    return result


@dataclass(slots=True)
class Movement:
    """What changed between a *before* and an *after* score over the same corpus."""

    fixed: list[Planted]  # missed before, caught after
    regressed: list[Planted]  # caught before, missed after
    new_false_positives: list[Candidate]
    removed_false_positives: list[Candidate]


def compare(before: Score, after: Score) -> Movement:
    before_caught = set(before.caught)
    after_caught = set(after.caught)
    before_fp = {(c.file, c.line, c.cwe_hint) for c in before.false_positives}
    after_fp = {(c.file, c.line, c.cwe_hint) for c in after.false_positives}
    return Movement(
        fixed=sorted(after_caught - before_caught, key=lambda p: (p.file, p.line)),
        regressed=sorted(before_caught - after_caught, key=lambda p: (p.file, p.line)),
        new_false_positives=[
            c for c in after.false_positives if (c.file, c.line, c.cwe_hint) not in before_fp
        ],
        removed_false_positives=[
            c for c in before.false_positives if (c.file, c.line, c.cwe_hint) not in after_fp
        ],
    )


def render_table(
    scores: Sequence[Score], *, languages: Sequence[str] = ("python", "javascript", "typescript")
) -> str:
    """A Markdown table: one row per engine (overall), then per language."""
    header = "| engine | scope | TP | FP | FN | recall | precision | F1 |"
    rule = "|---|---|---:|---:|---:|---:|---:|---:|"
    rows = [header, rule]
    for s in scores:
        rows.append(_row(s, "all"))
    for lang in languages:
        for s in scores:
            sub = s.restricted(lang)
            if sub.tp + sub.fn + sub.fp:
                rows.append(_row(sub, lang))
    return "\n".join(rows)


def _row(s: Score, scope: str) -> str:
    return (
        f"| {s.engine} | {scope} | {s.tp} | {s.fp} | {s.fn} | "
        f"{s.recall:.0%} | {s.precision:.0%} | {s.f1:.2f} |"
    )
