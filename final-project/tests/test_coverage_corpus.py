"""Measured SAST coverage on the planted corpus (``tests/corpus``): the numbers quoted in the PR.

These tests pin the before/after recall and precision so coverage cannot regress silently,
and verify the *movement*: every case tagged ``regex-miss`` is really missed by the
pre-existing regex fallback and caught once the threat map runs; every ``known-gap`` case is
really still missed by the threat-mapping engine (an honest, documented limit).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from ono import sast
from ono.planning import threat_map
from ono.planning.evaluate import Planted, Score, compare, planted_vulns, score

CORPUS = Path(__file__).parent / "corpus"
SCRIPT = Path(__file__).parent.parent / "scripts" / "coverage_eval.py"
BIG = 10_000


@pytest.fixture(scope="module")
def planted() -> list[Planted]:
    return planted_vulns(CORPUS)


@pytest.fixture(scope="module")
def regex(planted: list[Planted]) -> Score:
    return score("regex", planted, sast.dedupe(sast.regex_scan(CORPUS)))


@pytest.fixture(scope="module")
def engine_only(planted: list[Planted]) -> Score:
    return score("threat-map", planted, threat_map(CORPUS, [], max_candidates=BIG).queue)


@pytest.fixture(scope="module")
def combined(planted: list[Planted]) -> Score:
    shortlist = sast.dedupe(sast.regex_scan(CORPUS))
    return score(
        "regex+threat-map", planted, threat_map(CORPUS, shortlist, max_candidates=BIG).queue
    )


def test_corpus_shape(planted: list[Planted]) -> None:
    assert len(planted) == 60
    assert {p.cwe for p in planted} == {
        "CWE-22",
        "CWE-502",
        "CWE-78",
        "CWE-79",
        "CWE-89",
        "CWE-918",
        "CWE-95",
    }
    assert {p.language for p in planted} == {"python", "javascript", "typescript"}
    assert not [
        p
        for p in planted
        if p.file.startswith(("python/clean_", "javascript/clean_", "typescript/clean_"))
    ]
    assert all((CORPUS / p.file).exists() for p in planted)


def test_before_the_regex_fallback_is_python_only_and_partial(regex: Score) -> None:
    assert (regex.tp, regex.fp, regex.fn) == (21, 6, 39)
    assert regex.recall == pytest.approx(0.35) and regex.precision == pytest.approx(21 / 27)
    assert regex.restricted("javascript").tp == 0 and regex.restricted("typescript").tp == 0


def test_after_the_threat_map_catches_reachable_sinks_with_no_false_positives(
    engine_only: Score,
) -> None:
    assert (engine_only.tp, engine_only.fp, engine_only.fn) == (56, 0, 4)
    assert engine_only.recall >= 0.93 and engine_only.precision == 1.0
    for language in ("javascript", "typescript"):
        sub = engine_only.restricted(language)
        assert sub.recall == 1.0 and sub.fp == 0, language


def test_shipped_pipeline_regex_plus_threat_map(combined: Score, regex: Score) -> None:
    assert (combined.tp, combined.fp, combined.fn) == (59, 6, 1)
    assert combined.recall >= 0.98 and combined.precision >= 0.90
    assert combined.recall > regex.recall and combined.precision > regex.precision
    movement = compare(regex, combined)
    assert (
        len(movement.fixed) == 38
        and movement.regressed == []
        and movement.new_false_positives == []
    )


def test_every_regex_miss_tag_moves_from_miss_to_catch(
    regex: Score, combined: Score, planted: list[Planted]
) -> None:
    tagged = [p for p in planted if "regex-miss" in p.tags]
    assert len(tagged) == 38
    assert all(p in regex.missed for p in tagged), "a regex-miss tag is wrong: the regex catches it"
    assert all(p in combined.caught for p in tagged), (
        "a regex-miss case is still missed after the threat map"
    )


def test_known_gaps_are_really_still_missed_by_the_engine(
    engine_only: Score, planted: list[Planted]
) -> None:
    gaps = sorted(p.label for p in planted if "known-gap" in p.tags)
    assert gaps == [
        "python/django_views.py:56 CWE-78",  # taint through an object attribute across methods
        "python/fastapi_app.py:29 CWE-918",  # ``session.get(url)`` - generic ``.get`` is not a sink
        "python/flask_app.py:147 CWE-78",  # taint through module-level mutable state
    ]
    assert sorted(p.label for p in engine_only.missed if "known-gap" in p.tags) == gaps


def test_reachability_tiers_separate_true_from_false_positives(combined: Score) -> None:
    """Everything the map calls reachable is a planted sink; inherited regex FPs sort last."""
    reach = combined.by_reach()
    assert reach["direct"] == (48, 0) and reach["one-hop"] == (5, 0) and reach["param"] == (3, 0)
    assert reach["dynamic"][1] + reach["unmapped"][1] + reach["constant"][1] == combined.fp
    labels = {f"{c.file}:{c.line}" for c in combined.false_positives}
    assert labels == {
        "python/clean_flask.py:34",  # int() coerced value in an f-string (regex sees the f-string)
        "python/clean_flask.py:48",  # shlex.quote()d argument (regex sees os.popen)
        "python/clean_flask.py:86",  # constant command with shell=True
        "python/clean_flask.py:87",  # constant command in os.system
        "python/clean_utils.py:15",  # pickle.loads of a local cache file
        "python/clean_utils.py:34",  # ``def eval(self):`` - a method definition, not a call
    }


def test_coverage_script_runs_and_writes_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    spec = importlib.util.spec_from_file_location("coverage_eval", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = tmp_path / "scores.json"
    assert module.main(["--json", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "| regex+threat-map | all | 59 | 6 | 1 | 98% | 91% | 0.94 |" in printed
    assert "Fixed (missed before, caught after): 38" in printed
    data = json.loads(out.read_text())
    assert data["planted"] == 60 and data["engines"]["threat-map"]["fp"] == 0
