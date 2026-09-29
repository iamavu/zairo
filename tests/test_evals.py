"""The labelled changes in evals/ and the harness that scores zairo on
them -- everything short of asking a model."""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from zairo._util import normalize_cwe
from zairo.analyzer import analyze_impact

sys.path.insert(0, str(Path(__file__).parents[1] / "evals"))

from zairo_eval import Case, Run, build_repo, load_cases, scan_case, summarize  # noqa: E402

CASES = load_cases()


def test_there_are_vulnerable_and_clean_cases():
    assert sum(c.vulnerable for c in CASES) >= 5
    assert sum(not c.vulnerable for c in CASES) >= 5


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_a_case_is_a_change_zairo_sees_where_its_label_says(case: Case, tmp_path: Path):
    """Each case builds into a two-commit repo, the change touches symbols
    zairo can parse, and a vulnerable case's symbol is one of them -- or
    no scan could ever be scored as catching it."""
    assert case.description and case.before.is_dir() and case.after.is_dir()
    if case.vulnerable:
        assert case.symbol and normalize_cwe(case.cwe) == case.cwe
    else:
        assert case.symbol is None and case.cwe is None
    repo = build_repo(case, str(tmp_path))

    graph, _, coverage = analyze_impact(repo, depth=0, from_ref="HEAD~1", to_ref="HEAD")

    changed = {n["name"] for n in graph["nodes"] if n["status"] in ("modified", "added")}
    assert changed
    if case.vulnerable:
        assert case.symbol in changed
    assert all(f["outcome"] == "analyzed" for f in coverage["changed_files"])
    assert coverage["problems"] == []


def _case(case_id, vulnerable):
    return Case(
        id=case_id, description="", vulnerable=vulnerable, before=Path(), after=Path(),
        symbol="handler" if vulnerable else None, cwe="CWE-89" if vulnerable else None,
    )


def _finding(symbol, cwe="CWE-89"):
    return {"symbol": symbol, "title": "t", "severity": "high", "cwe": cwe, "line": 3}


def test_scores():
    cases = [_case("sqli", True), _case("clean", False)]
    runs = [
        Run("sqli", complete=True, gating=[_finding("handler")], tokens=10),
        Run("sqli", complete=True, gating=[_finding("helper")], tokens=10),  # flagged, but somewhere else
        Run("sqli", complete=False, error="rate limited"),
        Run("clean", complete=True),
        Run("clean", complete=True, gating=[_finding("handler")]),
    ]

    scores = summarize(cases, runs)

    assert scores["recall"] == 1 / 2
    assert scores["false_alarms"] == 1 / 2
    assert scores["precision"] == 1 / 3
    assert scores["stable"] == 0
    assert scores["cwe_matched"] == 1
    assert (scores["runs"], scores["incomplete_runs"], scores["tokens"]) == (5, 1, 20)
    assert scores["cases"]["sqli"] == {"vulnerable": True, "runs": 2, "incomplete": 1, "hits": 1, "stable": False}


def test_a_scan_counts_what_would_fail_the_gate(tmp_path: Path):
    """Only findings the change introduced, at or above the threshold."""
    case = next(c for c in CASES if c.id == "py-sqli-search")
    calls = []

    def scan(repo, output_dir, **options):
        calls.append(options)
        return SimpleNamespace(
            graph_data={"nodes": [{"id": "app:search_users", "name": "search_users"}]},
            vulnerabilities={"app:search_users": [
                {"title": "SQLi", "severity": "critical", "cwe": "89", "introduced_by_change": True, "line": 19},
                {"title": "Old", "severity": "critical", "introduced_by_change": False},
                {"title": "Minor", "severity": "low", "introduced_by_change": True},
            ]},
            complete=True, token_usage={"total_tokens": 1234},
        )

    run = scan_case(case, scan, "high", str(tmp_path), model="m")

    assert run.gating == [{"symbol": "search_users", "title": "SQLi", "severity": "critical", "cwe": "CWE-89", "line": 19}]
    assert (run.findings, run.tokens, run.on_target(case), run.cwe_matched(case)) == (3, 1234, True, True)
    [options] = calls
    assert (options["from_ref"], options["to_ref"], options["cache_path"], options["notes_path"]) == ("HEAD~1", "HEAD", None, None)
