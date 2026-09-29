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


def _finding(symbol, severity="high", introduced=True, cwe="CWE-89"):
    return {
        "symbol": symbol, "title": "t", "severity": severity, "cwe": cwe, "line": 3, "introduced": introduced,
        "gates": introduced is True and severity in ("high", "critical"),
    }


@pytest.mark.parametrize("run, verdict", [
    (Run("v", complete=True, findings=[_finding("handler")]), "caught"),
    # Another symbol failing doesn't undo a catch -- nor a miss on the one that matters.
    (Run("v", complete=False, findings=[_finding("handler")], failed={"helper": "boom"}), "caught"),
    (Run("v", complete=False, failed={"helper": "boom"}), "missed"),
    (Run("v", complete=True, findings=[_finding("handler", severity="medium")]), "below the gate"),
    (Run("v", complete=True, findings=[_finding("handler", introduced=False)]), "missed"),
    (Run("v", complete=True, findings=[_finding("helper")]), "missed"),
    (Run("v", complete=False, failed={"handler": "empty response"}), None),
    (Run("v", complete=False, error="git failed"), None),
])
def test_a_run_on_a_vulnerable_case_says(run, verdict):
    assert run.verdict(_case("v", True)) == verdict


@pytest.mark.parametrize("run, verdict", [
    (Run("c", complete=True), "passed"),
    (Run("c", complete=True, findings=[_finding("handler", severity="low")]), "passed"),
    # A PR blocked for nothing, whatever else failed.
    (Run("c", complete=False, findings=[_finding("handler")], failed={"helper": "boom"}), "flagged"),
    (Run("c", complete=False, failed={"helper": "boom"}), None),
])
def test_a_run_on_a_clean_case_says(run, verdict):
    assert run.verdict(_case("c", False)) == verdict


def test_scores():
    cases = [_case("sqli", True), _case("clean", False)]
    runs = [
        # Caught -- twice on the symbol, which is fine, and again under its module, which isn't.
        Run("sqli", complete=True, findings=[_finding("handler"), _finding("handler"), _finding("app.py", cwe="CWE-20")], tokens=10),
        Run("sqli", complete=True, findings=[_finding("helper")], tokens=10),  # flagged, but somewhere else
        Run("sqli", complete=True, findings=[_finding("handler", severity="medium")]),
        Run("sqli", complete=False, failed={"handler": "empty response"}),
        Run("clean", complete=True),
        Run("clean", complete=False, findings=[_finding("handler")], failed={"helper": "empty response"}),
    ]

    scores = summarize(cases, runs)

    assert scores["recall"] == 1 / 3
    assert scores["found"] == 2 / 3
    assert scores["false_alarms"] == 1 / 2
    assert scores["precision"] == 1 / 3
    assert scores["stable"] == 0
    assert scores["cwe_matched"] == 1
    assert (scores["runs"], scores["incomplete_runs"], scores["unscored_runs"], scores["tokens"]) == (6, 2, 1, 20)
    assert scores["failures"] == {"empty response": 2}
    assert (scores["elsewhere"], scores["caught_runs"]) == (1, 1)
    assert scores["cases"]["sqli"] == {
        "vulnerable": True, "runs": 4, "scored": 3, "hits": 1, "below_gate": 1, "elsewhere": 1, "stable": False,
    }


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
            complete=False, token_usage={"total_tokens": 1234},
            failed_nodes={"app": "empty response"}, problems=[{"level": "warning", "message": "no entry points"}],
        )

    run = scan_case(case, scan, "high", str(tmp_path), model="m")

    assert run.gating() == [{
        "symbol": "search_users", "title": "SQLi", "severity": "critical", "cwe": "CWE-89", "line": 19,
        "introduced": True, "gates": True,
    }]
    assert [(f["title"], f["introduced"], f["gates"]) for f in run.findings] == [
        ("SQLi", True, True), ("Old", False, False), ("Minor", True, False),
    ]
    assert (run.failed, run.problems) == ({"app": "empty response"}, [])
    assert (run.tokens, run.verdict(case), run.cwe_matched(case)) == (1234, "caught", True)
    [options] = calls
    assert (options["from_ref"], options["to_ref"], options["cache_path"], options["notes_path"]) == ("HEAD~1", "HEAD", None, None)
