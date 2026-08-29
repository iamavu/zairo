import json
from pathlib import Path

from zairo.fleet import build_fleet_summary, unique_slug, write_fleet_reports
from zairo.scan import ScanResult


def test_unique_slug_disambiguates_same_basename():
    used = set()
    assert unique_slug("/a/backend", used) == "backend"
    assert unique_slug("/b/backend", used) == "backend-2"
    assert unique_slug("/c/backend", used) == "backend-3"


def test_unique_slug_sanitizes_unsafe_characters():
    slug = unique_slug("/repos/my repo (fork)!", set())
    assert " " not in slug and "(" not in slug and "!" not in slug


def _ok_result(vulnerabilities=None):
    return ScanResult(
        repo_path="/repo",
        graph_data={"nodes": [{"id": "n1", "status": "modified"}, {"id": "n2", "status": "unchanged"}], "edges": []},
        vulnerabilities=vulnerabilities,
        token_usage=None,
        json_path="/out/repo/report.json",
        html_path="/out/repo/report.html",
        sarif_path="/out/repo/report.sarif" if vulnerabilities is not None else None,
    )


def test_build_fleet_summary_counts_severities_and_totals():
    results = [
        {"repo": "/a", "slug": "a", "status": "ok", "result": _ok_result({
            "n1": [{"severity": "critical"}, {"severity": "low"}],
        })},
        {"repo": "/b", "slug": "b", "status": "ok", "result": _ok_result({
            "n1": [{"severity": "critical"}],
        })},
        {"repo": "/c", "slug": "c", "status": "error", "error": "boom"},
    ]

    summary = build_fleet_summary(results)

    assert summary["totals"] == {"low": 1, "medium": 0, "high": 0, "critical": 2}
    by_slug = {r["slug"]: r for r in summary["repos"]}
    assert by_slug["a"]["num_findings"] == 2
    assert by_slug["a"]["worst_severity"] == "critical"
    assert by_slug["c"]["status"] == "error"
    assert by_slug["c"]["error"] == "boom"


def test_write_fleet_reports_escapes_untrusted_text_in_html(tmp_path: Path):
    """repo paths and error messages are attacker-influenceable (a repo path
    passed on the CLI, an exception message that can echo file/command
    content) -- fleet.html must not let them inject markup."""
    results = [{
        "repo": "<script>alert(1)</script>",
        "slug": "evil",
        "status": "error",
        "error": "<img src=x onerror=alert(2)>",
    }]

    reports = write_fleet_reports(results, str(tmp_path))

    html = Path(reports["html"]).read_text()
    assert "<script>alert(1)" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(2)&gt;" in html


def test_write_fleet_reports_sarif_omitted_when_no_repo_ran_llm(tmp_path: Path):
    results = [{"repo": "/a", "slug": "a", "status": "ok", "result": _ok_result(vulnerabilities=None)}]
    reports = write_fleet_reports(results, str(tmp_path))
    assert reports["sarif"] is None
    assert not (tmp_path / "fleet.sarif").exists()


def test_write_fleet_reports_sarif_merges_one_run_per_repo(tmp_path: Path):
    results = [
        {"repo": "/a", "slug": "a", "status": "ok", "result": _ok_result({"n1": [{"title": "X", "severity": "high"}]})},
        {"repo": "/b", "slug": "b", "status": "ok", "result": _ok_result({"n1": [{"title": "Y", "severity": "low"}]})},
    ]
    reports = write_fleet_reports(results, str(tmp_path))
    with open(reports["sarif"]) as f:
        sarif = json.load(f)
    assert len(sarif["runs"]) == 2
