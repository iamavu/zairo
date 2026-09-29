import json
from pathlib import Path

from zairo.rollup import build_rollup_summary, unique_slug, write_rollup_reports
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


def test_build_rollup_summary_counts_severities_and_totals():
    results = [
        {"repo": "/a", "slug": "a", "status": "ok", "result": _ok_result({
            "n1": [{"severity": "critical"}, {"severity": "low"}],
        })},
        {"repo": "/b", "slug": "b", "status": "ok", "result": _ok_result({
            "n1": [{"severity": "critical"}],
        })},
        {"repo": "/c", "slug": "c", "status": "error", "error": "boom"},
    ]

    summary = build_rollup_summary(results)

    assert summary["totals"] == {"low": 1, "medium": 0, "high": 0, "critical": 2}
    by_slug = {r["slug"]: r for r in summary["repos"]}
    assert by_slug["a"]["num_findings"] == 2
    assert by_slug["a"]["worst_severity"] == "critical"
    assert by_slug["c"]["status"] == "error"
    assert by_slug["c"]["error"] == "boom"


def test_write_rollup_reports_escapes_untrusted_text_in_html(tmp_path: Path):
    """repo paths and error messages are attacker-influenceable (a repo path
    passed on the CLI, an exception message that can echo file/command
    content) -- rollup.html must not let them inject markup."""
    results = [{
        "repo": "<script>alert(1)</script>",
        "slug": "evil",
        "status": "error",
        "error": "<img src=x onerror=alert(2)>",
    }]

    reports = write_rollup_reports(results, str(tmp_path))

    html = Path(reports["html"]).read_text()
    assert "<script>alert(1)" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(2)&gt;" in html


def test_write_rollup_reports_sarif_omitted_when_no_repo_ran_llm(tmp_path: Path):
    results = [{"repo": "/a", "slug": "a", "status": "ok", "result": _ok_result(vulnerabilities=None)}]
    reports = write_rollup_reports(results, str(tmp_path))
    assert reports["sarif"] is None
    assert not (tmp_path / "rollup.sarif").exists()


def test_write_rollup_reports_sarif_merges_one_run_per_repo(tmp_path: Path):
    results = [
        {"repo": "/a", "slug": "a", "status": "ok", "result": _ok_result({"n1": [{"title": "X", "severity": "high"}]})},
        {"repo": "/b", "slug": "b", "status": "ok", "result": _ok_result({"n1": [{"title": "Y", "severity": "low"}]})},
    ]
    reports = write_rollup_reports(results, str(tmp_path))
    with open(reports["sarif"]) as f:
        sarif = json.load(f)
    assert len(sarif["runs"]) == 2


def test_rollup_sarif_locations_are_rooted_under_each_repo(tmp_path: Path):
    """Repos share relative paths (every one has its own src/app.py), so
    rollup.sarif puts each under its repo's slug -- findings, and the
    notifications of nodes the scan couldn't assess."""
    repo = tmp_path / "repo"
    scan_result = ScanResult(
        repo_path=str(repo),
        graph_data={
            "nodes": [
                {"id": "n1", "name": "f", "status": "modified", "file": "src/app.py", "start_line": 3},
                {"id": "n2", "name": "g", "status": "modified", "file": "src/util.py", "start_line": 7},
            ],
            "edges": [],
        },
        vulnerabilities={"n1": [{"title": "X", "severity": "high"}]},
        token_usage={"failed_nodes": {"n2": "boom"}},
        json_path="", html_path="", sarif_path="",
    )
    results = [{"repo": str(repo), "slug": "repo", "status": "ok", "result": scan_result}]

    reports = write_rollup_reports(results, str(tmp_path / "out"))
    with open(reports["sarif"]) as f:
        run = json.load(f)["runs"][0]

    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "repo/src/app.py"
    assert location["region"]["startLine"] == 3
    [notification] = run["invocations"][0]["toolExecutionNotifications"]
    assert notification["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "repo/src/util.py"


def test_incomplete_repo_scan_is_flagged_in_rollup(tmp_path: Path):
    """A repo whose scan couldn't assess some nodes must not show up as a
    plain "ok" in the rollup."""
    incomplete = _ok_result(vulnerabilities={})
    incomplete.token_usage = {"failed_nodes": {"n1": "boom"}}
    failed_step = _ok_result(vulnerabilities=None)
    failed_step.problems = [{"level": "error", "message": "Couldn't parse the files as they were before the change"}]
    unparsed = _ok_result(vulnerabilities={})
    unparsed.changed_files = [{"path": "app.yaml", "outcome": "not_parsed"}]
    results = [
        {"repo": "/a", "slug": "a", "status": "ok", "result": incomplete},
        {"repo": "/b", "slug": "b", "status": "ok", "result": unparsed},
        {"repo": "/c", "slug": "c", "status": "ok", "result": _ok_result(vulnerabilities=None)},
        {"repo": "/d", "slug": "d", "status": "ok", "result": failed_step},
    ]

    reports = write_rollup_reports(results, str(tmp_path))

    with open(reports["json"]) as f:
        by_slug = {r["slug"]: r for r in json.load(f)["repos"]}
    assert (by_slug["a"]["complete"], by_slug["a"]["num_failed_symbols"]) == (False, 1)
    assert (by_slug["b"]["complete"], by_slug["b"]["not_reviewed_files"]) == (True, ["app.yaml"])
    assert by_slug["c"]["complete"] is True
    assert by_slug["d"]["complete"] is False
    html = Path(reports["html"]).read_text()
    assert html.count(">incomplete</span>") == 2
