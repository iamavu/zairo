import json
import re
from pathlib import Path

import pytest

from zairo.reporter import generate_reports


def _graph_data(file_path: str):
    return {
        "nodes": [
            {"id": "n1", "name": "vulnerable_exec", "kind": "function", "file": file_path,
             "start_line": 2, "end_line": 3, "complexity": 1, "status": "modified"},
        ],
        "edges": [],
    }


def test_generate_reports_writes_json_and_html(tmp_path: Path):
    graph_data = _graph_data("x.py")
    vulnerabilities = {"n1": [{"title": "Command Injection", "description": "...", "impact": "high", "severity": "critical"}]}

    output_dir = tmp_path / "out"
    json_path, html_path, sarif_path = generate_reports(graph_data, str(output_dir), vulnerabilities)

    assert Path(json_path).exists()
    assert Path(html_path).exists()

    with open(json_path) as f:
        written = json.load(f)
    assert written["symbols"][0]["vulnerabilities"] == vulnerabilities["n1"]

    html = Path(html_path).read_text()
    assert "Zairo Impact Analysis" in html


def test_reports_name_symbols_and_connections(tmp_path: Path):
    """The same words report.html and the CLI use, not the graph's own
    nodes and edges."""
    graph_data = _graph_data("x.py")
    graph_data["edges"] = [{"source": "n1", "target": "n1", "kind": "calls", "confidence": "certain", "lines": [3]}]
    findings = {"n1": [{"title": "X", "description": "d", "severity": "high"}]}

    json_path, _, sarif_path = generate_reports(graph_data, str(tmp_path / "out"), findings)

    with open(json_path) as f:
        written = json.load(f)
    assert set(written) == {"commits", "complete", "problems", "changed_files", "symbols", "connections"}
    assert written["connections"] == graph_data["edges"]
    with open(sarif_path) as f:
        assert json.load(f)["runs"][0]["results"][0]["properties"]["symbol"] == "vulnerable_exec"


def test_html_escapes_finding_and_node_text_before_rendering(tmp_path: Path):
    """report.html builds the node-detail panel by setting innerHTML from
    finding/node fields that ultimately come from scanned source code and
    LLM output -- neither is trusted. Every such interpolation must go
    through escapeHtml(); this guards against one being reintroduced raw."""
    graph_data = _graph_data("x.py")
    vulnerabilities = {"n1": [{"title": "X", "description": "d", "impact": "i", "severity": "high"}]}
    output_dir = tmp_path / "out"

    _, html_path, _ = generate_reports(graph_data, str(output_dir), vulnerabilities)
    html = Path(html_path).read_text()

    assert "function escapeHtml(" in html
    for field in ("v.title", "v.impact", "v.description", "v.trigger", "v.line", "d.name", "d.kind", "d.status", "d.file"):
        assert f"escapeHtml({field})" in html, f"{field} is interpolated without escapeHtml()"


def test_sarif_written_when_llm_scan_ran(tmp_path: Path):
    graph_data = _graph_data("x.py")
    vulnerabilities = {"n1": [{"title": "Command Injection", "description": "...", "impact": "high", "severity": "critical"}]}

    output_dir = tmp_path / "out"
    _, _, sarif_path = generate_reports(graph_data, str(output_dir), vulnerabilities)

    assert sarif_path is not None
    assert Path(sarif_path).exists()
    with open(sarif_path) as f:
        sarif = json.load(f)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "command-injection"
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "x.py"


def test_sarif_written_even_with_zero_findings(tmp_path: Path):
    """An empty-but-present SARIF file is what lets GitHub mark previously
    reported alerts as resolved on a clean scan."""
    graph_data = _graph_data("x.py")
    output_dir = tmp_path / "out"
    _, _, sarif_path = generate_reports(graph_data, str(output_dir), {})

    assert sarif_path is not None
    with open(sarif_path) as f:
        sarif = json.load(f)
    assert sarif["runs"][0]["results"] == []


def test_incomplete_scan_is_recorded_in_report_json_and_sarif(tmp_path: Path):
    graph_data = _graph_data("x.py")
    output_dir = tmp_path / "out"
    json_path, _, sarif_path = generate_reports(
        graph_data, str(output_dir), {}, failed_nodes={"n1": "boom"},
    )

    with open(json_path) as f:
        written = json.load(f)
    assert written["complete"] is False
    assert written["symbols"][0]["scan_error"] == "boom"
    with open(sarif_path) as f:
        assert json.load(f)["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_complete_scan_is_recorded_in_report_json(tmp_path: Path):
    graph_data = _graph_data("x.py")
    json_path, _, _ = generate_reports(graph_data, str(tmp_path / "out"), {})

    with open(json_path) as f:
        written = json.load(f)
    assert written["complete"] is True
    assert "scan_error" not in written["symbols"][0]


def test_coverage_is_in_every_report(tmp_path: Path):
    """What wasn't reviewed, and what failed, reach report.json and
    report.sarif -- and an error-level problem makes the run incomplete."""
    graph_data = _graph_data("x.py")
    changed_files = [{"path": "x.py", "outcome": "analyzed"}, {"path": "deploy/app.yaml", "outcome": "not_parsed"}]
    problems = [{"level": "error", "message": "Couldn't parse the files as they were before the change (boom)"}]

    json_path, html_path, sarif_path = generate_reports(
        graph_data, str(tmp_path / "out"), {}, changed_files=changed_files, problems=problems,
    )

    with open(json_path) as f:
        written = json.load(f)
    assert (written["complete"], written["changed_files"], written["problems"]) == (False, changed_files, problems)
    with open(sarif_path) as f:
        invocation = json.load(f)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    levels = [(n["level"], n["message"]["text"]) for n in invocation["toolExecutionNotifications"]]
    assert levels == [
        ("error", problems[0]["message"]),
        ("note", "Not reviewed: deploy/app.yaml (zairo doesn't parse this kind of file)."),
    ]
    assert "graphData.changed_files" in Path(html_path).read_text(encoding="utf-8")


def test_a_graph_only_run_is_complete_unless_the_analysis_failed(tmp_path: Path):
    graph_data = _graph_data("x.py")
    json_path, _, _ = generate_reports(graph_data, str(tmp_path / "out"), None)

    with open(json_path) as f:
        assert json.load(f)["complete"] is True


def test_no_sarif_when_llm_scan_did_not_run(tmp_path: Path):
    graph_data = _graph_data("x.py")
    output_dir = tmp_path / "out"
    _, _, sarif_path = generate_reports(graph_data, str(output_dir), None)

    assert sarif_path is None
    assert not (output_dir / "report.sarif").exists()


@pytest.mark.parametrize("findings, assessed, scanned_ids", [
    (None, None, []),      # --graph-only: no scan at all
    ({}, [], []),          # scan ran, but this symbol was never sent (skipped / context)
    ({}, ["n1"], ["n1"]),  # scanned clean: no findings, yet assessed
])
def test_html_distinguishes_unscanned_symbols_from_clean_scans(tmp_path, findings, assessed, scanned_ids):
    """What the scanner assessed comes from assessed_nodes, not from the
    findings dict -- the scanner only puts nodes *with* findings in there,
    so a symbol scanned clean would otherwise read as "Not scanned"."""
    graph_data = _graph_data("x.py")
    _, html_path, _ = generate_reports(
        graph_data, str(tmp_path / "out"), findings, assessed_nodes=assessed, repo_name="backend",
    )

    html = Path(html_path).read_text(encoding="utf-8")
    metadata = json.loads(re.search(r"const reportMeta = (.+);", html).group(1))
    assert metadata["scan_performed"] is (findings is not None)
    assert metadata["scanned_symbol_ids"] == scanned_ids
    assert metadata["repo_name"] == "backend"


def test_html_payloads_preserve_hostile_text_without_closing_script(tmp_path):
    payload = '</script><script>window.injected = true</script><img src=x onerror="alert(1)"> & résumé'
    graph_data = _graph_data(payload)
    graph_data["nodes"][0]["name"] = payload
    findings = {"n1": [{"title": payload, "description": payload, "impact": payload, "severity": "high"}]}
    _, html_path, _ = generate_reports(graph_data, str(tmp_path / "out"), findings, repo_name=payload)

    html = Path(html_path).read_text(encoding="utf-8")
    assert payload not in html
    graph = json.loads(re.search(r"const graphData = (.+);", html).group(1))
    metadata = json.loads(re.search(r"const reportMeta = (.+);", html).group(1))
    assert graph["symbols"][0]["name"] == payload
    assert graph["symbols"][0]["vulnerabilities"][0]["title"] == payload
    assert metadata["repo_name"] == payload


def test_html_shows_symbols_the_scan_could_not_assess(tmp_path):
    """report.html has to tell "no findings" apart from "never assessed",
    and the error text it shows comes from the provider/model -- untrusted,
    so it must go through escapeHtml like every other field."""
    graph_data = _graph_data("x.py")
    _, html_path, _ = generate_reports(
        graph_data, str(tmp_path / "out"), {}, failed_nodes={"n1": "<b>boom</b>"},
    )

    html = Path(html_path).read_text(encoding="utf-8")
    graph = json.loads(re.search(r"const graphData = (.+);", html).group(1))
    assert graph["symbols"][0]["scan_error"] == "<b>boom</b>"
    assert "<b>boom</b>" not in html
    assert "Could not assess: ${escapeHtml(oneLine(d.scan_error))}" in html
    assert "Scan incomplete" in html


def test_reports_say_why_a_symbol_was_not_scanned(tmp_path):
    """A bare "Not scanned" on changed code reads like a failed scan."""
    json_path, html_path, _ = generate_reports(
        _graph_data("x.py"), str(tmp_path / "out"), {},
        skipped_nodes={"n1": "only comments or blank lines changed"},
    )

    with open(json_path) as f:
        assert json.load(f)["symbols"][0]["scan_skipped"] == "only comments or blank lines changed"
    html = Path(html_path).read_text(encoding="utf-8")
    assert "Not scanned: ${escapeHtml(oneLine(d.scan_skipped))}." in html
    assert "Not scanned: unchanged, shown for context." in html


def test_deleted_symbols_start_hidden_in_the_graph(tmp_path):
    """Deleted symbols are context, not the change itself -- the map starts
    with them off, like unchanged ones on anything but a small graph."""
    _, html_path, _ = generate_reports(_graph_data("x.py"), str(tmp_path / "out"), None)

    html = Path(html_path).read_text(encoding="utf-8")
    toggle = re.search(r'<input[^>]*id="toggle-deleted"[^>]*>', html).group(0)
    assert "checked" not in toggle
