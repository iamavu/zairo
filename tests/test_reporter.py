import json
from pathlib import Path

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
    graph_data = _graph_data(str(tmp_path / "x.py"))
    vulnerabilities = {"n1": [{"title": "Command Injection", "description": "...", "impact": "high", "severity": "critical"}]}

    output_dir = tmp_path / "out"
    json_path, html_path, sarif_path = generate_reports(graph_data, str(output_dir), vulnerabilities, repo_root=str(tmp_path))

    assert Path(json_path).exists()
    assert Path(html_path).exists()

    with open(json_path) as f:
        written = json.load(f)
    assert written["nodes"][0]["vulnerabilities"] == vulnerabilities["n1"]

    html = Path(html_path).read_text()
    assert "Zairo Impact Analysis" in html


def test_html_escapes_finding_and_node_text_before_rendering(tmp_path: Path):
    """report.html builds the node-detail panel by setting innerHTML from
    finding/node fields that ultimately come from scanned source code and
    LLM output -- neither is trusted. Every such interpolation must go
    through escapeHtml(); this guards against one being reintroduced raw."""
    graph_data = _graph_data(str(tmp_path / "x.py"))
    vulnerabilities = {"n1": [{"title": "X", "description": "d", "impact": "i", "severity": "high"}]}
    output_dir = tmp_path / "out"

    _, html_path, _ = generate_reports(graph_data, str(output_dir), vulnerabilities, repo_root=str(tmp_path))
    html = Path(html_path).read_text()

    assert "function escapeHtml(" in html
    for field in ("v.title", "v.impact", "v.description", "d.name", "d.kind", "d.status", "d.file"):
        assert f"escapeHtml({field})" in html, f"{field} is interpolated without escapeHtml()"


def test_sarif_written_when_llm_scan_ran(tmp_path: Path):
    graph_data = _graph_data(str(tmp_path / "x.py"))
    vulnerabilities = {"n1": [{"title": "Command Injection", "description": "...", "impact": "high", "severity": "critical"}]}

    output_dir = tmp_path / "out"
    _, _, sarif_path = generate_reports(graph_data, str(output_dir), vulnerabilities, repo_root=str(tmp_path))

    assert sarif_path is not None
    assert Path(sarif_path).exists()
    with open(sarif_path) as f:
        sarif = json.load(f)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "command-injection"
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "x.py"


def test_sarif_written_even_with_zero_findings(tmp_path: Path):
    """An empty-but-present SARIF file is what lets GitHub mark previously
    reported alerts as resolved on a clean scan."""
    graph_data = _graph_data(str(tmp_path / "x.py"))
    output_dir = tmp_path / "out"
    _, _, sarif_path = generate_reports(graph_data, str(output_dir), {}, repo_root=str(tmp_path))

    assert sarif_path is not None
    with open(sarif_path) as f:
        sarif = json.load(f)
    assert sarif["runs"][0]["results"] == []


def test_no_sarif_when_llm_scan_did_not_run(tmp_path: Path):
    graph_data = _graph_data(str(tmp_path / "x.py"))
    output_dir = tmp_path / "out"
    _, _, sarif_path = generate_reports(graph_data, str(output_dir), None, repo_root=str(tmp_path))

    assert sarif_path is None
    assert not (output_dir / "report.sarif").exists()
