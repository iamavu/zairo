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


def test_incomplete_scan_is_recorded_in_report_json_and_sarif(tmp_path: Path):
    graph_data = _graph_data(str(tmp_path / "x.py"))
    output_dir = tmp_path / "out"
    json_path, _, sarif_path = generate_reports(
        graph_data, str(output_dir), {}, repo_root=str(tmp_path), failed_nodes={"n1": "boom"},
    )

    with open(json_path) as f:
        written = json.load(f)
    assert written["scan_complete"] is False
    assert written["nodes"][0]["scan_error"] == "boom"
    with open(sarif_path) as f:
        assert json.load(f)["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_complete_scan_is_recorded_in_report_json(tmp_path: Path):
    graph_data = _graph_data(str(tmp_path / "x.py"))
    json_path, _, _ = generate_reports(graph_data, str(tmp_path / "out"), {}, repo_root=str(tmp_path))

    with open(json_path) as f:
        written = json.load(f)
    assert written["scan_complete"] is True
    assert "scan_error" not in written["nodes"][0]


def test_no_scan_status_when_llm_scan_did_not_run(tmp_path: Path):
    graph_data = _graph_data(str(tmp_path / "x.py"))
    json_path, _, _ = generate_reports(graph_data, str(tmp_path / "out"), None, repo_root=str(tmp_path))

    with open(json_path) as f:
        assert "scan_complete" not in json.load(f)


def test_no_sarif_when_llm_scan_did_not_run(tmp_path: Path):
    graph_data = _graph_data(str(tmp_path / "x.py"))
    output_dir = tmp_path / "out"
    _, _, sarif_path = generate_reports(graph_data, str(output_dir), None, repo_root=str(tmp_path))

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
    graph_data = _graph_data(str(tmp_path / "x.py"))
    _, html_path, _ = generate_reports(
        graph_data, str(tmp_path / "out"), findings, repo_root=str(tmp_path), assessed_nodes=assessed,
    )

    html = Path(html_path).read_text(encoding="utf-8")
    metadata = json.loads(re.search(r"const reportMeta = (.+);", html).group(1))
    assert metadata["scan_performed"] is (findings is not None)
    assert metadata["scanned_node_ids"] == scanned_ids
    assert metadata["repo_root"] == str(tmp_path)
    assert metadata["repo_name"] == tmp_path.name


def test_html_payloads_preserve_hostile_text_without_closing_script(tmp_path):
    payload = '</script><script>window.injected = true</script><img src=x onerror="alert(1)"> & résumé'
    graph_data = _graph_data(payload)
    graph_data["nodes"][0]["name"] = payload
    findings = {"n1": [{"title": payload, "description": payload, "impact": payload, "severity": "high"}]}
    _, html_path, _ = generate_reports(graph_data, str(tmp_path / "out"), findings, repo_root=str(tmp_path / payload))

    html = Path(html_path).read_text(encoding="utf-8")
    assert payload not in html
    graph = json.loads(re.search(r"const graphData = (.+);", html).group(1))
    metadata = json.loads(re.search(r"const reportMeta = (.+);", html).group(1))
    assert graph["nodes"][0]["name"] == payload
    assert graph["nodes"][0]["vulnerabilities"][0]["title"] == payload
    assert metadata["repo_root"].endswith(payload)


def test_html_shows_symbols_the_scan_could_not_assess(tmp_path):
    """report.html has to tell "no findings" apart from "never assessed",
    and the error text it shows comes from the provider/model -- untrusted,
    so it must go through escapeHtml like every other field."""
    graph_data = _graph_data(str(tmp_path / "x.py"))
    _, html_path, _ = generate_reports(
        graph_data, str(tmp_path / "out"), {}, repo_root=str(tmp_path), failed_nodes={"n1": "<b>boom</b>"},
    )

    html = Path(html_path).read_text(encoding="utf-8")
    graph = json.loads(re.search(r"const graphData = (.+);", html).group(1))
    assert graph["nodes"][0]["scan_error"] == "<b>boom</b>"
    assert "<b>boom</b>" not in html
    assert "Could not assess: ${escapeHtml(oneLine(d.scan_error))}" in html
    assert "Scan incomplete" in html
