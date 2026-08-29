import json
from pathlib import Path

from zairo.reporter import generate_reports


def test_generate_reports_writes_json_and_html(tmp_path: Path):
    graph_data = {
        "nodes": [
            {"id": "n1", "name": "vulnerable_exec", "kind": "function", "file": "x.py",
             "start_line": 1, "end_line": 3, "complexity": 1, "status": "modified"},
        ],
        "edges": [],
    }
    vulnerabilities = {"n1": [{"title": "Command Injection", "description": "...", "impact": "high"}]}

    output_dir = tmp_path / "out"
    json_path, html_path = generate_reports(graph_data, str(output_dir), vulnerabilities)

    assert Path(json_path).exists()
    assert Path(html_path).exists()

    with open(json_path) as f:
        written = json.load(f)
    assert written["nodes"][0]["vulnerabilities"] == vulnerabilities["n1"]

    html = Path(html_path).read_text()
    assert "Zairo Impact Analysis" in html
