from zairo.sarif import build_sarif


def _graph(file_path):
    return {
        "nodes": [
            {"id": "n1", "name": "vulnerable_exec", "file": file_path, "start_line": 4},
            {"id": "n2", "name": "no_location_node", "file": None, "start_line": None},
        ],
        "edges": [],
    }


def test_maps_severity_to_sarif_level():
    graph_data = _graph("/repo/src/app.py")
    vulnerabilities = {
        "n1": [
            {"title": "Command Injection", "description": "d", "severity": "critical"},
            {"title": "Weak Random", "description": "d", "severity": "low"},
        ],
    }
    sarif = build_sarif(graph_data, vulnerabilities, repo_root="/repo")
    results = sarif["runs"][0]["results"]

    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["command-injection"] == "error"
    assert levels["weak-random"] == "note"


def test_location_is_repo_relative_posix_path():
    graph_data = _graph("/repo/src/app.py")
    vulnerabilities = {"n1": [{"title": "X", "description": "d", "severity": "high"}]}
    sarif = build_sarif(graph_data, vulnerabilities, repo_root="/repo")

    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/app.py"
    assert location["region"]["startLine"] == 4


def test_missing_file_omits_location_but_keeps_result():
    graph_data = _graph("/repo/src/app.py")
    vulnerabilities = {"n2": [{"title": "X", "description": "d", "severity": "medium"}]}
    sarif = build_sarif(graph_data, vulnerabilities, repo_root="/repo")

    result = sarif["runs"][0]["results"][0]
    assert "locations" not in result


def test_defaults_missing_severity_to_medium_warning():
    graph_data = _graph("/repo/src/app.py")
    vulnerabilities = {"n1": [{"title": "X", "description": "d"}]}
    sarif = build_sarif(graph_data, vulnerabilities, repo_root="/repo")

    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_empty_vulnerabilities_produce_valid_empty_log():
    graph_data = _graph("/repo/src/app.py")
    sarif = build_sarif(graph_data, {}, repo_root="/repo")

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "zairo"
