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


def test_same_cwe_different_titles_share_one_rule():
    """Two findings the model phrased differently but tagged with the same
    CWE should collapse into a single SARIF rule, not one each."""
    graph_data = _graph("/repo/src/app.py")
    vulnerabilities = {
        "n1": [
            {"title": "Command Injection", "description": "d1", "severity": "critical", "cwe": "CWE-78"},
            {"title": "Shell Injection via os.system", "description": "d2", "severity": "high", "cwe": "cwe:78"},
        ],
    }
    sarif = build_sarif(graph_data, vulnerabilities, repo_root="/repo")

    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    results = sarif["runs"][0]["results"]
    assert [r["id"] for r in rules] == ["cwe-78"]
    assert {r["ruleId"] for r in results} == {"cwe-78"}
    assert rules[0]["name"] == "OS Command Injection"
    assert rules[0]["helpUri"] == "https://cwe.mitre.org/data/definitions/78.html"
    assert [r["properties"]["cwe"] for r in results] == ["CWE-78", "CWE-78"]


def test_unknown_cwe_falls_back_to_bare_id_as_name():
    graph_data = _graph("/repo/src/app.py")
    vulnerabilities = {"n1": [{"title": "Odd Thing", "description": "d", "severity": "medium", "cwe": "CWE-9999"}]}
    sarif = build_sarif(graph_data, vulnerabilities, repo_root="/repo")

    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "cwe-9999"
    assert rule["name"] == "CWE-9999"


def test_missing_cwe_falls_back_to_title_slug():
    graph_data = _graph("/repo/src/app.py")
    vulnerabilities = {"n1": [{"title": "Some Novel Issue", "description": "d", "severity": "medium"}]}
    sarif = build_sarif(graph_data, vulnerabilities, repo_root="/repo")

    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "some-novel-issue"
    assert result["properties"]["cwe"] is None
