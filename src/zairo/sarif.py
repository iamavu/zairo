import os
import re
from typing import Any, Dict, List, Optional

from ._util import normalize_severity

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# GitHub code scanning (and SARIF generally) uses "error"/"warning"/"note"
# as the result level, plus a separate 0-10 "security-severity" score for
# its own severity-badge/sort UI -- both are derived from our four-level
# severity so the two views of the same finding never disagree.
_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}
_SECURITY_SEVERITY_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
}


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "finding"


def _relative_uri(file_path: Optional[str], repo_root: str) -> Optional[str]:
    """SARIF wants a repo-relative, forward-slash URI. Returns None if the
    node has no known file, or the file falls outside repo_root (e.g. an
    absolute stdlib path leaking through) -- such a result is still emitted,
    just without a location SARIF viewers can jump to."""
    if not file_path:
        return None
    rel = os.path.relpath(file_path, repo_root)
    if rel.startswith(".."):
        return None
    return rel.replace(os.sep, "/")


def build_sarif(
    graph_data: Dict[str, Any],
    vulnerabilities: Dict[str, List[Dict[str, Any]]],
    repo_root: str,
    tool_version: str = "0.0.0",
) -> Dict[str, Any]:
    """Converts zairo's LLM findings into a SARIF 2.1.0 log for GitHub code
    scanning (or any other SARIF-consuming viewer). Always returns a valid
    log, even with zero results -- uploading an empty SARIF file for a clean
    scan is what lets GitHub mark previously reported alerts as resolved."""
    nodes = {n["id"]: n for n in graph_data["nodes"]}

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for node_id, findings in vulnerabilities.items():
        node = nodes.get(node_id, {})
        uri = _relative_uri(node.get("file"), repo_root)
        start_line = node.get("start_line") or 1

        for finding in findings:
            title = finding.get("title") or "Potential vulnerability"
            severity = normalize_severity(finding.get("severity"))
            level = _LEVEL_BY_SEVERITY[severity]
            rule_id = _slugify(title)

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": title,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": finding.get("description") or title},
                    "defaultConfiguration": {"level": level},
                    "properties": {"security-severity": _SECURITY_SEVERITY_SCORE[severity]},
                }

            message = finding.get("description") or title
            if finding.get("impact"):
                message = f"{message} Impact: {finding['impact']}"

            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "properties": {"severity": severity, "node": node.get("name")},
            }
            if uri:
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": start_line},
                        }
                    }
                ]
            results.append(result)

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "zairo",
                        "informationUri": "https://github.com/iamavu/zairo",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
