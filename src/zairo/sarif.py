import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ._util import normalize_cwe, normalize_severity

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

# Non-exhaustive names for the CWEs an LLM code-diff scanner is most likely
# to flag -- good enough to make the common cases readable in a SARIF
# viewer. Anything not listed here still works: the rule just falls back to
# showing the bare "CWE-<n>" id as its name instead of a description.
_CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-119": "Improper Restriction of Operations within a Memory Buffer",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-209": "Information Exposure Through an Error Message",
    "CWE-259": "Use of Hard-coded Password",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted Upload of Dangerous File Type",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity Reference",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery",
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


def _rule_for(finding: Dict[str, Any], level: str, severity: str) -> Tuple[str, Dict[str, Any]]:
    """Picks a stable rule id/definition for a finding: keyed by CWE when the
    model gave one (so "SQL Injection" and "SQLi in query builder" -- two
    different titles for the same underlying category -- collapse into one
    rule instead of spawning a new one every time the wording differs), or a
    slug of the finding's own title as a fallback when it didn't."""
    cwe = normalize_cwe(finding.get("cwe"))
    if cwe:
        number = cwe.split("-", 1)[1]
        name = _CWE_NAMES.get(cwe, cwe)
        return cwe.lower(), {
            "id": cwe.lower(),
            "name": name,
            "shortDescription": {"text": name},
            "fullDescription": {"text": f"{name} ({cwe})."},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{number}.html",
            "defaultConfiguration": {"level": level},
            "properties": {"security-severity": _SECURITY_SEVERITY_SCORE[severity], "tags": [cwe]},
        }

    title = finding.get("title") or "Potential vulnerability"
    rule_id = _slugify(title)
    return rule_id, {
        "id": rule_id,
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {"text": finding.get("description") or title},
        "defaultConfiguration": {"level": level},
        "properties": {"security-severity": _SECURITY_SEVERITY_SCORE[severity]},
    }


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
            cwe = normalize_cwe(finding.get("cwe"))

            rule_id, rule = _rule_for(finding, level, severity)
            if rule_id not in rules:
                rules[rule_id] = rule

            message = finding.get("description") or title
            if finding.get("impact"):
                message = f"{message} Impact: {finding['impact']}"

            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "properties": {"severity": severity, "cwe": cwe, "node": node.get("name")},
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
