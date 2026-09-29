import re
from typing import Any, Dict, List, Optional, Tuple

from ._util import NOT_REVIEWED, normalize_confidence, normalize_cwe, normalize_severity, severity_rank

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


def _uri(file_path: Optional[str]) -> Optional[str]:
    """A node's file as a SARIF URI: repo-relative with forward slashes, as
    run_scan leaves it. None if the node has no known file, or it lies
    outside the repo -- such a result is still emitted, just without a
    location SARIF viewers can jump to."""
    if not file_path or file_path.startswith(("../", "/")) or file_path == "..":
        return None
    return file_path


def _location(node: Dict[str, Any], line: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """A fresh SARIF location for a node every call -- never share one
    between results, since the rollup rewrites each URI in place. Points at
    `line` when given (the line a finding cited), else the node's start."""
    uri = _uri(node.get("file"))
    if not uri:
        return None
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line or node.get("start_line") or 1},
        }
    }


def _rule_for(finding: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Picks a stable rule id/definition for a finding: keyed by CWE when the
    model gave one (so "SQL Injection" and "SQLi in query builder" -- two
    different titles for the same underlying category -- collapse into one
    rule instead of spawning a new one every time the wording differs), or a
    slug of the finding's own title as a fallback when it didn't. Its level
    and security-severity are build_sarif's to set: they depend on every
    finding under the rule, not just this one."""
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
            "properties": {"tags": [cwe]},
        }

    title = finding.get("title") or "Potential vulnerability"
    rule_id = _slugify(title)
    return rule_id, {
        "id": rule_id,
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {"text": finding.get("description") or title},
        "properties": {},
    }


def build_sarif(
    graph_data: Dict[str, Any],
    vulnerabilities: Dict[str, List[Dict[str, Any]]],
    tool_version: str = "0.0.0",
    failed_nodes: Optional[Dict[str, str]] = None,
    changed_files: Optional[List[Dict[str, str]]] = None,
    problems: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Converts zairo's LLM findings into a SARIF 2.1.0 log for GitHub code
    scanning (or any other SARIF-consuming viewer). Always returns a valid
    log, even with zero results -- uploading an empty SARIF file for a clean
    scan is what lets GitHub mark previously reported alerts as resolved.

    `failed_nodes` ({node id: error}) are nodes the scan couldn't assess:
    each becomes an error-level tool execution notification, and the run's
    invocation records executionSuccessful: false -- so zero results from
    an incomplete scan never look like a clean one. `problems` (see
    analyze_impact) become notifications at their own level, an error one
    failing the run the same way; and each of `changed_files` that nothing
    reviewed -- not parsed, or no symbol in it changed -- a note-level one,
    so the log says what it doesn't cover."""
    nodes = {n["id"]: n for n in graph_data["nodes"]}

    rules: Dict[str, Dict[str, Any]] = {}
    rule_severity: Dict[str, str] = {}  # {rule id: the worst severity among its findings}
    results: List[Dict[str, Any]] = []

    for node_id, findings in vulnerabilities.items():
        node = nodes.get(node_id, {})

        for finding in findings:
            title = finding.get("title") or "Potential vulnerability"
            severity = normalize_severity(finding.get("severity"))
            level = _LEVEL_BY_SEVERITY[severity]
            cwe = normalize_cwe(finding.get("cwe"))

            rule_id, rule = _rule_for(finding)
            rules.setdefault(rule_id, rule)
            worst = rule_severity.get(rule_id)
            if worst is None or severity_rank(severity) > severity_rank(worst):
                rule_severity[rule_id] = severity

            message = finding.get("description") or title
            if finding.get("trigger"):
                message = f"{message} Who can trigger it: {finding['trigger']}"
            if finding.get("impact"):
                message = f"{message} Impact: {finding['impact']}"

            introduced = finding.get("introduced_by_change")
            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "properties": {
                    "severity": severity,
                    "cwe": cwe,
                    "symbol": node.get("name"),
                    "introducedByChange": introduced if isinstance(introduced, bool) else None,
                    "confidence": normalize_confidence(finding.get("confidence")),
                },
            }
            # The scanner only keeps a line the model was actually shown;
            # anything else falls back to where the node starts.
            line = finding.get("line")
            location = _location(node, line if isinstance(line, int) and not isinstance(line, bool) else None)
            if location:
                result["locations"] = [location]
            results.append(result)

    # A rule's own level and security-severity are what GitHub shows on its
    # alerts, and what its code-scanning check can fail a PR on: they're
    # the worst of its findings', so a critical SQL injection is never
    # badged low because a low one came first.
    for rule_id, severity in rule_severity.items():
        rules[rule_id]["defaultConfiguration"] = {"level": _LEVEL_BY_SEVERITY[severity]}
        rules[rule_id]["properties"]["security-severity"] = _SECURITY_SEVERITY_SCORE[severity]

    notifications: List[Dict[str, Any]] = []
    for node_id, error in (failed_nodes or {}).items():
        node = nodes.get(node_id, {})
        notification: Dict[str, Any] = {
            "level": "error",
            "message": {"text": f"Could not assess {node.get('name', node_id)}: {error}"},
        }
        location = _location(node)
        if location:
            notification["locations"] = [location]
        notifications.append(notification)
    for problem in problems or []:
        notifications.append({"level": problem["level"], "message": {"text": problem["message"]}})
    for changed in changed_files or []:
        if changed["outcome"] in NOT_REVIEWED:
            notifications.append({
                "level": "note",
                "message": {"text": f"Not reviewed: {changed['path']} ({NOT_REVIEWED[changed['outcome']]})."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": changed["path"]}}}],
            })

    invocation: Dict[str, Any] = {"executionSuccessful": not any(n["level"] == "error" for n in notifications)}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

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
                "invocations": [invocation],
                "results": results,
            }
        ],
    }
