import json
import os
import re
from typing import Any, Dict, List, Optional

from jinja2 import Template

from ._util import SEVERITY_LEVELS, max_severity, normalize_severity
from .sarif import SARIF_SCHEMA_URI, build_sarif

FLEET_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Zairo Fleet Report</title>
    <style>
        body { font-family: sans-serif; margin: 0; padding: 24px; background-color: #1e1e1e; color: #fff; }
        h1 { font-size: 1.4em; border-bottom: 1px solid #3c3c3c; padding-bottom: 10px; }
        table { border-collapse: collapse; width: 100%; margin-top: 16px; }
        th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #3c3c3c; }
        th { color: #4fc1ff; font-size: 0.8em; text-transform: uppercase; }
        tr:hover { background: #252526; }
        a { color: #4fc1ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .status-error { color: #ff6b6b; }
        .status-ok { color: #4CAF50; }
        .count-nonzero { font-weight: bold; }
        .count-crit { color: #ff5252; }
        .count-high { color: #ff9e57; }
        .count-med { color: #ffd54f; }
        .count-low { color: #90a4ae; }
        .totals { margin-top: 20px; font-size: 0.9em; color: #aaa; }
    </style>
</head>
<body>
    <h1>Zairo Fleet Report — {{ repos|length }} repo(s)</h1>
    <table>
        <thead>
            <tr>
                <th>Repo</th><th>Status</th><th>Modified nodes</th><th>Findings</th>
                <th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Reports</th>
            </tr>
        </thead>
        <tbody>
        {% for r in repos %}
            <tr>
                <td>{{ r.repo }}</td>
            {% if r.status == 'error' %}
                <td class="status-error">error: {{ r.error }}</td>
                <td colspan="7"></td>
            {% else %}
                <td class="status-ok">ok</td>
                <td>{{ r.num_modified_nodes }}</td>
                <td>{{ r.num_findings }}</td>
                <td class="count-crit {{ 'count-nonzero' if r.severity_counts.critical else '' }}">{{ r.severity_counts.critical }}</td>
                <td class="count-high {{ 'count-nonzero' if r.severity_counts.high else '' }}">{{ r.severity_counts.high }}</td>
                <td class="count-med {{ 'count-nonzero' if r.severity_counts.medium else '' }}">{{ r.severity_counts.medium }}</td>
                <td class="count-low {{ 'count-nonzero' if r.severity_counts.low else '' }}">{{ r.severity_counts.low }}</td>
                <td>
                    <a href="{{ r.report_html }}">html</a> ·
                    <a href="{{ r.report_json }}">json</a>
                    {% if r.report_sarif %} · <a href="{{ r.report_sarif }}">sarif</a>{% endif %}
                </td>
            {% endif %}
            </tr>
        {% endfor %}
        </tbody>
    </table>
    <div class="totals">
        Totals across the fleet — critical: {{ totals.critical }}, high: {{ totals.high }},
        medium: {{ totals.medium }}, low: {{ totals.low }}
    </div>
</body>
</html>
"""


def unique_slug(repo_path: str, used: set) -> str:
    """A filesystem- and URL-safe directory name for a repo's own reports,
    disambiguated when two repo paths share a basename (e.g. two different
    orgs' "backend" checkouts)."""
    base = re.sub(r'[^a-zA-Z0-9._-]+', '-', os.path.basename(os.path.normpath(repo_path))).strip('-') or "repo"
    slug = base
    i = 2
    while slug in used:
        slug = f"{base}-{i}"
        i += 1
    used.add(slug)
    return slug


def build_fleet_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """`results` is a list of {"repo", "slug", "status", "result": ScanResult
    | None, "error": str | None} entries, one per repo `fleet` attempted.
    Returns a JSON-serializable rollup: per-repo status and severity counts,
    plus fleet-wide totals -- the shape both fleet.json and fleet.html render
    from."""
    repos_summary = []
    totals = {level: 0 for level in SEVERITY_LEVELS}

    for r in results:
        entry: Dict[str, Any] = {"repo": r["repo"], "slug": r["slug"], "status": r["status"]}
        if r["status"] == "error":
            entry["error"] = r["error"]
            repos_summary.append(entry)
            continue

        scan_result = r["result"]
        severity_counts = {level: 0 for level in SEVERITY_LEVELS}
        num_findings = 0
        if scan_result.vulnerabilities:
            for findings in scan_result.vulnerabilities.values():
                for finding in findings:
                    sev = normalize_severity(finding.get("severity"))
                    severity_counts[sev] += 1
                    totals[sev] += 1
                    num_findings += 1

        entry.update({
            "num_modified_nodes": sum(1 for n in scan_result.graph_data["nodes"] if n["status"] != "unchanged"),
            "num_findings": num_findings,
            "severity_counts": severity_counts,
            "worst_severity": max_severity(scan_result.vulnerabilities) if scan_result.vulnerabilities else None,
            "report_json": f"{r['slug']}/report.json",
            "report_html": f"{r['slug']}/report.html",
            "report_sarif": f"{r['slug']}/report.sarif" if scan_result.sarif_path else None,
        })
        repos_summary.append(entry)

    return {"repos": repos_summary, "totals": totals}


def _build_fleet_sarif(results: List[Dict[str, Any]], tool_version: str) -> Optional[Dict[str, Any]]:
    """Merges every scanned repo's SARIF results into one multi-run log (one
    `run` per repo) -- not written at all if no repo actually ran an LLM
    scan. Locations are re-rooted under "<slug>/..." so files that share a
    relative path across repos (e.g. every repo has its own src/app.py)
    don't collide when viewed in one flat aggregate."""
    runs = []
    for r in results:
        if r["status"] != "ok" or r["result"].vulnerabilities is None:
            continue
        scan_result = r["result"]
        repo_sarif = build_sarif(
            scan_result.graph_data, scan_result.vulnerabilities,
            repo_root=os.path.abspath(r["repo"]), tool_version=tool_version,
        )
        run = repo_sarif["runs"][0]
        for result in run["results"]:
            for loc in result.get("locations", []):
                artifact = loc["physicalLocation"]["artifactLocation"]
                artifact["uri"] = f"{r['slug']}/{artifact['uri']}"
        run["properties"] = {"repo": r["repo"]}
        runs.append(run)

    if not runs:
        return None
    return {"$schema": SARIF_SCHEMA_URI, "version": "2.1.0", "runs": runs}


def write_fleet_reports(
    results: List[Dict[str, Any]], output_dir: str, tool_version: str = "0.0.0",
) -> Dict[str, Optional[str]]:
    """Writes fleet.json (rollup summary), fleet.html (a dashboard table
    linking into each repo's own report.html/.json/.sarif), and fleet.sarif
    (all scanned repos merged into one multi-run log, omitted entirely if no
    repo ran an LLM scan). Returns {"json": ..., "html": ..., "sarif": ...}
    (sarif is None when omitted)."""
    os.makedirs(output_dir, exist_ok=True)
    summary = build_fleet_summary(results)

    json_path = os.path.join(output_dir, "fleet.json")
    with open(json_path, 'w') as f:
        json.dump(summary, f, indent=2)

    html_path = os.path.join(output_dir, "fleet.html")
    # autoescape=True: r.repo/r.error are user- and exception-supplied text,
    # not safe HTML -- unlike reporter.py's template, nothing here needs raw
    # markup through, so there's no reason not to escape everything.
    template = Template(FLEET_HTML_TEMPLATE, autoescape=True)
    with open(html_path, 'w') as f:
        f.write(template.render(**summary))

    sarif_path = None
    fleet_sarif = _build_fleet_sarif(results, tool_version)
    if fleet_sarif is not None:
        sarif_path = os.path.join(output_dir, "fleet.sarif")
        with open(sarif_path, 'w') as f:
            json.dump(fleet_sarif, f, indent=2)

    return {"json": json_path, "html": html_path, "sarif": sarif_path}
