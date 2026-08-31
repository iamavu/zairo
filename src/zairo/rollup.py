import json
import os
import re
from typing import Any, Dict, List, Optional

from jinja2 import Template

from ._util import SEVERITY_LEVELS, max_severity, normalize_severity
from .sarif import SARIF_SCHEMA_URI, build_sarif

ROLLUP_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Zairo Rollup Report</title>
    <style>
        /* Identical to reporter.py's HTML_TEMPLATE :root -- same source of
           truth for the palette, so report.html and rollup.html always
           match. See that file for why the status and severity variables
           are kept disjoint (a node's fill and severity ring render
           superimposed there); doesn't apply to this table, but the
           values stay shared regardless. */
        :root {
            --bg: #16161e;
            --panel: #1a1b26;
            --panel-2: #1f2335;
            --border: #292e42;
            --text: #c0caf5;
            --text-dim: #737aa2;
            --text-faint: #565f89;
            --accent: #7aa2f7;
            --accent-2: #bb9af7;
            --status-added: #9ece6a;
            --status-modified: #7aa2f7;
            --status-unchanged: #414868;
            --sev-critical: #f7768e;
            --sev-high: #ff9e64;
            --sev-medium: #e0af68;
            --sev-low: #565f89;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
            margin: 0; padding: 0; background-color: var(--bg); color: var(--text);
        }

        header {
            display: flex; align-items: center; gap: 24px;
            padding: 10px 20px; background: var(--panel);
            border-bottom: 1px solid var(--border);
        }
        header .brand { font-weight: 700; font-size: 1.05em; letter-spacing: 0.02em; }
        header .brand span { color: var(--accent); }
        .stats { display: flex; gap: 18px; margin-left: auto; font-size: 0.85em; color: var(--text-dim); }
        .stats b { color: var(--text); font-weight: 600; }
        .stats .stat-crit b { color: var(--sev-critical); }
        .stats .stat-high b { color: var(--sev-high); }

        .content { padding: 24px; }

        table {
            border-collapse: collapse; width: 100%;
            background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
            overflow: hidden;
        }
        th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 0.88em; }
        th {
            color: var(--text-faint); font-size: 0.72em; text-transform: uppercase;
            letter-spacing: 0.06em; font-weight: 600; background: var(--panel-2);
        }
        tbody tr:last-child td { border-bottom: none; }
        tbody tr:hover { background: var(--panel-2); }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }

        .badge {
            font-size: 0.72em; padding: 2px 8px; border-radius: 100px; font-weight: 600;
            text-transform: uppercase; letter-spacing: 0.03em; display: inline-block;
        }
        .badge.status-ok { background: rgba(158,206,106,0.18); color: var(--status-added); }
        .badge.status-error { background: rgba(247,118,142,0.18); color: var(--sev-critical); }

        .count { font-variant-numeric: tabular-nums; color: var(--text-faint); }
        .count.nonzero { font-weight: 700; }
        .count.sev-critical.nonzero { color: var(--sev-critical); }
        .count.sev-high.nonzero { color: var(--sev-high); }
        .count.sev-medium.nonzero { color: var(--sev-medium); }
        .count.sev-low.nonzero { color: var(--sev-low); }

        .error-text { color: var(--sev-critical); font-size: 0.85em; }

        .totals {
            margin-top: 20px; font-size: 0.85em; color: var(--text-dim);
            background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
            padding: 12px 16px;
        }
        .totals b { color: var(--text); font-weight: 600; }
    </style>
</head>
<body>
    <header>
        <div class="brand"><span>zairo</span> rollup report</div>
        <div class="stats">
            <span>Repos: <b>{{ repos|length }}</b></span>
            <span class="stat-high">High: <b>{{ totals.high }}</b></span>
            <span class="stat-crit">Critical: <b>{{ totals.critical }}</b></span>
        </div>
    </header>
    <div class="content">
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
                    <td><span class="badge status-error">error</span></td>
                    <td colspan="6" class="error-text">{{ r.error }}</td>
                    <td></td>
                {% else %}
                    <td><span class="badge status-ok">ok</span></td>
                    <td>{{ r.num_modified_nodes }}</td>
                    <td>{{ r.num_findings }}</td>
                    <td class="count sev-critical {{ 'nonzero' if r.severity_counts.critical else '' }}">{{ r.severity_counts.critical }}</td>
                    <td class="count sev-high {{ 'nonzero' if r.severity_counts.high else '' }}">{{ r.severity_counts.high }}</td>
                    <td class="count sev-medium {{ 'nonzero' if r.severity_counts.medium else '' }}">{{ r.severity_counts.medium }}</td>
                    <td class="count sev-low {{ 'nonzero' if r.severity_counts.low else '' }}">{{ r.severity_counts.low }}</td>
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
            Totals across all repos — critical: <b>{{ totals.critical }}</b>, high: <b>{{ totals.high }}</b>,
            medium: <b>{{ totals.medium }}</b>, low: <b>{{ totals.low }}</b>
        </div>
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


def build_rollup_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """`results` is a list of {"repo", "slug", "status", "result": ScanResult
    | None, "error": str | None} entries, one per repo scanned.
    Returns a JSON-serializable rollup: per-repo status and severity counts,
    plus totals across every repo -- the shape both rollup.json and
    rollup.html render from."""
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


def _build_rollup_sarif(results: List[Dict[str, Any]], tool_version: str) -> Optional[Dict[str, Any]]:
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


def write_rollup_reports(
    results: List[Dict[str, Any]], output_dir: str, tool_version: str = "0.0.0",
) -> Dict[str, Optional[str]]:
    """Writes rollup.json (summary), rollup.html (a dashboard table
    linking into each repo's own report.html/.json/.sarif), and rollup.sarif
    (all scanned repos merged into one multi-run log, omitted entirely if no
    repo ran an LLM scan). Returns {"json": ..., "html": ..., "sarif": ...}
    (sarif is None when omitted)."""
    os.makedirs(output_dir, exist_ok=True)
    summary = build_rollup_summary(results)

    json_path = os.path.join(output_dir, "rollup.json")
    with open(json_path, 'w') as f:
        json.dump(summary, f, indent=2)

    html_path = os.path.join(output_dir, "rollup.html")
    # autoescape=True: r.repo/r.error are user- and exception-supplied text,
    # not safe HTML -- unlike reporter.py's template, nothing here needs raw
    # markup through, so there's no reason not to escape everything.
    template = Template(ROLLUP_HTML_TEMPLATE, autoescape=True)
    with open(html_path, 'w') as f:
        f.write(template.render(**summary))

    sarif_path = None
    rollup_sarif = _build_rollup_sarif(results, tool_version)
    if rollup_sarif is not None:
        sarif_path = os.path.join(output_dir, "rollup.sarif")
        with open(sarif_path, 'w') as f:
            json.dump(rollup_sarif, f, indent=2)

    return {"json": json_path, "html": html_path, "sarif": sarif_path}
