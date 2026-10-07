import json
import os
from importlib.resources import files

from jinja2 import Template

from .sarif import build_sarif
from ._util import is_complete

HTML_TEMPLATE = files("zairo").joinpath("templates/report.html").read_text(encoding="utf-8")
# The graph libraries report.html runs on, written into every report so it
# opens offline and loads nothing from anywhere else. Rendered in as
# values, not template source: Cytoscape's code has "{{" in it.
_SCRIPTS = {
    f"{name}_js": files("zairo").joinpath(f"templates/vendor/{name}.min.js").read_text(encoding="utf-8")
    for name in ("cytoscape", "dagre")
}


def _json_for_script(data: dict) -> str:
    """json.dumps() doesn't escape "</script>", and graph_data can carry
    attacker-influenced text (a repo file path -- '<', '>', '"' are all
    valid filename characters on Linux/macOS -- or an LLM-generated finding
    title/description). Embedding that raw inside <script>...</script>
    lets it close the tag early and inject arbitrary HTML/script, which
    then runs in whoever opens the report. Escaping <, >, and & as their
    \\u escapes keeps the JSON semantically identical (they're meaningless
    outside of strings, and inside a JSON string \\u escapes decode back to
    the same character) while making it impossible to spell a literal
    "</script" anywhere in the output."""
    return (
        json.dumps(data)
        .replace('<', '\\u003c')
        .replace('>', '\\u003e')
        .replace('&', '\\u0026')
    )


def generate_reports(
    graph_data: dict,
    output_dir: str,
    vulnerabilities: dict = None,
    tool_version: str = "0.0.0",
    repo_name: str = None,
    failed_nodes: dict = None,
    assessed_nodes: list = None,
    skipped_nodes: dict = None,
    lookups: dict = None,
    changed_files: list = None,
    problems: list = None,
    commits: dict = None,
    seen: dict = None,
    usage: dict = None,
    usage_by_node: dict = None,
):
    """Returns (json_path, html_path, sarif_path). sarif_path is None unless
    an LLM scan actually ran (vulnerabilities is not None, including when it
    ran and found nothing) -- there's nothing meaningful to convert to SARIF
    otherwise.

    graph_data's node files are repo-relative (see run_scan), and
    `commits` ({"from", "to"}) says which commits they're from: "to" is
    None when the change is a working tree's.

    `failed_nodes` ({node id: error}) are nodes the LLM scan couldn't
    assess. Each gets a 'scan_error' in report.json, whose top-level
    'complete' is then false, and report.sarif marks its run as not
    executed successfully -- so neither can read as a clean result for code
    nobody actually reviewed.

    `changed_files` and `problems` are analyze_impact's coverage: what
    became of each changed file, and the parts of the analysis that failed
    -- an error-level one makes the run incomplete too. All three reports
    carry them.

    `assessed_nodes` are the ids the scan did get an answer for, findings
    or not. report.html needs them to tell a symbol that was scanned clean
    from one that was never scanned at all (skipped, or just context) --
    `vulnerabilities` can't, since it only holds nodes with findings.

    `skipped_nodes` ({node id: reason}) are changed nodes the scan left out
    on purpose (a comment-only change, ...). Each gets a
    'scan_skipped' reason, which report.html shows -- a bare "not scanned"
    on changed code reads like a failure.

    `lookups` ({node id: [{"tool", "input"[, "from_line"]}]}) are what a
    --dig scan looked up before answering for each node, which report.html
    lists -- what the answer rests on. `seen` ({node id: {"lines",
    "lines_shown", "related", "code_shown", "noted"}}) is how much of its
    own code and its surroundings the model was shown: a clean answer
    about a 400-line function it saw 60 lines of is worth less.

    `usage` is what the model scan used and cost, and how long the run took
    (see scan.run_usage), report.json's top-level 'usage'; `usage_by_node`
    ({node id: {"requests", "prompt_tokens", "completion_tokens",
    "total_tokens", "cost"}}) each symbol's own, its 'usage'."""
    os.makedirs(output_dir, exist_ok=True)
    failed_nodes = failed_nodes or {}
    skipped_nodes = skipped_nodes or {}
    lookups = lookups or {}
    seen = seen or {}
    usage_by_node = usage_by_node or {}
    changed_files = changed_files or []
    problems = problems or []

    # Attach vulnerabilities, scan failures and skip reasons to graph_data
    for node in graph_data['nodes']:
        if vulnerabilities and node['id'] in vulnerabilities:
            node['vulnerabilities'] = vulnerabilities[node['id']]
        if node['id'] in failed_nodes:
            node['scan_error'] = failed_nodes[node['id']]
        if node['id'] in skipped_nodes:
            node['scan_skipped'] = skipped_nodes[node['id']]
        if node['id'] in lookups:
            node['lookups'] = lookups[node['id']]
        if node['id'] in seen:
            node['seen'] = seen[node['id']]
        if node['id'] in usage_by_node:
            spent = usage_by_node[node['id']]
            node['usage'] = {
                "requests": spent['requests'], "prompt_tokens": spent['prompt_tokens'],
                "completion_tokens": spent['completion_tokens'], "total_tokens": spent['total_tokens'],
                "cost_usd": round(spent['cost'], 6) if spent['cost'] is not None else None,
            }

    json_path = os.path.join(output_dir, "report.json")
    html_path = os.path.join(output_dir, "report.html")

    # The reports say symbols and connections, like report.html's UI and
    # the CLI; nodes and edges are the graph's own terms, used internally.
    report = {
        "commits": commits or {"from": None, "to": None},
        "complete": is_complete(failed_nodes, problems),
        "problems": problems,
        "changed_files": changed_files,
        **({"usage": usage} if usage is not None else {}),
        "symbols": graph_data['nodes'],
        "connections": graph_data['edges'],
    }
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        **_SCRIPTS,
        graph_json=_json_for_script(report),
        report_meta_json=_json_for_script({
            "repo_name": repo_name or "",
            "scan_performed": vulnerabilities is not None,
            "scanned_symbol_ids": list(assessed_nodes or []),
        }),
    )

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    sarif_path = None
    if vulnerabilities is not None:
        sarif_data = build_sarif(graph_data, vulnerabilities, tool_version, failed_nodes, changed_files, problems)
        sarif_path = os.path.join(output_dir, "report.sarif")
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f, indent=2)

    return json_path, html_path, sarif_path
