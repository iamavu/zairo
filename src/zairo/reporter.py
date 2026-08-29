import json
import os
from jinja2 import Template

from .sarif import build_sarif

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Zairo Impact Analysis</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js"></script>
    <style>
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

            /* Node fill by change status. Deliberately disjoint from the
               severity ramp below -- these two scales render superimposed
               (fill + border ring on the same node) whenever a modified or
               added node has a finding, so any shared hex between the two
               scales makes that node's severity ring invisible against its
               own fill. (That's not hypothetical: an earlier version of
               this palette reused the same yellow for "modified" and
               "medium", and a modified node with only a medium-severity
               finding rendered as a plain filled circle, no ring at all.) */
            --status-added: #9ece6a;
            --status-modified: #7aa2f7;
            --status-unchanged: #414868;

            /* Finding severity, shown as a node's border ring and in badges.
               Only "added"/"modified" nodes can ever carry a finding (only
               they get LLM-scanned), so this only needs to avoid those two
               status colors, not --status-unchanged. */
            --sev-critical: #f7768e;
            --sev-high: #ff9e64;
            --sev-medium: #e0af68;
            --sev-low: #565f89;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
            margin: 0; padding: 0; display: flex; flex-direction: column;
            height: 100vh; background-color: var(--bg); color: var(--text);
        }
        code, .mono { font-family: "SF Mono", Menlo, Consolas, monospace; }

        header {
            display: flex; align-items: center; gap: 24px;
            padding: 10px 20px; background: var(--panel);
            border-bottom: 1px solid var(--border); flex-shrink: 0;
        }
        header .brand { font-weight: 700; font-size: 1.05em; letter-spacing: 0.02em; }
        header .brand span { color: var(--accent); }
        .stats { display: flex; gap: 18px; margin-left: auto; font-size: 0.85em; color: var(--text-dim); }
        .stats b { color: var(--text); font-weight: 600; }
        .stats .stat-crit b { color: var(--sev-critical); }
        .stats .stat-high b { color: var(--sev-high); }

        .main { flex: 1; display: flex; min-height: 0; }
        #cy { flex: 1; height: 100%; }

        #sidebar {
            width: 320px; flex-shrink: 0; height: 100%; background: var(--panel);
            padding: 16px; box-sizing: border-box; overflow-y: auto;
            border-left: 1px solid var(--border);
        }
        .section { margin-bottom: 20px; }
        .section-label {
            font-size: 0.72em; text-transform: uppercase; letter-spacing: 0.08em;
            color: var(--text-faint); margin-bottom: 8px; font-weight: 600;
        }

        input#search {
            width: 100%; padding: 8px 10px; background: var(--panel-2);
            border: 1px solid var(--border); border-radius: 6px; color: var(--text);
            font-size: 0.85em; outline: none;
        }
        input#search:focus { border-color: var(--accent); }

        .btn-row { display: flex; gap: 6px; }
        button {
            background: var(--panel-2); color: var(--text-dim); border: 1px solid var(--border);
            padding: 7px 10px; border-radius: 6px; cursor: pointer; font-size: 0.78em;
            flex: 1; transition: all 0.15s ease;
        }
        button:hover { background: var(--border); color: var(--text); }
        button.active { background: var(--accent); border-color: var(--accent); color: #16161e; font-weight: 600; }
        button.full { width: 100%; }

        .legend { display: flex; flex-direction: column; gap: 6px; font-size: 0.82em; margin-bottom: 10px; }
        .legend-item { display: flex; align-items: center; gap: 8px; color: var(--text-dim); }
        .legend-group-label { font-size: 0.72em; color: var(--text-faint); margin-bottom: 4px; }
        .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
        .dot.ring { background: transparent; border: 2px solid; box-sizing: content-box; width: 6px; height: 6px; }

        .empty-state {
            color: var(--text-faint); font-size: 0.85em; text-align: center;
            padding: 30px 10px; border: 1px dashed var(--border); border-radius: 8px;
        }

        .detail-card { background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
        .detail-card h2 { margin: 0 0 10px 0; font-size: 1em; color: var(--text); word-break: break-word; }
        .badge-row { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
        .badge {
            font-size: 0.72em; padding: 2px 8px; border-radius: 100px; font-weight: 600;
            background: var(--border); color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.03em;
        }
        .badge.status-modified { background: rgba(122,162,247,0.18); color: var(--status-modified); }
        .badge.status-added { background: rgba(158,206,106,0.18); color: var(--status-added); }
        .badge.sev-critical { background: rgba(247,118,142,0.18); color: var(--sev-critical); }
        .badge.sev-high { background: rgba(255,158,100,0.18); color: var(--sev-high); }
        .badge.sev-medium { background: rgba(224,175,104,0.18); color: var(--sev-medium); }
        .badge.sev-low { background: rgba(115,122,162,0.18); color: var(--sev-low); }
        .meta-row { font-size: 0.82em; color: var(--text-dim); margin-bottom: 4px; }
        .meta-row .mono { color: var(--text); }

        .vuln-heading {
            font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.06em;
            color: var(--text-faint); margin: 16px 0 8px 0; font-weight: 600;
        }
        .vuln-card {
            background: var(--bg); border-radius: 6px; padding: 10px 12px; margin-bottom: 8px;
            border-left: 3px solid var(--text-faint);
        }
        .vuln-card.sev-critical { border-left-color: var(--sev-critical); }
        .vuln-card.sev-high { border-left-color: var(--sev-high); }
        .vuln-card.sev-medium { border-left-color: var(--sev-medium); }
        .vuln-card.sev-low { border-left-color: var(--sev-low); }
        .vuln-card .vuln-title { font-weight: 600; font-size: 0.88em; margin-bottom: 4px; }
        .vuln-card p { margin: 4px 0 0 0; font-size: 0.82em; color: var(--text-dim); line-height: 1.4; }
        .vuln-card .badge-row { margin-bottom: 6px; }
    </style>
</head>
<body>
    <header>
        <div class="brand"><span>zairo</span> impact analysis</div>
        <div class="stats">
            <span>Nodes: <b id="stat-nodes">0</b></span>
            <span>Edges: <b id="stat-edges">0</b></span>
            <span>Modified: <b id="stat-modified">0</b></span>
            <span class="stat-high">Findings: <b id="stat-findings">0</b></span>
            <span class="stat-crit">Critical: <b id="stat-critical">0</b></span>
        </div>
    </header>
    <div class="main">
        <div id="cy"></div>
        <div id="sidebar">
            <div class="section">
                <div class="section-label">Search</div>
                <input id="search" type="text" placeholder="Filter by name..." autocomplete="off">
            </div>

            <div class="section">
                <div class="section-label">Layout</div>
                <div class="btn-row">
                    <button id="btn-dagre" class="active">Hierarchical</button>
                    <button id="btn-cose">Force-directed</button>
                </div>
            </div>

            <div class="section">
                <button id="btn-toggle" class="full">Toggle unchanged nodes</button>
            </div>

            <div class="section">
                <div class="section-label">Legend</div>
                <div class="legend-group-label">Node fill = change status</div>
                <div class="legend">
                    <div class="legend-item"><div class="dot" style="background: var(--status-added);"></div> Added</div>
                    <div class="legend-item"><div class="dot" style="background: var(--status-modified);"></div> Modified</div>
                    <div class="legend-item"><div class="dot" style="background: var(--status-unchanged);"></div> Unchanged</div>
                </div>
                <div class="legend-group-label">Border ring = worst finding severity</div>
                <div class="legend">
                    <div class="legend-item"><div class="dot ring" style="border-color: var(--sev-critical);"></div> Critical</div>
                    <div class="legend-item"><div class="dot ring" style="border-color: var(--sev-high);"></div> High</div>
                    <div class="legend-item"><div class="dot ring" style="border-color: var(--sev-medium);"></div> Medium</div>
                    <div class="legend-item"><div class="dot ring" style="border-color: var(--sev-low);"></div> Low</div>
                </div>
            </div>

            <div class="section">
                <div class="section-label">Details</div>
                <div id="node-details">
                    <div class="empty-state">Click a node to see its details.</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const graphData = {{ graph_json }};

        // Node/finding text ultimately comes from scanned source code and
        // LLM output -- neither is trusted input. Escape before it ever
        // touches innerHTML, or a crafted commit (or an LLM echoing it
        // back) can run script in whoever opens this report.
        function escapeHtml(s) {
            return String(s).replace(/[&<>"']/g, c => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[c]));
        }

        // Kept in exact sync with the --status-*/--sev-* CSS variables above
        // (Cytoscape's canvas renderer can't resolve CSS custom properties,
        // so these have to be literal hex here) -- the two scales must stay
        // disjoint, see the comment on --status-added in <style> for why.
        const STATUS_COLOR = { added: '#9ece6a', modified: '#7aa2f7', unchanged: '#414868' };
        const SEVERITY_COLOR = { critical: '#f7768e', high: '#ff9e64', medium: '#e0af68', low: '#565f89' };
        const SEVERITY_RANK = { critical: 3, high: 2, medium: 1, low: 0 };
        const KIND_SHAPE = {
            function: 'ellipse', method: 'ellipse', class: 'round-rectangle',
            module: 'round-rectangle', proxy: 'diamond'
        };

        function worstSeverity(vulns) {
            if (!vulns || vulns.length === 0) return null;
            let worst = null;
            vulns.forEach(v => {
                const sev = (v.severity || 'medium').toLowerCase();
                if (worst === null || (SEVERITY_RANK[sev] || 0) > (SEVERITY_RANK[worst] || 0)) worst = sev;
            });
            return worst;
        }

        let totalFindings = 0, totalCritical = 0, totalModified = 0;

        const elements = [];
        graphData.nodes.forEach(n => {
            const vulns = n.vulnerabilities || [];
            const worst = worstSeverity(vulns);
            totalFindings += vulns.length;
            vulns.forEach(v => { if ((v.severity || '').toLowerCase() === 'critical') totalCritical++; });
            if (n.status !== 'unchanged') totalModified++;

            const complexity = n.complexity || 1;
            const size = Math.max(26, Math.min(60, 24 + complexity * 3));

            elements.push({
                data: {
                    id: n.id,
                    name: n.name,
                    kind: n.kind || 'unknown',
                    file: n.file || 'unknown',
                    status: n.status,
                    start_line: n.start_line || '?',
                    end_line: n.end_line || '?',
                    color: STATUS_COLOR[n.status] || STATUS_COLOR.unchanged,
                    shape: KIND_SHAPE[n.kind] || 'hexagon',
                    size: size,
                    borderColor: worst ? SEVERITY_COLOR[worst] : 'transparent',
                    borderWidth: worst ? 3 : 0,
                    vulnerabilities: vulns
                }
            });
        });

        graphData.edges.forEach(e => {
            elements.push({
                data: {
                    source: e.source,
                    target: e.target,
                    kind: e.kind,
                    dashed: e.confidence && e.confidence !== 'certain'
                }
            });
        });

        document.getElementById('stat-nodes').textContent = graphData.nodes.length;
        document.getElementById('stat-edges').textContent = graphData.edges.length;
        document.getElementById('stat-modified').textContent = totalModified;
        document.getElementById('stat-findings').textContent = totalFindings;
        document.getElementById('stat-critical').textContent = totalCritical;

        if (typeof cytoscapeDagre !== 'undefined') {
            cytoscape.use( cytoscapeDagre );
        }

        const cy = cytoscape({
            container: document.getElementById('cy'),
            elements: elements,
            style: [
                {
                    selector: 'node',
                    style: {
                        'background-color': 'data(color)',
                        'shape': 'data(shape)',
                        'width': 'data(size)',
                        'height': 'data(size)',
                        'border-width': 'data(borderWidth)',
                        'border-color': 'data(borderColor)',
                        'label': 'data(name)',
                        'color': '#c0caf5',
                        'text-valign': 'bottom',
                        'text-margin-y': 6,
                        'text-outline-width': 2,
                        'text-outline-color': '#16161e',
                        'font-size': '10px'
                    }
                },
                {
                    // A third instance of the same collision class as the
                    // status/severity palette: reusing border-color here
                    // (even a different color) would still fight with the
                    // per-node severity ring on click. overlay-* draws a
                    // separate glow outside the border instead, so
                    // selection and severity never compete for the same
                    // pixels.
                    selector: 'node:selected',
                    style: { 'overlay-color': '#7aa2f7', 'overlay-opacity': 0.3, 'overlay-padding': 6 }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 1.6,
                        'line-color': '#414868',
                        'target-arrow-color': '#414868',
                        'target-arrow-shape': 'triangle',
                        'arrow-scale': 0.8,
                        'curve-style': 'bezier',
                        'label': 'data(kind)',
                        'font-size': '8px',
                        'text-rotation': 'autorotate',
                        'color': '#565f89',
                        'text-outline-width': 2,
                        'text-outline-color': '#16161e'
                    }
                },
                {
                    selector: 'edge[?dashed]',
                    style: { 'line-style': 'dashed', 'line-color': '#3b4261' }
                },
                {
                    selector: '.dimmed',
                    style: { 'opacity': 0.12 }
                }
            ],
            layout: {
                name: 'dagre'
            }
        });
        window.cy = cy; // inspectable from devtools/automation

        function severityBadge(sev) {
            if (!sev) return '';
            return `<span class="badge sev-${escapeHtml(sev)}">${escapeHtml(sev)}</span>`;
        }

        cy.on('tap', 'node', function(evt){
            const node = evt.target;
            const d = node.data();
            const worst = worstSeverity(d.vulnerabilities);

            let vulnHtml = '';
            if (d.vulnerabilities && d.vulnerabilities.length > 0) {
                vulnHtml = `<div class="vuln-heading">${d.vulnerabilities.length} finding(s)</div>`;
                d.vulnerabilities.forEach(v => {
                    const sev = (v.severity || 'medium').toLowerCase();
                    vulnHtml += `
                        <div class="vuln-card sev-${escapeHtml(sev)}">
                            <div class="badge-row">
                                ${severityBadge(sev)}
                                ${v.cwe ? `<span class="badge">${escapeHtml(v.cwe)}</span>` : ''}
                            </div>
                            <div class="vuln-title">${escapeHtml(v.title)}</div>
                            <p>${escapeHtml(v.description)}</p>
                            <p><strong>Impact:</strong> ${escapeHtml(v.impact)}</p>
                        </div>
                    `;
                });
            }

            document.getElementById('node-details').innerHTML = `
                <div class="detail-card">
                    <h2>${escapeHtml(d.name)}</h2>
                    <div class="badge-row">
                        <span class="badge">${escapeHtml(d.kind)}</span>
                        <span class="badge status-${escapeHtml(d.status)}">${escapeHtml(d.status)}</span>
                        ${worst ? severityBadge(worst) : ''}
                    </div>
                    <div class="meta-row">File: <span class="mono">${escapeHtml(d.file)}</span></div>
                    <div class="meta-row">Lines: <span class="mono">${escapeHtml(d.start_line)}-${escapeHtml(d.end_line)}</span></div>
                    ${vulnHtml}
                </div>
            `;
        });

        function setActiveLayoutButton(id) {
            document.getElementById('btn-dagre').classList.toggle('active', id === 'btn-dagre');
            document.getElementById('btn-cose').classList.toggle('active', id === 'btn-cose');
        }
        document.getElementById('btn-dagre').addEventListener('click', () => {
            cy.layout({ name: 'dagre' }).run();
            setActiveLayoutButton('btn-dagre');
        });
        document.getElementById('btn-cose').addEventListener('click', () => {
            cy.layout({ name: 'cose' }).run();
            setActiveLayoutButton('btn-cose');
        });

        let showUnchanged = true;
        const toggleBtn = document.getElementById('btn-toggle');
        toggleBtn.addEventListener('click', () => {
            showUnchanged = !showUnchanged;
            toggleBtn.classList.toggle('active', !showUnchanged);
            if (showUnchanged) {
                cy.nodes('[status = "unchanged"]').show();
            } else {
                cy.nodes('[status = "unchanged"]').hide();
            }
        });

        document.getElementById('search').addEventListener('input', (evt) => {
            const query = evt.target.value.trim().toLowerCase();
            if (!query) {
                cy.elements().removeClass('dimmed');
                return;
            }
            cy.nodes().forEach(n => {
                const match = (n.data('name') || '').toLowerCase().includes(query);
                n.toggleClass('dimmed', !match);
            });
            cy.edges().forEach(e => {
                const match = !e.source().hasClass('dimmed') && !e.target().hasClass('dimmed');
                e.toggleClass('dimmed', !match);
            });
        });
    </script>
</body>
</html>
"""

def generate_reports(
    graph_data: dict,
    output_dir: str,
    vulnerabilities: dict = None,
    repo_root: str = None,
    tool_version: str = "0.0.0",
):
    """Returns (json_path, html_path, sarif_path). sarif_path is None unless
    an LLM scan actually ran (vulnerabilities is not None, including when it
    ran and found nothing) -- there's nothing meaningful to convert to SARIF
    otherwise."""
    os.makedirs(output_dir, exist_ok=True)

    # Attach vulnerabilities to graph_data
    if vulnerabilities:
        for node in graph_data['nodes']:
            if node['id'] in vulnerabilities:
                node['vulnerabilities'] = vulnerabilities[node['id']]

    json_path = os.path.join(output_dir, "report.json")
    html_path = os.path.join(output_dir, "report.html")

    with open(json_path, 'w') as f:
        json.dump(graph_data, f, indent=2)

    template = Template(HTML_TEMPLATE)
    html_content = template.render(graph_json=json.dumps(graph_data))

    with open(html_path, 'w') as f:
        f.write(html_content)

    sarif_path = None
    if vulnerabilities is not None:
        sarif_data = build_sarif(graph_data, vulnerabilities, repo_root or output_dir, tool_version)
        sarif_path = os.path.join(output_dir, "report.sarif")
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f, indent=2)

    return json_path, html_path, sarif_path
