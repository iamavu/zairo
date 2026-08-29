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
        body { font-family: sans-serif; margin: 0; padding: 0; display: flex; height: 100vh; background-color: #1e1e1e; color: #fff;}
        #cy { width: 80%; height: 100%; }
        #sidebar { width: 20%; height: 100%; background: #252526; padding: 20px; box-sizing: border-box; overflow-y: auto; border-left: 1px solid #3c3c3c;}
        h1 { font-size: 1.2em; border-bottom: 1px solid #3c3c3c; padding-bottom: 10px; }
        .details { margin-top: 20px; font-size: 0.9em; }
        .details strong { color: #4fc1ff; }
        button { background: #0e639c; color: white; border: none; padding: 8px 12px; cursor: pointer; margin-bottom: 10px; width: 100%; }
        button:hover { background: #1177bb; }
        .legend { margin-top: 20px; font-size: 0.9em; border-top: 1px solid #3c3c3c; padding-top: 10px;}
        .legend-item { display: flex; align-items: center; margin-bottom: 5px; }
        .color-box { width: 15px; height: 15px; margin-right: 10px; }
    </style>
</head>
<body>
    <div id="cy"></div>
    <div id="sidebar">
        <h1>Zairo Impact</h1>
        <button id="btn-dagre">Layout: Hierarchical</button>
        <button id="btn-cose">Layout: Force-Directed</button>
        <button id="btn-toggle">Toggle Unchanged Nodes</button>
        
        <div class="legend">
            <div class="legend-item"><div class="color-box" style="background: #4CAF50;"></div> Added</div>
            <div class="legend-item"><div class="color-box" style="background: #d7ba7d;"></div> Modified</div>
            <div class="legend-item"><div class="color-box" style="background: #808080;"></div> Unchanged</div>
        </div>

        <div class="details" id="node-details">
            <p>Click a node to see details.</p>
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

        const elements = [];
        graphData.nodes.forEach(n => {
            let color = '#808080';
            if (n.status === 'modified') color = '#d7ba7d';
            if (n.status === 'added') color = '#4CAF50';
            
            // Add red border if vulnerable
            let borderColor = n.vulnerabilities && n.vulnerabilities.length > 0 ? '#ff0000' : 'transparent';
            let borderWidth = n.vulnerabilities && n.vulnerabilities.length > 0 ? 3 : 0;
            
            elements.push({
                data: {
                    id: n.id,
                    name: n.name,
                    kind: n.kind || 'unknown',
                    file: n.file || 'unknown',
                    status: n.status,
                    start_line: n.start_line || '?',
                    end_line: n.end_line || '?',
                    color: color,
                    borderColor: borderColor,
                    borderWidth: borderWidth,
                    vulnerabilities: n.vulnerabilities || []
                }
            });
        });
        
        graphData.edges.forEach(e => {
            elements.push({
                data: {
                    source: e.source,
                    target: e.target,
                    kind: e.kind
                }
            });
        });

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
                        'border-width': 'data(borderWidth)',
                        'border-color': 'data(borderColor)',
                        'label': 'data(name)',
                        'color': '#fff',
                        'text-valign': 'center',
                        'text-outline-width': 2,
                        'text-outline-color': '#222',
                        'font-size': '10px'
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 2,
                        'line-color': '#555',
                        'target-arrow-color': '#555',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'label': 'data(kind)',
                        'font-size': '8px',
                        'text-rotation': 'autorotate',
                        'color': '#888'
                    }
                }
            ],
            layout: {
                name: 'dagre'
            }
        });

        cy.on('tap', 'node', function(evt){
            const node = evt.target;
            const d = node.data();
            let vulnHtml = '';
            if (d.vulnerabilities && d.vulnerabilities.length > 0) {
                vulnHtml = '<h3 style="color:#ff4444; margin-top:10px;">Vulnerabilities Found:</h3>';
                d.vulnerabilities.forEach(v => {
                    vulnHtml += `
                        <div style="background:#440000; padding:10px; margin-bottom:10px; border-left: 3px solid #ff0000;">
                            <strong>${escapeHtml(v.title)}</strong> (Impact: ${escapeHtml(v.impact)})<br>
                            <p style="margin-top:5px; margin-bottom:0;">${escapeHtml(v.description)}</p>
                        </div>
                    `;
                });
            }

            document.getElementById('node-details').innerHTML = `
                <p><strong>Name:</strong> ${escapeHtml(d.name)}</p>
                <p><strong>ID:</strong> ${escapeHtml(d.id)}</p>
                <p><strong>Kind:</strong> ${escapeHtml(d.kind)}</p>
                <p><strong>Status:</strong> ${escapeHtml(d.status)}</p>
                <p><strong>File:</strong> ${escapeHtml(d.file)}</p>
                <p><strong>Lines:</strong> ${escapeHtml(d.start_line)} - ${escapeHtml(d.end_line)}</p>
                ${vulnHtml}
            `;
        });

        document.getElementById('btn-dagre').addEventListener('click', () => {
            cy.layout({ name: 'dagre' }).run();
        });
        document.getElementById('btn-cose').addEventListener('click', () => {
            cy.layout({ name: 'cose' }).run();
        });
        
        let showUnchanged = true;
        document.getElementById('btn-toggle').addEventListener('click', () => {
            showUnchanged = !showUnchanged;
            if (showUnchanged) {
                cy.nodes('[status = "unchanged"]').show();
            } else {
                cy.nodes('[status = "unchanged"]').hide();
            }
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
