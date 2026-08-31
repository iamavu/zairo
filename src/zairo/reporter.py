import json
import os
from jinja2 import Template

from .sarif import build_sarif

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Zairo Impact Analysis</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js" integrity="sha512-RcuA+PEnJcg1caTn53YLhZ3bYVFXphzcPL1BjBoAwFiA3bErav+AndZz1xrqpAtv/8Waep2X+9zn8KWpwacUSA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js" integrity="sha512-psLUZfcgPmi012lcpVHkWoOqyztollwCGu4w/mXijFMK/YcdUdP06voJNVOJ7f/dUIlO2tGlDLuypRyXX2lcvQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js" integrity="sha384-EHCdyFVbhtbpgI+4x7ETlZUvJwOkxJublmhTpH114NSk3fqfiUgcLl6pQm8JQwg9" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
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
            --status-deleted: #bb9af7;

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
            display: flex; align-items: center; gap: 20px; flex-wrap: wrap;
            padding: 10px 20px; background: var(--panel);
            border-bottom: 1px solid var(--border); flex-shrink: 0;
        }
        header .brand { font-weight: 700; font-size: 1.05em; letter-spacing: 0.02em; flex-shrink: 0; }
        header .brand span { color: var(--accent); }

        /* Global controls (search, layout/visibility toggles) live in the
           header -- they act on the whole graph, not on whatever's
           currently selected, so they don't belong in the sidebar. */
        .header-controls { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }

        input#search {
            width: 170px; padding: 7px 10px; background: var(--panel-2);
            border: 1px solid var(--border); border-radius: 6px; color: var(--text);
            font-size: 0.82em; outline: none;
        }
        input#search:focus { border-color: var(--accent); }

        .toggle-group { display: flex; align-items: center; gap: 12px; }
        .toggle {
            display: flex; align-items: center; gap: 7px; font-size: 0.8em;
            color: var(--text-dim); cursor: pointer; user-select: none;
        }
        .toggle input { position: absolute; opacity: 0; width: 0; height: 0; }
        .toggle .track {
            width: 30px; height: 16px; border-radius: 100px; flex-shrink: 0;
            background: var(--panel-2); border: 1px solid var(--border);
            position: relative; transition: background 0.15s ease, border-color 0.15s ease;
        }
        .toggle .track::after {
            content: ''; position: absolute; top: 1px; left: 1px;
            width: 12px; height: 12px; border-radius: 50%; background: var(--text-faint);
            transition: transform 0.15s ease, background 0.15s ease;
        }
        .toggle input:checked + .track { background: rgba(122,162,247,0.25); border-color: var(--accent); }
        .toggle input:checked + .track::after { transform: translateX(14px); background: var(--accent); }
        .toggle input:focus-visible + .track { outline: 2px solid var(--accent); outline-offset: 2px; }

        .stats { display: flex; gap: 18px; margin-left: auto; font-size: 0.85em; color: var(--text-dim); flex-shrink: 0; }
        .stats b { color: var(--text); font-weight: 600; }
        .stats .stat-crit b { color: var(--sev-critical); }
        .stats .stat-high b { color: var(--sev-high); }

        .main { flex: 1; display: flex; min-height: 0; position: relative; }
        #cy { flex: 1; height: 100%; }

        /* Floats over the bottom-left of the graph canvas instead of
           taking up permanent sidebar space -- it's reference material for
           reading the graph, not something that needs to always be visible
           at full size. */
        .legend-panel {
            position: absolute; bottom: 16px; left: 16px; z-index: 5;
            background: rgba(26,27,38,0.94); border: 1px solid var(--border);
            border-radius: 8px; padding: 12px 14px; max-width: 220px;
        }
        .legend { display: flex; flex-direction: column; gap: 6px; font-size: 0.8em; margin-bottom: 10px; }
        .legend:last-child { margin-bottom: 0; }
        .legend-item { display: flex; align-items: center; gap: 8px; color: var(--text-dim); }
        .legend-group-label { font-size: 0.7em; color: var(--text-faint); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.04em; }
        .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
        .dot.ring { background: transparent; border: 2px solid; box-sizing: content-box; width: 6px; height: 6px; }
        .dot.deleted { background: transparent; border: 2px dashed; box-sizing: content-box; width: 6px; height: 6px; opacity: 0.75; }

        #sidebar {
            width: 320px; flex-shrink: 0; height: 100%; background: var(--panel);
            padding: 16px; box-sizing: border-box; overflow-y: auto; overflow-wrap: anywhere;
            border-left: 1px solid var(--border);
        }

        .empty-state {
            display: flex; flex-direction: column; align-items: center; gap: 8px;
            color: var(--text-faint); font-size: 0.85em; text-align: center;
            padding: 40px 16px; border: 1px dashed var(--border); border-radius: 8px;
        }
        .empty-state .icon { font-size: 1.6em; opacity: 0.5; }

        .detail-card { background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
        .detail-card h2 { margin: 0 0 10px 0; font-size: 1em; color: var(--text); overflow-wrap: anywhere; }
        .badge-row { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
        .badge {
            font-size: 0.72em; padding: 2px 8px; border-radius: 100px; font-weight: 600;
            background: var(--border); color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.03em;
            white-space: nowrap;
        }
        .badge.status-modified { background: rgba(122,162,247,0.18); color: var(--status-modified); }
        .badge.status-added { background: rgba(158,206,106,0.18); color: var(--status-added); }
        .badge.status-deleted { background: rgba(187,154,247,0.18); color: var(--status-deleted); }
        .badge.sev-critical { background: rgba(247,118,142,0.18); color: var(--sev-critical); }
        .badge.sev-high { background: rgba(255,158,100,0.18); color: var(--sev-high); }
        .badge.sev-medium { background: rgba(224,175,104,0.18); color: var(--sev-medium); }
        .badge.sev-low { background: rgba(115,122,162,0.18); color: var(--sev-low); }
        .meta-row { font-size: 0.82em; color: var(--text-dim); margin-bottom: 4px; overflow-wrap: anywhere; }
        .meta-row .mono { color: var(--text); overflow-wrap: anywhere; }

        .vuln-heading {
            font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.06em;
            color: var(--text-faint); margin: 16px 0 8px 0; font-weight: 600;
        }
        .vuln-card {
            background: var(--bg); border-radius: 6px; padding: 10px 12px; margin-bottom: 8px;
            overflow-wrap: anywhere;
        }
        .vuln-card .vuln-title { font-weight: 600; font-size: 0.88em; margin-bottom: 4px; }
        .vuln-card p { margin: 4px 0 0 0; font-size: 0.82em; color: var(--text-dim); line-height: 1.4; }
        .vuln-card .badge-row { margin-bottom: 6px; }
    </style>
</head>
<body>
    <header>
        <div class="brand"><span>zairo</span> impact analysis</div>
        <div class="header-controls">
            <input id="search" type="text" placeholder="Filter by name..." autocomplete="off">
            <div class="toggle-group">
                <label class="toggle">
                    <input type="checkbox" id="toggle-unchanged" checked>
                    <span class="track"></span>
                    Unchanged
                </label>
                <label class="toggle">
                    <input type="checkbox" id="toggle-deleted" checked>
                    <span class="track"></span>
                    Deleted
                </label>
            </div>
        </div>
        <div class="stats">
            <span>Modified: <b id="stat-modified">0</b></span>
            <span>Deleted: <b id="stat-deleted">0</b></span>
            <span class="stat-high">Findings: <b id="stat-findings">0</b></span>
            <span class="stat-crit">Critical: <b id="stat-critical">0</b></span>
        </div>
    </header>
    <div class="main">
        <div id="cy"></div>
        <div class="legend-panel">
            <div class="legend-group-label">Node fill = change status</div>
            <div class="legend">
                <div class="legend-item"><div class="dot" style="background: var(--status-added);"></div> Added</div>
                <div class="legend-item"><div class="dot" style="background: var(--status-modified);"></div> Modified</div>
                <div class="legend-item"><div class="dot" style="background: var(--status-unchanged);"></div> Unchanged</div>
                <div class="legend-item"><div class="dot deleted" style="border-color: var(--status-deleted);"></div> Deleted</div>
            </div>
            <div class="legend-group-label">Border ring = worst finding severity</div>
            <div class="legend">
                <div class="legend-item"><div class="dot ring" style="border-color: var(--sev-critical);"></div> Critical</div>
                <div class="legend-item"><div class="dot ring" style="border-color: var(--sev-high);"></div> High</div>
                <div class="legend-item"><div class="dot ring" style="border-color: var(--sev-medium);"></div> Medium</div>
                <div class="legend-item"><div class="dot ring" style="border-color: var(--sev-low);"></div> Low</div>
            </div>
        </div>
        <div id="sidebar">
            <div id="node-details">
                <div class="empty-state">
                    <div class="icon">◇</div>
                    <div>Select a node to see its details</div>
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
        const STATUS_COLOR = { added: '#9ece6a', modified: '#7aa2f7', unchanged: '#414868', deleted: '#bb9af7' };
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

        let totalFindings = 0, totalCritical = 0, totalModified = 0, totalDeleted = 0;

        // "contains" edges (module -> the functions/classes it defines) are
        // rendered as Cytoscape compound nesting -- a subtle box drawn
        // around a node's children -- instead of arrows. An arrow for every
        // single definition in a file added a lot of visual noise for a
        // relationship a containing box already shows more simply, and
        // reads more like the file/folder structure it actually is.
        const parentOf = {};
        graphData.edges.forEach(e => {
            if (e.kind === 'contains') parentOf[e.target] = e.source;
        });
        const parentIds = new Set(Object.values(parentOf));

        const elements = [];
        graphData.nodes.forEach(n => {
            const vulns = n.vulnerabilities || [];
            const worst = worstSeverity(vulns);
            const isDeleted = n.status === 'deleted';
            const isParent = parentIds.has(n.id);
            totalFindings += vulns.length;
            vulns.forEach(v => { if ((v.severity || '').toLowerCase() === 'critical') totalCritical++; });
            if (isDeleted) totalDeleted++;
            else if (n.status !== 'unchanged') totalModified++;

            const complexity = n.complexity || 1;
            const size = Math.max(26, Math.min(60, 24 + complexity * 3));
            const color = STATUS_COLOR[n.status] || STATUS_COLOR.unchanged;

            const data = {
                id: n.id,
                name: n.name,
                kind: n.kind || 'unknown',
                file: n.file || 'unknown',
                status: n.status,
                start_line: n.start_line || '?',
                end_line: n.end_line || '?',
                color: color,
                shape: KIND_SHAPE[n.kind] || 'hexagon',
                size: size,
                // A deleted node never has findings (it's never sent to
                // the LLM scanner -- there's no live source left to
                // scan), so it always falls to its own status color as
                // a baseline ring; a real severity ring still wins where
                // both could apply. A container with neither still gets a
                // faint 1px outline in its own color -- barely-there, but
                // enough that its boundary reads as intentional rather than
                // like a rendering glitch.
                borderColor: worst ? SEVERITY_COLOR[worst] : (isDeleted ? STATUS_COLOR.deleted : (isParent ? color : 'transparent')),
                borderWidth: worst ? 3 : (isDeleted ? 2 : (isParent ? 1 : 0)),
                deleted: isDeleted,
                vulnerabilities: vulns
            };
            // Cytoscape treats an explicit parent:undefined the same as a
            // dangling reference to a nonexistent node -- omit the key
            // entirely for a top-level (unparented) node instead.
            if (parentOf[n.id]) data.parent = parentOf[n.id];
            elements.push({ data });
        });

        graphData.edges.forEach(e => {
            if (e.kind === 'contains') return; // expressed as compound nesting above, not an arrow
            elements.push({
                data: {
                    source: e.source,
                    target: e.target,
                    kind: e.kind,
                    dashed: e.confidence && e.confidence !== 'certain'
                }
            });
        });

        document.getElementById('stat-modified').textContent = totalModified;
        document.getElementById('stat-deleted').textContent = totalDeleted;
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
                        'font-size': '10px'
                    }
                },
                {
                    // :parent matches a compound node (one with children --
                    // see parentOf above). Cytoscape auto-sizes these to fit
                    // their children regardless of the width/height mapped
                    // above (verified: compound bounds come from layout, not
                    // style), so this only needs to override the *look* --
                    // a subtle translucent box instead of a small filled
                    // shape, label on top like a heading rather than below
                    // like a leaf node's. border-color/-width stay data-
                    // driven so a module with its own finding still shows
                    // a real severity ring, not just the subtle default.
                    selector: ':parent',
                    style: {
                        'background-color': 'data(color)',
                        'background-opacity': 0.10,
                        'border-width': 'data(borderWidth)',
                        'border-color': 'data(borderColor)',
                        'border-opacity': 0.6,
                        'shape': 'round-rectangle',
                        'label': 'data(name)',
                        'color': '#c0caf5',
                        'text-valign': 'top',
                        'text-halign': 'center',
                        'text-margin-y': -6,
                        'font-size': '10px',
                        'font-weight': '600',
                        'text-outline-width': 2,
                        'text-outline-color': '#16161e',
                        'padding': '18px'
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
                    // No-longer-exists reads as dashed + faded, on top of
                    // whatever border color it already got above (its own
                    // status color as a baseline, or a severity ring if it
                    // somehow has one) -- a deleted node needs to look
                    // distinctly "gone", not just differently colored.
                    selector: 'node[?deleted]',
                    style: { 'border-style': 'dashed', 'opacity': 0.65 }
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
                    </div>
                    <div class="meta-row">${d.deleted ? 'Was at' : 'File'}: <span class="mono">${escapeHtml(d.file)}</span></div>
                    <div class="meta-row">Lines: <span class="mono">${escapeHtml(d.start_line)}-${escapeHtml(d.end_line)}</span></div>
                    ${vulnHtml}
                </div>
            `;
        });

        // Layout must run on cy.elements(':visible'), not the whole graph --
        // a layout run over hidden elements still reserves their space (a
        // dagre rank still gets allocated) even though nothing is drawn
        // there, so the visible nodes never actually close the gap.
        // Restricting the collection is what makes them redistribute into
        // the freed-up space instead of just holding their old positions.
        const relayout = () => cy.elements(':visible').layout({ name: 'dagre' }).run();

        document.getElementById('toggle-unchanged').addEventListener('change', (evt) => {
            const nodes = cy.nodes('[status = "unchanged"]');
            if (evt.target.checked) nodes.show(); else nodes.hide();
            relayout();
        });

        document.getElementById('toggle-deleted').addEventListener('change', (evt) => {
            const nodes = cy.nodes('[?deleted]');
            if (evt.target.checked) nodes.show(); else nodes.hide();
            relayout();
        });

        document.getElementById('search').addEventListener('input', (evt) => {
            const query = evt.target.value.trim().toLowerCase();
            if (!query) {
                cy.elements().removeClass('dimmed');
                return;
            }
            const nameMatches = n => (n.data('name') || '').toLowerCase().includes(query);
            cy.nodes().forEach(n => {
                // A compound container's opacity cascades down to its
                // children (Cytoscape multiplies effective opacity up the
                // ancestor chain), so dimming a container would dim a
                // matching node nested inside it too. A container stays
                // undimmed whenever any descendant matches, not just itself.
                const match = nameMatches(n) || (n.isParent() && n.descendants().some(nameMatches));
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
    html_content = template.render(graph_json=_json_for_script(graph_data))

    with open(html_path, 'w') as f:
        f.write(html_content)

    sarif_path = None
    if vulnerabilities is not None:
        sarif_data = build_sarif(graph_data, vulnerabilities, repo_root or output_dir, tool_version)
        sarif_path = os.path.join(output_dir, "report.sarif")
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f, indent=2)

    return json_path, html_path, sarif_path
