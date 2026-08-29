import os
from typing import Any, Callable, Dict, Optional
from trailmark.query.api import QueryEngine
from .git_utils import get_modified_lines
from ._util import display_name as _display_name


def _enum_value(x: Any, default: str = "unknown") -> str:
    """Trailmark graph fields (node kind, edge kind, edge confidence) are
    enums with a `.value`, except on a malformed/dangling reference where
    the field can come through as a bare string or be missing entirely --
    normalize either shape to a plain string instead of typing this check
    out again at each call site."""
    if x is None:
        return default
    return x.value if hasattr(x, 'value') else str(x)


def analyze_impact(
    repo_path: str,
    depth: int = 1,
    base: str = None,
    target: str = None,
    language: str = "auto",
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    `repo_path` must already be checked out at the state to be indexed: the
    caller is responsible for pointing it at a worktree checked out to
    `target` when diffing two commits, so that node locations/contents line
    up with the line numbers `git diff base target` reports.
    """
    log = log or (lambda msg: None)

    analysis_root = os.path.abspath(repo_path)

    modified_files_lines = get_modified_lines(analysis_root, base, target, log=log)
    log(f"git diff found {len(modified_files_lines)} modified file(s):")
    for f, lines in modified_files_lines.items():
        log(f"  {f}: {len(lines)} line(s) changed -> {sorted(lines.keys())}")

    # Initialize Trailmark
    log(f"Indexing {analysis_root} with Trailmark (language={language})...")
    engine = QueryEngine.from_directory(analysis_root, language=language)
    total_nodes = len(engine._store._graph.nodes)
    total_edges = len(engine._store._graph.edges)
    log(f"Trailmark graph: {total_nodes} node(s), {total_edges} edge(s)")

    # 1. Identify seed nodes (modified/added)
    seed_nodes = set()
    node_metadata = {}

    for node_id, node in engine._store._graph.nodes.items():
        node_metadata[node_id] = {
            "id": node_id,
            "name": getattr(node, 'name', node_id),
            "kind": _enum_value(getattr(node, 'kind', None)),
            "file": node.location.file_path if getattr(node, 'location', None) else None,
            "start_line": node.location.start_line if getattr(node, 'location', None) else None,
            "end_line": node.location.end_line if getattr(node, 'location', None) else None,
            "complexity": getattr(node, 'cyclomatic_complexity', 0),
            "status": "unchanged" # default
        }

        if getattr(node, 'location', None) and node.location.file_path in modified_files_lines:
            file_mod_lines = modified_files_lines[node.location.file_path]
            start = node.location.start_line
            end = node.location.end_line
            changed_lines = {ln: text for ln, text in file_mod_lines.items() if start <= ln <= end}
            if changed_lines:
                seed_nodes.add(node_id)
                node_metadata[node_id]["status"] = "modified"
                node_metadata[node_id]["changed_lines"] = changed_lines
                log(f"  seed: {_display_name(node_metadata[node_id]['name'])} ({node.location.file_path}:{start}-{end}), {len(changed_lines)} line(s) changed")

    log(f"Identified {len(seed_nodes)} seed node(s)")

    # 2. Traverse graph to build subgraph up to `depth`
    subgraph_nodes = set(seed_nodes)
    current_frontier = set(seed_nodes)

    for hop in range(depth):
        next_frontier = set()
        for edge in engine._store._graph.edges:
            source = edge.source_id
            edge_target = edge.target_id

            if source in current_frontier and edge_target not in subgraph_nodes:
                next_frontier.add(edge_target)
                subgraph_nodes.add(edge_target)
            elif edge_target in current_frontier and source not in subgraph_nodes:
                next_frontier.add(source)
                subgraph_nodes.add(source)

        log(f"Hop {hop + 1}/{depth}: added {len(next_frontier)} node(s), frontier now {len(subgraph_nodes)} total")
        current_frontier = next_frontier

    # Extract edges for subgraph
    final_edges = []
    for edge in engine._store._graph.edges:
        if edge.source_id in subgraph_nodes and edge.target_id in subgraph_nodes:
            final_edges.append({
                "source": edge.source_id,
                "target": edge.target_id,
                "kind": _enum_value(getattr(edge, 'kind', None)),
                "confidence": _enum_value(getattr(edge, 'confidence', None)),
            })

    nodes = []
    for n_id in subgraph_nodes:
        # An edge can reference a node id Trailmark's own graph has no entry
        # for (a dangling/malformed reference -- seen from complex chained
        # expressions like `.map(fn).filter(...)`). The fallback must carry
        # the same fields as a normal node, or downstream code that assumes
        # e.g. 'file' always exists (to read source for LLM context) crashes
        # with a bare KeyError on this one bad node instead of just treating
        # it as having no known location.
        nodes.append(node_metadata.get(n_id, {
            "id": n_id,
            "name": n_id,
            "kind": "unknown",
            "file": None,
            "start_line": None,
            "end_line": None,
            "complexity": 0,
            "status": "unchanged",
        }))

    return {
        "nodes": nodes,
        "edges": final_edges
    }
