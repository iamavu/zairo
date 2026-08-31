import json
import os
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from trailmark import parse_directory
from trailmark.query.api import QueryEngine
from .git_utils import get_changed_file_paths, get_modified_lines
from ._util import display_name as _display_name


def _find_deleted_nodes(
    repo_path: str,
    changed_files: List[str],
    base_ref: str,
    target_node_ids: Set[str],
    language: str,
    log: Callable[[str], None],
) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    """Detects functions/classes/modules that existed in `base_ref` but have
    no corresponding id in the target graph at all -- deleted outright, not
    just edited. Trailmark's target-tree graph can never represent these on
    its own (it only ever parses the tree as it currently is).

    Reconstructs each changed file's base-ref content under a fresh temp
    directory at its correct relative path, then parses that directory as
    one batch with Trailmark's public parse_directory(). The relative path
    matters: Trailmark computes a node's id from its path relative to the
    parsed root (e.g. "src.utils.helpers:parse"), so parsing a file in
    isolation elsewhere produces a different id than the same file gets
    when the real repo is parsed, and nothing would match target_node_ids.

    Returns (deleted_node_metadata, deleted_edges) in the same shapes
    analyze_impact already builds for regular nodes/edges. Never raises --
    a base revision can contain content the installed Trailmark can't parse
    (syntax it doesn't support, a binary file, ...), which has nothing to
    do with whether the current analysis should succeed; any failure here
    just means deletions aren't detected for this run, logged not fatal.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="zairo-deleted-") as tmp_dir:
            found_any = False
            for rel_path in changed_files:
                result = subprocess.run(
                    ["git", "show", f"{base_ref}:{rel_path}"],
                    cwd=repo_path, capture_output=True, text=True,
                )
                if result.returncode != 0:
                    continue  # didn't exist at base_ref (a newly added file) -- nothing to compare
                dest = os.path.join(tmp_dir, rel_path)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, 'w', encoding='utf-8', errors='surrogateescape') as f:
                    f.write(result.stdout)
                found_any = True

            if not found_any:
                return {}, []

            base_graph = parse_directory(tmp_dir, language=language)

            deleted_metadata = {}
            for node_id, unit in base_graph.nodes.items():
                if node_id in target_node_ids or unit.kind.value == 'proxy':
                    continue
                location = unit.location
                # location.file_path points into tmp_dir, which is gone the
                # moment this `with` block exits -- rewrite it to where that
                # file would be under the real repo, consistent with every
                # other node's 'file' convention (even though the deleted
                # code obviously can't be read from there anymore).
                rel = os.path.relpath(location.file_path, tmp_dir)
                deleted_metadata[node_id] = {
                    "id": node_id,
                    "name": unit.name,
                    "kind": unit.kind.value,
                    "file": os.path.join(repo_path, rel),
                    "start_line": location.start_line,
                    "end_line": location.end_line,
                    "complexity": unit.cyclomatic_complexity,
                    "status": "deleted",
                }

            deleted_edges = [
                {"source": e.source_id, "target": e.target_id, "kind": e.kind.value, "confidence": e.confidence.value}
                for e in base_graph.edges
            ]
            return deleted_metadata, deleted_edges
    except Exception as e:
        log(f"Skipping deleted-node detection: could not parse {base_ref} ({e})")
        return {}, []


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
    # engine.to_json() is Trailmark's public serialization of the graph --
    # unlike reaching into engine._store._graph (two layers of underscore-
    # prefixed internals with no stability contract; even Trailmark's own
    # to_json() has to do that same reach internally, with a lint
    # suppression acknowledging it's not meant to be public), this is the
    # one interface Trailmark commits to keeping working. indent=None since
    # the pretty-printing is wasted work on a string we immediately reparse.
    graph = json.loads(engine.to_json(indent=None))
    graph_nodes: Dict[str, Any] = graph["nodes"]  # {node_id: unit_dict}
    graph_edges = graph["edges"]  # [{"source", "target", "kind", "confidence", ...}]
    log(f"Trailmark graph: {len(graph_nodes)} node(s), {len(graph_edges)} edge(s)")

    # 1. Identify seed nodes (modified/added)
    seed_nodes = set()
    node_metadata = {}

    for node_id, unit in graph_nodes.items():
        location = unit["location"]
        node_metadata[node_id] = {
            "id": node_id,
            "name": unit["name"],
            "kind": unit["kind"],
            "file": location["file_path"],
            "start_line": location["start_line"],
            "end_line": location["end_line"],
            "complexity": unit["cyclomatic_complexity"],
            "status": "unchanged" # default
        }

        if location["file_path"] in modified_files_lines:
            file_mod_lines = modified_files_lines[location["file_path"]]
            start = location["start_line"]
            end = location["end_line"]
            changed_lines = {ln: text for ln, text in file_mod_lines.items() if start <= ln <= end}
            if changed_lines:
                seed_nodes.add(node_id)
                node_metadata[node_id]["status"] = "modified"
                node_metadata[node_id]["changed_lines"] = changed_lines
                log(f"  seed: {_display_name(node_metadata[node_id]['name'])} ({location['file_path']}:{start}-{end}), {len(changed_lines)} line(s) changed")

    log(f"Identified {len(seed_nodes)} seed node(s)")

    # 2. Traverse graph to build subgraph up to `depth`
    subgraph_nodes = set(seed_nodes)
    current_frontier = set(seed_nodes)

    for hop in range(depth):
        next_frontier = set()
        for edge in graph_edges:
            source = edge["source"]
            edge_target = edge["target"]

            if source in current_frontier and edge_target not in subgraph_nodes:
                next_frontier.add(edge_target)
                subgraph_nodes.add(edge_target)
            elif edge_target in current_frontier and source not in subgraph_nodes:
                next_frontier.add(source)
                subgraph_nodes.add(source)

        log(f"Hop {hop + 1}/{depth}: added {len(next_frontier)} node(s), frontier now {len(subgraph_nodes)} total")
        current_frontier = next_frontier

    # 3. Deleted nodes -- present in the base revision, absent from the
    # target graph entirely (not just outside the traversal depth above).
    # Always treated as seeds, like modified/added, since a deletion is
    # itself the primary change of interest, not something reached by
    # traversing from one.
    effective_base = base or "HEAD"
    changed_file_paths = get_changed_file_paths(analysis_root, base, target, log=log)
    deleted_metadata, deleted_edges = _find_deleted_nodes(
        analysis_root, changed_file_paths, effective_base, set(graph_nodes.keys()), language, log,
    )
    if deleted_metadata:
        log(f"Found {len(deleted_metadata)} deleted node(s) (present in {effective_base}, absent from the current tree)")
        subgraph_nodes.update(deleted_metadata.keys())
        node_metadata.update(deleted_metadata)

    # Extract edges for subgraph -- base-revision edges included (filtered
    # by the same rule) so deleted nodes still connect to whatever
    # surviving node used to contain or call them. Deduplicated: a node that
    # exists unchanged on both sides (e.g. the module containing a deleted
    # function) contributes the identical edge from both graph_edges and
    # deleted_edges.
    seen_edges = set()
    final_edges = []
    for edge in (graph_edges + deleted_edges):
        if edge["source"] not in subgraph_nodes or edge["target"] not in subgraph_nodes:
            continue
        key = (edge["source"], edge["target"], edge["kind"], edge["confidence"])
        if key in seen_edges:
            continue
        seen_edges.add(key)
        final_edges.append({"source": edge["source"], "target": edge["target"], "kind": edge["kind"], "confidence": edge["confidence"]})

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
