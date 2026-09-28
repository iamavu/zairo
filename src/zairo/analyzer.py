import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from trailmark import parse_directory
from .git_utils import get_changed_file_paths, get_diff_hunks, hunk_lines, hunks_in_range
from ._util import display_name as _display_name

# Cap on how many `git show` subprocesses run at once in _find_deleted_nodes.
# Each is I/O-bound (process spawn + reading one blob out of git's object
# store), not CPU-bound, so well beyond the CPU count is fine -- but an
# unbounded pool on a diff touching tens of thousands of files would spawn
# that many git processes simultaneously.
_MAX_GIT_SHOW_WORKERS = 32


def _edge_dict(edge, with_line: bool = True) -> Dict[str, Any]:
    """A Trailmark edge as a plain dict. `line` is where in the source node's
    file the edge occurs -- for a call, the call site -- when Trailmark
    knows it (it reports 0 for "unknown" in places)."""
    location = edge.location if with_line else None
    return {
        "source": edge.source_id,
        "target": edge.target_id,
        "kind": edge.kind.value,
        "confidence": edge.confidence.value,
        "line": location.start_line if location and location.start_line > 0 else None,
    }


def _node_name(unit, root: str) -> str:
    """A module goes by its file's path under `root` ("src/utils/merge-with.spec.ts")
    rather than Trailmark's name for it, a dotted id that has to escape any
    dot in a file or directory name ("src.utils.merge-with\\.spec"). The
    node's id stays Trailmark's."""
    if unit.kind.value != 'module':
        return unit.name
    try:
        rel = os.path.relpath(unit.location.file_path, root)
    except ValueError:  # another drive, on Windows
        return unit.name
    outside = rel == os.pardir or rel.startswith(os.pardir + os.sep)
    return unit.name if outside else rel.replace(os.sep, '/')


def _find_deleted_nodes(
    repo_path: str,
    changed_files: List[str],
    from_ref: str,
    to_node_ids: Set[str],
    language: str,
    log: Callable[[str], None],
) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    """Detects functions/classes/modules that existed in `from_ref` but have
    no corresponding id in the to-side graph at all -- deleted outright, not
    just edited. Trailmark's to-side graph can never represent these on its
    own (it only ever parses the tree as it currently is).

    Reconstructs each changed file's from_ref content under a fresh temp
    directory at its correct relative path, then parses that directory as
    one batch with Trailmark's public parse_directory(). The relative path
    matters: Trailmark computes a node's id from its path relative to the
    parsed root (e.g. "src.utils.helpers:parse"), so parsing a file in
    isolation elsewhere produces a different id than the same file gets
    when the real repo is parsed, and nothing would match to_node_ids.

    Returns (deleted_node_metadata, deleted_edges) in the same shapes
    analyze_impact already builds for regular nodes/edges. Never raises --
    a from_ref revision can contain content the installed Trailmark can't parse
    (syntax it doesn't support, a binary file, ...), which has nothing to
    do with whether the current analysis should succeed; any failure here
    just means deletions aren't detected for this run, logged not fatal.

    Fetches every changed file's from_ref content concurrently -- each
    `git show` is independent and I/O-bound, so a diff touching thousands
    of files no longer pays thousands of sequential process-spawn round
    trips one at a time.
    """
    def fetch(rel_path: str) -> Optional[Tuple[str, str]]:
        result = subprocess.run(
            ["git", "show", f"{from_ref}:{rel_path}"],
            cwd=repo_path, capture_output=True, text=True,
        )
        if result.returncode != 0:
            return None  # didn't exist at from_ref (a newly added file) -- nothing to compare
        return rel_path, result.stdout

    try:
        with tempfile.TemporaryDirectory(prefix="zairo-deleted-") as tmp_dir:
            found_any = False
            if changed_files:
                # File writes happen back on this thread as results come in
                # (pool.map preserves submission order) -- only the git
                # subprocess calls themselves run concurrently, so there's
                # no need to lock around tmp_dir.
                with ThreadPoolExecutor(max_workers=min(_MAX_GIT_SHOW_WORKERS, len(changed_files))) as pool:
                    for outcome in pool.map(fetch, changed_files):
                        if outcome is None:
                            continue
                        rel_path, content = outcome
                        dest = os.path.join(tmp_dir, rel_path)
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, 'w', encoding='utf-8', errors='surrogateescape') as f:
                            f.write(content)
                        found_any = True

            if not found_any:
                return {}, []

            base_graph = parse_directory(tmp_dir, language=language)

            deleted_metadata = {}
            for node_id, unit in base_graph.nodes.items():
                if node_id in to_node_ids or unit.kind.value == 'proxy':
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
                    "name": _node_name(unit, tmp_dir),
                    "kind": unit.kind.value,
                    "file": os.path.join(repo_path, rel),
                    "start_line": location.start_line,
                    "end_line": location.end_line,
                    "complexity": unit.cyclomatic_complexity,
                    "status": "deleted",
                }

            # Only edges touching a deleted node: an edge between two nodes
            # that both survive is the to-side graph's to report -- a
            # from_ref one would show a call the change removed as still
            # there. No lines either: they'd point into from_ref's copy of
            # the file, not the one on disk.
            deleted_edges = [
                _edge_dict(e, with_line=False)
                for e in base_graph.edges
                if e.source_id in deleted_metadata or e.target_id in deleted_metadata
            ]
            return deleted_metadata, deleted_edges
    except Exception as e:
        log(f"Skipping deleted-node detection: could not parse {from_ref} ({e})")
        return {}, []


def analyze_impact(
    repo_path: str,
    depth: int = 1,
    from_ref: str = None,
    to_ref: str = None,
    language: str = "auto",
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    `repo_path` must already be checked out at the state to be indexed: the
    caller is responsible for pointing it at a worktree checked out to
    `to_ref` when diffing two commits, so that node locations/contents line
    up with the line numbers `git diff from_ref to_ref` reports.
    """
    log = log or (lambda msg: None)

    analysis_root = os.path.abspath(repo_path)

    diff_hunks = get_diff_hunks(analysis_root, from_ref, to_ref, log=log)
    log(f"git diff found {len(diff_hunks)} modified file(s):")
    for f, hunks in diff_hunks.items():
        log(f"  {f}: {len(hunks)} hunk(s) at line(s) {[hunk_lines(h)[0] for h in hunks]}")

    # Initialize Trailmark
    log(f"Indexing {analysis_root} with Trailmark (language={language})...")
    # parse_directory() is Trailmark's public parser entry point, and its
    # CodeGraph keeps each edge's location -- the call site, for a call --
    # which QueryEngine.to_json() drops. The scanner needs that to show a
    # caller around where it calls the changed code.
    graph = parse_directory(analysis_root, language=language)
    graph_edges = [_edge_dict(e) for e in graph.edges]
    log(f"Trailmark graph: {len(graph.nodes)} node(s), {len(graph_edges)} edge(s)")

    # 1. Identify seed nodes (modified/added)
    seed_nodes = set()
    node_metadata = {}

    for node_id, unit in graph.nodes.items():
        location = unit.location
        node_metadata[node_id] = {
            "id": node_id,
            "name": _node_name(unit, analysis_root),
            "kind": unit.kind.value,
            "file": location.file_path,
            "start_line": location.start_line,
            "end_line": location.end_line,
            "complexity": unit.cyclomatic_complexity,
            "status": "unchanged" # default
        }

        if location.file_path in diff_hunks:
            start = location.start_line
            end = location.end_line
            node_hunks = hunks_in_range(diff_hunks[location.file_path], start, end)
            if node_hunks:
                seed_nodes.add(node_id)
                node_metadata[node_id]["status"] = "modified"
                node_metadata[node_id]["diff_hunks"] = node_hunks
                log(f"  seed: {_display_name(node_metadata[node_id]['name'])} ({location.file_path}:{start}-{end}), {len(node_hunks)} hunk(s)")

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

    # 3. Deleted nodes -- present in the from_ref revision, absent from the
    # to-side graph entirely (not just outside the traversal depth above).
    # Always treated as seeds, like modified/added, since a deletion is
    # itself the primary change of interest, not something reached by
    # traversing from one.
    effective_from_ref = from_ref or "HEAD"
    changed_file_paths = get_changed_file_paths(analysis_root, from_ref, to_ref)
    deleted_metadata, deleted_edges = _find_deleted_nodes(
        analysis_root, changed_file_paths, effective_from_ref, set(graph.nodes), language, log,
    )
    if deleted_metadata:
        log(f"Found {len(deleted_metadata)} deleted node(s) (present in {effective_from_ref}, absent from the current tree)")
        subgraph_nodes.update(deleted_metadata.keys())
        node_metadata.update(deleted_metadata)

    # Extract edges for subgraph -- from_ref revision edges included (filtered
    # by the same rule) so deleted nodes still connect to whatever
    # surviving node used to contain or call them. Deduplicated, since
    # Trailmark emits one edge per call site: each edge appears once, with
    # `lines` listing every place in its source's file where it occurs.
    merged_edges: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    for edge in (graph_edges + deleted_edges):
        if edge["source"] not in subgraph_nodes or edge["target"] not in subgraph_nodes:
            continue
        key = (edge["source"], edge["target"], edge["kind"], edge["confidence"])
        merged = merged_edges.setdefault(key, {
            "source": edge["source"], "target": edge["target"], "kind": edge["kind"],
            "confidence": edge["confidence"], "lines": [],
        })
        if edge["line"] is not None and edge["line"] not in merged["lines"]:
            merged["lines"].append(edge["line"])
    final_edges = list(merged_edges.values())
    for edge in final_edges:
        edge["lines"].sort()

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
