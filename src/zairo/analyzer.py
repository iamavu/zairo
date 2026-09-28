import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from trailmark import parse_directory
from trailmark.analysis.entrypoints import detect_entrypoints
from .git_utils import get_changed_file_paths, get_diff_hunks, hunk_lines, hunks_in_range
from ._util import display_name as _display_name, is_test_file

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


def _in_test_file(file_path: str, root: str) -> bool:
    try:
        return is_test_file(os.path.relpath(file_path, root))
    except ValueError:  # another drive, on Windows
        return False


# Trailmark finds a decorator-based entry point by looking for decorator-
# like lines within this many lines before and after a function's start.
_DECORATOR_LOOKBACK, _DECORATOR_LOOKAHEAD = 12, 3


def _looks_like_decorator(line: str) -> bool:
    s = line.strip()
    return s.startswith("@") or s.startswith("#[") or (s.startswith("[") and not s.startswith("[["))


def _decorator_is_anothers(unit, prev_end: int, lines: List[str]) -> bool:
    """Whether a decorator-based entry-point tag on `unit` rests only on
    decorators that belong to other functions. Trailmark's window around a
    function reaches into its neighbors: a helper right after a Flask route
    gets tagged as a route too. A decorator is this function's own if it
    comes after the previous definition in the file ends (`prev_end`) and
    before this one does. With no decorator-like line in the window at all,
    the tag came from something else (a name like main(), a file path) and
    stands."""
    start, end = unit.location.start_line, unit.location.end_line
    window = range(max(1, start - _DECORATOR_LOOKBACK), min(len(lines), start + _DECORATOR_LOOKAHEAD) + 1)
    decorators = [ln for ln in window if _looks_like_decorator(lines[ln - 1])]
    return bool(decorators) and not any(prev_end < ln <= end for ln in decorators)


def _entrypoints(graph, root: str, log: Callable[[str], None]) -> Dict[str, Dict[str, Any]]:
    """Trailmark's entry points -- HTTP routes, CLI commands, task handlers,
    ... -- as {node id: {"kind", "trust", "description"}}. Best effort: an
    error here just means no entry points."""
    try:
        tags = detect_entrypoints(graph, root)
    except Exception as e:
        log(f"Skipping entry-point detection: {e}")
        return {}
    definitions: Dict[str, list] = {}
    for unit in graph.nodes.values():
        if unit.kind.value in ('function', 'method', 'class'):
            definitions.setdefault(unit.location.file_path, []).append(unit)
    file_lines: Dict[str, List[str]] = {}
    found = {}
    for node_id, tag in tags.items():
        unit = graph.nodes.get(node_id)
        if unit is None:
            continue
        path = unit.location.file_path
        if path not in file_lines:
            try:
                with open(path, encoding='utf-8', errors='replace') as f:
                    file_lines[path] = f.read().splitlines()
            except OSError:
                file_lines[path] = []
        start = unit.location.start_line
        prev_end = max((u.location.end_line for u in definitions.get(path, []) if u.location.end_line < start), default=0)
        if _decorator_is_anothers(unit, prev_end, file_lines[path]):
            continue
        found[node_id] = {"kind": tag.kind.value, "trust": tag.trust_level.value, "description": tag.description}
    return found


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


def _symbol(node_id: str, unit, root: str) -> Dict[str, Any]:
    """A Trailmark unit as the graph's node dict, status "unchanged".

    A proxy is an external/unresolved call target (e.g. `os.system`).
    Trailmark places it at the first call to it that it came across, but it
    has no source of its own: it's recorded without a location, so it can't
    count as changed just because that call did, and the report shows it as
    an external reference, not as code at that line."""
    is_proxy = unit.kind.value == 'proxy'
    location = unit.location
    return {
        "id": node_id,
        "name": _node_name(unit, root),
        "kind": unit.kind.value,
        "file": None if is_proxy else location.file_path,
        "start_line": None if is_proxy else location.start_line,
        "end_line": None if is_proxy else location.end_line,
        "complexity": unit.cyclomatic_complexity,
        "status": "unchanged",
    }


def list_symbols(repo_path: str, language: str = "auto", log: Optional[Callable[[str], None]] = None) -> List[Dict[str, Any]]:
    """Every symbol in the repo as it is on disk, test code and external
    call targets aside -- what --warm-up writes notes for. No diff involved."""
    log = log or (lambda msg: None)
    root = os.path.abspath(repo_path)
    log(f"Indexing {root} with Trailmark (language={language})...")
    graph = parse_directory(root, language=language)
    return [
        _symbol(node_id, unit, root) for node_id, unit in graph.nodes.items()
        if unit.kind.value != 'proxy' and not _in_test_file(unit.location.file_path, root)
    ]


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
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Returns (graph_data, context), both {"nodes": [...], "edges": [...]}:
    graph_data is the report's graph -- the changed nodes plus whatever lies
    within `depth` hops of them -- and context is the whole graph (test code
    aside), for the scanner to read a changed node's surroundings from.

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
    # Test code stays out of the graph entirely (see _util.is_test_file):
    # a change to it isn't a change to the attack surface.
    changed_tests = [f for f in diff_hunks if _in_test_file(f, analysis_root)]
    for f in changed_tests:
        del diff_hunks[f]
    if changed_tests:
        log(f"Leaving out {len(changed_tests)} changed test file(s): test code isn't part of the graph")

    # Initialize Trailmark
    log(f"Indexing {analysis_root} with Trailmark (language={language})...")
    # parse_directory() is Trailmark's public parser entry point, and its
    # CodeGraph keeps each edge's location -- the call site, for a call --
    # which QueryEngine.to_json() drops. The scanner needs that to show a
    # caller around where it calls the changed code.
    graph = parse_directory(analysis_root, language=language)
    log(f"Trailmark graph: {len(graph.nodes)} node(s), {len(graph.edges)} edge(s)")
    # Nor can traversal reach test code: a test calling changed code isn't a
    # caller that matters to its security. Proxies (external call targets)
    # sit at wherever Trailmark first saw them called, which may be a test,
    # but belong to no file -- they stay.
    test_nodes = {
        node_id for node_id, unit in graph.nodes.items()
        if unit.kind.value != 'proxy' and _in_test_file(unit.location.file_path, analysis_root)
    }
    graph_edges = [
        _edge_dict(e) for e in graph.edges
        if e.source_id not in test_nodes and e.target_id not in test_nodes
    ]
    entrypoints = _entrypoints(graph, analysis_root, log)
    log(f"Found {len(entrypoints)} entry point(s)")

    # 1. Identify seed nodes (modified/added)
    seed_nodes = set()
    node_metadata = {}
    proxies = set()

    for node_id, unit in graph.nodes.items():
        if node_id in test_nodes:
            continue
        location = unit.location
        is_proxy = unit.kind.value == 'proxy'
        if is_proxy:
            proxies.add(node_id)
        node_metadata[node_id] = _symbol(node_id, unit, analysis_root)
        if node_id in entrypoints:
            node_metadata[node_id]["entrypoint"] = entrypoints[node_id]

        if not is_proxy and location.file_path in diff_hunks:
            start = location.start_line
            end = location.end_line
            node_hunks = hunks_in_range(diff_hunks[location.file_path], start, end)
            if node_hunks:
                seed_nodes.add(node_id)
                node_metadata[node_id]["status"] = "modified"
                node_metadata[node_id]["diff_hunks"] = node_hunks
                log(f"  seed: {_display_name(node_metadata[node_id]['name'])} ({location.file_path}:{start}-{end}), {len(node_hunks)} hunk(s)")

    log(f"Identified {len(seed_nodes)} seed node(s)")

    # 2. Traverse graph to build the report's subgraph up to `depth`. It's
    # only what the report shows: the scanner reads a changed node's
    # surroundings from the full graph (see `context` below). A proxy joins
    # the subgraph -- the change calls os.system -- but traversal never goes
    # on through it: every function anywhere that calls os.system links to
    # that one node, and none of them is related to the change.
    subgraph_nodes = set(seed_nodes)
    current_frontier = set(seed_nodes)

    for hop in range(depth):
        next_frontier = set()
        for edge in graph_edges:
            source = edge["source"]
            edge_target = edge["target"]

            if source in current_frontier and edge_target not in subgraph_nodes:
                subgraph_nodes.add(edge_target)
                if edge_target not in proxies:
                    next_frontier.add(edge_target)
            elif edge_target in current_frontier and source not in subgraph_nodes:
                subgraph_nodes.add(source)
                if source not in proxies:
                    next_frontier.add(source)

        log(f"Hop {hop + 1}/{depth}: added {len(next_frontier)} node(s), frontier now {len(subgraph_nodes)} total")
        current_frontier = next_frontier

    # 3. Deleted nodes -- present in the from_ref revision, absent from the
    # to-side graph entirely (not just outside the traversal depth above).
    # Always treated as seeds, like modified/added, since a deletion is
    # itself the primary change of interest, not something reached by
    # traversing from one.
    effective_from_ref = from_ref or "HEAD"
    changed_file_paths = [p for p in get_changed_file_paths(analysis_root, from_ref, to_ref) if not is_test_file(p)]
    deleted_metadata, deleted_edges = _find_deleted_nodes(
        analysis_root, changed_file_paths, effective_from_ref, set(graph.nodes), language, log,
    )
    if deleted_metadata:
        log(f"Found {len(deleted_metadata)} deleted node(s) (present in {effective_from_ref}, absent from the current tree)")
        subgraph_nodes.update(deleted_metadata.keys())
        node_metadata.update(deleted_metadata)

    # Every edge, deduplicated -- Trailmark emits one per call site: each
    # appears once, with `lines` listing every place in its source's file
    # where it occurs. from_ref revision edges are included so deleted nodes
    # still connect to whatever surviving node used to contain or call them.
    merged_edges: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    for edge in (graph_edges + deleted_edges):
        key = (edge["source"], edge["target"], edge["kind"], edge["confidence"])
        merged = merged_edges.setdefault(key, {
            "source": edge["source"], "target": edge["target"], "kind": edge["kind"],
            "confidence": edge["confidence"], "lines": [],
        })
        if edge["line"] is not None and edge["line"] not in merged["lines"]:
            merged["lines"].append(edge["line"])
    all_edges = list(merged_edges.values())
    for edge in all_edges:
        edge["lines"].sort()
    final_edges = [e for e in all_edges if e["source"] in subgraph_nodes and e["target"] in subgraph_nodes]

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

    graph_data = {"nodes": nodes, "edges": final_edges}
    # What the scanner reads a changed node's surroundings from -- its
    # direct callers and callees, and the other definitions in its file --
    # whatever --depth the report's graph was built with.
    context = {"nodes": list(node_metadata.values()), "edges": all_edges}
    return graph_data, context
