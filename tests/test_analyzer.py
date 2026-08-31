from pathlib import Path

from zairo.analyzer import analyze_impact


def test_finds_modified_function_and_expands_subgraph(git_repo: Path):
    graph = analyze_impact(str(git_repo), depth=1, base="HEAD~1", target="HEAD")

    nodes_by_id = {n["id"]: n for n in graph["nodes"]}
    vulnerable = next(
        (n for n in nodes_by_id.values() if n.get("name") == "vulnerable_exec"), None
    )
    assert vulnerable is not None
    assert vulnerable["status"] == "modified"
    assert vulnerable["kind"] == "function"

    # Depth-1 expansion should pull in whatever vulnerable_exec calls.
    assert any(
        e["source"] == vulnerable["id"] or e["target"] == vulnerable["id"]
        for e in graph["edges"]
    )


def test_depth_zero_yields_only_seed_and_deleted_nodes(git_repo: Path):
    """At depth 0, no neighbor traversal happens -- every node present must
    be a seed (modified/added) or a deletion, never something pulled in by
    a hop that didn't run."""
    graph = analyze_impact(str(git_repo), depth=0, base="HEAD~1", target="HEAD")
    statuses = {n["status"] for n in graph["nodes"]}
    assert statuses <= {"modified", "added", "deleted"}


def test_finds_functions_deleted_between_base_and_target(git_repo: Path):
    """git_repo's second commit replaces a()/b()/c() outright with unrelated
    content -- Trailmark's target-tree graph can never represent that on its
    own (it only parses the tree as it currently is), so this is purely on
    zairo's own base-revision diffing to detect."""
    graph = analyze_impact(str(git_repo), depth=1, base="HEAD~1", target="HEAD")

    by_name = {n["name"]: n for n in graph["nodes"] if n["status"] == "deleted"}
    assert set(by_name.keys()) == {"a", "b", "c"}
    assert all(n["kind"] == "function" for n in by_name.values())

    # The module itself survives (still has vulnerable_exec in it), so a
    # deleted function should still connect to it in the graph, not float
    # disconnected.
    module_id = next(n["id"] for n in graph["nodes"] if n["kind"] == "module")
    deleted_ids = {n["id"] for n in by_name.values()}
    assert any(
        e["kind"] == "contains" and e["source"] == module_id and e["target"] in deleted_ids
        for e in graph["edges"]
    )


def test_no_deleted_nodes_when_nothing_was_deleted(git_repo: Path):
    """Diffing a ref against itself: nothing changed, so nothing should be
    reported as deleted either."""
    graph = analyze_impact(str(git_repo), depth=1, base="HEAD", target="HEAD")
    assert not any(n["status"] == "deleted" for n in graph["nodes"])
