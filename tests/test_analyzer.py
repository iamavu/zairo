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


def test_depth_zero_yields_only_seed_nodes(git_repo: Path):
    graph = analyze_impact(str(git_repo), depth=0, base="HEAD~1", target="HEAD")
    modified_ids = {n["id"] for n in graph["nodes"] if n["status"] == "modified"}
    assert len(graph["nodes"]) == len(modified_ids)
