import subprocess
from pathlib import Path

from zairo.analyzer import analyze_impact


def test_finds_modified_function_and_expands_subgraph(git_repo: Path):
    graph, _ = analyze_impact(str(git_repo), depth=1, from_ref="HEAD~1", to_ref="HEAD")

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


def test_modified_node_carries_its_own_diff_hunks(git_repo: Path):
    """git_repo's second commit replaces a()/b()/c() with vulnerable_exec in
    one hunk: vulnerable_exec gets that hunk cut to its own lines, with the
    code it replaced -- what the scanner shows the model as the change."""
    graph, _ = analyze_impact(str(git_repo), depth=0, from_ref="HEAD~1", to_ref="HEAD")

    vulnerable = next(n for n in graph["nodes"] if n.get("name") == "vulnerable_exec")
    [hunk] = vulnerable["diff_hunks"]
    assert hunk["start"] == 2
    assert hunk["added"] == ["def vulnerable_exec(user_input):", "    return os.system(user_input)"]
    assert "def a():" in hunk["removed"]


def test_depth_zero_yields_only_seed_and_deleted_nodes(git_repo: Path):
    """At depth 0, no neighbor traversal happens -- every node present must
    be a seed (modified/added) or a deletion, never something pulled in by
    a hop that didn't run."""
    graph, _ = analyze_impact(str(git_repo), depth=0, from_ref="HEAD~1", to_ref="HEAD")
    statuses = {n["status"] for n in graph["nodes"]}
    assert statuses <= {"modified", "added", "deleted"}


def test_finds_functions_deleted_between_base_and_target(git_repo: Path):
    """git_repo's second commit replaces a()/b()/c() outright with unrelated
    content -- Trailmark's to-side graph can never represent that on its
    own (it only parses the tree as it currently is), so this is purely on
    zairo's own from_ref-revision diffing to detect."""
    graph, _ = analyze_impact(str(git_repo), depth=1, from_ref="HEAD~1", to_ref="HEAD")

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


def _commit_file(repo: Path, name: str, content: str, message: str) -> None:
    (repo / name).write_text(content)
    subprocess.run(["git", "add", name], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=repo, check=True, capture_output=True)


def test_call_edges_list_every_call_site(git_repo: Path):
    """Trailmark emits one edge per call; the graph keeps one edge per pair,
    with every call site's line -- what the scanner centers a caller's
    context on."""
    _commit_file(git_repo, "app.py", "def helper(x):\n    return x\n\ndef caller(y):\n    a = helper(y)\n    return helper(a)\n", "add app")
    _commit_file(git_repo, "app.py", "def helper(x):\n    return x + 1\n\ndef caller(y):\n    a = helper(y)\n    return helper(a)\n", "change helper")

    graph, _ = analyze_impact(str(git_repo), depth=1, from_ref="HEAD~1", to_ref="HEAD")

    ids = {n["name"]: n["id"] for n in graph["nodes"]}
    [edge] = [e for e in graph["edges"] if e["source"] == ids["caller"] and e["target"] == ids["helper"]]
    assert edge["kind"] == "calls"
    assert edge["lines"] == [5, 6]


def test_a_call_the_change_removed_is_not_an_edge(git_repo: Path):
    """handle() stopped calling check(); both still exist. The from_ref
    graph (parsed to find deletions) still has that call -- it must not
    make it into the graph as if handle() still made it."""
    _commit_file(git_repo, "app.py", "def check(x):\n    return x\n\ndef handle(y):\n    return check(y)\n", "add app")
    _commit_file(git_repo, "app.py", "def check(x):\n    return x\n\ndef handle(y):\n    return y\n", "drop the check")

    graph, _ = analyze_impact(str(git_repo), depth=1, from_ref="HEAD~1", to_ref="HEAD")

    ids = {n["name"]: n["id"] for n in graph["nodes"]}
    assert "check" in ids  # in the graph, via the module that contains it
    assert not any(e["source"] == ids["handle"] and e["target"] == ids["check"] for e in graph["edges"])


def test_modules_are_named_by_their_file_path(git_repo: Path):
    """Trailmark names a module with a dotted id that has to escape any dot
    in a file name ("pkg.settings\\.local") -- the graph shows its path."""
    (git_repo / "pkg").mkdir()
    _commit_file(git_repo, "pkg/settings.local.py", "DEBUG = False\n", "add settings")
    _commit_file(git_repo, "pkg/settings.local.py", "DEBUG = True\n", "debug on")

    graph, _ = analyze_impact(str(git_repo), depth=0, from_ref="HEAD~1", to_ref="HEAD")

    [module] = [n for n in graph["nodes"] if n["kind"] == "module"]
    assert module["name"] == "pkg/settings.local.py"
    assert module["id"] == "pkg.settings\\.local"  # the id stays Trailmark's


def test_deleted_modules_are_named_by_their_file_path(git_repo: Path):
    _commit_file(git_repo, "old.helpers.py", "def f():\n    return 1\n", "add helpers")
    subprocess.run(["git", "rm", "-q", "old.helpers.py"], cwd=git_repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "drop helpers"], cwd=git_repo, check=True, capture_output=True)

    graph, _ = analyze_impact(str(git_repo), depth=0, from_ref="HEAD~1", to_ref="HEAD")

    assert {n["name"] for n in graph["nodes"] if n["status"] == "deleted"} == {"old.helpers.py", "f"}


def test_test_code_stays_out_of_the_graph(git_repo: Path):
    """Neither a change to a test file nor a test calling changed code puts
    test code in the graph -- or, through it, in the model's context."""
    (git_repo / "tests").mkdir()
    _commit_file(git_repo, "app.py", "def get_invoice(i, t):\n    return db.get(i, t)\n", "add app")
    _commit_file(git_repo, "tests/test_app.py", "from app import get_invoice\n\n\ndef test_it():\n    assert get_invoice(1, 2)\n", "add test")
    (git_repo / "app.py").write_text("def get_invoice(i, t):\n    return db.get(i)\n")
    subprocess.run(["git", "add", "app.py"], cwd=git_repo, check=True, capture_output=True)
    _commit_file(git_repo, "tests/test_app.py", "from app import get_invoice\n\n\ndef test_it():\n    assert get_invoice(1, 3)\n", "change both")

    graph, _ = analyze_impact(str(git_repo), depth=1, from_ref="HEAD~1", to_ref="HEAD")

    names = {n["name"] for n in graph["nodes"] if n["kind"] != "proxy"}
    assert {"app.py", "get_invoice"} <= names
    assert not names & {"tests/test_app.py", "test_it"}


def test_a_repo_inside_a_tests_directory_is_not_all_test_code(tmp_path: Path):
    """Test code is recognized by its path within the repo, not by where the
    repo itself happens to live."""
    repo = tmp_path / "tests" / "svc"
    repo.mkdir(parents=True)
    for args in (["init", "-q"], ["config", "user.email", "t@e"], ["config", "user.name", "T"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    _commit_file(repo, "app.py", "def f():\n    return 1\n", "add app")
    _commit_file(repo, "app.py", "def f():\n    return 2\n", "change app")

    graph, _ = analyze_impact(str(repo), depth=0, from_ref="HEAD~1", to_ref="HEAD")

    assert "f" in {n["name"] for n in graph["nodes"]}


def test_external_calls_are_never_changed_and_never_expanded_through(git_repo: Path):
    """Trailmark places the os.system proxy at the first call to it it saw --
    here, the changed one. It must not count as changed for that, and even
    at depth 2 the graph must not reach b.py through it: every function that
    calls os.system links to that one node."""
    _commit_file(git_repo, "b.py", "import os\n\ndef unrelated():\n    return os.system('ls')\n", "add b")
    _commit_file(git_repo, "a.py", "import os\n\ndef run(cmd):\n    return os.system('echo ' + cmd)\n", "add a")
    _commit_file(git_repo, "a.py", "import os\n\ndef run(cmd):\n    return os.system(cmd)\n", "change a")

    graph, _ = analyze_impact(str(git_repo), depth=2, from_ref="HEAD~1", to_ref="HEAD")

    by_name = {n["name"]: n for n in graph["nodes"]}
    assert "unrelated" not in by_name
    [proxy] = [n for n in graph["nodes"] if n["kind"] == "proxy" and "os.system" in n["name"]]
    assert proxy["status"] == "unchanged"
    assert (proxy["file"], proxy["start_line"]) == (None, None)  # an external reference, not code in a.py
    assert any(e["source"] == by_name["run"]["id"] and e["target"] == proxy["id"] for e in graph["edges"])


def test_context_is_the_whole_graph_whatever_the_depth(git_repo: Path):
    """--depth 0 keeps the report's graph to the change itself; the scanner
    still gets the caller, from context."""
    _commit_file(git_repo, "app.py", "def helper(x):\n    return x\n\ndef caller(y):\n    return helper(y)\n", "add app")
    _commit_file(git_repo, "app.py", "def helper(x):\n    return x + 1\n\ndef caller(y):\n    return helper(y)\n", "change helper")

    graph, context = analyze_impact(str(git_repo), depth=0, from_ref="HEAD~1", to_ref="HEAD")

    assert "caller" not in {n["name"] for n in graph["nodes"]}
    ids = {n["name"]: n["id"] for n in context["nodes"]}
    [edge] = [e for e in context["edges"] if e["source"] == ids["caller"] and e["target"] == ids["helper"]]
    assert edge["lines"] == [5]


def test_no_deleted_nodes_when_nothing_was_deleted(git_repo: Path):
    """Diffing a ref against itself: nothing changed, so nothing should be
    reported as deleted either."""
    graph, _ = analyze_impact(str(git_repo), depth=1, from_ref="HEAD", to_ref="HEAD")
    assert not any(n["status"] == "deleted" for n in graph["nodes"])
