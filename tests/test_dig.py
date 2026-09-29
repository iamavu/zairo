import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

import zairo.llm_scanner as llm_scanner
from zairo.cli import app
from zairo.dig import MAX_LOOKUPS, TOOLS, Lookups
from zairo.notes import format_note, note_key, save_notes

_NOTE = {"does": "Checks the invoice's tenant", "inputs": "user, invoice", "checks": "tenant", "sinks": "none", "passes_on": "none"}


def _repo(tmp_path: Path) -> dict:
    """app.py: check(), then get_invoice(), which changed and no longer
    calls it; settings.py; and a test file that search must leave out."""
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    app_py = root / "app.py"
    app_py.write_text(
        "def check(user, invoice):\n    return invoice.tenant == user.tenant\n\n"
        "def get_invoice(user, invoice_id):\n    invoice = Invoice.get(invoice_id)\n    return invoice\n"
        "\ndef long_one():\n" + "".join(f"    x{i} = {i}\n" for i in range(250))
    )
    (root / "settings.py").write_text("TENANT_CHECKS = True\n")
    (root / "tests" / "test_app.py").write_text("TENANT_CHECKS = False\n")
    check = {"id": "app:check", "name": "check", "kind": "function", "file": str(app_py), "start_line": 1, "end_line": 2, "status": "unchanged"}
    get = {"id": "app:get_invoice", "name": "get_invoice", "kind": "function", "file": str(app_py), "start_line": 4, "end_line": 6,
           "status": "modified", "diff_hunks": [{"start": 5, "removed": ["    check(user, invoice)"], "added": ["    invoice = Invoice.get(invoice_id)"]}]}
    long_one = {"id": "app:long_one", "name": "long_one", "kind": "function", "file": str(app_py), "start_line": 8, "end_line": 258, "status": "unchanged"}
    view = {"id": "views:check", "name": "check", "kind": "function", "file": str(app_py), "start_line": 1, "end_line": 2, "status": "unchanged"}
    proxy = {"id": "Invoice.get", "name": "Invoice.get", "kind": "proxy", "file": None, "start_line": None, "end_line": None, "status": "unchanged"}
    return {"root": str(root), "nodes": [check, get, long_one, proxy], "view": view,
            "edges": [{"source": "app:get_invoice", "target": "Invoice.get", "kind": "calls", "confidence": "certain", "lines": [5]}]}


def _lookups(repo: dict, nodes=None, note_of=lambda n: _NOTE if n["name"] == "check" else None) -> Lookups:
    nodes = nodes or repo["nodes"]
    calls_in, calls_out = {}, {}
    for e in repo["edges"]:
        calls_in.setdefault(e["target"], []).append(e["source"])
        calls_out.setdefault(e["source"], []).append(e["target"])
    return Lookups(nodes, calls_in, calls_out, repo["root"], note_of, llm_scanner._numbered_source)


def _tag(text: str) -> str:
    return re.search(r"<<<REPO TEXT ([0-9a-f]+)>>>", text).group(1)


def test_every_result_is_sealed_repo_text(tmp_path):
    result, lookup = _lookups(_repo(tmp_path)).run("note", '{"symbol": "check"}')

    assert result.startswith("Text from the repository is between <<<REPO TEXT ")
    tag = _tag(result)
    assert f"<<<REPO TEXT {tag}>>>\n{format_note(_NOTE)}\n<<<END REPO TEXT {tag}>>>" in result
    assert lookup == {"tool": "note", "input": "check"}


def test_note_says_when_there_is_none(tmp_path):
    result, _ = _lookups(_repo(tmp_path)).run("note", {"symbol": "get_invoice"})

    assert "No warm-up note on get_invoice (function, app.py:4-6). code() shows its source." in result


def test_code_is_numbered_and_pages_through_a_long_function(tmp_path):
    lookups = _lookups(_repo(tmp_path))

    first, _ = lookups.run("code", {"symbol": "long_one"})
    rest, lookup = lookups.run("code", {"symbol": "long_one", "from_line": 208})

    assert "    8 | def long_one():" in first and "  207 |     x198 = 198" in first
    assert "(lines 208-258 not shown: code() with from_line=208 shows more)" in first
    assert "(lines 8-207 not shown)" in rest and "  258 |     x249 = 249" in rest
    assert lookup == {"tool": "code", "input": "long_one", "from_line": 208}


def test_callers_and_callees_come_from_the_call_graph(tmp_path):
    lookups = _lookups(_repo(tmp_path))

    callees, _ = lookups.run("callees", {"symbol": "get_invoice"})
    callers, _ = lookups.run("callers", {"symbol": "check"})

    assert "get_invoice (function, app.py:4-6) calls:\n- Invoice.get (external, or not resolved)" in callees
    assert "In the call graph, check (function, app.py:1-2) is called by nothing." in callers


def test_search_finds_text_in_the_repo_but_not_in_test_code(tmp_path):
    lookups = _lookups(_repo(tmp_path))

    found, lookup = lookups.run("search", {"text": "tenant_checks"})
    short, _ = lookups.run("search", {"text": "x"})
    missing, _ = lookups.run("search", {"text": "no such text"})

    tag = _tag(found)
    assert f"In settings.py:\n<<<REPO TEXT {tag}>>>\n    1 | TENANT_CHECKS = True\n<<<END REPO TEXT {tag}>>>" in found
    assert "tests/" not in found
    assert lookup == {"tool": "search", "input": "tenant_checks"}
    assert "at least 3 characters" in short and "No line in the repository contains 'no such text'" in missing


def test_an_ambiguous_name_lists_the_candidates_and_file_name_picks_one(tmp_path):
    repo = _repo(tmp_path)
    views_py = Path(repo["root"]) / "views.py"
    views_py.write_text("def check(request):\n    return True\n")
    view = dict(repo["view"], file=str(views_py))
    lookups = _lookups(repo, nodes=repo["nodes"] + [view])

    ambiguous, _ = lookups.run("code", {"symbol": "check"})
    picked, _ = lookups.run("code", {"symbol": "views.py:check"})
    prefixed, _ = lookups.run("code", {"symbol": "file:views.py:check"})  # how models have written it
    by_id, _ = lookups.run("code", {"symbol": "views:check"})
    unknown, _ = lookups.run("code", {"symbol": "nope"})

    assert "2 symbols match 'check'. Ask again with one of their ids:" in ambiguous
    assert "- app:check: check (function, app.py:1-2)" in ambiguous and "- views:check: check (function, views.py:1-2)" in ambiguous
    assert all("def check(request):" in result for result in (picked, prefixed, by_id))
    assert "No function or class named 'nope' in the code graph." in unknown


def test_bad_arguments_and_unknown_tools_are_answered_not_raised(tmp_path):
    lookups = _lookups(_repo(tmp_path))

    bad, _ = lookups.run("code", "{not json")
    unknown, _ = lookups.run("delete_file", {"symbol": "check"})

    assert "Couldn't read the arguments" in bad
    assert "There's no tool named 'delete_file'" in unknown


def _answer(content: str):
    message = SimpleNamespace(content=content, tool_calls=None, role="assistant")
    usage = SimpleNamespace(prompt_tokens=100, completion_tokens=10, total_tokens=110)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop")], usage=usage)


def _ask(*calls):
    tool_calls = [SimpleNamespace(id=f"call_{i}", type="function", function=SimpleNamespace(name=name, arguments=json.dumps(args)))
                  for i, (name, args) in enumerate(calls)]
    message = SimpleNamespace(content=None, tool_calls=tool_calls, role="assistant")
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="tool_calls")], usage=None)


def _scripted(monkeypatch, responses) -> MagicMock:
    fake_litellm = MagicMock()
    fake_litellm.completion.side_effect = responses
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)
    return fake_litellm


_FINDING = '{"vulnerabilities": [{"title": "Tenant check removed", "severity": "high", "line": 5, "introduced_by_change": true}]}'


def _dig_scan(repo: dict, **kwargs):
    graph = {"nodes": repo["nodes"], "edges": repo["edges"]}
    return llm_scanner.scan_graph_for_vulnerabilities(graph, "fake-model", dig=True, repo_root=repo["root"], **kwargs)


def test_dig_looks_things_up_then_answers(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    check = repo["nodes"][0]
    notes_path = str(tmp_path / "notes.json")
    save_notes(notes_path, {note_key(llm_scanner.get_source_code(check["file"], 1, 2)): _NOTE})
    fake_litellm = _scripted(monkeypatch, [_ask(("note", {"symbol": "check"}), ("search", {"text": "TENANT_CHECKS"})), _answer(_FINDING)])

    vulnerabilities, token_usage = _dig_scan(repo, cache_path=None, notes_path=notes_path)

    first, second = fake_litellm.completion.call_args_list
    assert first.kwargs["tools"] == TOOLS
    system = first.kwargs["messages"][0]
    assert system["role"] == "system" and f"at most {MAX_LOOKUPS} lookups" in system["content"]
    results = [m for m in second.kwargs["messages"] if isinstance(m, dict) and m["role"] == "tool"]
    assert [m["tool_call_id"] for m in results] == ["call_0", "call_1"]
    assert "Checks the invoice's tenant" in results[0]["content"] and "TENANT_CHECKS = True" in results[1]["content"]
    assert results[0]["content"].endswith(f"({MAX_LOOKUPS - 1} of {MAX_LOOKUPS} lookups left.)")
    assert results[1]["content"].endswith(f"({MAX_LOOKUPS - 2} of {MAX_LOOKUPS} lookups left.)")
    assert vulnerabilities["app:get_invoice"][0]["title"] == "Tenant check removed"
    assert vulnerabilities["app:get_invoice"][0]["line"] == 5
    assert token_usage["lookups"]["app:get_invoice"] == [{"tool": "note", "input": "check"}, {"tool": "search", "input": "TENANT_CHECKS"}]
    assert (token_usage["lookups_made"], token_usage["requests"], token_usage["requests_without_usage"]) == (2, 2, 1)
    assert token_usage["total_tokens"] == 110
    assert token_usage["notes_used"] == 1  # check's, through a lookup


def test_dig_stops_a_model_that_keeps_asking_past_its_lookups(monkeypatch, tmp_path):
    fake_litellm = _scripted(monkeypatch, [_ask(("search", {"text": f"thing {i}"})) for i in range(MAX_LOOKUPS + 2)])

    vulnerabilities, token_usage = _dig_scan(_repo(tmp_path), cache_path=None)

    assert fake_litellm.completion.call_count == MAX_LOOKUPS + 2
    last = [m for m in fake_litellm.completion.call_args_list[-1].kwargs["messages"] if isinstance(m, dict) and m["role"] == "tool"]
    assert f"That was the last of your {MAX_LOOKUPS} lookups" in last[MAX_LOOKUPS - 1]["content"]
    assert last[-1]["content"].startswith(f"Not run: all {MAX_LOOKUPS} lookups are used.")
    assert len(token_usage["lookups"]["app:get_invoice"]) == MAX_LOOKUPS
    assert "never answered" in token_usage["failed_nodes"]["app:get_invoice"]
    assert vulnerabilities == {}


def test_dig_answers_are_cached_per_commit_with_what_they_looked_up(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    fake_litellm = _scripted(monkeypatch, [_ask(("code", {"symbol": "check"})), _answer(_FINDING)])
    cache_path = str(tmp_path / "cache.json")

    _dig_scan(repo, cache_path=cache_path, dig_revision="abc123")
    vulnerabilities, token_usage = _dig_scan(repo, cache_path=cache_path, dig_revision="abc123")

    assert fake_litellm.completion.call_count == 2  # the first scan's two; none for the second
    assert token_usage["lookups"]["app:get_invoice"] == [{"tool": "code", "input": "check"}]
    assert token_usage["lookups_made"] == 0
    assert vulnerabilities["app:get_invoice"][0]["title"] == "Tenant check removed"


def test_dig_answers_are_not_cached_without_a_commit(monkeypatch, tmp_path):
    repo = _repo(tmp_path)
    fake_litellm = _scripted(monkeypatch, [_answer(_FINDING), _answer(_FINDING)])
    cache_path = str(tmp_path / "cache.json")

    _dig_scan(repo, cache_path=cache_path)
    _dig_scan(repo, cache_path=cache_path)

    assert fake_litellm.completion.call_count == 2


def test_a_scan_without_dig_offers_no_tools(monkeypatch, tmp_path):
    fake_litellm = _scripted(monkeypatch, [_answer('{"vulnerabilities": []}')])
    repo = _repo(tmp_path)

    llm_scanner.scan_graph_for_vulnerabilities({"nodes": repo["nodes"], "edges": repo["edges"]}, "fake-model", cache_path=None)

    [call] = fake_litellm.completion.call_args_list
    assert "tools" not in call.kwargs
    assert "lookups" not in call.kwargs["messages"][0]["content"]


runner = CliRunner()


def test_dig_takes_no_graph_only_batching_or_warm_up(tmp_path):
    graph_only = runner.invoke(app, [str(tmp_path), "--dig", "--graph-only"])
    batched = runner.invoke(app, [str(tmp_path), "--dig", "--batch-size", "2"])
    warm_up = runner.invoke(app, [str(tmp_path), "--dig", "--warm-up"])

    assert graph_only.exit_code == batched.exit_code == warm_up.exit_code == 1
    assert "--dig is a way of scanning, so it can't take --graph-only" in graph_only.output
    assert "can't take --batch-size above 1" in " ".join(batched.output.split())
    assert "--warm-up only writes notes, so it can't take --dig" in warm_up.output


def test_dig_end_to_end_records_the_lookups_in_the_report(git_repo: Path, tmp_path: Path):
    def complete(model, messages, max_tokens, timeout, tools=None):
        asked = any(isinstance(m, dict) and m.get("role") == "tool" for m in messages)
        return _answer('{"vulnerabilities": []}') if asked else _ask(("callers", {"symbol": "vulnerable_exec"}))

    fake_litellm = MagicMock()
    fake_litellm.completion.side_effect = complete
    output_dir = tmp_path / "out"

    with patch("zairo.llm_scanner.litellm", fake_litellm), patch("zairo.llm_scanner._ensure_litellm", return_value=fake_litellm):
        result = runner.invoke(app, [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--dig", "--output", str(output_dir)])

    assert result.exit_code == 0, result.output
    assert re.search(r"--dig: the model made (\d+) lookup\(s\) for \1 symbol\(s\)\.", " ".join(result.output.split()))
    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    [symbol] = [s for s in report["symbols"] if s["name"] == "vulnerable_exec"]
    assert symbol["lookups"] == [{"tool": "callers", "input": "vulnerable_exec"}]
    assert "Looked up before answering" in (output_dir / "report.html").read_text(encoding="utf-8")
