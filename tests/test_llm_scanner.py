import json
from unittest.mock import MagicMock

import zairo
import zairo.llm_scanner as llm_scanner

# A real, short, non-test-named file to use as node source -- llm_scanner
# skips anything it recognizes as a test file, and skips nodes whose source
# can't be read at all, so the mocked litellm call would never actually
# fire against a fake/test-shaped path.
_FAKE_FILE = zairo.__file__


def _node(node_id: str, name: str) -> dict:
    return {
        "id": node_id, "name": name, "kind": "function", "file": _FAKE_FILE,
        "start_line": 1, "end_line": 1, "status": "modified",
        "diff_hunks": [{"start": 1, "removed": [], "added": ["__version__ = ..."]}],
    }


def _mock_litellm(monkeypatch, error: Exception) -> MagicMock:
    fake_litellm = MagicMock()
    fake_litellm.completion.side_effect = error
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)
    return fake_litellm


def _mock_litellm_response(monkeypatch, content: str) -> MagicMock:
    fake_litellm = MagicMock()
    fake_response = MagicMock()
    fake_response.choices[0].message.content = content
    fake_response.choices[0].finish_reason = "stop"
    fake_response.usage = None
    fake_litellm.completion.return_value = fake_response
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)
    return fake_litellm


def test_scan_errors_are_surfaced_when_every_node_fails(monkeypatch):
    _mock_litellm(monkeypatch, RuntimeError("AuthenticationError: no API key provided"))
    graph_data = {"nodes": [_node("n1", "vulnerable_fn")], "edges": []}

    vulnerabilities, token_usage = llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None,
    )

    assert vulnerabilities == {}
    assert token_usage["requests"] == 1
    assert sum(token_usage["errors"].values()) == 1
    assert "AuthenticationError" in next(iter(token_usage["errors"]))


def test_scan_errors_are_deduplicated_by_message(monkeypatch):
    _mock_litellm(monkeypatch, RuntimeError("boom"))
    graph_data = {
        "nodes": [_node("n1", "fn_one"), _node("n2", "fn_two")],
        "edges": [],
    }

    _, token_usage = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=None)

    assert token_usage["errors"] == {"boom": 2}


def test_multiline_exception_messages_are_trimmed_to_one_line(monkeypatch):
    """Some providers (seen from litellm on a Gemini auth failure) bake a
    full traceback into the exception's own message text -- the always-on
    warning should show a short summary, not reproduce it verbatim."""
    _mock_litellm(monkeypatch, RuntimeError(
        "litellm.APIConnectionError: Missing Gemini API key.\n"
        "Traceback (most recent call last):\n"
        "  File \"litellm/main.py\", line 5702, in completion\n"
        "ValueError: Missing Gemini API key."
    ))
    graph_data = {"nodes": [_node("n1", "vulnerable_fn")], "edges": []}

    _, token_usage = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=None)

    assert list(token_usage["errors"].keys()) == ["litellm.APIConnectionError: Missing Gemini API key."]


def test_multiline_json_error_body_shows_useful_content_not_just_a_brace(monkeypatch):
    """Some providers put the actually useful text several lines into a
    pretty-printed JSON error body (e.g. litellm on a Gemini 404) -- the
    summary must surface that message, not just whatever precedes the
    first newline (which can be as useless as a lone opening brace)."""
    _mock_litellm(monkeypatch, RuntimeError(
        'litellm.NotFoundError: GeminiException - {\n'
        '  "error": {\n'
        '    "code": 404,\n'
        '    "message": "models/gemini-1.5-pro is not found for API version v1beta.",\n'
        '    "status": "NOT_FOUND"\n'
        '  }\n'
        '}\n'
    ))
    graph_data = {"nodes": [_node("n1", "vulnerable_fn")], "edges": []}

    _, token_usage = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=None)

    summary = next(iter(token_usage["errors"]))
    assert "models/gemini-1.5-pro is not found" in summary
    assert "\n" not in summary


def test_no_errors_key_populated_on_a_clean_run(monkeypatch):
    fake_litellm = MagicMock()
    fake_response = MagicMock()
    fake_response.choices[0].message.content = '{"vulnerabilities": []}'
    fake_response.usage = None
    fake_litellm.completion.return_value = fake_response
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)

    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}
    _, token_usage = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=None)

    assert token_usage["errors"] == {}
    assert token_usage["failed_nodes"] == {}


def test_failed_nodes_records_which_nodes_were_never_assessed(monkeypatch):
    """Per-node, not just per-message: the reports need to mark exactly
    which nodes nobody reviewed."""
    _mock_litellm(monkeypatch, RuntimeError("boom"))
    graph_data = {"nodes": [_node("n1", "fn_one"), _node("n2", "fn_two")], "edges": []}

    _, token_usage = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=None)

    assert token_usage["failed_nodes"] == {"n1": "boom", "n2": "boom"}


def test_debug_log_receives_prompt_and_response_on_success(monkeypatch):
    fake_litellm = MagicMock()
    fake_response = MagicMock()
    fake_response.choices[0].message.content = '{"vulnerabilities": []}'
    fake_response.choices[0].finish_reason = "stop"
    fake_response.usage = None
    fake_litellm.completion.return_value = fake_response
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)

    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}
    entries = []
    llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None, debug_log=entries.append,
    )

    combined = "\n".join(entries)
    assert "PROMPT" in combined and "fn_one" in combined
    assert "RESPONSE" in combined and '"vulnerabilities": []' in combined


def test_debug_log_receives_prompt_and_error_on_failure(monkeypatch):
    _mock_litellm(monkeypatch, RuntimeError("boom"))
    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}
    entries = []

    llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None, debug_log=entries.append,
    )

    combined = "\n".join(entries)
    assert "PROMPT" in combined and "fn_one" in combined
    assert "ERROR" in combined and "boom" in combined


def test_debug_log_not_called_for_a_cache_hit(monkeypatch, tmp_path):
    """A cache hit never touches the LLM -- nothing to log for it."""
    fake_litellm = MagicMock()
    fake_response = MagicMock()
    fake_response.choices[0].message.content = '{"vulnerabilities": []}'
    fake_response.choices[0].finish_reason = "stop"
    fake_response.usage = None
    fake_litellm.completion.return_value = fake_response
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)

    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}
    cache_path = str(tmp_path / "cache.json")
    llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=cache_path)

    entries = []
    llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=cache_path, debug_log=entries.append,
    )

    assert entries == []


def test_batch_size_one_uses_original_single_node_prompt_shape(monkeypatch):
    """batch_size defaults to (and here is explicitly) 1 -- the prompt sent
    must be byte-identical in shape to what zairo has always sent, not the
    multi-node batch format, so existing cache entries and expectations
    about model behavior aren't disturbed for anyone who never opts in."""
    fake_litellm = MagicMock()
    fake_response = MagicMock()
    fake_response.choices[0].message.content = '{"vulnerabilities": []}'
    fake_response.choices[0].finish_reason = "stop"
    fake_response.usage = None
    fake_litellm.completion.return_value = fake_response
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)

    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}
    entries = []
    llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None, debug_log=entries.append, batch_size=1,
    )

    combined = "\n".join(entries)
    assert "Node id:" not in combined  # the batch-format marker, absent at batch_size=1


def test_batch_size_groups_nodes_and_reduces_request_count(monkeypatch):
    fake_litellm = MagicMock()
    fake_response = MagicMock()
    fake_response.choices[0].message.content = json.dumps({f"n{i}": [] for i in range(1, 5)})
    fake_response.choices[0].finish_reason = "stop"
    fake_response.usage = None
    fake_litellm.completion.return_value = fake_response
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)

    graph_data = {"nodes": [_node(f"n{i}", f"fn_{i}") for i in range(1, 5)], "edges": []}

    vulnerabilities, token_usage = llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None, batch_size=2,
    )

    assert fake_litellm.completion.call_count == 2  # 4 nodes / batch_size 2 -> 2 real calls
    assert token_usage["requests"] == 2
    assert vulnerabilities == {}


def test_batch_findings_are_attributed_to_the_correct_node(monkeypatch):
    fake_litellm = MagicMock()
    fake_response = MagicMock()
    fake_response.choices[0].message.content = json.dumps({
        "n1": [{"title": "Command injection", "severity": "high"}],
        "n2": [],
    })
    fake_response.choices[0].finish_reason = "stop"
    fake_response.usage = None
    fake_litellm.completion.return_value = fake_response
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)

    graph_data = {"nodes": [_node("n1", "fn_one"), _node("n2", "fn_two")], "edges": []}

    vulnerabilities, _ = llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None, batch_size=2,
    )

    assert set(vulnerabilities.keys()) == {"n1"}
    assert vulnerabilities["n1"][0]["title"] == "Command injection"


def test_batch_response_missing_a_node_key_errors_only_that_node(monkeypatch):
    fake_litellm = MagicMock()
    fake_response = MagicMock()
    fake_response.choices[0].message.content = '{"n1": []}'  # n2's key omitted
    fake_response.choices[0].finish_reason = "stop"
    fake_response.usage = None
    fake_litellm.completion.return_value = fake_response
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)

    graph_data = {"nodes": [_node("n1", "fn_one"), _node("n2", "fn_two")], "edges": []}

    vulnerabilities, token_usage = llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None, batch_size=2,
    )

    assert vulnerabilities == {}
    assert sum(token_usage["errors"].values()) == 1  # only n2 (missing) counted as failed


def test_batch_call_failure_errors_every_node_in_the_batch(monkeypatch):
    """A whole-batch failure (exception, malformed response) fails every
    node in that batch -- the blast radius is the batch, not one node."""
    _mock_litellm(monkeypatch, RuntimeError("boom"))
    graph_data = {"nodes": [_node("n1", "fn_one"), _node("n2", "fn_two")], "edges": []}

    vulnerabilities, token_usage = llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None, batch_size=2,
    )

    assert vulnerabilities == {}
    assert token_usage["errors"] == {"boom": 2}
    assert token_usage["requests"] == 1  # one call covers both nodes, not one call each
    assert token_usage["nodes_scanned"] == 2  # but 2 nodes were actually in it


def test_nodes_scanned_counts_nodes_not_batched_calls(monkeypatch):
    """Regression: the failure-summary line divides by nodes_scanned, not
    requests. With batching, requests (real API calls) can be much smaller
    than the number of nodes those calls covered -- e.g. 12 nodes at
    batch_size=4 is 3 calls. Using 'requests' as the denominator there
    produced a nonsensical "12/3 node scan(s) failed" (more failures than
    the printed total)."""
    _mock_litellm(monkeypatch, RuntimeError("boom"))
    graph_data = {"nodes": [_node(f"n{i}", f"fn_{i}") for i in range(12)], "edges": []}

    _, token_usage = llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None, batch_size=4,
    )

    assert token_usage["requests"] == 3  # 12 nodes / batch_size 4
    assert token_usage["nodes_scanned"] == 12
    assert sum(token_usage["errors"].values()) == 12
    # The number the CLI would print as "X/Y failed" -- X must never exceed Y.
    assert sum(token_usage["errors"].values()) <= token_usage["nodes_scanned"]


def test_non_answer_is_a_failed_scan_and_never_cached(monkeypatch, tmp_path):
    """Valid JSON that isn't a findings list -- a refusal, "unable to
    assess" -- must fail the node, not become (and get cached as) a clean
    "no vulnerabilities" result that later runs silently reuse."""
    fake_litellm = _mock_litellm_response(monkeypatch, '{"message": "unable to assess"}')
    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}
    cache_path = str(tmp_path / "cache.json")

    for _ in range(2):
        vulnerabilities, token_usage = llm_scanner.scan_graph_for_vulnerabilities(
            graph_data, "fake-model", cache_path=cache_path,
        )
        assert vulnerabilities == {}
        assert list(token_usage["failed_nodes"]) == ["n1"]
        assert "no 'vulnerabilities' list" in token_usage["failed_nodes"]["n1"]

    assert fake_litellm.completion.call_count == 2  # the second run wasn't a cache hit


def test_findings_that_are_not_objects_fail_the_node(monkeypatch):
    _mock_litellm_response(monkeypatch, '{"vulnerabilities": ["SQL injection somewhere"]}')
    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}

    _, token_usage = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=None)

    assert list(token_usage["failed_nodes"]) == ["n1"]


def test_bare_json_string_fails_the_node(monkeypatch):
    _mock_litellm_response(monkeypatch, '"No issues found."')
    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}

    _, token_usage = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=None)

    assert list(token_usage["failed_nodes"]) == ["n1"]


def test_bare_findings_list_is_still_accepted(monkeypatch):
    _mock_litellm_response(monkeypatch, '[{"title": "Command injection", "severity": "HIGH"}]')
    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}

    vulnerabilities, token_usage = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=None)

    assert token_usage["failed_nodes"] == {}
    assert vulnerabilities["n1"][0]["severity"] == "high"


def test_batch_entry_that_is_not_a_findings_list_fails_only_that_node(monkeypatch):
    _mock_litellm_response(monkeypatch, json.dumps({"n1": [], "n2": "looks fine"}))
    graph_data = {"nodes": [_node("n1", "fn_one"), _node("n2", "fn_two")], "edges": []}

    _, token_usage = llm_scanner.scan_graph_for_vulnerabilities(
        graph_data, "fake-model", cache_path=None, batch_size=2,
    )

    assert list(token_usage["failed_nodes"]) == ["n2"]


def test_changing_the_prompt_invalidates_cached_verdicts(monkeypatch, tmp_path):
    """The cache key covers the whole prompt, not just the code in it -- a
    verdict reached under different instructions isn't reusable."""
    fake_litellm = _mock_litellm_response(monkeypatch, '{"vulnerabilities": []}')
    graph_data = {"nodes": [_node("n1", "fn_one")], "edges": []}
    cache_path = str(tmp_path / "cache.json")

    llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=cache_path)
    llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=cache_path)
    assert fake_litellm.completion.call_count == 1  # same prompt: cache hit

    build_prompt = llm_scanner._build_prompt
    monkeypatch.setattr(llm_scanner, "_build_prompt", lambda *a: build_prompt(*a) + "\nNew instruction.")
    llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=cache_path)
    assert fake_litellm.completion.call_count == 2  # prompt changed: cache miss


def test_assessed_nodes_lists_every_node_with_a_valid_answer(monkeypatch, tmp_path):
    """Clean answers, answers with findings, and cache hits all count as
    assessed; a failed node doesn't -- and neither does a skipped one."""
    fake_litellm = MagicMock()

    def answer(model, messages, max_tokens):
        prompt = messages[0]["content"]
        response = MagicMock()
        response.choices[0].finish_reason = "stop"
        response.usage = None
        response.choices[0].message.content = (
            '{"vulnerabilities": [{"title": "X", "severity": "high"}]}' if "fn_vuln" in prompt
            else '{"message": "unable to assess"}' if "fn_fail" in prompt
            else '{"vulnerabilities": []}'
        )
        return response

    fake_litellm.completion.side_effect = answer
    monkeypatch.setattr(llm_scanner, "litellm", fake_litellm)
    monkeypatch.setattr(llm_scanner, "_ensure_litellm", lambda: fake_litellm)
    skipped = dict(_node("n4", "fn_test"), file="tests/test_x.py")  # test files are never sent
    graph_data = {"nodes": [_node("n1", "fn_clean"), _node("n2", "fn_vuln"), _node("n3", "fn_fail"), skipped], "edges": []}
    cache_path = str(tmp_path / "cache.json")

    _, first = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=cache_path)
    _, second = llm_scanner.scan_graph_for_vulnerabilities(graph_data, "fake-model", cache_path=cache_path)

    assert sorted(first["assessed_nodes"]) == ["n1", "n2"]
    assert sorted(second["assessed_nodes"]) == ["n1", "n2"]  # this time from the cache


def _prompts(fake_litellm: MagicMock) -> list:
    return [call.kwargs["messages"][0]["content"] for call in fake_litellm.completion.call_args_list]


def test_prompt_shows_what_the_change_removed(monkeypatch):
    """The code after a change can't show a check that was taken out --
    only the diff can."""
    fake_litellm = _mock_litellm_response(monkeypatch, '{"vulnerabilities": []}')
    node = dict(_node("n1", "fn_one"), diff_hunks=[
        {"start": 1, "removed": ["require_same_tenant(user, invoice)"], "added": ["__version__ = ..."]},
    ])

    llm_scanner.scan_graph_for_vulnerabilities({"nodes": [node], "edges": []}, "fake-model", cache_path=None)

    [prompt] = _prompts(fake_litellm)
    assert "-require_same_tenant(user, invoice)" in prompt
    assert "+__version__ = ..." in prompt
    assert "what this change makes newly possible" in prompt


def test_entirely_new_node_says_so_instead_of_repeating_its_code(monkeypatch):
    fake_litellm = _mock_litellm_response(monkeypatch, '{"vulnerabilities": []}')

    llm_scanner.scan_graph_for_vulnerabilities({"nodes": [_node("n1", "fn_one")], "edges": []}, "fake-model", cache_path=None)

    [prompt] = _prompts(fake_litellm)
    assert "entirely new in this change" in prompt
    assert "```diff" not in prompt


def _module_and_function(tmp_path, module_hunks, function_hunks):
    """app.py: a module-level import, then f() on lines 3-4."""
    src = tmp_path / "app.py"
    src.write_text("import os\n\ndef f(x):\n    return os.system(x)\n")
    module = {"id": "m", "name": "app", "kind": "module", "file": str(src), "start_line": 1, "end_line": 4,
              "status": "modified", "diff_hunks": module_hunks}
    function = {"id": "f", "name": "f", "kind": "function", "file": str(src), "start_line": 3, "end_line": 4,
                "status": "modified", "diff_hunks": function_hunks}
    return {"nodes": [module, function], "edges": []}


def test_module_is_not_scanned_again_for_changes_inside_its_functions(monkeypatch, tmp_path):
    """f's change is f's own scan -- the module has nothing of its own to review."""
    fake_litellm = _mock_litellm_response(monkeypatch, '{"vulnerabilities": []}')
    hunk = {"start": 4, "removed": ["    return x"], "added": ["    return os.system(x)"]}

    llm_scanner.scan_graph_for_vulnerabilities(
        _module_and_function(tmp_path, [hunk], [hunk]), "fake-model", cache_path=None,
    )

    [prompt] = _prompts(fake_litellm)
    assert "Modified Function: f" in prompt


def test_module_diff_leaves_out_its_functions_lines(monkeypatch, tmp_path):
    """One hunk adding the import and f together: the module's diff shows
    the import, but f's body stays in f's own scan -- the same reason the
    module's code collapses nested bodies."""
    fake_litellm = _mock_litellm_response(monkeypatch, '{"vulnerabilities": []}')
    added = ["import os", "", "def f(x):", "    return os.system(x)"]
    whole = {"start": 1, "removed": ["import shlex"], "added": added}
    in_f = {"start": 3, "removed": ["import shlex"], "added": added[2:]}

    llm_scanner.scan_graph_for_vulnerabilities(
        _module_and_function(tmp_path, [whole], [in_f]), "fake-model", cache_path=None,
    )

    [module_prompt] = [p for p in _prompts(fake_litellm) if "Modified Module: app" in p]
    diff = module_prompt.split("```diff")[1]
    assert "+import os" in diff and "-import shlex" in diff
    assert "os.system" not in diff


def test_code_is_numbered_so_findings_can_cite_lines(monkeypatch):
    fake_litellm = _mock_litellm_response(monkeypatch, '{"vulnerabilities": []}')

    llm_scanner.scan_graph_for_vulnerabilities({"nodes": [_node("n1", "fn_one")], "edges": []}, "fake-model", cache_path=None)

    [prompt] = _prompts(fake_litellm)
    assert "    1 | __version__" in prompt
    assert "'introduced_by_change'" in prompt and "'confidence'" in prompt


def test_finding_fields_are_normalized_and_lines_checked_against_what_was_shown(monkeypatch):
    """_node shows line 1 only: a finding citing it keeps it; one citing a
    line the model never saw gets None -- but keeps the finding itself."""
    _mock_litellm_response(monkeypatch, json.dumps({"vulnerabilities": [
        {"title": "A", "severity": "high", "line": "1", "introduced_by_change": "yes",
         "trigger": "any logged-in user", "confidence": "HIGH"},
        {"title": "B", "severity": "low", "line": 99, "introduced_by_change": "maybe", "confidence": "certain"},
        {"title": "C", "severity": "low", "line": True, "introduced_by_change": False},
    ]}))

    vulnerabilities, _ = llm_scanner.scan_graph_for_vulnerabilities(
        {"nodes": [_node("n1", "fn_one")], "edges": []}, "fake-model", cache_path=None,
    )

    a, b, c = vulnerabilities["n1"]
    assert (a["line"], a["introduced_by_change"], a["trigger"], a["confidence"]) == (1, True, "any logged-in user", "high")
    assert (b["line"], b["introduced_by_change"], b["trigger"], b["confidence"]) == (None, None, None, None)
    assert (c["line"], c["introduced_by_change"]) == (None, False)


def test_module_code_is_numbered_and_collapsed_lines_cannot_be_cited(monkeypatch, tmp_path):
    """The placeholder for a nested body has no line number and sits on its
    own line; a finding citing a line inside that body -- which the model
    never saw -- loses its line."""
    src = tmp_path / "app.py"
    src.write_text("import os\n\ndef f(x):\n    return os.system(x)\n\nX = 1\n")
    module = {"id": "m", "name": "app", "kind": "module", "file": str(src), "start_line": 1, "end_line": 6,
              "status": "modified", "diff_hunks": [{"start": 6, "removed": ["X = 0"], "added": ["X = 1"]}]}
    function = {"id": "f", "name": "f", "kind": "function", "file": str(src), "start_line": 3, "end_line": 4,
                "status": "unchanged"}
    fake_litellm = _mock_litellm_response(monkeypatch, json.dumps({"vulnerabilities": [
        {"title": "in f", "severity": "high", "line": 4},
        {"title": "module level", "severity": "low", "line": 6},
    ]}))

    vulnerabilities, _ = llm_scanner.scan_graph_for_vulnerabilities(
        {"nodes": [module, function], "edges": []}, "fake-model", cache_path=None,
    )

    [prompt] = _prompts(fake_litellm)
    assert "do not guess its contents) ...\n    5 | " in prompt
    assert "    4 | " not in prompt
    assert [finding["line"] for finding in vulnerabilities["m"]] == [None, 6]


def test_large_function_lines_outside_its_windows_cannot_be_cited(monkeypatch, tmp_path):
    src = tmp_path / "big.py"
    src.write_text("def big(x):\n" + "".join(f"    x += {i}\n" for i in range(2, 151)))
    node = {"id": "b", "name": "big", "kind": "function", "file": str(src), "start_line": 1, "end_line": 150,
            "status": "modified", "diff_hunks": [{"start": 120, "removed": ["    x += 0"], "added": ["    x += 120"]}]}
    _mock_litellm_response(monkeypatch, json.dumps({"vulnerabilities": [
        {"title": "near the change", "severity": "high", "line": 120},
        {"title": "between windows", "severity": "high", "line": 50},
    ]}))

    vulnerabilities, _ = llm_scanner.scan_graph_for_vulnerabilities({"nodes": [node], "edges": []}, "fake-model", cache_path=None)

    assert [finding["line"] for finding in vulnerabilities["b"]] == [120, None]


def test_batch_prompt_spells_out_the_finding_format(monkeypatch):
    """It used to say "using the same rules as before" -- with no "before" in
    a batch prompt, which is a standalone request."""
    fake_litellm = _mock_litellm_response(monkeypatch, json.dumps({"n1": [], "n2": []}))

    llm_scanner.scan_graph_for_vulnerabilities(
        {"nodes": [_node("n1", "fn_one"), _node("n2", "fn_two")], "edges": []}, "fake-model", cache_path=None, batch_size=2,
    )

    [prompt] = _prompts(fake_litellm)
    assert "same rules as before" not in prompt
    for field in ("'severity'", "'line'", "'introduced_by_change'", "'trigger'", "'confidence'"):
        assert field in prompt


def test_replacing_module_code_with_a_comment_is_not_trivial(monkeypatch, tmp_path):
    """Only comments were *added* -- but real code was removed, which is
    exactly the kind of change that must not be skipped."""
    fake_litellm = _mock_litellm_response(monkeypatch, '{"vulnerabilities": []}')
    src = tmp_path / "settings.py"
    src.write_text("# auth disabled for now\nDEBUG = True\n")
    module = {"id": "m", "name": "settings", "kind": "module", "file": str(src), "start_line": 1, "end_line": 2,
              "status": "modified",
              "diff_hunks": [{"start": 1, "removed": ["require_auth(app)"], "added": ["# auth disabled for now"]}]}

    llm_scanner.scan_graph_for_vulnerabilities({"nodes": [module], "edges": []}, "fake-model", cache_path=None)

    assert fake_litellm.completion.call_count == 1
