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
        "start_line": 1, "end_line": 1, "status": "modified", "changed_lines": {1: "__version__ = ..."},
    }


def _mock_litellm(monkeypatch, error: Exception) -> MagicMock:
    fake_litellm = MagicMock()
    fake_litellm.completion.side_effect = error
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
