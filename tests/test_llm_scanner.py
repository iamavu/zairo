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
