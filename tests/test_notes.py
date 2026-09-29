import re

from zairo.notes import (
    NOTE_INSTRUCTIONS, NOTE_MAX_LINES, format_note, is_notable, load_notes, note_key, notes_messages, save_notes,
    validated_note,
)


def test_validated_note_normalizes_fields():
    note = validated_note({"does": "  Saves\n the file ", "inputs": ["f", "request.user"], "checks": None, "sinks": "x" * 500})

    assert note["does"] == "Saves the file"
    assert note["inputs"] == "f; request.user"
    assert note["checks"] == "" and note["passes_on"] == ""
    assert len(note["sinks"]) == 200 and note["sinks"].endswith("…")


def test_validated_note_rejects_what_isnt_a_note():
    assert validated_note("saves the file") is None
    assert validated_note({"inputs": "f"}) is None  # no 'does'
    assert validated_note({"does": "   "}) is None


def test_format_note_keeps_none_and_marks_partial_notes():
    """"checks: none" is what a security review needs to know."""
    note = {"does": "Saves f", "inputs": "f", "checks": "none", "sinks": "", "passes_on": "f to write()", "partial": True}

    assert format_note(note) == (
        f"does: Saves f; inputs: f; checks: none; passes on: f to write() (from its first {NOTE_MAX_LINES} lines)"
    )


def test_note_key_depends_on_the_code_only():
    """Not on the model: a scan finds a note whichever model wrote it."""
    assert note_key("def f():\n    return 1\n") == note_key("def f():\n    return 1\n")
    assert note_key("def f():\n    return 1\n") != note_key("def f():\n    return 2\n")


def test_notes_prompt_labels_functions_and_cuts_long_ones():
    long_code = "\n".join(f"    x{i} = {i}" for i in range(NOTE_MAX_LINES + 50))

    system, user = notes_messages([("short", "def short():\n    pass"), ("long", long_code)])

    assert system == {"role": "system", "content": NOTE_INSTRUCTIONS}
    prompt = user["content"]
    tag = re.search(r"<<<REPO TEXT ([0-9a-f]+)>>>", prompt).group(1)
    assert f"=== F1: short ===\n<<<REPO TEXT {tag}>>>\ndef short():\n    pass\n<<<END REPO TEXT {tag}>>>" in prompt
    assert f"=== F2: long (its first {NOTE_MAX_LINES} of {NOTE_MAX_LINES + 50} lines) ===" in prompt
    assert f"x{NOTE_MAX_LINES - 1} =" in prompt and f"x{NOTE_MAX_LINES} =" not in prompt


def test_only_live_functions_and_methods_get_notes():
    base = {"file": "a.py", "start_line": 1, "end_line": 2, "status": "unchanged"}
    assert is_notable(dict(base, kind="function")) and is_notable(dict(base, kind="method"))
    assert not is_notable(dict(base, kind="module"))
    assert not is_notable(dict(base, kind="function", status="deleted"))
    assert not is_notable(dict(base, kind="proxy", file=None))


def test_notes_round_trip_and_a_broken_file_reads_as_empty(tmp_path):
    path = str(tmp_path / "notes.json")
    save_notes(path, {"k": {"does": "x"}})
    assert load_notes(path) == {"k": {"does": "x"}}

    (tmp_path / "notes.json").write_text("{not json")
    assert load_notes(path) == {}
    assert load_notes(str(tmp_path / "missing.json")) == {}
