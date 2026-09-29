"""--dig: the model looks up what it needs before it answers -- warm-up
notes, source, callers and callees, a text search -- instead of seeing
only the context zairo picks for it.

Each changed symbol is a conversation: the same prompt as a normal scan,
plus read-only tools, up to MAX_LOOKUPS lookups, then the same findings
JSON as a normal scan. A lookup's result is repo text, so it comes back
in tagged blocks like the prompt's (see untrusted.py)."""
import json
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ._util import is_test_file
from .git_utils import list_files
from .notes import format_note
from .untrusted import block, inline, seal

MAX_LOOKUPS = 8

_CODE_LINES = 200
_SEARCH_MIN_CHARS = 3
_SEARCH_MATCHES = 30
_SEARCH_LINE_CHARS = 200
_SEARCH_MAX_FILE_BYTES = 1_000_000
_LISTED = 30  # callers, callees, or symbols matching an ambiguous name
_GUTTER = 5

_SYMBOL = {"type": "string", "description": "The function's or class's name as the prompt shows it, file:name to pick one of several with that name, or its id."}

TOOLS = [
    {"type": "function", "function": {
        "name": "note",
        "description": "The warm-up note on a function: a short machine-written summary of what its own code does -- its inputs, the checks it performs, its security-sensitive operations, and what it passes to which calls. Cheap: try it before code().",
        "parameters": {"type": "object", "properties": {"symbol": _SYMBOL}, "required": ["symbol"]},
    }},
    {"type": "function", "function": {
        "name": "code",
        "description": f"A function's or class's source, numbered, up to {_CODE_LINES} lines from from_line (default: its first line).",
        "parameters": {"type": "object", "properties": {
            "symbol": _SYMBOL,
            "from_line": {"type": "integer", "description": "The file line to start from, for a long one."},
        }, "required": ["symbol"]},
    }},
    {"type": "function", "function": {
        "name": "callers",
        "description": "What calls a function, from the call graph -- which can miss calls made through callbacks, dynamic dispatch or frameworks.",
        "parameters": {"type": "object", "properties": {"symbol": _SYMBOL}, "required": ["symbol"]},
    }},
    {"type": "function", "function": {
        "name": "callees",
        "description": "What a function calls, from the call graph.",
        "parameters": {"type": "object", "properties": {"symbol": _SYMBOL}, "required": ["symbol"]},
    }},
    {"type": "function", "function": {
        "name": "search",
        "description": f"The lines in the repository's files (test code aside) that contain this text, ignoring case -- the first {_SEARCH_MATCHES}. For what the call graph doesn't show: where a setting, route or decorator is defined or used.",
        "parameters": {"type": "object", "properties": {"text": {"type": "string", "description": f"At least {_SEARCH_MIN_CHARS} characters, matched literally."}}, "required": ["text"]},
    }},
]

INSTRUCTIONS = f"""Before you answer, you can look things up with the tools you have -- at most {MAX_LOOKUPS} lookups for this review. Use them to settle what the code shown can't: whether a check happens before the changed code is reached, what a function it calls really does with its input, where a value or setting comes from. Try a function's note before its code. Don't look up what you don't need, and answer as soon as you can."""

GROUNDING = """Base every finding on code you've actually seen, shown above or looked up; don't guess at code you haven't seen -- look it up, or leave it out. Report findings in the modified code: a flaw in code you looked up counts only if this change makes it newly reachable, and then belongs on the modified line that reaches it. A finding's 'line' is always a line of the modified code in the user message."""


class Lookups:
    """The tools, over one scan's graph and the repo at the revision
    scanned. Safe to share between the scan's worker threads."""

    def __init__(
        self, nodes: List[Dict[str, Any]], calls_in: Dict[str, List[str]], calls_out: Dict[str, List[str]],
        root: str, note_of: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
        numbered: Callable[[str, int, int], Tuple[List[str], List[int]]],
    ):
        self._by_id = {n['id']: n for n in nodes}
        # Deleted symbols' lines are where they used to be; proxies have no source.
        self._live = [n for n in nodes if n.get('file') and n.get('kind') != 'proxy' and n.get('status') != 'deleted']
        self._live_ids = {n['id'] for n in self._live}
        self._calls_in, self._calls_out = calls_in, calls_out
        self._root = root
        self._note_of = note_of
        self._numbered = numbered
        self._files: Optional[List[str]] = None
        self._files_lock = threading.Lock()

    def run(self, name: str, arguments: Any) -> Tuple[str, Dict[str, Any]]:
        """A tool call's result, sealed, and the lookup as the reports record
        it: {"tool", "input"[, "from_line"]}."""
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else dict(arguments or {})
            if not isinstance(args, dict):
                raise ValueError("not an object")
        except (ValueError, TypeError) as e:
            return seal(f"Couldn't read the arguments ({e}). Pass a JSON object."), {"tool": str(name), "input": str(arguments)[:200]}
        lookup = {"tool": str(name), "input": str(args.get("symbol", args.get("text", "")))[:200]}
        if name == "note":
            text = self._note(args.get("symbol", ""))
        elif name == "code":
            from_line = args.get("from_line")
            if isinstance(from_line, (int, float)) and not isinstance(from_line, bool):
                lookup["from_line"] = int(from_line)
            text = self._code(args.get("symbol", ""), lookup.get("from_line"))
        elif name == "callers":
            text = self._related(args.get("symbol", ""), self._calls_in, "is called by")
        elif name == "callees":
            text = self._related(args.get("symbol", ""), self._calls_out, "calls")
        elif name == "search":
            text = self._search(args.get("text", ""))
        else:
            text = f"There's no tool named {inline(name)!r}: use note, code, callers, callees or search."
        return seal(text), lookup

    def _rel(self, path: str) -> str:
        try:
            return os.path.relpath(path, self._root).replace(os.sep, "/")
        except ValueError:  # another drive, on Windows
            return path

    def _label(self, n: Dict[str, Any]) -> str:
        return f"{inline(n['name'])} ({n.get('kind')}, {inline(self._rel(n['file']))}:{n.get('start_line')}-{n.get('end_line')})"

    def _resolve(self, symbol: Any) -> Tuple[Optional[Dict[str, Any]], str]:
        """The one symbol `symbol` names -- or None, and what to do instead."""
        symbol = str(symbol).strip()
        if symbol in self._live_ids:
            return self._by_id[symbol], ""

        def named(n: Dict[str, Any], name: str) -> bool:
            return n['name'] == name or n['id'].endswith(("." + name, ":" + name))

        matches = [n for n in self._live if named(n, symbol)]
        path, _, name = symbol.rpartition(":")
        if not matches and path:
            matches = [n for n in self._live if named(n, name) and self._rel(n['file']).endswith(path)]
        if len(matches) == 1:
            return matches[0], ""
        if not matches:
            return None, (
                f"No function or class named {inline(symbol)!r} in the code graph. "
                f"search() finds text anywhere in the repository."
            )
        listed = "\n".join(f"- {inline(n['id'], limit=None)}: {self._label(n)}" for n in matches[:_LISTED])
        more = f"\n- ... and {len(matches) - _LISTED} more" if len(matches) > _LISTED else ""
        return None, f"{len(matches)} symbols match {inline(symbol)!r}. Ask again with one of their ids:\n{listed}{more}"

    def _note(self, symbol: Any) -> str:
        n, problem = self._resolve(symbol)
        if n is None:
            return problem
        note = self._note_of(n)
        if not note:
            return f"No warm-up note on {self._label(n)}. code() shows its source."
        return f"Note on {self._label(n)}, machine-written from its code:\n{block(format_note(note))}"

    def _code(self, symbol: Any, from_line: Optional[int]) -> str:
        n, problem = self._resolve(symbol)
        if n is None:
            return problem
        start, end = n['start_line'], n['end_line']
        lo = min(max(start, from_line), end) if from_line is not None else start
        hi = min(end, lo + _CODE_LINES - 1)
        lines, _numbers = self._numbered(n['file'], lo, hi)
        if not lines:
            return f"The source of {self._label(n)} couldn't be read."
        parts = [f"{self._label(n)}:"]
        if lo > start:
            parts.append(f"(lines {start}-{lo - 1} not shown)")
        parts.append(block("\n".join(lines)))
        if hi < end:
            parts.append(f"(lines {hi + 1}-{end} not shown: code() with from_line={hi + 1} shows more)")
        return "\n".join(parts)

    def _related(self, symbol: Any, edges: Dict[str, List[str]], relation: str) -> str:
        n, problem = self._resolve(symbol)
        if n is None:
            return problem
        rows = []
        for other_id in sorted(set(edges.get(n['id'], []))):
            other = self._by_id.get(other_id)
            if other is None or other.get('status') == 'deleted':
                continue
            if other.get('kind') == 'proxy' or not other.get('file'):
                rows.append(f"- {inline(other['name'])} (external, or not resolved)")
            else:
                rows.append(f"- {self._label(other)}")
        if not rows:
            return (
                f"In the call graph, {self._label(n)} {relation} nothing. It can miss calls made through "
                f"callbacks, dynamic dispatch or frameworks; search() can find those."
            )
        more = f"\n- ... and {len(rows) - _LISTED} more" if len(rows) > _LISTED else ""
        return f"{self._label(n)} {relation}:\n" + "\n".join(rows[:_LISTED]) + more

    def _tracked(self) -> List[str]:
        with self._files_lock:
            if self._files is None:
                try:
                    self._files = [path for path in list_files(self._root) if not is_test_file(path)]
                except RuntimeError:
                    self._files = []
            return self._files

    def _search(self, text: Any) -> str:
        text = str(text)
        if len(text.strip()) < _SEARCH_MIN_CHARS:
            return f"Search for at least {_SEARCH_MIN_CHARS} characters."
        needle = text.lower()
        found: Dict[str, List[str]] = {}
        count, cut = 0, False
        for rel in self._tracked():
            path = os.path.join(self._root, rel)
            try:
                if os.path.getsize(path) > _SEARCH_MAX_FILE_BYTES:
                    continue
                with open(path, 'r', encoding='utf-8') as f:
                    lines = f.read().splitlines()
            except (OSError, UnicodeDecodeError):
                continue  # gone, unreadable, or not text
            for number, line in enumerate(lines, 1):
                if needle in line.lower():
                    if count == _SEARCH_MATCHES:
                        cut = True
                        break
                    found.setdefault(rel, []).append(f"{number:>{_GUTTER}} | {line[:_SEARCH_LINE_CHARS]}")
                    count += 1
            if cut:
                break
        if not found:
            return f"No line in the repository contains {inline(text)!r}."
        heading = f"Lines containing {inline(text)!r}" + (f" (the first {_SEARCH_MATCHES})" if cut else "") + ":"
        return heading + "".join(f"\nIn {inline(rel)}:\n{block(chr(10).join(rows))}" for rel, rows in found.items())


@dataclass
class DigRun:
    """One symbol's conversation so far -- kept by the caller, so what it
    cost and looked up survives an error partway."""
    lookups: List[Dict[str, Any]] = field(default_factory=list)
    requests: int = 0
    requests_without_usage: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def usage(self) -> Dict[str, int]:
        return {
            'prompt_tokens': self.prompt_tokens, 'completion_tokens': self.completion_tokens,
            'total_tokens': self.total_tokens, 'requests': self.requests,
            'requests_without_usage': self.requests_without_usage,
        }


def dig(
    completion: Callable[..., Any], model: str, messages: List[Dict[str, Any]], lookups: Lookups, max_tokens: int,
    run: DigRun, log: Callable[[str], None] = lambda text: None,
) -> Tuple[str, str]:
    """Runs one symbol's conversation until the model answers. Returns its
    answer and finish reason -- "lookups_exhausted" if it kept asking for
    lookups after it had used them all. Raises what `completion` raises.
    `log` gets each lookup and its result, for --debug."""
    conversation = list(messages)
    turns_past_budget = 0
    while True:
        response = completion(model=model, messages=conversation, tools=TOOLS, max_tokens=max_tokens)
        run.requests += 1
        usage = getattr(response, 'usage', None)
        if usage is None:
            run.requests_without_usage += 1
        else:
            run.prompt_tokens += getattr(usage, 'prompt_tokens', 0) or 0
            run.completion_tokens += getattr(usage, 'completion_tokens', 0) or 0
            run.total_tokens += getattr(usage, 'total_tokens', 0) or 0
        choice = response.choices[0]
        message = choice.message
        calls = getattr(message, 'tool_calls', None) or []
        if not calls:
            return message.content or "", getattr(choice, 'finish_reason', 'unknown')

        # The model's own message, as it came: some providers need fields
        # of theirs in it (e.g. Gemini's thought signatures) kept intact.
        conversation.append(message)
        if len(run.lookups) >= MAX_LOOKUPS:
            turns_past_budget += 1
        for call in calls:
            name = call.function.name
            if len(run.lookups) < MAX_LOOKUPS:
                result, lookup = lookups.run(name, call.function.arguments)
                run.lookups.append(lookup)
                if len(run.lookups) == MAX_LOOKUPS:
                    result += f"\n\nThat was the last of your {MAX_LOOKUPS} lookups: answer next, with the JSON object only."
            else:
                result = f"Not run: all {MAX_LOOKUPS} lookups are used. Answer now, with the JSON object only."
            log(f"LOOKUP {name}({call.function.arguments})\n{result}")
            conversation.append({"role": "tool", "tool_call_id": call.id, "name": name, "content": result})
        if turns_past_budget >= 2:
            return "", "lookups_exhausted"
