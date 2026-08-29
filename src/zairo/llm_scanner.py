import hashlib
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from typing import Callable, Dict, List, Optional, Tuple, Any

# `litellm` transitively imports the openai/anthropic SDKs and their full
# Pydantic type trees (~3s). Import it lazily, only once actual scanning
# happens, so `--help` and non-`--llm` runs don't pay that cost.
litellm = None

def _ensure_litellm():
    global litellm
    if litellm is None:
        import litellm as _litellm
        litellm = _litellm
    return litellm

from ._util import display_name as _display_name, normalize_cwe, normalize_severity

# Comment/blank-only diffs (docs, version bumps, log messages) can't produce a
# real vulnerability finding — skip them before spending an LLM call.
_COMMENT_PREFIXES = ("//", "#", "*", "/*", "<!--", "-->", "--", "'''", '"""')

# Test files aren't part of the shipped attack surface. Scanning them tends
# to produce either a duplicate of a finding already attached to the real
# implementation they exercise, or a category error (treating mock/test
# scaffolding as if it were exploitable production code) -- wasted LLM calls
# for low-value output either way.
_TEST_DIR_NAMES = {'test', 'tests', '__tests__', 'spec', 'specs'}
_TEST_STEM_PREFIXES = ('test_', 'test-')
_TEST_STEM_SUFFIXES = ('_test', '-test', '.test', '_spec', '-spec', '.spec')


def _is_test_file(file_path: Optional[str]) -> bool:
    if not file_path:
        return False
    parts = re.split(r'[/\\]', file_path)
    if any(p.lower() in _TEST_DIR_NAMES for p in parts[:-1]):
        return True
    # Strip exactly one extension so "index.test.ts" -> "index.test" (still
    # matches the ".test" suffix) without over-stripping "test_utils.py".
    stem = re.sub(r'\.[a-zA-Z0-9]+$', '', parts[-1]).lower()
    return stem.startswith(_TEST_STEM_PREFIXES) or stem.endswith(_TEST_STEM_SUFFIXES)

# Functions larger than this get a windowed view around the changed lines
# instead of their full body, so a one-line change in a 600-line function
# doesn't cost 600 lines of prompt. Padding is generous on purpose: a tight
# window can hide the guard clause or sanitization that makes a line safe,
# which turns "efficient" into "wrong" for a security review specifically.
_LARGE_FUNCTION_LINES = 100
_WINDOW_PADDING = 20
# Signature + early guard clauses are usually here — always include them
# even when the diff itself is much further down the function.
_GUARD_HEAD_LINES = 15

# Neighbor (caller/callee) context is for orientation, not full audit — cap it.
_NEIGHBOR_MAX_LINES = 30

# Reasoning ("thinking") models count their internal reasoning tokens against
# this same budget. Too low a cap can make the model exhaust it mid-thought
# and return empty content before ever writing the JSON answer — so this
# needs real headroom, not just enough for the expected output size.
_DEFAULT_MAX_OUTPUT_TOKENS = 4096


@lru_cache(maxsize=4096)
def get_source_code(file_path: str, start_line: Optional[int], end_line: Optional[int]) -> str:
    if not file_path or not os.path.exists(file_path):
        return ""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if start_line is None or end_line is None:
            return "".join(lines)

        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), end_line)
        return "".join(lines[start_idx:end_idx])
    except Exception as e:
        return f"// Error reading file: {e}"


def _is_trivial_change(changed_lines: Optional[Dict[int, str]]) -> bool:
    """True if every added/removed line is blank or a comment — not worth an
    LLM call. A pure-deletion marker can bundle several removed lines into
    one multi-line value, so check each physical line within it, not just
    the value as a whole."""
    if not changed_lines:
        return False  # no diff info available; don't risk a false skip
    for text in changed_lines.values():
        for physical_line in (text.splitlines() or [text]):
            stripped = physical_line.strip()
            if not stripped:
                continue
            if stripped.startswith(_COMMENT_PREFIXES):
                continue
            return False
    return True


def _windowed_source(file_path: str, start_line: int, end_line: int, changed_lines: Dict[int, str]) -> str:
    """Full body for small functions; a padded window around changed lines for
    large ones, plus the function's head (signature + early guard clauses)
    unconditionally — a check made there determines whether a flagged line
    further down is actually reachable/dangerous."""
    if (end_line - start_line + 1) <= _LARGE_FUNCTION_LINES or not changed_lines:
        return get_source_code(file_path, start_line, end_line)

    ranges = []

    def add_range(lo, hi):
        if ranges and lo <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], hi))
        else:
            ranges.append((lo, hi))

    add_range(start_line, min(end_line, start_line + _GUARD_HEAD_LINES - 1))
    for ln in sorted(changed_lines.keys()):
        lo = max(start_line, ln - _WINDOW_PADDING)
        hi = min(end_line, ln + _WINDOW_PADDING)
        add_range(lo, hi)

    chunks = [f"# lines {lo}-{hi}\n{get_source_code(file_path, lo, hi)}" for lo, hi in ranges]
    return "\n...\n".join(chunks)


def _sibling_outline(mod_node: Dict[str, Any], nodes: Dict[str, Dict[str, Any]]) -> str:
    """For a module/file-level node, a windowed snippet alone loses all
    orientation — the model can't tell what else the file contains. List the
    other definitions in the same file (name + line range only, no bodies)
    so it has that context without paying to send them in full."""
    siblings = [
        n for n in nodes.values()
        if n.get('file') == mod_node.get('file')
        and n['id'] != mod_node['id']
        and n.get('kind') in ('function', 'class', 'method')
    ]
    if not siblings:
        return ""
    siblings.sort(key=lambda n: n.get('start_line') or 0)
    lines = [f"- {n['name']} ({n.get('kind')}, lines {n.get('start_line')}-{n.get('end_line')})" for n in siblings]
    return "Other definitions in this file (not shown in full):\n" + "\n".join(lines)


def _collapse_nested_definitions(
    file_path: str, start_line: int, end_line: int, nested: List[Dict[str, Any]]
) -> str:
    """For a module/file-level node, replace the body of each nested
    top-level function/class with a one-line placeholder instead of sending
    it in full. A nested definition that changed is already covered by its
    own, more specific seed node — including its full body here too means
    the same vulnerable line gets independently re-flagged under the
    enclosing module as well: wasted cost, and a confusing/duplicate
    attribution in the report (e.g. a vulnerability inside `parse` showing
    up as "module X is vulnerable" instead of "parse is vulnerable")."""
    if not nested:
        return get_source_code(file_path, start_line, end_line)

    skip_ranges = sorted(
        (max(start_line, n['start_line']), min(end_line, n['end_line']), n['name'])
        for n in nested
        if n.get('start_line') is not None and n.get('end_line') is not None
        and n['end_line'] >= start_line and n['start_line'] <= end_line
    )

    chunks = []
    cursor = start_line
    for lo, hi, name in skip_ranges:
        if lo < cursor:
            continue  # nested-within-nested overlap already covered by a prior placeholder
        if lo > cursor:
            chunks.append(get_source_code(file_path, cursor, lo - 1))
        chunks.append(f"    # ... body of `{name}` NOT SHOWN (reviewed separately -- do not guess its contents) ...")
        cursor = hi + 1

    if cursor <= end_line:
        chunks.append(get_source_code(file_path, cursor, end_line))

    return "".join(chunks)


def _neighbor_snippet(n: Dict[str, Any]) -> Optional[str]:
    # .get() throughout: a neighbor can be a malformed/dangling graph node
    # missing these fields entirely (see analyzer.py's subgraph-assembly
    # fallback) -- treat it as having no known source rather than crashing.
    code = get_source_code(n.get('file'), n.get('start_line'), n.get('end_line'))
    if not code.strip():
        return None
    lines = code.splitlines()
    if len(lines) > _NEIGHBOR_MAX_LINES:
        truncated = len(lines) - _NEIGHBOR_MAX_LINES
        code = "\n".join(lines[:_NEIGHBOR_MAX_LINES]) + f"\n... ({truncated} more line(s) truncated)"
    return f"Function: {n.get('name', '?')}\n```\n{code}\n```"


def _hash_prompt(model: str, mod_code: str, neighbor_contexts: List[str]) -> str:
    h = hashlib.sha256()
    h.update(model.encode('utf-8'))
    h.update(b'\x00')
    h.update(mod_code.encode('utf-8', errors='ignore'))
    for c in sorted(neighbor_contexts):
        h.update(b'\x00')
        h.update(c.encode('utf-8', errors='ignore'))
    return h.hexdigest()


def _load_cache(cache_path: Optional[str]) -> Dict[str, List[Dict]]:
    if not cache_path or not os.path.exists(cache_path):
        return {}
    try:
        with open(cache_path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache_path: Optional[str], cache: Dict[str, List[Dict]]) -> None:
    if not cache_path:
        return
    try:
        os.makedirs(os.path.dirname(cache_path) or ".", exist_ok=True)
        with open(cache_path, 'w') as f:
            json.dump(cache, f)
    except Exception:
        pass


# Strips a leading/trailing code fence regardless of language tag
# (```json, ```JSON, or bare ```), which is the only variant the old
# literal-string `startswith("```json")` check handled.
_FENCE_RE = re.compile(r'^\s*```[a-zA-Z]*\s*\n?|\n?\s*```\s*$')

# Some models embed regex-like text (e.g. \w, \d) directly inside a JSON
# string without escaping the backslash -- only \", \\, \/, \b, \f, \n, \r,
# \t, \uXXXX are valid JSON escapes, so a raw \w is a hard parse error.
# The first alternative below matches (and leaves untouched) any already-
# valid escape as a single unit; the second only fires on a lone/invalid
# backslash, so this is a no-op on already-valid JSON.
_INVALID_ESCAPE_RE = re.compile(r'\\(["\\/bfnrtu])|\\')


def _fix_invalid_escapes(s: str) -> str:
    return _INVALID_ESCAPE_RE.sub(lambda m: m.group(0) if m.group(1) else '\\\\', s)


_JSON_DECODER = json.JSONDecoder(strict=False)  # strict=False: tolerate raw
# control characters (e.g. literal newlines) inside string values, which
# some models emit instead of a proper \n escape.


def _extract_json(content: str) -> dict:
    """Parses the model's response, tolerating fence variants, stray prose,
    trailing content after the JSON (some smaller/less-aligned models keep
    generating after a complete answer — duplicate output, trailing
    commentary — which plain json.loads() rejects outright as "Extra data"),
    invalid backslash escapes from embedded regex-like text, and a bare
    `[...]` findings array where a `{"vulnerabilities": [...]}` object was
    asked for (normalized back into that shape here, at the parsing
    boundary, so callers can always rely on a dict with a "vulnerabilities"
    key). Uses JSONDecoder.raw_decode, which parses the first complete JSON
    value and stops there instead of requiring the whole string to be one
    value.
    """
    fixed = _fix_invalid_escapes(content)
    stripped = _FENCE_RE.sub('', fixed).strip()

    candidates = [stripped]
    first_brace = fixed.find('{')
    if first_brace != -1:
        candidates.append(fixed[first_brace:].strip())

    last_err = None
    last_candidate = None
    for candidate in candidates:
        if not candidate:
            continue
        try:
            obj, _ = _JSON_DECODER.raw_decode(candidate)
            if isinstance(obj, list):
                obj = {"vulnerabilities": obj}
            return obj
        except json.JSONDecodeError as e:
            last_err, last_candidate = e, candidate

    # Show the text around the actual failure point, not just the start of
    # the response — a generic head-of-string preview doesn't help diagnose
    # a structural error (e.g. a missing comma) that occurs deep in the doc.
    if last_err is not None:
        pos = last_err.pos
        window = last_candidate[max(0, pos - 80):pos + 80]
        raise ValueError(f"could not find valid JSON ({last_err}); near failure point: {window!r}")

    raise ValueError(f"could not find valid JSON in model response: {content[:200]!r}")


def _build_prompt(mod_node: Dict[str, Any], mod_code: str, neighbor_contexts: List[str]) -> str:
    kind_label = mod_node.get('kind') or 'function'
    return f"""
You are an expert security auditor. Analyze the following modified {kind_label} for vulnerabilities.
Modified {kind_label.capitalize()}: {mod_node['name']}
```
{mod_code}
```
Context Functions (Callers/Callees):
{chr(10).join(neighbor_contexts)}

Base every finding strictly on the code actually shown above. Do not speculate about the contents of omitted/NOT-SHOWN function bodies, imports, or third-party libraries based on their name alone — if you haven't seen the code, don't report a vulnerability in it.

Return ONLY a JSON object with a single key 'vulnerabilities' — no markdown code fence, no prose before or after it. The value should be a list of objects containing 'title', 'description', 'impact', 'severity', and 'cwe'. Keep 'title'/'description'/'impact' to 1-2 sentences each. 'severity' must be exactly one of: "critical" (remote code execution, full system/data compromise), "high" (significant data exposure or privilege escalation), "medium" (real but limited impact, or requires specific conditions to exploit), "low" (minor or defense-in-depth). 'cwe' is the single most applicable CWE identifier in the form "CWE-<number>" (e.g. "CWE-78" for OS command injection, "CWE-89" for SQL injection) — use null if none clearly applies, don't guess one that doesn't fit. If no vulnerabilities are found, return {{"vulnerabilities": []}}.
"""


def scan_graph_for_vulnerabilities(
    graph_data: Dict[str, Any],
    model: str,
    log: Optional[Callable[[str], None]] = None,
    concurrency: int = 5,
    cache_path: Optional[str] = None,
    max_tokens: int = _DEFAULT_MAX_OUTPUT_TOKENS,
) -> Tuple[Dict[str, List[Dict]], Dict[str, int]]:
    """Returns (vulnerabilities, token_usage). token_usage has
    prompt_tokens/completion_tokens/total_tokens summed across every real
    LLM call made (cache hits don't count -- they made no call), plus
    requests/requests_without_usage so a caller can tell whether the token
    totals are complete or partial (e.g. some providers don't report it)."""
    log = log or (lambda msg: None)
    log_lock = threading.Lock()

    def safe_log(msg: str) -> None:
        with log_lock:
            log(msg)

    vulnerabilities = {}
    nodes = {n['id']: n for n in graph_data['nodes']}
    edges = graph_data['edges']
    cache = _load_cache(cache_path)

    model_label = model

    modified_nodes = [n for n in graph_data['nodes'] if n['status'] in ['modified', 'added']]
    log(f"Scanning {len(modified_nodes)} modified/added node(s) with {model_label}")

    # Build prompts up front (cheap, local) so trivial/cached nodes never
    # touch the network, and only real work goes into the thread pool.
    jobs = []
    for mod_node in modified_nodes:
        if mod_node.get('kind') == 'proxy':
            # A proxy node represents an external/unresolved call target
            # (e.g. `fs.unlinkSync`), shared across every call site to it in
            # the whole codebase -- it isn't first-party source with a real
            # body of its own. Scanning it pulls in ALL of its callers as
            # "context" (anyone who calls fs.unlinkSync, anywhere), which
            # leaks fully unrelated, unchanged functions from other files
            # into the prompt and produces findings misattributed to code
            # that was never touched by this diff.
            log(f"  skip (proxy node, not first-party source): {_display_name(mod_node['name'])}")
            continue
        if _is_test_file(mod_node.get('file')):
            log(f"  skip (test file, not shipped attack surface): {_display_name(mod_node['name'])} ({mod_node.get('file')})")
            continue
        changed_lines = mod_node.get('changed_lines')
        # Trivial-skip only applies to module-level edits (e.g. a version
        # bump, a standalone doc comment). Skipping a function-kind node
        # because its own diff happens to be comment-only would also skip
        # scanning whatever pre-existing vulnerable code the rest of that
        # (possibly still-unfixed) function contains -- and small functions
        # cost nothing extra to scan in full anyway, so there's no real
        # savings being traded away by not skipping them.
        if mod_node.get('kind') == 'module' and _is_trivial_change(changed_lines):
            log(f"  skip (trivial diff): {_display_name(mod_node['name'])} ({mod_node.get('file')})")
            continue

        start, end = mod_node.get('start_line'), mod_node.get('end_line')
        if mod_node.get('kind') == 'module' and start is not None and end is not None:
            # A module/file node's own scan shouldn't re-send full bodies of
            # nested functions/classes -- those are already covered by their
            # own, more specific seed node when they change, and including
            # them here too just duplicates cost and mis-attributes their
            # findings to the enclosing module instead of the actual function.
            nested = [
                n for n in nodes.values()
                if n.get('file') == mod_node['file']
                and n['id'] != mod_node['id']
                and n.get('kind') in ('function', 'class')
                and n.get('start_line') is not None and n.get('end_line') is not None
                and n['start_line'] >= start and n['end_line'] <= end
            ]
            mod_code = _collapse_nested_definitions(mod_node['file'], start, end, nested)
        elif changed_lines and start is not None and end is not None:
            mod_code = _windowed_source(mod_node['file'], start, end, changed_lines)
        else:
            mod_code = get_source_code(mod_node['file'], start, end)

        if not mod_code.strip():
            log(f"  skip (no source found): {_display_name(mod_node['name'])}")
            continue

        # A module/file-level node's window is a tiny slice of the whole
        # file — without an outline of what else is there, the model has no
        # idea whether the flagged line is actually reachable in isolation.
        if mod_node.get('kind') == 'module':
            outline = _sibling_outline(mod_node, nodes)
            if outline:
                mod_code = outline + "\n\n" + mod_code

        # "contains" edges are structural nesting (module -> its functions),
        # not a caller/callee relationship -- pulling a contained child's
        # full body in here as "context" would (a) re-leak exactly the
        # content the collapse step above just excluded from a module's own
        # scan, reintroducing the duplicate-attribution bug, and (b) for a
        # function node, pointlessly pull in its enclosing module's source
        # under a "Callers/Callees" label where it doesn't belong.
        neighbor_ids = set()
        for e in edges:
            if e.get('kind') == 'contains':
                continue
            if e['source'] == mod_node['id']:
                neighbor_ids.add(e['target'])
            elif e['target'] == mod_node['id']:
                neighbor_ids.add(e['source'])

        neighbor_contexts = []
        for n_id in neighbor_ids:
            if n_id in nodes and n_id != mod_node['id']:
                snippet = _neighbor_snippet(nodes[n_id])
                if snippet:
                    neighbor_contexts.append(snippet)

        prompt_hash = _hash_prompt(model_label, mod_code, neighbor_contexts)
        cached = cache.get(prompt_hash)
        if cached is not None:
            log(f"  cache hit: {_display_name(mod_node['name'])} ({len(cached)} finding(s))")
            if cached:
                vulnerabilities[mod_node['id']] = cached
            continue

        jobs.append((mod_node, prompt_hash, _build_prompt(mod_node, mod_code, neighbor_contexts)))

    def run_job(job):
        mod_node, prompt_hash, prompt = job
        usage = None  # unavailable if the provider doesn't report it
        try:
            response = litellm.completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
            )
            choice = response.choices[0]
            content = choice.message.content or ""
            finish_reason = getattr(choice, 'finish_reason', 'unknown')
            empty_note = (
                f" (finish_reason={finish_reason}) — likely exhausted max_tokens={max_tokens} "
                f"on internal reasoning before writing an answer; try --max-tokens with a higher value"
            )
            resp_usage = getattr(response, 'usage', None)
            if resp_usage is not None:
                usage = {
                    'prompt_tokens': getattr(resp_usage, 'prompt_tokens', 0) or 0,
                    'completion_tokens': getattr(resp_usage, 'completion_tokens', 0) or 0,
                    'total_tokens': getattr(resp_usage, 'total_tokens', 0) or 0,
                }

            if not content.strip():
                safe_log(f"  error scanning {_display_name(mod_node['name'])}: model returned empty content{empty_note}")
                return mod_node['id'], prompt_hash, None, usage

            try:
                parsed = _extract_json(content)
            except ValueError as e:
                safe_log(f"  error scanning {_display_name(mod_node['name'])}: {e}")
                return mod_node['id'], prompt_hash, None, usage

            findings = parsed.get("vulnerabilities", [])
            for finding in findings:
                finding["severity"] = normalize_severity(finding.get("severity"))
                finding["cwe"] = normalize_cwe(finding.get("cwe"))
            safe_log(f"  found {len(findings)} vulnerability finding(s): {_display_name(mod_node['name'])}")
            return mod_node['id'], prompt_hash, findings, usage
        except Exception as e:
            safe_log(f"  error scanning {_display_name(mod_node['name'])}: {e}")
            return mod_node['id'], prompt_hash, None, usage

    token_usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'requests': 0, 'requests_without_usage': 0}

    if jobs:
        _ensure_litellm()  # deferred until there's actually a request to make
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            futures = [pool.submit(run_job, job) for job in jobs]
            for future in as_completed(futures):
                node_id, prompt_hash, findings, usage = future.result()
                token_usage['requests'] += 1
                if usage:
                    token_usage['prompt_tokens'] += usage['prompt_tokens']
                    token_usage['completion_tokens'] += usage['completion_tokens']
                    token_usage['total_tokens'] += usage['total_tokens']
                else:
                    token_usage['requests_without_usage'] += 1
                if findings is None:
                    continue  # request failed; don't cache a non-result
                cache[prompt_hash] = findings
                if findings:
                    vulnerabilities[node_id] = findings

    _save_cache(cache_path, cache)
    return vulnerabilities, token_usage
