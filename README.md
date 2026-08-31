# zairo

[![CI](https://github.com/iamavu/zairo/actions/workflows/ci.yml/badge.svg)](https://github.com/iamavu/zairo/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/zairo.svg)](https://pypi.org/project/zairo/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Git-diff-aware security scanning.** `zairo` scans what actually changed in
a commit or PR, not the whole codebase, so LLM-based vulnerability scanning
stays fast and cheap enough to run on every diff.

## Why

Pointing an LLM at an entire repository on every commit doesn't scale: it's
slow, expensive, and buries the two lines that actually changed under
thousands that didn't. So `zairo` narrows the scope first, then scans:

1. **Diff.** Find exactly which lines changed.
2. **Build a small graph around them**, the changed functions plus their
   direct callers/callees, using [Trailmark](https://pypi.org/project/trailmark/)
   (Python, TypeScript/JavaScript, Java, Go, Rust, C/C++, C#, Ruby, PHP,
   Swift, Kotlin, and more, auto-detected).
3. **Scan each changed function on its own**, with real caller/callee
   snippets as context (and, for a whole-file-level change, an outline of
   what else lives in that file). Only what's in the graph is ever sent:
   nothing else in the repo.
4. **Write a browsable report**, plus SARIF for your existing security
   tooling.

## Contents

- [Why](#why)
- [Install](#install)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Output files](#output-files)
- [CI / PR gating](#ci--pr-gating)
- [Caching](#caching)
- [Development](#development)

## Install

```bash
pip install zairo
```

- Needs **Python 3.12+** (Trailmark, a core dependency, requires it).
- `--llm` scanning goes through [LiteLLM](https://docs.litellm.ai/docs/providers),
  so you'll need an API key for whatever `--model` you use, set via the
  environment variable your provider expects: `GEMINI_API_KEY` for the
  default `gemini/gemini-2.5-pro`, `ANTHROPIC_API_KEY` for Claude,
  `OPENAI_API_KEY` for GPT, and so on. Full list in
  [LiteLLM's provider docs](https://docs.litellm.ai/docs/providers).

## Quickstart

```bash
# Analyze uncommitted changes in a repo
zairo /path/to/repo

# Diff two refs, and run an LLM scan on what changed
zairo /path/to/repo --base main --target HEAD --llm
```

## Usage

```bash
# Scan whatever you haven't committed yet
zairo .

# Scan a PR/branch diff with the LLM vulnerability scanner
zairo . --base main --target HEAD --llm

# Same, but fail the build if anything high-severity turns up
zairo . --base main --target HEAD --llm --fail-on high
```

Give it more than one repo, as extra arguments or one per line in a
`--repos-file` (or both, merged into one list), and it switches to
**multi-repo mode** on its own: every repo gets its own report, plus one
combined summary.

```bash
zairo backend frontend infra --base main --llm --fail-on high -o zairo_multi_out
```

`--base`/`--target` (and every other option) apply the same way to every
repo in the list, so multi-repo mode fits best when they all diff against
the same thing (e.g. everyone's `main`). Repos with different conventions
need separate runs.

### Flags

**What to scan**

- `--base`, `-b` *(none)*: ref to diff from, e.g. `main` or `HEAD~3`. Left out, `zairo` scans uncommitted changes instead.
- `--target`, `-t` *(none)*: ref to diff to. Needs `--base`; left out (with `--base` set), it diffs against your working tree.
- `--depth`, `-d` *(1)*: how many hops of callers/callees to pull into the impact graph around each change.
- `--language`, `-l` *(auto)*: force a language instead of letting Trailmark auto-detect it.

**LLM scanning**

- `--llm` *(off)*: turn on the vulnerability scan. Without it you just get the impact graph, no findings.
- `--model` *(`gemini/gemini-2.5-pro`)*: any [LiteLLM model string](https://docs.litellm.ai/docs/providers).
- `--concurrency`, `-c` *(5)*: parallel LLM requests, within one repo's scan.
- `--max-tokens` *(4096)*: output budget per request. Reasoning models burn this on internal thinking too, so raise it if you see empty responses.
- `--cache` / `--no-cache` *(cache on)*: skip re-scanning code that's unchanged since the last run (cached by content hash in `<output>/.llm_cache.json`).
- `--tokens` *(off)*: print how many tokens the scan actually used (cache hits don't count, since they made no call).

**Output & gating**

- `--output`, `-o` *(`zairo_out`)*: where the reports go. Multi-repo mode: each repo gets its own `<output>/<repo-slug>/`, plus a combined `rollup.*` here too.
- `--fail-on` *(none)*: exit non-zero if a finding at or above this severity turns up (`low`/`medium`/`high`/`critical`). Needs `--llm`. Multi-repo mode: checked across all repos combined. See [CI / PR gating](#ci--pr-gating).
- `--verbose`, `-v` *(off)*: print what's happening step by step (git commands, worktree setup, per-node scan progress).

**Multi-repo mode only**

- `--repos-file` *(none)*: one repo path per line (`#` comments allowed), merged with any repos given directly.
- `--repo-concurrency` *(1)*: how many repos to scan at once. Total in-flight LLM requests can reach `--concurrency` × `--repo-concurrency`, so mind your provider's rate limits. Above 1, progress prints one summary line per repo on completion instead of live step-by-step detail.
- `--continue-on-error` / `--stop-on-error` *(continue)*: keep scanning the rest of the list, or stop, when one repo fails. Either way, any failed repo still fails the overall exit code.

Run `zairo --help` any time for this same list from the CLI.

## Output files

- **`report.json`** *(always)*: the raw impact graph (nodes, edges, and any attached findings), as data.
- **`report.html`** *(always)*: a self-contained, interactive dependency-graph viewer (Cytoscape.js). Click a node to see its findings.
- **`report.sarif`** *(when `--llm` is used)*: findings in [SARIF 2.1.0](https://sarifweb.azurewebsites.net/), for GitHub code scanning or any other SARIF consumer. Always written, even for a clean scan (an empty-but-valid log), so a scanning UI can mark previously reported alerts resolved. Findings are grouped into rules by CWE when the model tagged one, so recurring issues of the same kind collapse into one rule instead of a new one per wording variant.

Multi-repo mode produces the same three files per repo, plus `rollup.json` /
`rollup.html` / `rollup.sarif`: per-repo status and severity
counts, a dashboard table linking into each repo's reports, and every
repo's SARIF results merged into one multi-run log.

### Deleted code

A function/class/module removed entirely (not just edited) still shows up
in `report.html`, with status `deleted`: a dashed, faded node marking
where it used to live. Trailmark's graph can't represent this on its own
(it only ever reflects the tree as it stands now), so `zairo` detects
deletions separately: it also parses the changed files as they existed at
`--base` (or `HEAD`, if `--base` wasn't given) and diffs the two symbol
sets. A deleted function is never sent to the LLM scanner (there's no live
code left to scan), so it carries only its name, kind, and former
location, never findings.

## CI / PR gating

`--fail-on <low|medium|high|critical>` exits non-zero if any finding at or
above that severity is found (across all repos combined, in multi-repo
mode), so a CI step can block a merge on it. A couple of things worth
knowing:

- It requires `--llm`.
- It never suppresses the SARIF output: that's still written even on a
  failed gate, so a scanning UI reflects the current state either way.

```bash
zairo . --base "$BASE_REF" --target HEAD --llm --fail-on high -o zairo_out
```

See [examples/github-actions/zairo-pr-scan.yml](examples/github-actions/zairo-pr-scan.yml)
for a full PR-scan workflow: it runs zairo on the PR diff, uploads
`report.sarif` to GitHub's code scanning, and fails the job if the gate
fails.

## Caching

LLM findings are cached by a hash of the exact prompt content (the code
sent, plus its neighbor context), not by commit or file path. So
re-running `zairo` after an unrelated change elsewhere in the repo, or
after reverting a change back to something already scanned, skips the LLM
call entirely for anything unchanged. The cache lives at
`<output>/.llm_cache.json`; delete it (or pass `--no-cache`) to force a
fresh scan.

## Development

```bash
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest
```

The package uses a `src/` layout (`src/zairo/`), so `pip install -e .` is
required for `import zairo` to resolve: it isn't importable by just being
on `PYTHONPATH` from the repo root.

## License

MIT. See [LICENSE](LICENSE).
