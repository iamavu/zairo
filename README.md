# zairo

[![CI](https://github.com/iamavu/zairo/actions/workflows/ci.yml/badge.svg)](https://github.com/iamavu/zairo/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/zairo.svg)](https://pypi.org/project/zairo/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Git-diff-aware security scanning.** `zairo` scans what actually changed in
a commit or PR, not the whole codebase — so LLM-based vulnerability scanning
stays fast and cheap enough to run on every diff.

## Why

Pointing an LLM at an entire repository on every commit doesn't scale: it's
slow, expensive, and buries the two lines that actually changed under
thousands that didn't. `zairo` instead:

1. Diffs the repo to find exactly which lines changed.
2. Builds a small dependency graph around those lines — the changed
   functions plus their direct callers/callees — using
   [Trailmark](https://pypi.org/project/trailmark/) (supports Python,
   TypeScript/JavaScript, Java, Go, Rust, C/C++, C#, Ruby, PHP, Swift,
   Kotlin, and more, auto-detected).
3. Scans each changed function/method individually: the model sees that
   code plus real caller/callee snippets — and, when the change is at the
   whole-file level rather than inside one function, an outline of the
   file's other definitions too. All of it pulled from the subgraph only;
   nothing outside it is ever sent.
4. Writes the result as a browsable report, and optionally as SARIF for
   your existing security tooling.

## Contents

- [Why](#why)
- [Install](#install)
- [Quickstart](#quickstart)
- [Usage](#usage) — one command, auto-detects single-repo vs. fleet mode
- [Output files](#output-files)
- [CI / PR gating](#ci--pr-gating)
- [Caching](#caching)
- [Development](#development)

## Install

```bash
pip install zairo
```

Requires Python 3.12+ (a core dependency, Trailmark, requires it). LLM scanning (`--llm`) goes through
[LiteLLM](https://docs.litellm.ai/docs/providers), so you'll also need an
API key for whatever `--model` you use — set via the environment variable
your provider expects (e.g. `GEMINI_API_KEY` for the default
`gemini/gemini-2.5-pro`, `ANTHROPIC_API_KEY` for Claude models, `OPENAI_API_KEY`
for GPT models). See [LiteLLM's provider docs](https://docs.litellm.ai/docs/providers)
for the full list.

## Quickstart

```bash
# Analyze uncommitted changes in a repo
zairo /path/to/repo

# Diff two refs, and run an LLM scan on what changed
zairo /path/to/repo --base main --target HEAD --llm
```

No repo handy? Generate a few small ones with known, distinct
vulnerabilities to try it on:

```bash
python examples/generate_sample_repos.py
zairo examples/sample-repos/cmd-injection-app --base HEAD~1 --target HEAD --llm
```

This creates `examples/sample-repos/{cmd-injection-app,sql-injection-app,path-traversal-app}`
— each a 2-commit repo with one commit introducing a specific,
LLM-findable vulnerability. (Not committed to this repo: a usable git
history can't live nested inside another repo's `.git`, so the generator
creates them locally on demand.)

## Usage

There's one command. It auto-detects which mode to run based on how many
repos end up in the list — however they were given:

```bash
# One repo -> a direct report.json/.html/.sarif
zairo /path/to/repo --base main --target HEAD --llm

# More than one repo (positional, here) -> fleet mode: each repo gets its
# own <output>/<repo-slug>/ subdirectory, plus an aggregate rollup
zairo /path/to/repo-a /path/to/repo-b --base main --target HEAD --llm

# Or from a file, one repo path per line ('#' comments allowed) -- also
# fleet mode once the file has more than one entry, single-repo mode if
# it has exactly one
zairo --repos-file repos.txt --base main --target HEAD --llm --fail-on high
```

Positional paths and `--repos-file` entries combine into one list before the
mode is decided — one positional path plus a one-line `--repos-file` is two
repos total, so it's fleet mode.

In fleet mode, every option below applies identically to *every* repo — that
means `--base`/`--target` need to mean the same thing across all of them,
which fits best when your repos share a diffing convention (e.g. all
diffing against `main`). Repos with different conventions need separate
invocations.

**What to diff:**

| Option | Default | Meaning |
|---|---|---|
| `--base`, `-b` | *(none)* | Ref to diff from (e.g. `main`, `HEAD~3`). Omitted entirely: diffs uncommitted changes against `HEAD`. |
| `--target`, `-t` | *(none)* | Ref to diff to (e.g. `HEAD`, a branch name). Requires `--base`. Omitted with `--base` set: diffs `--base` against the working tree. |
| `--depth`, `-d` | `1` | How many hops to traverse out from changed nodes when building the impact subgraph (callers-of-callers, etc.). |
| `--language`, `-l` | `auto` | Force a specific language for Trailmark parsing instead of auto-detecting. |

**LLM scanning:**

| Option | Default | Meaning |
|---|---|---|
| `--llm` | off | Run the LLM vulnerability scan. Without it, `zairo` only produces the impact graph, no findings. |
| `--model` | `gemini/gemini-2.5-pro` | Any [LiteLLM model string](https://docs.litellm.ai/docs/providers). |
| `--concurrency`, `-c` | `5` | Parallel LLM requests, *within* one repo's scan. |
| `--max-tokens` | `4096` | Output token budget per request. Reasoning models count their internal thinking against this too — too low can produce empty responses; raise it if you see that. |
| `--cache` / `--no-cache` | cache on | Cache findings by content hash in `<output>/.llm_cache.json`, so re-running against unchanged code skips the LLM entirely. |
| `--tokens` | off | Print total prompt/completion/total token usage across real API calls (cache hits aren't counted — they made no call). In fleet mode, one combined total across every repo, not a per-repo breakdown. |

**Output & gating:**

| Option | Default | Meaning |
|---|---|---|
| `--output`, `-o` | `zairo_out` | Single repo: output directory for `report.json` / `report.html` / `report.sarif`. Fleet mode: each repo's reports go under `<output>/<repo-slug>/`, plus an aggregate `fleet.json` / `fleet.html` / `fleet.sarif` here. |
| `--fail-on` | *(none)* | Exit non-zero if any finding is at or above this severity (`low`/`medium`/`high`/`critical`). Requires `--llm`. Fleet mode: evaluated across **all** repos combined — one `critical` finding anywhere fails the whole run. See [CI / PR gating](#ci--pr-gating). |
| `--verbose`, `-v` | off | Print diagnostic detail: git commands run, worktree setup, node matching, per-node LLM scan progress, and full (untruncated) per-node error messages. |

**Fleet mode only** (ignored for a single repo):

| Option | Default | Meaning |
|---|---|---|
| `--repos-file` | *(none)* | A text file, one repo path per line, merged with any positional paths. |
| `--repo-concurrency` | `1` (sequential) | How many repos to scan in parallel. Above 1, progress prints one summary line per repo on completion (in completion order) instead of the default's live per-stage detail — concurrent repos' output can't safely interleave line-by-line. `--stop-on-error` also becomes best-effort: it cancels repos that haven't started yet, but can't interrupt one already in flight. |
| `--continue-on-error` / `--stop-on-error` | continue | Whether one repo failing (bad path, parse error, ...) aborts the rest of the run. Either way, any failed repo still fails the overall exit code. |

Note `--concurrency` and `--repo-concurrency` control different things:
`--concurrency` is LLM requests in parallel *within* one repo's scan;
`--repo-concurrency` is how many repos run at once. Combined, total
in-flight LLM requests can reach their product — mind your provider's rate
limits.

Run `zairo --help` for this same list from the CLI.

## Output files

| File | When | What it is |
|---|---|---|
| `report.json` | always | The raw impact graph (nodes, edges, and any attached findings) as data. |
| `report.html` | always | A self-contained, interactive dependency-graph viewer (Cytoscape.js) — click a node to see its findings. |
| `report.sarif` | `--llm` used | Findings in [SARIF 2.1.0](https://sarifweb.azurewebsites.net/), for GitHub code scanning or any other SARIF consumer. Written even for a clean scan (an empty-but-valid log) — that's what lets a scanning UI mark previously reported alerts as resolved. Findings are grouped into SARIF rules by CWE when the model tagged one, so recurring issues of the same category collapse into one rule instead of a new one every time the wording differs. |

Fleet mode produces the same three files per repo, plus `fleet.json` /
`fleet.html` / `fleet.sarif` (a rollup: per-repo status and severity counts,
a dashboard table linking into each repo's reports, and every repo's SARIF
results merged into one multi-run log).

### Deleted code

A function/class/module removed entirely (not just edited) shows up in
`report.html` too, with status `deleted` — a dashed, faded node showing
where it used to live. This isn't something Trailmark's graph can represent
on its own (it only ever reflects the tree as it currently is); `zairo`
detects it separately by also parsing the changed files as they existed at
`--base` (or `HEAD`, if `--base` wasn't given) and diffing the two symbol
sets. A deleted function is never sent to the LLM scanner — there's no live
code left to scan — so it never carries findings, only its name, kind, and
where it used to be.

## CI / PR gating

`--fail-on <low|medium|high|critical>` exits non-zero if any finding at or
above that severity is found (evaluated across all repos combined in fleet
mode), so a CI step can block a merge on it. It requires `--llm`, and
doesn't suppress the SARIF output — it's still written even on a failed
gate, so a scanning UI reflects the current state either way.

```bash
zairo . --base "$BASE_REF" --target HEAD --llm --fail-on high -o zairo_out
```

See [examples/github-actions/zairo-pr-scan.yml](examples/github-actions/zairo-pr-scan.yml)
for a full PR-scan workflow: it runs zairo on the PR diff, uploads
`report.sarif` to GitHub's code scanning, and fails the job if the gate
fails.

## Caching

LLM findings are cached by a hash of the exact prompt content (the code
sent, plus its neighbor context) — not by commit or file path. So re-running
`zairo` after an unrelated change elsewhere in the repo, or after reverting
a change back to something previously scanned, skips the LLM call entirely
for anything unchanged. The cache lives at `<output>/.llm_cache.json`;
delete it (or pass `--no-cache`) to force a fresh scan.

## Development

```bash
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest
```

The package uses a `src/` layout (`src/zairo/`), so `pip install -e .` is
required for `import zairo` to resolve correctly during development — the
package isn't importable by just being on `PYTHONPATH` from the repo root.

## License

MIT — see [LICENSE](LICENSE).
