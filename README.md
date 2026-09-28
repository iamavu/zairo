# zairo
Diff security scanners miss the effects of the changes, Zairo finds those effects and looks for vulnerabilities.
Zairo scans what has changed in your code with context, makes a subgraph for you to look at and finds vulnerabilities using LLMs of your choice.

![graph](images/graph.png)


## Installation

```bash
pipx install zairo
```
## Usage

```bash
# Scan whatever you haven't committed yet
zairo .

# Scan what the latest commit changed
zairo . --from HEAD~1 --to HEAD

# Scan a PR/branch diff
zairo . --from main --to HEAD

# Fail the build if anything high-severity turns up
zairo . --from main --to HEAD --fail-on high
```

Give it more than one repo, as extra arguments or one per line in a `--repos-file` (or both, merged into one list), and it switches to **multi-repo mode** on its own: every repo gets its own report, plus one combined summary.
```bash
zairo backend frontend infra --from main --fail-on high -o zairo_multi_out
```

`--from`/`--to` (and every other option) apply the same way to every repo in the list, so multi-repo mode fits best when they all diff against the same thing (e.g. everyone's `main`). Repos with different conventions need separate runs.

### Flags

**What to scan**

- `--from`, `-f` *(none)*: ref to diff from (the older side), e.g. `main` or `HEAD~3`. Left out, `zairo` scans uncommitted changes instead: staged, unstaged, and new untracked files (anything `.gitignore`d is skipped).
- `--to`, `-t` *(none)*: ref to diff to (the newer side), e.g. `HEAD` or a branch. Needs `--from`, and errors without it; left out (with `--from` set), it diffs against your working tree.
- `--depth`, `-d` *(1)*: how many hops of callers/callees the report's graph shows around each change. It doesn't change what the model sees: that's always each changed symbol's direct callers and callees (up to 8 in full, the rest by name), whatever the depth. Calls into external code (e.g. `os.system`) show up as external references, but the graph never expands through them, since they'd link every function that makes the same call.
- `--language`, `-l` *(auto)*: force a language instead of letting Trailmark auto-detect it.

**LLM scanning**

- `--graph-only` *(off)*: skip the vulnerability scan and only build the impact graph -- no findings, no `report.sarif`.
- `--model` *(`gemini/gemini-2.5-pro`)*: any [LiteLLM model string](https://docs.litellm.ai/docs/providers).
- `--concurrency`, `-c` *(5)*: parallel LLM requests, within one repo's scan.
- `--batch-size` *(1)*: group this many nodes into a single LLM request instead of one call per node -- fewer requests (helps with provider rate limits), at the cost of shared fault isolation: a bad/malformed response fails every node in that batch, not just one. Caching stays per-node either way.
- `--max-tokens` *(4096)*: output budget per request. Reasoning models burn this on internal thinking too, so raise it if you see empty responses.
- `--cache` / `--no-cache` *(cache on)*: skip re-scanning code that's unchanged since the last run (cached by content hash in `<output>/.llm_cache.json`).
- `--tokens` *(off)*: print how many tokens the scan actually used (cache hits don't count, since they made no call).

**Output & gating**

- `--output`, `-o` *(`zairo_out`)*: where the reports go. Multi-repo mode: each repo gets its own `<output>/<repo-slug>/`, plus a combined `rollup.*` here too.
- `--fail-on` *(none)*: exit non-zero if a finding at or above this severity turns up (`low`/`medium`/`high`/`critical`), or if the scan is incomplete (any node the model couldn't assess). Errors if combined with `--graph-only` (nothing to gate on). Multi-repo mode: checked across all repos combined. See [CI / PR gating](#ci--pr-gating).
- `--verbose`, `-v` *(off)*: print what's happening step by step (git commands, worktree setup, per-node scan progress).
- `--debug`, `-vv` *(off)*: everything `--verbose` prints, plus the exact prompt sent to the LLM and its raw response for every node -- written to `<output>/debug.log` (per-repo in multi-repo mode), since it's too much to print to the console.

**Multi-repo mode only**

- `--repos-file` *(none)*: one repo path per line (`#` comments allowed), merged with any repos given directly.
- `--repo-concurrency` *(1)*: how many repos to scan at once. Total in-flight LLM requests can reach `--concurrency` × `--repo-concurrency`, so mind your provider's rate limits. Above 1, progress prints one summary line per repo on completion instead of live step-by-step detail.
- `--continue-on-error` / `--stop-on-error` *(continue)*: keep scanning the rest of the list, or stop, when one repo fails. Either way, any failed repo still fails the overall exit code.

Run `zairo --help` any time for this same list from the CLI.

## Output files

- **`report.json`** *(always)*: the raw impact graph (nodes, edges, and any attached findings), as data. Each changed node carries its `diff_hunks`: the lines the change removed and added there, which is also what the model is shown alongside the code. Each edge carries `lines`: where in its source's file it occurs (for a call, every call site), when Trailmark knows. The model sees a long caller around those call sites rather than from the top. After a vulnerability scan, `scan_complete` says whether every node got assessed, and each one that didn't carries a `scan_error` saying why. A changed node left out on purpose (a comment-only change, source that can't be read, ...) carries a `scan_skipped` reason instead. Modules are named by their file path (`src/config/settings.local.ts`); their `id` is Trailmark's dotted form of it, which escapes dots in file names (`src.config.settings\.local`). Each finding has a `title`, `description`, `impact`, `severity` and `cwe`, plus:
  - `line`: the line it's about. The model is shown numbered code, and a line it cites is kept only if it was one of those shown; otherwise it's `null`.
  - `introduced_by_change`: `true` if this change introduced it or made it reachable (for example by removing a check), `false` if it was already there.
  - `trigger`: who can trigger it, and how.
  - `confidence`: `high`/`medium`/`low`, how sure the model is that it's real. This is separate from `severity`, which is how bad it would be.
- **`report.html`** *(always)*: a self-contained, interactive dependency-graph viewer (Cytoscape.js). Click a node to see its findings.
- **`report.sarif`** *(unless `--graph-only` is used)*: findings in [SARIF 2.1.0](https://sarifweb.azurewebsites.net/), for GitHub code scanning or any other SARIF consumer. Always written, even for a clean scan (an empty-but-valid log), so a scanning UI can mark previously reported alerts resolved. Findings are grouped into rules by CWE when the model tagged one, so recurring issues of the same kind collapse into one rule instead of a new one per wording variant. Each result points at the line its finding cites (or where the function starts, if it cited none), and carries `introducedByChange` and `confidence` as properties. An incomplete scan is marked `executionSuccessful: false`, with an error notification per node that couldn't be assessed.

Multi-repo mode produces the same three files per repo, plus `rollup.json` / `rollup.html` / `rollup.sarif`: per-repo status (including `incomplete` scans) and severity counts, a dashboard table linking into each repo's reports, and every repo's SARIF results merged into one multi-run log.

### Test code

Test code isn't part of what you ship, so it's left out of the graph entirely: a change to a test file isn't a changed node, and a test calling changed code isn't pulled in as a caller, so the model never sees it either. A file counts as test code by its path within the repo: a directory named `test`, `tests`, `__tests__`, `spec` or `specs`, or a file name starting with `test_`/`test-` or ending in `_test`, `-test`, `.test`, `_spec`, `-spec` or `.spec` (before the extension, e.g. `index.test.ts`).

### Deleted code

A function/class/module removed entirely (not just edited) still shows up in `report.html`, with status `deleted`: a dashed, faded node marking where it used to live. Trailmark's graph can't represent this on its own (it only ever reflects the tree as it stands now), so `zairo` detects deletions separately: it also parses the changed files as they existed at `--from` (or `HEAD`, if `--from` wasn't given) and diffs the two symbol sets. A deleted function is never sent to the LLM scanner (there's no live code left to scan), so it carries only its name, kind, and former location, never findings.

## CI / PR gating

`--fail-on <low|medium|high|critical>` exits non-zero if any finding at or
above that severity is found (across all repos combined, in multi-repo
mode), so a CI step can block a merge on it. A few things worth knowing:

- It also fails whenever the scan is incomplete: a node the model couldn't
  assess (a provider error, a missing API key, a response that wasn't a
  scan result) is code nobody reviewed, so it can't count as a pass. On
  PRs from forks, GitHub withholds secrets such as the model's API key, so
  expect the gate to fail there rather than silently pass.
- `--from`/`--to` have to name commits that exist in the checkout; an
  unknown ref is an error rather than an empty diff. CI checkouts are
  often shallow, so fetch full history (`fetch-depth: 0` in
  `actions/checkout`, as in the example below).
- It errors if combined with `--graph-only` (there'd be nothing to gate on).
- It never suppresses the SARIF output: that's still written even on a
  failed gate, so a scanning UI reflects the current state either way.

```bash
zairo . --from "$BASE_REF" --to HEAD --fail-on high -o zairo_out
```

See [examples/github-actions/zairo-pr-scan.yml](examples/github-actions/zairo-pr-scan.yml)
for a full PR-scan workflow: it runs zairo on the PR diff, uploads
`report.sarif` to GitHub's code scanning, and fails the job if the gate
fails.
