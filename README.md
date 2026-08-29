# zairo

Git-diff-aware security impact analysis. `zairo` diffs a repository, builds a
dependency subgraph (via [Trailmark](https://pypi.org/project/trailmark/))
around whatever changed, and can run an LLM vulnerability scan limited to
just that changed code — instead of re-scanning the whole codebase on every
change.

Output is a `report.json` (raw graph data), a self-contained `report.html`
(interactive dependency graph viewer), and — when `--llm` is used — a
`report.sarif` for tools that consume [SARIF](https://sarifweb.azurewebsites.net/)
(e.g. GitHub code scanning).

## Install

```bash
pip install zairo
```

For local development:

```bash
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Analyze uncommitted changes in a repo
zairo /path/to/repo

# Diff two refs, traverse 2 hops out from changed nodes, run an LLM scan
zairo /path/to/repo --base main --target HEAD --depth 2 --llm
```

Run `zairo --help` for the full option list.

## CI / PR gating

`--fail-on <low|medium|high|critical>` exits non-zero if any finding at or
above that severity is found, so a CI step can block a merge on it. It
requires `--llm`, and doesn't suppress `report.sarif` — the SARIF file is
still written even on a failed gate (including a clean, empty one on a
passing scan), so a scanning UI reflects the current state either way.

```bash
zairo . --base "$BASE_REF" --target HEAD --llm --fail-on high -o zairo_out
```

See [examples/github-actions/zairo-pr-scan.yml](examples/github-actions/zairo-pr-scan.yml)
for a full PR-scan workflow: it runs zairo on the PR diff, uploads
`report.sarif` to GitHub's code scanning, and fails the job if the gate
fails.

## Development

```bash
pytest
```

## License

MIT — see [LICENSE](LICENSE).
