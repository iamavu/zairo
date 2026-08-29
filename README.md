# zairo

Git-diff-aware security impact analysis. `zairo` diffs a repository, builds a
dependency subgraph (via [Trailmark](https://pypi.org/project/trailmark/))
around whatever changed, and can run an LLM vulnerability scan limited to
just that changed code — instead of re-scanning the whole codebase on every
change.

Output is a `report.json` (raw graph data) and a self-contained
`report.html` (interactive dependency graph viewer).

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

## Development

```bash
pytest
```

## License

MIT — see [LICENSE](LICENSE).
