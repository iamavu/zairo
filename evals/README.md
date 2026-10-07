# Measuring zairo

zairo's unit tests check that it builds the right prompts and handles
answers correctly. They can't tell you whether a model, given those
prompts, finds a vulnerability a change introduced, or flags one that isn't
there. That's what this directory is for: a set of labelled changes, and a
runner that scans each one several times with a real model and scores the
results.

```bash
pip install -e .                      # from the repo root
export GEMINI_API_KEY=...             # whichever key your --model needs
python evals/run.py --model gemini/gemini-2.5-flash --repeats 3 --out results.json
```

Each case costs roughly one request per changed symbol per repeat. The 16
cases here change 1 to 4 symbols each, so a run of 3 repeats makes about
100 requests. Every run asks the model afresh: no cache, no warm-up notes.

## The cases

Each directory in [`cases/`](cases) is one change: `before/` and `after/`
hold the whole (small) repo on each side, and `case.json` labels it:

```json
{
  "description": "What the change does, and why it's vulnerable or not.",
  "vulnerable": true,
  "symbol": "search_users",
  "cwe": "CWE-89",
  "source": "synthetic"
}
```

A vulnerable case names the changed `symbol` the vulnerability is in and
its `cwe`, plus, in `also_cwe`, any others that describe it as well: a
spoofable header is CWE-290, but CWE-287 and CWE-306 aren't wrong. A clean
case has none of these, and should be clean beyond argument. A change
that's safe at `high` but has a fair `medium` finding in it measures noise,
not false alarms. The runner commits `before`, then
`after`, into a fresh repo and scans `HEAD~1..HEAD`, as a PR scan would.

There are 9 vulnerable cases (SQL injection, path traversal, a dropped
tenant check, unsafe YAML loading, command injection, an open redirect,
SSRF, disabled TLS verification, and an auth bypass through a spoofable
header) and 7 clean ones. Several clean ones are built to look risky: a
SQL injection being fixed, an `ORDER BY` formatted in from an allowlist,
a `subprocess` call with a fixed argument list.

These files are deliberately vulnerable sample code. They're never
packaged or run, but a scanner pointed at this repository will find them.

## The scores

A finding **gates** when `--fail-on` would block the PR on it: marked
`introduced_by_change: true`, at or above `--fail-on` (default `high`).
Each run gets a verdict:

- On a vulnerable case, it **caught** the bug (a gating finding on the
  case's `symbol`), found it **below the gate** (a finding the change
  introduced there, at a lower severity), or **missed** it.
- On a clean case, it **flagged** the change (any gating finding) or
  **passed** it.

A run is left unscored only when it says nothing either way: the symbol
that matters couldn't be assessed, or a clean case wasn't flagged but some
symbol failed. A gating finding counts whatever else failed, since the
gate would still have blocked the PR on it. The runner prints the most
common reasons symbols failed, and `--out` keeps them per run. A reasoning
model that spends all of `--max-tokens` thinking never answers, so raise
it (to 16384, say) if that's the reason given.

- **recall**: of the scored runs on vulnerable cases, the share that
  caught it. A finding on another symbol doesn't count.
- **found**: the share that found it at any severity. A bug found below
  the gate is still reported; it just doesn't block. An open redirect is
  commonly rated medium, for instance.
- **false alarms**: of the scored runs on clean cases, the share flagged:
  a PR blocked for nothing.
- **precision**: of the runs with a gating finding, the share where it was
  on target in a vulnerable case.
- **stable**: the share of cases where every scored run agreed on whether
  the gate blocks.
  Model answers vary; a case that's caught one run in three is a coin
  toss in CI.
- **CWE matched**: of the on-target runs, the share that also named the
  case's CWE. It's secondary: the right bug under a neighbouring CWE
  still blocks the right PR.
- **elsewhere**: in the runs that caught the bug, the gating findings on
  other symbols. Usually that's the same bug reported again, on the file
  that holds the function, say: one bug, several alerts. Two findings on
  the vulnerable symbol itself don't count: that's the model splitting one
  bug by how it's reached (`name` and `sort` into the same query).

`--out` writes every run's findings (symbol, title, severity, CWE, line,
whether the change introduced it and whether it gates), the symbols that
failed and why, token counts, costs and timings, so two runs, such as two models or
before and after a prompt change, can be compared case by case.

## Limits

Sixteen small, synthetic cases are a smoke test for detection quality, not
a benchmark. Each is a single change with a single intended bug, in code
far simpler than a real service, and the vulnerable ones are the kind of
bug a reviewer would hope to catch. Real vulnerability-introducing commits
(the reverse of a CVE fix, say) are the best cases to add. Put the files
it touched, before and after, in a new directory, and label it. Keep them
small enough that the change is the point.

`tests/test_evals.py` checks every case without a model: that it builds,
that zairo parses every file it changes, and that a vulnerable case's
`symbol` is among the symbols the change touched. Otherwise no scan could
ever be scored as catching it.
