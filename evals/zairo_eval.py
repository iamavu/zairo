"""How well zairo finds what a change breaks: runs it on a set of labelled
changes -- each a small repo before and after, marked vulnerable (with the
symbol and CWE a finding should be on) or clean -- several times over, and
measures recall, false alarms, precision, how stable its verdicts are, and
what it cost. See evals/README.md."""
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from zairo._util import normalize_cwe, normalize_severity, severity_rank

CASES_DIR = Path(__file__).parent / "cases"


@dataclass
class Case:
    id: str
    description: str
    vulnerable: bool
    before: Path
    after: Path
    # Where a finding should be, for a vulnerable case: the changed
    # symbol's name, and the CWE it's an instance of.
    symbol: Optional[str] = None
    cwe: Optional[str] = None
    source: str = ""


def load_cases(cases_dir: Path = CASES_DIR, only: Optional[List[str]] = None) -> List[Case]:
    cases = []
    for case_dir in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
        if only and case_dir.name not in only:
            continue
        meta = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        cases.append(Case(
            id=case_dir.name, description=meta["description"], vulnerable=meta["vulnerable"],
            before=case_dir / "before", after=case_dir / "after",
            symbol=meta.get("symbol"), cwe=meta.get("cwe"), source=meta.get("source", ""),
        ))
    if only:
        missing = set(only) - {c.id for c in cases}
        if missing:
            raise ValueError(f"no such case(s): {', '.join(sorted(missing))}")
    return cases


def _git(repo: str, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=zairo-eval", "-c", "user.email=eval@zairo", *args],
        cwd=repo, check=True, capture_output=True,
    )


def build_repo(case: Case, root: str) -> str:
    """The case as a git repo under `root`: one commit of `before`, then one
    of `after`. Returns its path."""
    repo = os.path.join(root, case.id)
    shutil.copytree(case.before, repo)
    _git(repo, "init", "-q", ".")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "before")
    for entry in os.listdir(repo):
        if entry != ".git":
            path = os.path.join(repo, entry)
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
    shutil.copytree(case.after, repo, dirs_exist_ok=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "after")
    return repo


@dataclass
class Run:
    """One scan of one case."""
    case: str
    complete: bool
    # Findings the change introduced at or above the gate's threshold --
    # what --fail-on would block the PR on -- as {"symbol", "title",
    # "severity", "cwe", "line"}.
    gating: List[Dict[str, Any]] = field(default_factory=list)
    findings: int = 0  # all of them, gating or not
    tokens: int = 0
    seconds: float = 0.0
    error: Optional[str] = None

    def flagged(self) -> bool:
        return bool(self.gating)

    def on_target(self, case: Case) -> bool:
        """A gating finding on the symbol the case's vulnerability is in."""
        return any(f["symbol"] == case.symbol for f in self.gating)

    def cwe_matched(self, case: Case) -> bool:
        return any(f["symbol"] == case.symbol and f["cwe"] == normalize_cwe(case.cwe) for f in self.gating)


def scan_case(case: Case, scan: Callable[..., Any], fail_on: str, root: str, **scan_options: Any) -> Run:
    """Scans the case once with `scan` (zairo.scan.run_scan, or a stand-in),
    with no cache and no notes: every run asks the model afresh."""
    started = time.monotonic()
    repo = build_repo(case, tempfile.mkdtemp(dir=root))
    try:
        result = scan(
            repo, os.path.join(repo, ".zairo_out"), from_ref="HEAD~1", to_ref="HEAD", llm=True,
            cache_path=None, notes_path=None, **scan_options,
        )
    except Exception as e:
        return Run(case=case.id, complete=False, seconds=time.monotonic() - started, error=str(e))
    names = {n["id"]: n["name"] for n in result.graph_data["nodes"]}
    gating, count = [], 0
    for node_id, found in (result.vulnerabilities or {}).items():
        for f in found:
            count += 1
            severity = normalize_severity(f.get("severity"))
            if f.get("introduced_by_change") is True and severity_rank(severity) >= severity_rank(fail_on):
                gating.append({
                    "symbol": names.get(node_id, node_id), "title": f.get("title"), "severity": severity,
                    "cwe": normalize_cwe(f.get("cwe")), "line": f.get("line"),
                })
    return Run(
        case=case.id, complete=result.complete, gating=gating, findings=count,
        tokens=(result.token_usage or {}).get("total_tokens", 0), seconds=time.monotonic() - started,
    )


def _ratio(n: int, d: int) -> Optional[float]:
    return n / d if d else None


def summarize(cases: List[Case], runs: List[Run]) -> Dict[str, Any]:
    """Scores the complete runs -- an incomplete one says nothing about what
    the model would have found -- per case and overall:

      recall:       of the runs on vulnerable cases, the share with a gating
                    finding on the vulnerable symbol;
      false alarms: of the runs on clean cases, the share with any gating
                    finding -- a PR --fail-on would have blocked for nothing;
      precision:    of the runs with a gating finding, the share where it
                    was right: on target in a vulnerable case. A vulnerable
                    case flagged only somewhere else counts against it;
      stable:       the share of cases where every run gave the same verdict;
      cwe matched:  of the on-target runs, the share that also named the
                    case's CWE."""
    by_case = {c.id: c for c in cases}
    per_case, counted = {}, [r for r in runs if r.complete]
    for case in cases:
        mine = [r for r in counted if r.case == case.id]
        verdicts = [r.on_target(case) if case.vulnerable else r.flagged() for r in mine]
        per_case[case.id] = {
            "vulnerable": case.vulnerable,
            "runs": len(mine),
            "incomplete": sum(1 for r in runs if r.case == case.id and not r.complete),
            # For a vulnerable case, how often it was caught; for a clean
            # one, how often it was falsely flagged.
            "hits": sum(verdicts),
            "stable": len(set(verdicts)) <= 1,
        }
    vulnerable_runs = [r for r in counted if by_case[r.case].vulnerable]
    clean_runs = [r for r in counted if not by_case[r.case].vulnerable]
    caught = [r for r in vulnerable_runs if r.on_target(by_case[r.case])]
    flagged = [r for r in counted if r.flagged()]
    return {
        "cases": per_case,
        "recall": _ratio(len(caught), len(vulnerable_runs)),
        "false_alarms": _ratio(sum(1 for r in clean_runs if r.flagged()), len(clean_runs)),
        "precision": _ratio(len(caught), len(flagged)),
        "stable": _ratio(sum(1 for c in per_case.values() if c["runs"] and c["stable"]), sum(1 for c in per_case.values() if c["runs"])),
        "cwe_matched": _ratio(sum(1 for r in caught if r.cwe_matched(by_case[r.case])), len(caught)),
        "runs": len(runs),
        "incomplete_runs": len(runs) - len(counted),
        "tokens": sum(r.tokens for r in runs),
        "seconds": sum(r.seconds for r in runs),
    }
