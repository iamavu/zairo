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
    # Every finding, as {"symbol", "title", "severity", "cwe", "line",
    # "introduced", "gates"}: "gates" when --fail-on would block the PR on
    # it -- the change introduced it, at or above the threshold.
    findings: List[Dict[str, Any]] = field(default_factory=list)
    # {symbol: why the model's answer on it was unusable}, and the error
    # messages of the parts of the analysis that failed: what made the run
    # incomplete.
    failed: Dict[str, str] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)
    tokens: int = 0
    seconds: float = 0.0
    error: Optional[str] = None  # the scan itself raised this

    def gating(self) -> List[Dict[str, Any]]:
        return [f for f in self.findings if f["gates"]]

    def flagged(self) -> bool:
        return bool(self.gating())

    def on_target(self, case: Case) -> bool:
        """A gating finding on the symbol the case's vulnerability is in."""
        return any(f["symbol"] == case.symbol for f in self.gating())

    def found(self, case: Case) -> bool:
        """A finding the change introduced on that symbol, at any severity."""
        return any(f["symbol"] == case.symbol and f["introduced"] is True for f in self.findings)

    def cwe_matched(self, case: Case) -> bool:
        return any(f["symbol"] == case.symbol and f["cwe"] == normalize_cwe(case.cwe) for f in self.gating())

    def verdict(self, case: Case) -> Optional[str]:
        """What this run says about the case, or None when it says nothing.

        Vulnerable: "caught" (a gating finding on its symbol), "below the
        gate" (found there, but not at a severity the gate blocks on) or
        "missed" -- None if its symbol's own assessment failed. Clean:
        "flagged" (a gating finding anywhere: a PR blocked for nothing,
        whatever else failed) or "passed" -- None if it wasn't flagged but
        the run was incomplete."""
        if self.error:
            return None
        if case.vulnerable:
            if self.on_target(case):
                return "caught"
            if case.symbol in self.failed:
                return None
            return "below the gate" if self.found(case) else "missed"
        if self.flagged():
            return "flagged"
        return "passed" if self.complete else None


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
    findings = []
    for node_id, found in (result.vulnerabilities or {}).items():
        for f in found:
            severity = normalize_severity(f.get("severity"))
            introduced = f.get("introduced_by_change")
            findings.append({
                "symbol": names.get(node_id, node_id), "title": f.get("title"), "severity": severity,
                "cwe": normalize_cwe(f.get("cwe")), "line": f.get("line"),
                "introduced": introduced if isinstance(introduced, bool) else None,
                "gates": introduced is True and severity_rank(severity) >= severity_rank(fail_on),
            })
    return Run(
        case=case.id, complete=result.complete, findings=findings,
        failed={names.get(node_id, node_id): error for node_id, error in result.failed_nodes.items()},
        problems=[p["message"] for p in result.problems if p["level"] == "error"],
        tokens=(result.token_usage or {}).get("total_tokens", 0), seconds=time.monotonic() - started,
    )


def _ratio(n: int, d: int) -> Optional[float]:
    return n / d if d else None


def summarize(cases: List[Case], runs: List[Run]) -> Dict[str, Any]:
    """Scores each run by its verdict (see Run.verdict) -- a run whose
    verdict is None is left out, since it says nothing either way -- per
    case and overall:

      recall:       of the scored runs on vulnerable cases, the share that
                    caught it: a gating finding on the vulnerable symbol;
      found:        the share that found it at any severity, gating or not;
      false alarms: of the scored runs on clean cases, the share with any
                    gating finding -- a PR --fail-on would have blocked for
                    nothing;
      precision:    of the runs with a gating finding, the share where it
                    was right: on target in a vulnerable case. A vulnerable
                    case flagged only somewhere else counts against it;
      stable:       the share of cases where every scored run agreed on
                    whether the gate blocks;
      cwe matched:  of the runs that caught it, the share that also named
                    the case's CWE;
      elsewhere:    in the runs that caught it, the gating findings on
                    other symbols -- the same bug reported again, under the
                    enclosing module, say: one bug, several alerts. More
                    than one on the vulnerable symbol itself doesn't count:
                    that's the model splitting one bug by how it's reached.
    `failures` counts why symbols failed across every run, the scored ones
    too: one failed symbol can leave a run's verdict standing."""
    by_case = {c.id: c for c in cases}
    verdicts = [(r, r.verdict(by_case[r.case])) for r in runs]
    scored = [(r, v) for r, v in verdicts if v is not None]
    per_case = {}
    for case in cases:
        mine = [v for r, v in scored if r.case == case.id]
        gated = [v in ("caught", "flagged") for v in mine]
        per_case[case.id] = {
            "vulnerable": case.vulnerable,
            "runs": sum(1 for r in runs if r.case == case.id),
            "scored": len(mine),
            # For a vulnerable case, how often it was caught; for a clean
            # one, how often it was falsely flagged.
            "hits": sum(gated),
            "below_gate": mine.count("below the gate"),
            "elsewhere": sum(
                sum(1 for f in r.gating() if f["symbol"] != case.symbol)
                for r, v in scored if r.case == case.id and v == "caught"
            ),
            "stable": len(set(gated)) <= 1,
        }
    vulnerable = [v for r, v in scored if by_case[r.case].vulnerable]
    clean = [v for r, v in scored if not by_case[r.case].vulnerable]
    caught = [r for r, v in scored if v == "caught"]
    failures: Dict[str, int] = {}
    for r in runs:
        for message in [*r.failed.values(), *r.problems, *([r.error] if r.error else [])]:
            failures[message] = failures.get(message, 0) + 1
    return {
        "cases": per_case,
        "recall": _ratio(len(caught), len(vulnerable)),
        "found": _ratio(sum(1 for v in vulnerable if v in ("caught", "below the gate")), len(vulnerable)),
        "false_alarms": _ratio(clean.count("flagged"), len(clean)),
        "precision": _ratio(len(caught), sum(1 for r in runs if r.flagged())),
        "stable": _ratio(sum(1 for c in per_case.values() if c["scored"] and c["stable"]), sum(1 for c in per_case.values() if c["scored"])),
        "cwe_matched": _ratio(sum(1 for r in caught if r.cwe_matched(by_case[r.case])), len(caught)),
        "elsewhere": sum(c["elsewhere"] for c in per_case.values()),
        "caught_runs": len(caught),
        "runs": len(runs),
        "incomplete_runs": sum(1 for r in runs if not r.complete),
        "unscored_runs": len(runs) - len(scored),
        "failures": dict(sorted(failures.items(), key=lambda kv: -kv[1])),
        "tokens": sum(r.tokens for r in runs),
        "seconds": sum(r.seconds for r in runs),
    }
