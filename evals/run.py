"""Runs zairo on the labelled changes in evals/cases and scores it -- see
evals/README.md.

    python evals/run.py --model gemini/gemini-2.5-flash --repeats 3

Needs the model's API key in the environment, as zairo does. Makes about
(changed symbols per case) x --repeats requests per case."""
import argparse
import json
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from zairo.scan import run_scan  # noqa: E402
from zairo_eval import load_cases, scan_case, summarize  # noqa: E402


def _pct(value) -> str:
    return "-" if value is None else f"{value:.0%}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--model", required=True, help="LiteLLM model string, as zairo --model takes")
    parser.add_argument("--repeats", type=int, default=3, help="scans per case: verdicts vary between runs (default 3)")
    parser.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"],
                        help="the gate's threshold: a finding the change introduced at or above it counts as flagged (default high)")
    parser.add_argument("--cases", help="comma-separated case ids to run (default: all)")
    parser.add_argument("--jobs", type=int, default=4, help="scans to run at once (default 4)")
    parser.add_argument("--dig", action="store_true", help="scan with --dig")
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--out", help="write every run's details and the scores here as JSON")
    args = parser.parse_args()

    cases = load_cases(only=args.cases.split(",") if args.cases else None)
    jobs = [case for case in cases for _ in range(args.repeats)]
    print(f"{len(cases)} case(s) x {args.repeats} run(s) with {args.model}{' --dig' if args.dig else ''}, gate at {args.fail_on}")

    with tempfile.TemporaryDirectory(prefix="zairo-eval-") as root:
        def one(case):
            run = scan_case(
                case, run_scan, args.fail_on, root, model=args.model, max_tokens=args.max_tokens, dig=args.dig,
            )
            mark = "incomplete" if not run.complete else ("flagged" if run.flagged() else "clean")
            print(f"  {case.id}: {mark}{' -- ' + run.error if run.error else ''}", flush=True)
            return run

        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            runs = list(pool.map(one, jobs))

    scores = summarize(cases, runs)
    width = max(len(c.id) for c in cases)
    print(f"\n{'case':<{width}}  kind        result")
    for case in cases:
        c = scores["cases"][case.id]
        kind = "vulnerable" if case.vulnerable else "clean"
        said = f"caught {c['hits']}/{c['runs']}" if case.vulnerable else f"flagged {c['hits']}/{c['runs']}"
        notes = [n for n in ("" if c["stable"] else "unstable", f"{c['incomplete']} incomplete" if c["incomplete"] else "") if n]
        print(f"{case.id:<{width}}  {kind:<10}  {said}{'  (' + ', '.join(notes) + ')' if notes else ''}")
    print(
        f"\nrecall {_pct(scores['recall'])}, false alarms {_pct(scores['false_alarms'])}, "
        f"precision {_pct(scores['precision'])}, stable {_pct(scores['stable'])}, "
        f"CWE matched {_pct(scores['cwe_matched'])}"
    )
    print(
        f"{scores['runs']} run(s), {scores['incomplete_runs']} incomplete (not scored); "
        f"{scores['tokens']:,} tokens; {scores['seconds']:.0f}s of scanning"
    )
    if args.out:
        Path(args.out).write_text(json.dumps({
            "model": args.model, "repeats": args.repeats, "fail_on": args.fail_on, "dig": args.dig,
            "when": time.strftime("%Y-%m-%dT%H:%M:%S"), "scores": scores, "runs": [asdict(r) for r in runs],
        }, indent=2), encoding="utf-8")
        print(f"Details: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
