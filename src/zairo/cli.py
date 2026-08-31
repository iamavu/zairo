import enum
import os
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from typing import List, Optional

import typer
from rich.console import Console
from . import __version__
from .fleet import unique_slug, write_fleet_reports
from .scan import run_scan
from ._util import max_severity, severity_rank

app = typer.Typer(add_completion=False)
console = Console()


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def _require_llm_for_fail_on(fail_on: Optional[Severity], llm: bool) -> None:
    if fail_on is not None and not llm:
        console.print("[bold red]Error:[/bold red] --fail-on requires --llm.")
        raise typer.Exit(1)


def _severity_gate_failure(vulnerabilities: dict, fail_on: Severity) -> Optional[str]:
    """The worst severity found, if it meets or exceeds fail_on's threshold
    -- None if the gate passes (including when there are no findings)."""
    worst = max_severity(vulnerabilities)
    if worst is not None and severity_rank(worst) >= severity_rank(fail_on.value):
        return worst
    return None


def _print_scan_errors(token_usage: dict, indent: str = "") -> None:
    """Surfaces per-node LLM scan failures unconditionally -- NOT gated
    behind --verbose. A scan where every node failed (missing/invalid API
    key, rate limiting, ...) must never look identical to a clean "0
    vulnerabilities found" scan; that's a false sense of security for a
    security tool specifically. Error messages are deduplicated since many
    failed nodes typically share the same root cause (e.g. one bad API key)."""
    errors = token_usage['errors']
    if not errors:
        return
    total_failed = sum(errors.values())
    console.print(
        f"{indent}[bold red]Warning:[/bold red] {total_failed}/{token_usage['requests']} node scan(s) failed "
        f"— results may be incomplete:"
    )
    for message, count in sorted(errors.items(), key=lambda kv: -kv[1])[:3]:
        console.print(f"{indent}  [red]× ({count}x)[/red] {message}")
    if len(errors) > 3:
        console.print(f"{indent}  [dim]... {len(errors) - 3} more distinct error(s); rerun with --verbose for full detail[/dim]")


def _analyze_on_event(event: str, **kw) -> None:
    if event == "graph_built":
        console.print(f"[bold blue]Found {kw['num_modified']} modified/added node(s), {kw['num_deleted']} deleted node(s).[/bold blue]")
        console.print(f"[bold blue]Total nodes in subgraph: {kw['num_nodes']}[/bold blue]")
        console.print(f"[bold blue]Total edges in subgraph: {kw['num_edges']}[/bold blue]")
    elif event == "llm_scan_started":
        console.print(f"[bold yellow]Running LLM scanner using {kw['model']} (concurrency={kw['concurrency']})...[/bold yellow]")
    elif event == "llm_scan_done":
        console.print(f"[bold yellow]Found vulnerabilities in {kw['num_vulnerable_nodes']} nodes.[/bold yellow]")
        _print_scan_errors(kw['token_usage'])


def _print_token_usage(token_usage: dict) -> None:
    if token_usage['requests'] == 0:
        console.print("[dim]Token usage: no LLM requests were made (all results came from cache or were skipped).[/dim]")
    elif token_usage['requests'] == token_usage['requests_without_usage']:
        console.print(
            f"[dim]Token usage: unavailable for all {token_usage['requests']} request(s) "
            f"(provider/backend did not report it).[/dim]"
        )
    else:
        counted = token_usage['requests'] - token_usage['requests_without_usage']
        console.print(
            f"[bold magenta]Tokens used:[/bold magenta] "
            f"{token_usage['prompt_tokens']:,} prompt + {token_usage['completion_tokens']:,} completion "
            f"= {token_usage['total_tokens']:,} total across {counted} request(s)"
        )
        if token_usage['requests_without_usage']:
            console.print(
                f"[dim]  ({token_usage['requests_without_usage']} additional request(s) had no usage "
                f"data reported by the provider — not counted above)[/dim]"
            )


def _sum_token_usage(token_usages: List[dict]) -> dict:
    """Combines every repo's token_usage in a fleet run into one totals dict
    with the same shape _print_token_usage expects, so the fleet-wide number
    is printed the exact same way a single `analyze` run's is."""
    total = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'requests': 0, 'requests_without_usage': 0}
    for usage in token_usages:
        if not usage:
            continue
        for key in total:
            total[key] += usage.get(key, 0)
    return total


@app.command()
def analyze(
    repo_path: str = typer.Argument(..., help="Path to the git repository"),
    depth: int = typer.Option(1, "--depth", "-d", help="Depth of connections to traverse from changed nodes"),
    output_dir: str = typer.Option("zairo_out", "--output", "-o", help="Output directory for reports"),
    base: str = typer.Option(None, "--base", "-b", help="Base commit/ref to diff from (e.g. HEAD~3, main, a1b2c3d)"),
    target: str = typer.Option(None, "--target", "-t", help="Target commit/ref to diff to (e.g. HEAD, feature-branch). Requires --base."),
    language: str = typer.Option("auto", "--language", "-l", help="Language for Trailmark parsing (auto, python, typescript, rust, etc.)"),
    llm: bool = typer.Option(False, "--llm", help="Run LLM vulnerability scanning on modified nodes"),
    model: str = typer.Option("gemini/gemini-2.5-pro", "--model", help="LiteLLM model string to use for scanning"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Number of LLM scan requests to run in parallel"),
    cache: bool = typer.Option(True, "--cache/--no-cache", help="Cache LLM findings by content hash in <output>/.llm_cache.json to skip re-scanning unchanged nodes across runs"),
    max_tokens: int = typer.Option(4096, "--max-tokens", help="Max output tokens per LLM scan request. Reasoning models count internal thinking against this budget too — too low can cause empty responses"),
    tokens: bool = typer.Option(False, "--tokens", help="Show total LLM tokens used by the scan (prompt/completion/total, across real API calls -- cache hits don't count)"),
    fail_on: Severity = typer.Option(None, "--fail-on", help="Exit with a non-zero status if any finding at or above this severity is found (requires --llm) -- for gating CI/PR checks"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print detailed diagnostic output (git commands, worktree setup, node matching, per-node LLM scan progress)")
):
    """Diffs a single repo, builds the impact graph around what changed, and optionally runs an LLM vulnerability scan on it -- writing report.json/report.html (and report.sarif when --llm is used)."""
    def log(msg: str) -> None:
        if verbose:
            console.print(f"[dim]  · {msg}[/dim]")

    _require_llm_for_fail_on(fail_on, llm)

    if base and target:
        console.print(f"[bold green]Analyzing {repo_path} at depth {depth} — diff {base}..{target}[/bold green]")
    elif base:
        console.print(f"[bold green]Analyzing {repo_path} at depth {depth} — diff {base}..working tree[/bold green]")
    else:
        console.print(f"[bold green]Analyzing {repo_path} at depth {depth} — uncommitted changes[/bold green]")

    cache_path = os.path.join(output_dir, ".llm_cache.json") if (llm and cache) else None
    try:
        result = run_scan(
            repo_path, output_dir, depth, base, target, language, llm, model, concurrency,
            cache_path, max_tokens, log=log, on_event=_analyze_on_event,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    should_fail = False
    if llm:
        if fail_on is not None:
            worst = _severity_gate_failure(result.vulnerabilities, fail_on)
            if worst is not None:
                should_fail = True
                console.print(
                    f"[bold red]Gate failed:[/bold red] found a '{worst}' severity finding "
                    f"(threshold: {fail_on.value})."
                )
        if tokens:
            _print_token_usage(result.token_usage)

    console.print("[bold green]Success![/bold green] Reports generated:")
    console.print(f"  - {result.json_path}")
    console.print(f"  - {result.html_path}")
    if result.sarif_path:
        console.print(f"  - {result.sarif_path}")

    if should_fail:
        raise typer.Exit(1)


@app.command()
def fleet(
    repo_paths: Optional[List[str]] = typer.Argument(None, help="Paths to git repositories to scan"),
    repos_file: str = typer.Option(None, "--repos-file", help="Text file with one repo path per line (blank lines and '#' comments ignored); merged with any positional repo paths"),
    depth: int = typer.Option(1, "--depth", "-d", help="Depth of connections to traverse from changed nodes"),
    output_dir: str = typer.Option("zairo_fleet_out", "--output", "-o", help="Output directory -- each repo gets its own subdirectory, plus an aggregate fleet.json/fleet.html/fleet.sarif"),
    base: str = typer.Option(None, "--base", "-b", help="Base commit/ref to diff from, applied to every repo (e.g. main)"),
    target: str = typer.Option(None, "--target", "-t", help="Target commit/ref to diff to, applied to every repo. Requires --base."),
    language: str = typer.Option("auto", "--language", "-l", help="Language for Trailmark parsing (auto, python, typescript, rust, etc.)"),
    llm: bool = typer.Option(False, "--llm", help="Run LLM vulnerability scanning on modified nodes, in every repo"),
    model: str = typer.Option("gemini/gemini-2.5-pro", "--model", help="LiteLLM model string to use for scanning"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Number of LLM scan requests to run in parallel, per repo"),
    repo_concurrency: int = typer.Option(1, "--repo-concurrency", help="Number of repos to scan in parallel (default: one at a time). Above 1, progress prints one summary line per repo on completion instead of live per-stage detail, and --stop-on-error only cancels repos that haven't started yet -- it can't interrupt one already in flight"),
    cache: bool = typer.Option(True, "--cache/--no-cache", help="Cache LLM findings by content hash to skip re-scanning unchanged nodes across runs"),
    max_tokens: int = typer.Option(4096, "--max-tokens", help="Max output tokens per LLM scan request"),
    tokens: bool = typer.Option(False, "--tokens", help="Show total LLM tokens used across all repos (prompt/completion/total, across real API calls -- cache hits don't count)"),
    fail_on: Severity = typer.Option(None, "--fail-on", help="Exit with a non-zero status if any finding across ANY repo is at or above this severity (requires --llm)"),
    continue_on_error: bool = typer.Option(True, "--continue-on-error/--stop-on-error", help="Keep scanning remaining repos if one fails (default), instead of aborting the whole fleet run"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print detailed diagnostic output for every repo"),
):
    """Scans multiple repos with the same settings and produces one aggregate fleet.json/fleet.html/fleet.sarif alongside each repo's own reports -- for a security team that owns many repos, not just one."""
    def log(msg: str) -> None:
        if verbose:
            console.print(f"[dim]    · {msg}[/dim]")

    _require_llm_for_fail_on(fail_on, llm)

    paths = list(repo_paths or [])
    if repos_file:
        with open(repos_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    paths.append(line)

    if not paths:
        console.print("[bold red]Error:[/bold red] no repos given (pass paths as arguments or --repos-file).")
        raise typer.Exit(1)

    used_slugs: set = set()
    slugs = [unique_slug(p, used_slugs) for p in paths]  # computed upfront, sequentially --
    # unique_slug mutates a shared set, so doing this per-repo inside a
    # worker thread (the repo_concurrency > 1 path) would race.

    def scan_one(repo_path: str, slug: str, on_event) -> dict:
        repo_output_dir = os.path.join(output_dir, slug)
        cache_path = os.path.join(repo_output_dir, ".llm_cache.json") if (llm and cache) else None
        try:
            scan_result = run_scan(
                repo_path, repo_output_dir, depth, base, target, language, llm, model, concurrency,
                cache_path, max_tokens, log=log, on_event=on_event,
            )
            return {"repo": repo_path, "slug": slug, "status": "ok", "result": scan_result}
        except Exception as e:
            return {"repo": repo_path, "slug": slug, "status": "error", "error": str(e)}

    results = []
    if repo_concurrency <= 1:
        console.print(f"[bold green]Scanning {len(paths)} repo(s)...[/bold green]")
        for i, (repo_path, slug) in enumerate(zip(paths, slugs), 1):
            console.print(f"[bold cyan][{i}/{len(paths)}][/bold cyan] {repo_path}")

            def on_event(event: str, **kw) -> None:
                if event == "graph_built":
                    console.print(f"    {kw['num_modified']} modified/added node(s), {kw['num_deleted']} deleted node(s); {kw['num_nodes']} node(s), {kw['num_edges']} edge(s) in subgraph")
                elif event == "llm_scan_started":
                    console.print(f"    running LLM scan ({kw['model']})...")
                elif event == "llm_scan_done":
                    console.print(f"    {kw['num_vulnerable_nodes']} node(s) with findings")
                    _print_scan_errors(kw['token_usage'], indent="    ")

            entry = scan_one(repo_path, slug, on_event)
            results.append(entry)
            if entry["status"] == "error":
                console.print(f"    [bold red]error:[/bold red] {entry['error']}")
                if not continue_on_error:
                    console.print("[bold red]Aborting fleet run (--stop-on-error).[/bold red]")
                    break
    else:
        # Multiple repos run genuinely concurrently here, so live per-stage
        # progress (the sequential path above) can't be printed safely --
        # interleaved console output from different repos would garble
        # into an unreadable mix. Every print() below happens in the main
        # thread only, after a repo's scan_one() has fully returned, so
        # there's nothing to interleave: one complete summary line per repo,
        # in completion order (not necessarily submission order).
        console.print(f"[bold green]Scanning {len(paths)} repo(s) ({repo_concurrency} at a time)...[/bold green]")
        stop_requested = False
        with ThreadPoolExecutor(max_workers=repo_concurrency) as pool:
            futures = {
                pool.submit(scan_one, repo_path, slug, None): repo_path
                for repo_path, slug in zip(paths, slugs)
            }
            completed = 0
            for future in as_completed(futures):
                try:
                    entry = future.result()
                except CancelledError:
                    continue  # never started -- not an attempt, don't count it
                completed += 1
                results.append(entry)

                if entry["status"] == "ok":
                    sr = entry["result"]
                    num_modified = sum(1 for n in sr.graph_data['nodes'] if n['status'] in ('modified', 'added'))
                    num_deleted = sum(1 for n in sr.graph_data['nodes'] if n['status'] == 'deleted')
                    summary = f"{num_modified} modified/added node(s), {num_deleted} deleted node(s)"
                    if llm:
                        summary += f", {len(sr.vulnerabilities or {})} node(s) with findings"
                    console.print(f"[bold cyan][{completed}/{len(paths)}][/bold cyan] {entry['repo']} — {summary}")
                    if llm:
                        _print_scan_errors(sr.token_usage, indent="    ")
                else:
                    console.print(f"[bold cyan][{completed}/{len(paths)}][/bold cyan] {entry['repo']} — [bold red]error:[/bold red] {entry['error']}")

                if entry["status"] == "error" and not continue_on_error and not stop_requested:
                    stop_requested = True
                    console.print("[bold red]A repo failed -- cancelling repos that haven't started yet (--stop-on-error)...[/bold red]")
                    for f in futures:
                        f.cancel()  # no-op for already-running/completed futures

    ok_results = [r for r in results if r["status"] == "ok"]
    errored_results = [r for r in results if r["status"] == "error"]

    reports = write_fleet_reports(results, output_dir, tool_version=__version__)

    console.print(f"[bold green]Scanned {len(ok_results)}/{len(results)} repo(s) successfully.[/bold green]")
    if errored_results:
        console.print(f"[bold red]{len(errored_results)} repo(s) failed:[/bold red] " + ", ".join(r["repo"] for r in errored_results))
    if llm and tokens:
        _print_token_usage(_sum_token_usage([r["result"].token_usage for r in ok_results]))
    console.print("Fleet reports generated:")
    console.print(f"  - {reports['json']}")
    console.print(f"  - {reports['html']}")
    if reports['sarif']:
        console.print(f"  - {reports['sarif']}")

    should_fail = bool(errored_results)
    if llm and fail_on is not None:
        combined_vulns = {}
        for r in ok_results:
            for node_id, findings in (r["result"].vulnerabilities or {}).items():
                combined_vulns[f"{r['slug']}:{node_id}"] = findings
        worst = _severity_gate_failure(combined_vulns, fail_on)
        if worst is not None:
            should_fail = True
            console.print(
                f"[bold red]Gate failed:[/bold red] found a '{worst}' severity finding across the fleet "
                f"(threshold: {fail_on.value})."
            )

    if should_fail:
        raise typer.Exit(1)


def main():
    app()

if __name__ == "__main__":
    main()
