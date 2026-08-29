import enum
import os
import typer
from rich.console import Console
from . import __version__
from .analyzer import analyze_impact
from .reporter import generate_reports
from .llm_scanner import scan_graph_for_vulnerabilities
from .git_utils import create_worktree, remove_worktree
from ._util import max_severity, severity_rank

app = typer.Typer(add_completion=False)
console = Console()


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

@app.command()
def analyze(
    repo_path: str = typer.Argument(..., help="Path to the git repository"),
    depth: int = typer.Option(1, "--depth", "-d", help="Depth of connections to traverse from changed nodes"),
    output_dir: str = typer.Option("zairo_out", "--output", "-o", help="Output directory for reports"),
    base: str = typer.Option(None, "--base", "-b", help="Base commit/ref to diff from (e.g. HEAD~3, main, a1b2c3d)"),
    target: str = typer.Option(None, "--target", "-t", help="Target commit/ref to diff to (e.g. HEAD, feature-branch). Requires --base."),
    language: str = typer.Option("auto", "--language", "-l", help="Language for Trailmark parsing (auto, python, typescript, rust, etc.)"),
    llm: bool = typer.Option(False, "--llm", help="Run LLM vulnerability scanning on modified nodes"),
    model: str = typer.Option("gemini/gemini-1.5-pro", "--model", help="LiteLLM model string to use for scanning"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Number of LLM scan requests to run in parallel"),
    cache: bool = typer.Option(True, "--cache/--no-cache", help="Cache LLM findings by content hash in <output>/.llm_cache.json to skip re-scanning unchanged nodes across runs"),
    max_tokens: int = typer.Option(4096, "--max-tokens", help="Max output tokens per LLM scan request. Reasoning models count internal thinking against this budget too — too low can cause empty responses"),
    tokens: bool = typer.Option(False, "--tokens", help="Show total LLM tokens used by the scan (prompt/completion/total, across real API calls -- cache hits don't count)"),
    fail_on: Severity = typer.Option(None, "--fail-on", help="Exit with a non-zero status if any finding at or above this severity is found (requires --llm) -- for gating CI/PR checks"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print detailed diagnostic output (git commands, worktree setup, node matching, per-node LLM scan progress)")
):
    def log(msg: str) -> None:
        if verbose:
            console.print(f"[dim]  · {msg}[/dim]")

    if fail_on is not None and not llm:
        console.print("[bold red]Error:[/bold red] --fail-on requires --llm.")
        raise typer.Exit(1)

    if base and target:
        console.print(f"[bold green]Analyzing {repo_path} at depth {depth} — diff {base}..{target}[/bold green]")
    elif base:
        console.print(f"[bold green]Analyzing {repo_path} at depth {depth} — diff {base}..working tree[/bold green]")
    else:
        console.print(f"[bold green]Analyzing {repo_path} at depth {depth} — uncommitted changes[/bold green]")
    # When diffing two commits, all downstream steps (graph analysis AND the
    # LLM scan, which re-reads source files from disk) need to see `target`'s
    # tree — not whatever happens to be checked out in repo_path already.
    # The worktree must stay alive until every step that reads files is done.
    abs_repo = os.path.abspath(repo_path)
    worktree_path = None
    analysis_root = abs_repo
    should_fail = False
    try:
        if base and target:
            log(f"Checking out '{target}' into a temporary worktree (base+target diff mode)...")
            worktree_path = create_worktree(abs_repo, target)
            analysis_root = worktree_path
            log(f"Worktree ready at {worktree_path}")

        graph_data = analyze_impact(analysis_root, depth, base, target, language, log=log)

        num_modified = sum(1 for n in graph_data['nodes'] if n['status'] != 'unchanged')
        console.print(f"[bold blue]Found {num_modified} modified/added nodes.[/bold blue]")
        console.print(f"[bold blue]Total nodes in subgraph: {len(graph_data['nodes'])}[/bold blue]")
        console.print(f"[bold blue]Total edges in subgraph: {len(graph_data['edges'])}[/bold blue]")

        vulnerabilities = None
        if llm:
            console.print(f"[bold yellow]Running LLM scanner using {model} (concurrency={concurrency})...[/bold yellow]")
            cache_path = os.path.join(output_dir, ".llm_cache.json") if cache else None
            vulnerabilities, token_usage = scan_graph_for_vulnerabilities(
                graph_data, model, log=log, concurrency=concurrency, cache_path=cache_path,
                max_tokens=max_tokens,
            )
            console.print(f"[bold yellow]Found vulnerabilities in {len(vulnerabilities)} nodes.[/bold yellow]")

            if fail_on is not None:
                worst = max_severity(vulnerabilities)
                if worst is not None and severity_rank(worst) >= severity_rank(fail_on.value):
                    should_fail = True
                    console.print(
                        f"[bold red]Gate failed:[/bold red] found a '{worst}' severity finding "
                        f"(threshold: {fail_on.value})."
                    )

            if tokens:
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

        # SARIF locations must be relative to wherever node['file'] paths were
        # actually resolved from -- that's analysis_root (the worktree when
        # diffing two commits), not abs_repo, which can be a wholly separate
        # directory in that mode. Since a worktree mirrors abs_repo's tree
        # structure, the resulting relative paths are the same either way.
        j_path, h_path, sarif_path = generate_reports(
            graph_data, output_dir, vulnerabilities, repo_root=analysis_root, tool_version=__version__,
        )

        console.print(f"[bold green]Success![/bold green] Reports generated:")
        console.print(f"  - {j_path}")
        console.print(f"  - {h_path}")
        if sarif_path:
            console.print(f"  - {sarif_path}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)
    finally:
        if worktree_path:
            log(f"Removing temporary worktree {worktree_path}")
            remove_worktree(abs_repo, worktree_path)

    if should_fail:
        raise typer.Exit(1)

def main():
    app()

if __name__ == "__main__":
    main()
