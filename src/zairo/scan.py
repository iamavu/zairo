import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .analyzer import analyze_impact
from .git_utils import create_worktree, remove_worktree
from .llm_scanner import scan_graph_for_vulnerabilities
from .reporter import generate_reports


@dataclass
class ScanResult:
    repo_path: str
    graph_data: Dict[str, Any]
    vulnerabilities: Optional[Dict[str, List[Dict[str, Any]]]]
    token_usage: Optional[Dict[str, int]]
    json_path: str
    html_path: str
    sarif_path: Optional[str]


def run_scan(
    repo_path: str,
    output_dir: str,
    depth: int = 1,
    base: Optional[str] = None,
    target: Optional[str] = None,
    language: str = "auto",
    llm: bool = False,
    model: str = "gemini/gemini-2.5-pro",
    concurrency: int = 5,
    cache_path: Optional[str] = None,
    max_tokens: int = 4096,
    log: Optional[Callable[[str], None]] = None,
    on_event: Optional[Callable[..., None]] = None,
    debug_log: Optional[Callable[[str], None]] = None,
) -> ScanResult:
    """Runs the full single-repo pipeline: diff -> impact graph -> optional
    LLM scan -> reports on disk. Shared by the single-repo and multi-repo
    code paths in the `analyze` CLI command so the worktree/graph/scan/report
    logic exists in exactly one place.

    Raises on failure (git/Trailmark/LLM errors) -- it's the caller's call
    whether that aborts everything (a single-repo run) or gets recorded
    and skipped so the rest of a multi-repo run can still complete.

    `on_event(event: str, **kwargs)` is called at the same three checkpoints
    `analyze` used to print inline ("graph_built", "llm_scan_started",
    "llm_scan_done") so callers can render live progress however suits them,
    without this function needing to know about console styling.

    `debug_log`, if given, receives the exact prompt sent to the LLM and its
    raw response for every node scanned -- kept separate from `log` since
    that content is far too large for a normal --verbose console stream and
    is meant to go straight to a file instead (see -vv/--debug in cli.py).
    """
    log = log or (lambda msg: None)
    on_event = on_event or (lambda event, **kwargs: None)

    abs_repo = os.path.abspath(repo_path)
    worktree_path = None
    analysis_root = abs_repo
    try:
        if base and target:
            log(f"Checking out '{target}' into a temporary worktree (base+target diff mode)...")
            worktree_path = create_worktree(abs_repo, target)
            analysis_root = worktree_path
            log(f"Worktree ready at {worktree_path}")

        graph_data = analyze_impact(analysis_root, depth, base, target, language, log=log)
        num_modified = sum(1 for n in graph_data['nodes'] if n['status'] in ('modified', 'added'))
        num_deleted = sum(1 for n in graph_data['nodes'] if n['status'] == 'deleted')
        on_event(
            "graph_built",
            num_modified=num_modified,
            num_deleted=num_deleted,
            num_nodes=len(graph_data['nodes']),
            num_edges=len(graph_data['edges']),
        )

        vulnerabilities = None
        token_usage = None
        if llm:
            on_event("llm_scan_started", model=model, concurrency=concurrency)
            vulnerabilities, token_usage = scan_graph_for_vulnerabilities(
                graph_data, model, log=log, concurrency=concurrency, cache_path=cache_path,
                max_tokens=max_tokens, debug_log=debug_log,
            )
            num_vulnerabilities = sum(len(findings) for findings in vulnerabilities.values())
            on_event(
                "llm_scan_done",
                num_vulnerable_nodes=len(vulnerabilities),
                num_vulnerabilities=num_vulnerabilities,
                token_usage=token_usage,
            )

        # SARIF locations must be relative to wherever node['file'] paths were
        # actually resolved from -- that's analysis_root (the worktree when
        # diffing two commits), not abs_repo, which can be a wholly separate
        # directory in that mode. Since a worktree mirrors abs_repo's tree
        # structure, the resulting relative paths are the same either way.
        json_path, html_path, sarif_path = generate_reports(
            graph_data, output_dir, vulnerabilities, repo_root=analysis_root, tool_version=__version__,
        )

        return ScanResult(
            repo_path=repo_path,
            graph_data=graph_data,
            vulnerabilities=vulnerabilities,
            token_usage=token_usage,
            json_path=json_path,
            html_path=html_path,
            sarif_path=sarif_path,
        )
    finally:
        if worktree_path:
            log(f"Removing temporary worktree {worktree_path}")
            remove_worktree(abs_repo, worktree_path)
