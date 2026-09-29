import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .analyzer import analyze_impact, list_symbols
from .git_utils import create_worktree, remove_worktree, resolve_commit
from .llm_scanner import scan_graph_for_vulnerabilities, supports_tools, write_notes
from .reporter import generate_reports
from ._util import is_complete


@dataclass
class ScanResult:
    repo_path: str
    # Where graph_data's node['file'] paths are rooted: the temporary
    # worktree when diffing two commits (already removed by the time a
    # caller sees this -- it's only for making those paths relative), the
    # repo itself otherwise.
    analysis_root: str
    graph_data: Dict[str, Any]
    vulnerabilities: Optional[Dict[str, List[Dict[str, Any]]]]
    token_usage: Optional[Dict[str, int]]
    json_path: str
    html_path: str
    sarif_path: Optional[str]
    # analyze_impact's coverage: what became of each changed file, and the
    # parts of the analysis that failed.
    changed_files: List[Dict[str, str]] = field(default_factory=list)
    problems: List[Dict[str, str]] = field(default_factory=list)

    @property
    def failed_nodes(self) -> Dict[str, str]:
        return (self.token_usage or {}).get("failed_nodes", {})

    @property
    def complete(self) -> bool:
        return is_complete(self.failed_nodes, self.problems)


def run_warm_up(
    repo_path: str,
    notes_path: str,
    model: str,
    language: str = "auto",
    concurrency: int = 5,
    max_tokens: int = 4096,
    log: Optional[Callable[[str], None]] = None,
    on_event: Optional[Callable[..., None]] = None,
    debug_log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """--warm-up: writes notes for every function in the repo as it is on
    disk that doesn't have one yet, into `notes_path`, for later scans to
    read. No diff, no scan, no reports. Returns write_notes()'s counts;
    `on_event` gets its "notes_*" events."""
    return write_notes(
        list_symbols(repo_path, language, log=log), model, notes_path, log=log, concurrency=concurrency,
        max_tokens=max_tokens, debug_log=debug_log, on_event=on_event,
    )


def run_scan(
    repo_path: str,
    output_dir: str,
    depth: int = 1,
    from_ref: Optional[str] = None,
    to_ref: Optional[str] = None,
    language: str = "auto",
    llm: bool = False,
    model: str = "gemini/gemini-2.5-pro",
    concurrency: int = 5,
    cache_path: Optional[str] = None,
    max_tokens: int = 4096,
    log: Optional[Callable[[str], None]] = None,
    on_event: Optional[Callable[..., None]] = None,
    debug_log: Optional[Callable[[str], None]] = None,
    batch_size: int = 1,
    notes_path: Optional[str] = None,
    dig: bool = False,
) -> ScanResult:
    """Runs the full single-repo pipeline: diff -> impact graph -> optional
    LLM scan -> reports on disk. Shared by the single-repo and multi-repo
    code paths in the `analyze` CLI command so the worktree/graph/scan/report
    logic exists in exactly one place.

    Raises on failure (git/Trailmark/LLM errors) -- it's the caller's call
    whether that aborts everything (a single-repo run) or gets recorded
    and skipped so the rest of a multi-repo run can still complete.

    `on_event(event: str, **kwargs)` is called at each checkpoint --
    "graph_built", "llm_scan_started", "llm_scan_progress" (done, total:
    symbols sent to the model so far), "llm_scan_done" -- so callers can
    render live progress however suits them, without this function needing
    to know about console styling.

    `debug_log`, if given, receives the exact prompt sent to the LLM and its
    raw response for every node scanned -- kept separate from `log` since
    that content is far too large for a normal --verbose console stream and
    is meant to go straight to a file instead (see -vv/--debug in cli.py).

    `notes_path` is where run_warm_up() keeps its notes; the scan reads
    them from there when the file exists.

    `dig` lets the model look things up before it answers (see dig.py).
    When LiteLLM doesn't list the model as able to call tools, a
    "dig_warning" event says so before the scan tries anyway.
    """
    log = log or (lambda msg: None)
    on_event = on_event or (lambda event, **kwargs: None)

    abs_repo = os.path.abspath(repo_path)
    worktree_path = None
    analysis_root = abs_repo
    try:
        # Pinned to commit ids in the repo itself, before any worktree
        # exists -- see resolve_commit for why.
        if from_ref:
            from_ref = resolve_commit(abs_repo, from_ref)
            log(f"--from resolves to {from_ref}")
        if to_ref:
            to_ref = resolve_commit(abs_repo, to_ref)
            log(f"--to resolves to {to_ref}")

        if from_ref and to_ref:
            log(f"Checking out '{to_ref}' into a temporary worktree (--from + --to diff mode)...")
            worktree_path = create_worktree(abs_repo, to_ref)
            analysis_root = worktree_path
            log(f"Worktree ready at {worktree_path}")

        graph_data, context, coverage = analyze_impact(analysis_root, depth, from_ref, to_ref, language, log=log)
        num_modified = sum(1 for n in graph_data['nodes'] if n['status'] in ('modified', 'added'))
        num_deleted = sum(1 for n in graph_data['nodes'] if n['status'] == 'deleted')
        on_event(
            "graph_built",
            num_modified=num_modified,
            num_deleted=num_deleted,
            num_nodes=len(graph_data['nodes']),
            num_edges=len(graph_data['edges']),
            changed_files=coverage['changed_files'],
            problems=coverage['problems'],
        )

        vulnerabilities = None
        token_usage = None
        if llm:
            on_event("llm_scan_started", model=model, concurrency=concurrency)
            if dig and num_modified and not supports_tools(model):
                on_event("dig_warning", message=(
                    f"LiteLLM doesn't list {model} as able to call tools, which --dig needs; "
                    f"trying anyway, but expect the scan to fail if it can't."
                ))
            vulnerabilities, token_usage = scan_graph_for_vulnerabilities(
                graph_data, model, log=log, concurrency=concurrency, cache_path=cache_path,
                max_tokens=max_tokens, debug_log=debug_log, batch_size=batch_size, context=context,
                notes_path=notes_path,
                on_progress=lambda done, total: on_event("llm_scan_progress", done=done, total=total),
                # A --dig answer is cached per commit: a working tree has none.
                dig=dig, repo_root=analysis_root, dig_revision=to_ref if (from_ref and to_ref) else None,
            )
            num_vulnerabilities = sum(len(findings) for findings in vulnerabilities.values())
            on_event(
                "llm_scan_done",
                num_vulnerable_nodes=len(vulnerabilities),
                num_vulnerabilities=num_vulnerabilities,
                token_usage=token_usage,
                notes_path=notes_path,
                dig=dig,
            )

        # SARIF locations must be relative to wherever node['file'] paths were
        # actually resolved from -- that's analysis_root (the worktree when
        # diffing two commits), not abs_repo, which can be a wholly separate
        # directory in that mode. Since a worktree mirrors abs_repo's tree
        # structure, the resulting relative paths are the same either way.
        json_path, html_path, sarif_path = generate_reports(
            graph_data, output_dir, vulnerabilities, repo_root=analysis_root, tool_version=__version__,
            repo_name=os.path.basename(abs_repo),
            failed_nodes=token_usage['failed_nodes'] if token_usage else None,
            assessed_nodes=token_usage['assessed_nodes'] if token_usage else None,
            skipped_nodes=token_usage['skipped_nodes'] if token_usage else None,
            lookups=token_usage['lookups'] if token_usage else None,
            changed_files=coverage['changed_files'],
            problems=coverage['problems'],
        )

        return ScanResult(
            repo_path=repo_path,
            analysis_root=analysis_root,
            graph_data=graph_data,
            vulnerabilities=vulnerabilities,
            token_usage=token_usage,
            json_path=json_path,
            html_path=html_path,
            sarif_path=sarif_path,
            changed_files=coverage['changed_files'],
            problems=coverage['problems'],
        )
    finally:
        if worktree_path:
            log(f"Removing temporary worktree {worktree_path}")
            remove_worktree(abs_repo, worktree_path)
