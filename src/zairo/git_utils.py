import subprocess
import re
import os
import tempfile
from collections import defaultdict
from typing import Dict, List, Optional


def create_worktree(repo_path: str, ref: str) -> str:
    """
    Checks out `ref` into a new temporary git worktree and returns its path.

    Used so that node locations/contents indexed by Trailmark line up with the
    line numbers reported by `git diff base target` — those line numbers refer
    to `target`'s tree, which may differ arbitrarily from whatever happens to
    be checked out in the caller's working directory.
    """
    worktree_path = tempfile.mkdtemp(prefix="zairo-worktree-")
    result = subprocess.run(
        ["git", "worktree", "add", "--detach", "--force", worktree_path, ref],
        cwd=repo_path,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to check out '{ref}' into a worktree: {result.stderr.strip()}")
    return worktree_path


def remove_worktree(repo_path: str, worktree_path: str) -> None:
    subprocess.run(
        ["git", "worktree", "remove", "--force", worktree_path],
        cwd=repo_path,
        capture_output=True,
        text=True,
    )

def get_modified_lines(
    repo_path: str,
    base: str = None,
    target: str = None,
    log: Optional[callable] = None,
) -> Dict[str, Dict[int, str]]:
    """
    Parses `git diff -U0` to find which lines have been added/modified.

    - No base/target: compares working tree vs HEAD (uncommitted changes).
    - base only:      compares working tree vs that commit.
    - base + target:  compares two commits (e.g. HEAD~3..HEAD).

    Returns a dict mapping absolute file paths to a dict of
    {target line number: representative changed text}. The text is used to
    cheaply filter out non-substantive changes (comments, blank lines)
    before spending an LLM call on them, and to build a windowed view of
    large functions instead of sending their full body.

    A hunk with zero added lines (a pure deletion, e.g. `@@ -11 +10,0 @@`)
    has no "+" line to anchor to in the target tree, but the enclosing node
    still changed — a deleted validation check or sanitization call is
    exactly the kind of change a security scan most needs to catch. Those
    are recorded under a synthetic marker at the deletion's boundary line
    in the target file, with the removed text as its value, so the
    enclosing node is still found instead of silently skipped.
    """
    log = log or (lambda msg: None)

    # Build the git diff command
    cmd = ["git", "diff", "-U0"]
    if base and target:
        cmd += [base, target]
    elif base:
        cmd += [base]
    log(f"Running: {' '.join(cmd)} (cwd={repo_path})")
    result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True)

    if result.returncode != 0:
        log(f"git diff failed (exit {result.returncode}): {result.stderr.strip()}")
        return {}

    diff_output = result.stdout

    modified_lines = defaultdict(dict)
    current_file = None
    next_line_num = None
    pending_deletion_line = None
    pending_deletion_text = []

    def flush_pending_deletion():
        if current_file and pending_deletion_line is not None and pending_deletion_text:
            modified_lines[current_file][pending_deletion_line] = "\n".join(pending_deletion_text)

    for line in diff_output.splitlines():
        if line.startswith("+++ "):
            flush_pending_deletion()
            pending_deletion_line, pending_deletion_text = None, []
            if line.startswith("+++ b/"):
                # New file path — resolve to absolute so it matches Trailmark's locations
                rel_path = line[6:]
                current_file = os.path.abspath(os.path.join(repo_path, rel_path))
            else:
                # "+++ /dev/null": the whole file was deleted in the target.
                # There's no target-side file to attribute this hunk to, and
                # without resetting this, a stale current_file from the
                # PREVIOUS file section in the diff would silently absorb
                # this file's content -- a genuine cross-file data leak.
                current_file = None
            next_line_num = None
        elif line.startswith("@@ ") and current_file:
            flush_pending_deletion()
            pending_deletion_line, pending_deletion_text = None, []
            # Parse the + part of the hunk header
            match = re.search(r'\+([0-9]+)(?:,([0-9]+))?', line)
            if match:
                start_line = int(match.group(1))
                count = match.group(2)
                count = int(count) if count is not None else 1
                if count > 0:
                    next_line_num = start_line
                else:
                    next_line_num = None
                    pending_deletion_line = max(1, start_line)
        elif current_file and next_line_num is not None and line.startswith("+") and not line.startswith("+++"):
            # With -U0 there are no context lines, so every "+" line after a
            # hunk header maps to the next line number in the added range.
            modified_lines[current_file][next_line_num] = line[1:]
            next_line_num += 1
        elif current_file and pending_deletion_line is not None and line.startswith("-") and not line.startswith("---"):
            pending_deletion_text.append(line[1:])

    flush_pending_deletion()
    return dict(modified_lines)
