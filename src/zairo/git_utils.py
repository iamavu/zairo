import subprocess
import re
import os
import shutil
import tempfile
from collections import defaultdict
from typing import Callable, Dict, List, Optional


def _git_error(result: subprocess.CompletedProcess) -> str:
    """The first line of a failed git command's stderr -- some failures
    (e.g. `git diff` outside a repository) follow the actual reason with the
    command's entire usage text."""
    lines = result.stderr.strip().splitlines()
    return lines[0] if lines else f"exit {result.returncode}"


def resolve_commit(repo_path: str, ref: str) -> str:
    """The full commit id `ref` names, resolved in repo_path itself.

    This has to happen before a --to worktree exists: inside it,
    HEAD-relative refs (HEAD, HEAD~1, @, ...) resolve against the
    worktree's own checkout, so `--from HEAD --to feature` would silently
    diff feature against itself. Raises on a ref that doesn't name a commit,
    rather than letting `git diff` fail into what looks like "nothing
    changed". A leading "-" is rejected outright -- no ref starts with one,
    and git would read it as an option instead.
    """
    result = None
    if not ref.startswith("-"):
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            cwd=repo_path, capture_output=True, text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()

    message = f"'{ref}' doesn't name a commit in {repo_path}"
    if result is not None and result.stderr.strip():
        message += f" ({result.stderr.strip()})"
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=repo_path, capture_output=True, text=True,
    )
    if shallow.stdout.strip() == "true":
        message += (
            ". This is a shallow clone, so it may just not have been fetched"
            " -- in GitHub Actions, check out with fetch-depth: 0"
        )
    raise RuntimeError(message)


def create_worktree(repo_path: str, ref: str) -> str:
    """
    Checks out `ref` into a new temporary git worktree and returns its path.

    Used so that node locations/contents indexed by Trailmark line up with the
    line numbers reported by `git diff from_ref to_ref` — those line numbers refer
    to `to_ref`'s tree, which may differ arbitrarily from whatever happens to
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
        # `git worktree add` never took ownership of worktree_path (it
        # failed before/while doing so), so it's still just an empty
        # mkdtemp() dir -- nothing else will ever clean it up.
        shutil.rmtree(worktree_path, ignore_errors=True)
        raise RuntimeError(f"Failed to check out '{ref}' into a worktree: {result.stderr.strip()}")
    return worktree_path


def remove_worktree(repo_path: str, worktree_path: str) -> None:
    subprocess.run(
        ["git", "worktree", "remove", "--force", worktree_path],
        cwd=repo_path,
        capture_output=True,
        text=True,
    )


def _diff_refs(repo_path: str, from_ref: Optional[str], to_ref: Optional[str]) -> List[str]:
    """The ref argument(s) to pass `git diff` for each mode:

    - from_ref + to_ref: two commits (e.g. HEAD~3..HEAD).
    - from_ref only:     that commit vs the working tree.
    - neither:           HEAD vs the working tree -- staged AND unstaged
                         changes. A bare `git diff` compares against the
                         index instead, so anything already `git add`ed
                         would silently vanish from the scan.
    """
    if from_ref and to_ref:
        return [from_ref, to_ref]
    if from_ref:
        return [from_ref]
    head = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "HEAD"],
        cwd=repo_path, capture_output=True, text=True,
    )
    if head.returncode == 0:
        return ["HEAD"]
    # No commits yet, so there's no HEAD to diff against -- use the empty
    # tree instead (every tracked file counts as added). Hashed rather than
    # hardcoded so it's right for SHA-256 repos too.
    empty_tree = subprocess.run(
        ["git", "hash-object", "-t", "tree", "--stdin"],
        cwd=repo_path, input="", capture_output=True, text=True,
    )
    return [empty_tree.stdout.strip()]


# Same binary-detection heuristic git itself uses: a NUL byte in the first
# 8000 bytes.
_BINARY_SNIFF_BYTES = 8000

# How to decode git output that carries paths. Git prints them as raw
# bytes: decode as UTF-8, not the locale's encoding, and with
# surrogateescape, so no byte sequence can crash the decode and each path
# maps to the same str the filesystem -- and so Trailmark -- gives it.
_GIT_PATH_TEXT = {"encoding": "utf-8", "errors": "surrogateescape"}

_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13}


def _unquote_git_path(path: str) -> str:
    """Undoes git's C-style quoting of a path in a diff header. Even with
    core.quotePath=false, a path containing a double quote, backslash, or
    control character comes out as e.g. "b/we\\"ird.py", with octal escapes
    for raw bytes -- matching it literally would never find the file."""
    if len(path) < 2 or not (path.startswith('"') and path.endswith('"')):
        return path
    body = path[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            escaped = body[i + 1]
            if escaped in "01234567":
                out.append(int(body[i + 1:i + 4], 8))
                i += 4
            else:
                out.append(_C_ESCAPES.get(escaped, ord(escaped)))
                i += 2
        else:
            out += body[i].encode("utf-8", errors="surrogateescape")
            i += 1
    return out.decode("utf-8", errors="surrogateescape")


def _untracked_file_lines(repo_path: str, log: Callable[[str], None]) -> Dict[str, Dict[int, str]]:
    """Every line of every untracked (and not .gitignore'd) text file, as if
    added in full. `git diff` never lists a file git isn't tracking yet, so
    a brand-new file that hasn't been `git add`ed would otherwise be
    invisible to the scan -- despite being exactly the kind of uncommitted
    change it exists to catch."""
    result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=repo_path, capture_output=True, **_GIT_PATH_TEXT,
    )
    if result.returncode != 0:
        log(f"git ls-files --others failed (exit {result.returncode}): {result.stderr.strip()}")
        return {}

    lines_by_file = {}
    for rel_path in result.stdout.split("\0"):
        if not rel_path:
            continue
        abs_path = os.path.abspath(os.path.join(repo_path, rel_path))
        try:
            with open(abs_path, "rb") as f:
                head = f.read(_BINARY_SNIFF_BYTES)
                if b"\0" in head:
                    continue
                data = head + f.read()
        except OSError:
            continue
        # split("\n"), not splitlines(): the latter also breaks on form
        # feeds and other separators git doesn't, which would shift every
        # later line number out of step with Trailmark's node locations.
        lines = data.decode("utf-8", errors="replace").split("\n")
        if lines and lines[-1] == "":
            lines.pop()  # trailing newline, not an extra empty line
        if lines:
            # rstrip("\r"): CRLF files, matching the diff-derived lines,
            # which text-mode subprocess output has already normalized.
            lines_by_file[abs_path] = {i: text.rstrip("\r") for i, text in enumerate(lines, 1)}
    return lines_by_file


def get_changed_file_paths(
    repo_path: str,
    from_ref: str = None,
    to_ref: str = None,
) -> List[str]:
    """Repo-relative paths of every file that changed (`git diff --name-only`),
    including a file deleted in its entirety -- unlike get_modified_lines,
    which intentionally excludes those (there's no to-side line range for a
    fully deleted file to anchor to). Untracked files aren't listed: they
    didn't exist at from_ref, so they can't contain a deletion. Raises if
    the diff itself fails."""
    # -z: NUL-separated and never quoted, whatever characters a path has.
    cmd = ["git", "diff", "--name-only", "-z"] + _diff_refs(repo_path, from_ref, to_ref)
    result = subprocess.run(cmd, cwd=repo_path, capture_output=True, **_GIT_PATH_TEXT)
    if result.returncode != 0:
        raise RuntimeError(f"git diff --name-only failed: {_git_error(result)}")
    return [path for path in result.stdout.split("\0") if path]


def get_modified_lines(
    repo_path: str,
    from_ref: str = None,
    to_ref: str = None,
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Dict[int, str]]:
    """
    Parses `git diff -U0` to find which lines have been added/modified.

    - Neither ref:       compares working tree vs HEAD (uncommitted changes,
                         staged or not).
    - from_ref only:     compares working tree vs that commit.
    - from_ref + to_ref: compares two commits (e.g. HEAD~3..HEAD).

    In both working-tree modes, untracked (not .gitignore'd) files count
    too, with every line treated as added. Raises if the diff itself fails
    -- a failed diff is not an empty one.

    Returns a dict mapping absolute file paths to a dict of
    {to-side line number: representative changed text}. The text is used to
    cheaply filter out non-substantive changes (comments, blank lines)
    before spending an LLM call on them, and to build a windowed view of
    large functions instead of sending their full body.

    A hunk with zero added lines (a pure deletion, e.g. `@@ -11 +10,0 @@`)
    has no "+" line to anchor to in the to-side tree, but the enclosing node
    still changed — a deleted validation check or sanitization call is
    exactly the kind of change a security scan most needs to catch. Those
    are recorded under a synthetic marker at the deletion's boundary line
    in the to-side file, with the removed text as its value, so the
    enclosing node is still found instead of silently skipped.
    """
    log = log or (lambda msg: None)

    # core.quotePath=false: print non-ASCII paths as-is instead of quoted
    # with octal escapes; the few paths git quotes regardless are undone by
    # _unquote_git_path below. The other flags pin the plain unified format
    # the parser expects, whatever the user's git config says -- e.g.
    # diff.mnemonicPrefix would turn "b/" into "w/", color.ui=always adds
    # escape codes even into a pipe, and diff.external swaps in another tool.
    cmd = [
        "git", "-c", "core.quotePath=false", "diff", "-U0",
        "--no-color", "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/",
    ] + _diff_refs(repo_path, from_ref, to_ref)
    log(f"Running: {' '.join(cmd)} (cwd={repo_path})")
    result = subprocess.run(cmd, cwd=repo_path, capture_output=True, **_GIT_PATH_TEXT)

    if result.returncode != 0:
        raise RuntimeError(f"git diff failed: {_git_error(result)}")

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
            # Git appends a tab after a path containing a space (for
            # patch(1)'s sake) and C-quotes unusual ones -- undo both, or
            # the path never matches the file's real one.
            path = _unquote_git_path(line[4:].removesuffix("\t"))
            if path.startswith("b/"):
                # New file path — resolve to absolute so it matches Trailmark's locations
                current_file = os.path.abspath(os.path.join(repo_path, path[2:]))
            else:
                # "+++ /dev/null": the whole file was deleted on the to side.
                # There's no to-side file to attribute this hunk to, and
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

    if not (from_ref and to_ref):
        untracked = _untracked_file_lines(repo_path, log)
        if untracked:
            log(f"Including {len(untracked)} untracked file(s), every line as added")
            modified_lines.update(untracked)

    return dict(modified_lines)
