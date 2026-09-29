import subprocess
import re
import os
import shutil
import tempfile
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional


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


def head_commit(repo_path: str) -> Optional[str]:
    """The commit HEAD points at, or None in a repo with no commits yet."""
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
        cwd=repo_path, capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


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


def _untracked_file_hunks(repo_path: str, log: Callable[[str], None]) -> Dict[str, List[Dict[str, Any]]]:
    """Every untracked (and not .gitignore'd) text file as a single hunk
    adding all of its lines. `git diff` never lists a file git isn't tracking yet, so
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

    hunks_by_file = {}
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
            hunks_by_file[abs_path] = [{"start": 1, "removed": [], "added": [text.rstrip("\r") for text in lines]}]
    return hunks_by_file


def get_changed_file_paths(
    repo_path: str,
    from_ref: str = None,
    to_ref: str = None,
) -> List[str]:
    """Repo-relative paths of every file that changed (`git diff --name-only`),
    including a file deleted in its entirety -- unlike get_diff_hunks,
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


def list_files(repo_path: str) -> List[str]:
    """Repo-relative paths of the files in the working tree that git would
    commit: tracked ones, and untracked ones that aren't ignored."""
    cmd = ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    result = subprocess.run(cmd, cwd=repo_path, capture_output=True, **_GIT_PATH_TEXT)
    if result.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {_git_error(result)}")
    return sorted({path for path in result.stdout.split("\0") if path})


def hunk_lines(hunk: Dict[str, Any]) -> List[int]:
    """The to-side line numbers a hunk touches: its added lines -- or, for a
    pure deletion, the line the removed ones used to follow (at least 1),
    since a deleted check still changes the code around it."""
    if hunk["added"]:
        return list(range(hunk["start"], hunk["start"] + len(hunk["added"])))
    return [max(1, hunk["start"])]


def hunks_in_range(hunks: List[Dict[str, Any]], start: int, end: int) -> List[Dict[str, Any]]:
    """The hunks touching to-side lines start..end, with added lines outside
    that range cut off. Removed lines are kept whole: they have no to-side
    position to cut by, and what a change took away is the part a reviewer
    can't see anywhere else."""
    within = []
    for hunk in hunks:
        lines = [ln for ln in hunk_lines(hunk) if start <= ln <= end]
        if not lines:
            continue
        if not hunk["added"]:
            within.append(hunk)
            continue
        first, last = lines[0], lines[-1]
        within.append({
            "start": first,
            "removed": hunk["removed"],
            "added": hunk["added"][first - hunk["start"]:last - hunk["start"] + 1],
        })
    return within


_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def get_diff_hunks(
    repo_path: str,
    from_ref: str = None,
    to_ref: str = None,
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parses `git diff -U0` into the hunks of every changed file.

    - Neither ref:       compares working tree vs HEAD (uncommitted changes,
                         staged or not).
    - from_ref only:     compares working tree vs that commit.
    - from_ref + to_ref: compares two commits (e.g. HEAD~3..HEAD).

    In both working-tree modes, untracked (not .gitignore'd) files count
    too, as one hunk adding every line. Raises if the diff itself fails --
    a failed diff is not an empty one.

    Returns {absolute file path: [hunk, ...]}, each hunk a dict of:
      start:   the to-side line number of its first added line -- or, for
               a pure deletion, the line the removed ones used to follow
               (0 at the top of the file), as git reports it;
      removed: the text of the lines it removed, in order;
      added:   the text of the lines it added, in order (line start + i).

    Keeping what was removed, not just what was added, is the point: a
    deleted validation check or sanitization call is exactly the kind of
    change a security review most needs to see, and the code after the
    change can't show it.
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

    hunks_by_file = defaultdict(list)
    current_file = None
    hunk = None
    removed_left = added_left = 0

    for line in result.stdout.splitlines():
        if removed_left or added_left:
            # Inside a hunk, -U0 lists exactly as many removed lines, then
            # added lines, as its header announced. Counting them off -- not
            # guessing from each line's prefix -- means a removed "-- SQL
            # comment" (shown as "--- SQL comment") can't pass for a file
            # header. "\ No newline at end of file" markers aren't counted.
            if line.startswith("-") and removed_left:
                hunk["removed"].append(line[1:])
                removed_left -= 1
            elif line.startswith("+") and added_left:
                hunk["added"].append(line[1:])
                added_left -= 1
            continue

        if line.startswith("+++ "):
            # Git appends a tab after a path containing a space (for
            # patch(1)'s sake) and C-quotes unusual ones -- undo both, or
            # the path never matches the file's real one.
            path = _unquote_git_path(line[4:].removesuffix("\t"))
            if path.startswith("b/"):
                # New file path — resolve to absolute so it matches Trailmark's locations
                current_file = os.path.abspath(os.path.join(repo_path, path[2:]))
            else:
                # "+++ /dev/null": the whole file was deleted on the to side.
                # There's no to-side file to attribute its hunks to, and
                # without resetting this, a stale current_file from the
                # PREVIOUS file section in the diff would silently absorb
                # this file's content -- a genuine cross-file data leak.
                current_file = None
        elif line.startswith("@@ ") and current_file:
            match = _HUNK_HEADER_RE.match(line)
            if match:
                removed_count, start, added_count = match.groups()
                removed_left = int(removed_count) if removed_count is not None else 1
                added_left = int(added_count) if added_count is not None else 1
                hunk = {"start": int(start), "removed": [], "added": []}
                hunks_by_file[current_file].append(hunk)

    if not (from_ref and to_ref):
        untracked = _untracked_file_hunks(repo_path, log)
        if untracked:
            log(f"Including {len(untracked)} untracked file(s), every line as added")
            hunks_by_file.update(untracked)

    return dict(hunks_by_file)
