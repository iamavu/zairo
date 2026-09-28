import subprocess
import sys
from pathlib import Path

import pytest

from zairo.git_utils import get_changed_file_paths, get_modified_lines, resolve_commit


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_diff_between_two_commits(git_repo: Path):
    modified = get_modified_lines(str(git_repo), "HEAD~1", "HEAD")
    file_path = str((git_repo / "test.py").resolve())

    assert file_path in modified
    changed = modified[file_path]
    # Every line of the new (post-vulnerability) file was added in this commit.
    assert set(changed.keys()) == {1, 2, 3}
    assert "os.system(user_input)" in changed[3]


def test_uncommitted_changes(git_repo: Path):
    test_py = git_repo / "test.py"
    test_py.write_text(test_py.read_text() + "\n# trailing comment\n")

    modified = get_modified_lines(str(git_repo))
    file_path = str(test_py.resolve())

    assert file_path in modified
    assert 4 in modified[file_path]


def test_no_base_or_target_diffs_working_tree_vs_head(git_repo: Path):
    # With no changes at all, nothing should show up as modified.
    modified = get_modified_lines(str(git_repo))
    assert modified == {}


def test_staged_changes_are_included(git_repo: Path):
    """A bare `git diff` compares against the index, so a change that's
    already been `git add`ed would vanish from an uncommitted-changes scan
    -- it has to be diffed against HEAD instead."""
    test_py = git_repo / "test.py"
    test_py.write_text(test_py.read_text() + "def staged(cmd):\n    return os.popen(cmd)\n")
    _git(git_repo, "add", "test.py")

    modified = get_modified_lines(str(git_repo))
    file_path = str(test_py.resolve())

    assert file_path in modified
    assert "os.popen(cmd)" in modified[file_path][5]
    assert get_changed_file_paths(str(git_repo)) == ["test.py"]


def test_untracked_file_counts_as_entirely_added(git_repo: Path):
    new_py = git_repo / "new.py"
    new_py.write_text("import os\ndef run(cmd):\n    return os.system(cmd)\n")

    modified = get_modified_lines(str(git_repo))

    assert modified[str(new_py.resolve())] == {
        1: "import os",
        2: "def run(cmd):",
        3: "    return os.system(cmd)",
    }


def test_gitignored_and_binary_untracked_files_are_skipped(git_repo: Path):
    (git_repo / ".gitignore").write_text("ignored.py\n")
    (git_repo / "ignored.py").write_text("def f():\n    pass\n")
    (git_repo / "blob.bin").write_bytes(b"\x00\x01\x02")

    modified = get_modified_lines(str(git_repo))

    assert str((git_repo / "ignored.py").resolve()) not in modified
    assert str((git_repo / "blob.bin").resolve()) not in modified


def test_untracked_files_not_included_when_diffing_two_commits(git_repo: Path):
    """from_ref + to_ref compares two commits -- whatever happens to be lying
    around untracked in the working tree isn't part of either."""
    (git_repo / "new.py").write_text("def f():\n    pass\n")

    modified = get_modified_lines(str(git_repo), "HEAD~1", "HEAD")

    assert str((git_repo / "new.py").resolve()) not in modified


def test_repo_with_no_commits_yet(tmp_path: Path):
    """No HEAD to diff against: every staged and untracked file counts as
    added, instead of `git diff HEAD` erroring out and finding nothing."""
    repo = tmp_path / "fresh"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "staged.py").write_text("def a():\n    pass\n")
    _git(repo, "add", "staged.py")
    (repo / "untracked.py").write_text("def b():\n    pass\n")

    modified = get_modified_lines(str(repo))

    assert set(modified[str((repo / "staged.py").resolve())]) == {1, 2}
    assert set(modified[str((repo / "untracked.py").resolve())]) == {1, 2}


def test_resolve_commit_returns_the_full_commit_id(git_repo: Path):
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=git_repo, capture_output=True, text=True).stdout.strip()
    assert resolve_commit(str(git_repo), "HEAD") == head


def test_resolve_commit_rejects_an_unknown_ref(git_repo: Path):
    """A ref that doesn't exist must be an error, not a `git diff` failure
    that reads as "nothing changed"."""
    with pytest.raises(RuntimeError, match="'no-such-ref' doesn't name a commit"):
        resolve_commit(str(git_repo), "no-such-ref")


def test_resolve_commit_rejects_an_option_looking_ref(git_repo: Path):
    with pytest.raises(RuntimeError, match="doesn't name a commit"):
        resolve_commit(str(git_repo), "--output=/tmp/x")


def test_resolve_commit_in_a_shallow_clone_hints_at_fetch_depth(git_repo: Path, tmp_path: Path):
    """The classic CI mistake: a depth-1 checkout doesn't have the base
    commit at all."""
    shallow = tmp_path / "shallow"
    _git(tmp_path, "clone", "-q", "--depth", "1", git_repo.as_uri(), str(shallow))

    with pytest.raises(RuntimeError, match="fetch-depth: 0"):
        resolve_commit(str(shallow), "HEAD~1")


def test_failed_git_diff_raises_instead_of_reporting_no_changes(git_repo: Path):
    with pytest.raises(RuntimeError, match="git diff failed"):
        get_modified_lines(str(git_repo), "no-such-ref", "HEAD")


@pytest.mark.parametrize("name", [
    "résumé.py",
    "my file.py",
    pytest.param('we"ird.py', marks=pytest.mark.skipif(sys.platform == "win32", reason="not a valid Windows filename")),
])
def test_unusual_filenames_are_matched(git_repo: Path, name: str):
    """In diff headers git quotes some paths ("b/r\303\251sum\303\251.py"),
    and puts a tab after any containing a space -- neither may keep a
    changed file out of the scan, or out of deleted-code detection."""
    (git_repo / name).write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
    _git(git_repo, "add", "--", name)
    _git(git_repo, "commit", "-q", "-m", "add")

    modified = get_modified_lines(str(git_repo), "HEAD~1", "HEAD")

    assert set(modified[str((git_repo / name).resolve())]) == {1, 2}
    assert get_changed_file_paths(str(git_repo), "HEAD~1", "HEAD") == [name]


def test_user_diff_config_cannot_change_the_parsed_format(git_repo: Path):
    """mnemonicPrefix turns "b/" into "w/", noprefix drops it, and
    color.ui=always adds escape codes even into a pipe -- any of these
    would otherwise make every changed file invisible."""
    for key, value in (("diff.mnemonicPrefix", "true"), ("diff.noprefix", "true"), ("color.ui", "always")):
        _git(git_repo, "config", key, value)
    test_py = git_repo / "test.py"
    test_py.write_text(test_py.read_text() + "def added():\n    pass\n")

    modified = get_modified_lines(str(git_repo))

    assert set(modified[str(test_py.resolve())]) == {4, 5}
