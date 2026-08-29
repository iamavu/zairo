from pathlib import Path

from zairo.git_utils import get_modified_lines


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
