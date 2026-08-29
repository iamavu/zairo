import subprocess
from pathlib import Path

import pytest


def _run_git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A throwaway git repo with two commits: an initial safe version of
    test.py, then a commit that introduces a command-injection vulnerability.
    The working tree is left clean (HEAD == target commit)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.email", "test@example.com")
    _run_git(repo, "config", "user.name", "Test")

    test_py = repo / "test.py"
    test_py.write_text(
        "def a():\n"
        "    return 2\n"
        "def b():\n"
        "    return a()\n"
        "def c():\n"
        "    return b()\n"
    )
    _run_git(repo, "add", "test.py")
    _run_git(repo, "commit", "-q", "-m", "initial")

    test_py.write_text(
        "import os\n"
        "def vulnerable_exec(user_input):\n"
        "    return os.system(user_input)\n"
    )
    _run_git(repo, "add", "test.py")
    _run_git(repo, "commit", "-q", "-m", "add vulnerability")

    return repo


@pytest.fixture
def make_git_repo(tmp_path: Path):
    """Factory for a throwaway single-commit git repo with trivial content,
    for tests that need more than one independent repo (git_repo above
    gives exactly one, with specific vulnerable content)."""
    def _make(name: str) -> Path:
        repo = tmp_path / name
        repo.mkdir()
        _run_git(repo, "init", "-q")
        _run_git(repo, "config", "user.email", "test@example.com")
        _run_git(repo, "config", "user.name", "Test")
        (repo / "app.py").write_text("def f():\n    return 1\n")
        _run_git(repo, "add", "app.py")
        _run_git(repo, "commit", "-q", "-m", "initial")
        return repo
    return _make
