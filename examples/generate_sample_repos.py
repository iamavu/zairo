#!/usr/bin/env python3
"""Generates a handful of small, distinctly-vulnerable sample git repos under
examples/sample-repos/ for trying `zairo` against -- one path scans just
that repo, multiple paths (or --repos-file) auto-switch to fleet mode.

Each one isn't committed to zairo's own repo -- a real git history can't
live nested inside another repo's .git (see examples/dummy_repo, which has
the same constraint) -- so run this locally to create them:

    python examples/generate_sample_repos.py
    zairo examples/sample-repos/cmd-injection-app --base HEAD~1 --target HEAD --llm
    zairo examples/sample-repos/* --base HEAD~1 --target HEAD --llm
"""
import shutil
import subprocess
from pathlib import Path

SAMPLE_REPOS_DIR = Path(__file__).parent / "sample-repos"

# Each repo is 2 commits: a safe "before", then a commit that introduces one
# specific, LLM-findable vulnerability -- so `--base HEAD~1 --target HEAD`
# works immediately, and passing all of them at once has genuinely
# different repos (not just copies of one) to demonstrate fleet mode's
# rollup with.
REPOS = {
    "cmd-injection-app": {
        "file": "app.py",
        "before": '''import subprocess


def run_diagnostics(hostname):
    return subprocess.run(["ping", "-c", "1", hostname], capture_output=True, text=True).stdout
''',
        "after": '''import os


def run_diagnostics(hostname):
    return os.popen(f"ping -c 1 {hostname}").read()
''',
        "message": "switch to shell-based ping for wider platform support",
    },
    "sql-injection-app": {
        "file": "app.py",
        "before": '''def get_user(db, user_id):
    cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
''',
        "after": '''def get_user(db, user_id):
    cursor = db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
''',
        "message": "simplify query building",
    },
    "path-traversal-app": {
        "file": "app.py",
        "before": '''import os

ALLOWED_DIR = "/var/app/uploads"


def read_upload(filename):
    safe_name = os.path.basename(filename)
    with open(os.path.join(ALLOWED_DIR, safe_name)) as f:
        return f.read()
''',
        "after": '''import os

ALLOWED_DIR = "/var/app/uploads"


def read_upload(filename):
    with open(os.path.join(ALLOWED_DIR, filename)) as f:
        return f.read()
''',
        "message": "support nested upload subfolders",
    },
}


def _run_git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def generate(name: str, spec: dict) -> Path:
    repo = SAMPLE_REPOS_DIR / name
    if repo.exists():
        shutil.rmtree(repo)
    repo.mkdir(parents=True)

    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.email", "example@zairo.dev")
    _run_git(repo, "config", "user.name", "zairo examples")

    target = repo / spec["file"]
    target.write_text(spec["before"])
    _run_git(repo, "add", spec["file"])
    _run_git(repo, "commit", "-q", "-m", "initial")

    target.write_text(spec["after"])
    _run_git(repo, "add", spec["file"])
    _run_git(repo, "commit", "-q", "-m", spec["message"])

    return repo


def main() -> None:
    SAMPLE_REPOS_DIR.mkdir(exist_ok=True)
    for name, spec in REPOS.items():
        repo = generate(name, spec)
        print(f"created {repo} (2 commits: initial -> {spec['message']!r})")

    print("\nTry:")
    print(f"  zairo {SAMPLE_REPOS_DIR / 'cmd-injection-app'} --base HEAD~1 --target HEAD --llm")
    print(f"  zairo {SAMPLE_REPOS_DIR}/* --base HEAD~1 --target HEAD --llm  # multiple paths -> fleet mode")


if __name__ == "__main__":
    main()
