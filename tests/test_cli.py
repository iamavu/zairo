import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from zairo.cli import app

runner = CliRunner()


def test_single_repo_writes_a_direct_report(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [str(git_repo), "--base", "HEAD~1", "--target", "HEAD", "--output", str(output_dir)],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "report.json").exists()
    assert (output_dir / "report.html").exists()
    assert not (output_dir / "report.sarif").exists()  # no --llm, nothing to convert
    assert not (output_dir / "rollup.json").exists()  # single repo -> no rollup
    assert "Success!" in result.output


def test_single_repo_fail_on_without_llm_is_rejected(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [str(git_repo), "--base", "HEAD~1", "--target", "HEAD", "--output", str(output_dir), "--fail-on", "high"],
    )

    assert result.exit_code != 0
    assert "--fail-on requires --llm" in result.output


def test_multiple_positional_paths_trigger_multi_repo_mode(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            str(git_repo), str(git_repo),
            "--base", "HEAD~1", "--target", "HEAD", "--output", str(output_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "rollup.json").exists()
    assert (output_dir / "rollup.html").exists()
    assert not (output_dir / "rollup.sarif").exists()  # no --llm, nothing to convert
    assert not (output_dir / "report.json").exists()  # multi-repo mode -> no direct single-repo report

    with open(output_dir / "rollup.json") as f:
        summary = json.load(f)
    assert len(summary["repos"]) == 2
    assert summary["repos"][0]["slug"] != summary["repos"][1]["slug"]  # de-duplicated
    for r in summary["repos"]:
        assert r["status"] == "ok"
        assert (output_dir / r["report_json"]).exists()
        assert (output_dir / r["report_html"]).exists()


def test_repos_file_with_one_entry_triggers_single_repo_mode(git_repo: Path, tmp_path: Path):
    """Mode is decided purely by the final repo count, regardless of whether
    it came from positional args or --repos-file."""
    repos_file = tmp_path / "repos.txt"
    repos_file.write_text(f"{git_repo}\n")
    output_dir = tmp_path / "out"

    result = runner.invoke(app, ["--repos-file", str(repos_file), "--output", str(output_dir)])

    assert result.exit_code == 0, result.output
    assert (output_dir / "report.json").exists()
    assert not (output_dir / "rollup.json").exists()


def test_repos_file_with_multiple_entries_triggers_multi_repo_mode(git_repo: Path, tmp_path: Path):
    repos_file = tmp_path / "repos.txt"
    repos_file.write_text(f"{git_repo}\n# a comment\n\n{git_repo}\n")
    output_dir = tmp_path / "out"

    result = runner.invoke(app, ["--repos-file", str(repos_file), "--output", str(output_dir)])

    assert result.exit_code == 0, result.output
    assert (output_dir / "rollup.json").exists()
    with open(output_dir / "rollup.json") as f:
        summary = json.load(f)
    assert len(summary["repos"]) == 2


def test_positional_paths_and_repos_file_combine(git_repo: Path, tmp_path: Path):
    """A single positional path plus a --repos-file entry totals two repos
    -> multi-repo mode, even though neither source alone would have."""
    repos_file = tmp_path / "repos.txt"
    repos_file.write_text(f"{git_repo}\n")
    output_dir = tmp_path / "out"

    result = runner.invoke(app, [str(git_repo), "--repos-file", str(repos_file), "--output", str(output_dir)])

    assert result.exit_code == 0, result.output
    assert (output_dir / "rollup.json").exists()
    with open(output_dir / "rollup.json") as f:
        summary = json.load(f)
    assert len(summary["repos"]) == 2


def test_multi_repo_continues_past_a_failing_repo_by_default(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    bad_repo = tmp_path / "not_a_repo"
    bad_repo.mkdir()

    result = runner.invoke(
        app,
        [str(bad_repo), str(git_repo), "--output", str(output_dir)],
    )

    assert result.exit_code != 0  # a repo failed -> overall failure
    with open(output_dir / "rollup.json") as f:
        summary = json.load(f)
    statuses = {r["slug"]: r["status"] for r in summary["repos"]}
    assert len(statuses) == 2
    assert "error" in statuses.values()
    assert "ok" in statuses.values()


def test_multi_repo_repo_concurrency_scans_all_repos(make_git_repo, tmp_path: Path):
    repos = [make_git_repo(f"repo{i}") for i in range(3)]
    output_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [*[str(r) for r in repos], "--repo-concurrency", "2", "--output", str(output_dir)],
    )

    assert result.exit_code == 0, result.output
    with open(output_dir / "rollup.json") as f:
        summary = json.load(f)
    # Completion order isn't submission order under real concurrency --
    # check the set of outcomes, not positions.
    assert len(summary["repos"]) == 3
    assert all(r["status"] == "ok" for r in summary["repos"])
    for r in summary["repos"]:
        assert (output_dir / r["report_json"]).exists()


def test_multi_repo_repo_concurrency_continues_past_error_by_default(make_git_repo, tmp_path: Path):
    good_repos = [make_git_repo(f"repo{i}") for i in range(3)]
    bad_repo = tmp_path / "not_a_repo"
    bad_repo.mkdir()
    output_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [str(bad_repo), *[str(r) for r in good_repos], "--repo-concurrency", "2", "--output", str(output_dir)],
    )

    assert result.exit_code != 0  # a repo failed -> overall failure
    with open(output_dir / "rollup.json") as f:
        summary = json.load(f)
    statuses = [r["status"] for r in summary["repos"]]
    assert len(statuses) == 4  # continue-on-error (default): every repo attempted
    assert statuses.count("error") == 1
    assert statuses.count("ok") == 3


def test_multi_repo_repo_concurrency_stop_on_error_cancels_queued_repos(make_git_repo, tmp_path: Path):
    """With only 2 worker slots and a repo guaranteed to fail immediately
    (nonexistent path -> no Trailmark work at all) submitted first, the
    repos beyond the first 2 are still queued -- not yet handed to a worker
    -- when the failure is processed, so --stop-on-error should be able to
    cancel them before they ever run."""
    bad_repo = tmp_path / "not_a_repo"
    bad_repo.mkdir()
    good_repos = [make_git_repo(f"repo{i}") for i in range(5)]
    output_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            str(bad_repo), *[str(r) for r in good_repos],
            "--repo-concurrency", "2", "--stop-on-error", "--output", str(output_dir),
        ],
    )

    assert result.exit_code != 0
    with open(output_dir / "rollup.json") as f:
        summary = json.load(f)
    # Not a precise count (real thread timing) -- but at least one queued
    # repo must have been skipped, or this test proves nothing.
    assert len(summary["repos"]) < 6
    assert any(r["status"] == "error" for r in summary["repos"])


def test_no_repos_given_is_rejected(tmp_path: Path):
    result = runner.invoke(app, ["--output", str(tmp_path / "out")])

    assert result.exit_code != 0
    assert "no repos given" in result.output


def test_multi_repo_fail_on_without_llm_is_rejected(git_repo: Path, tmp_path: Path):
    result = runner.invoke(
        app,
        [str(git_repo), str(git_repo), "--output", str(tmp_path / "out"), "--fail-on", "high"],
    )

    assert result.exit_code != 0
    assert "--fail-on requires --llm" in result.output


def test_multi_repo_tokens_without_llm_is_silent(git_repo: Path, tmp_path: Path):
    """--tokens has nothing to report without --llm -- unlike --fail-on,
    there's no invalid combination here, it should just print nothing."""
    result = runner.invoke(
        app,
        [str(git_repo), str(git_repo), "--output", str(tmp_path / "out"), "--tokens"],
    )

    assert result.exit_code == 0, result.output
    assert "Token usage" not in result.output
    assert "Tokens used" not in result.output


def test_multi_repo_tokens_sums_usage_across_repos(make_git_repo, tmp_path: Path):
    repo_a = make_git_repo("repo_a")
    repo_b = make_git_repo("repo_b")

    fake_usage = {
        "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
        "requests": 1, "requests_without_usage": 0, "errors": {},
    }

    with patch("zairo.scan.scan_graph_for_vulnerabilities", return_value=({}, fake_usage)):
        result = runner.invoke(
            app,
            [str(repo_a), str(repo_b), "--llm", "--tokens", "--output", str(tmp_path / "out")],
        )

    assert result.exit_code == 0, result.output
    # 2 repos x fake_usage each -> summed totals
    assert "200 prompt" in result.output
    assert "40 completion" in result.output
    assert "240 total" in result.output
    assert "2 request(s)" in result.output
