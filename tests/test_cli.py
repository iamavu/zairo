import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from zairo.cli import app

runner = CliRunner()


def test_analyze_end_to_end(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        ["analyze", str(git_repo), "--base", "HEAD~1", "--target", "HEAD", "--output", str(output_dir)],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "report.json").exists()
    assert (output_dir / "report.html").exists()
    assert not (output_dir / "report.sarif").exists()  # no --llm, nothing to convert
    assert "Success!" in result.output


def test_analyze_fail_on_without_llm_is_rejected(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        ["analyze", str(git_repo), "--base", "HEAD~1", "--target", "HEAD", "--output", str(output_dir), "--fail-on", "high"],
    )

    assert result.exit_code != 0
    assert "--fail-on requires --llm" in result.output


def test_fleet_scans_multiple_repos(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "fleet", str(git_repo), str(git_repo),
            "--base", "HEAD~1", "--target", "HEAD", "--output", str(output_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "fleet.json").exists()
    assert (output_dir / "fleet.html").exists()
    assert not (output_dir / "fleet.sarif").exists()  # no --llm, nothing to convert

    with open(output_dir / "fleet.json") as f:
        summary = json.load(f)
    assert len(summary["repos"]) == 2
    assert summary["repos"][0]["slug"] != summary["repos"][1]["slug"]  # de-duplicated
    for r in summary["repos"]:
        assert r["status"] == "ok"
        assert (output_dir / r["report_json"]).exists()
        assert (output_dir / r["report_html"]).exists()


def test_fleet_continues_past_a_failing_repo_by_default(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    bad_repo = tmp_path / "not_a_repo"
    bad_repo.mkdir()

    result = runner.invoke(
        app,
        ["fleet", str(bad_repo), str(git_repo), "--output", str(output_dir)],
    )

    assert result.exit_code != 0  # a repo failed -> overall failure
    with open(output_dir / "fleet.json") as f:
        summary = json.load(f)
    statuses = {r["slug"]: r["status"] for r in summary["repos"]}
    assert len(statuses) == 2
    assert "error" in statuses.values()
    assert "ok" in statuses.values()


def test_fleet_requires_at_least_one_repo(tmp_path: Path):
    result = runner.invoke(app, ["fleet", "--output", str(tmp_path / "out")])

    assert result.exit_code != 0
    assert "no repos given" in result.output


def test_fleet_fail_on_without_llm_is_rejected(git_repo: Path, tmp_path: Path):
    result = runner.invoke(
        app,
        ["fleet", str(git_repo), "--output", str(tmp_path / "out"), "--fail-on", "high"],
    )

    assert result.exit_code != 0
    assert "--fail-on requires --llm" in result.output


def test_fleet_tokens_without_llm_is_silent(git_repo: Path, tmp_path: Path):
    """--tokens has nothing to report without --llm -- unlike --fail-on,
    there's no invalid combination here, it should just print nothing."""
    result = runner.invoke(
        app,
        ["fleet", str(git_repo), "--output", str(tmp_path / "out"), "--tokens"],
    )

    assert result.exit_code == 0, result.output
    assert "Token usage" not in result.output
    assert "Tokens used" not in result.output


def test_fleet_tokens_sums_usage_across_repos(make_git_repo, tmp_path: Path):
    repo_a = make_git_repo("repo_a")
    repo_b = make_git_repo("repo_b")

    fake_usage = {
        "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
        "requests": 1, "requests_without_usage": 0, "errors": {},
    }

    with patch("zairo.scan.scan_graph_for_vulnerabilities", return_value=({}, fake_usage)):
        result = runner.invoke(
            app,
            ["fleet", str(repo_a), str(repo_b), "--llm", "--tokens", "--output", str(tmp_path / "out")],
        )

    assert result.exit_code == 0, result.output
    # 2 repos x fake_usage each -> summed totals
    assert "200 prompt" in result.output
    assert "40 completion" in result.output
    assert "240 total" in result.output
    assert "2 request(s)" in result.output
