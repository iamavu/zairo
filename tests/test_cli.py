from pathlib import Path

from typer.testing import CliRunner

from zairo.cli import app

runner = CliRunner()


def test_analyze_end_to_end(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [str(git_repo), "--base", "HEAD~1", "--target", "HEAD", "--output", str(output_dir)],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "report.json").exists()
    assert (output_dir / "report.html").exists()
    assert not (output_dir / "report.sarif").exists()  # no --llm, nothing to convert
    assert "Success!" in result.output


def test_fail_on_without_llm_is_rejected(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [str(git_repo), "--base", "HEAD~1", "--target", "HEAD", "--output", str(output_dir), "--fail-on", "high"],
    )

    assert result.exit_code != 0
    assert "--fail-on requires --llm" in result.output
