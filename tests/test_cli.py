import json
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from zairo.cli import app
from zairo.notes import NOTE_INSTRUCTIONS

runner = CliRunner()


def _text(messages) -> str:
    """A request's messages -- system, then user -- as one text."""
    return "\n".join(m["content"] for m in messages)


def test_single_repo_writes_a_direct_report(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--output", str(output_dir), "--graph-only"],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "report.json").exists()
    assert (output_dir / "report.html").exists()
    assert not (output_dir / "report.sarif").exists()  # --graph-only, nothing to convert
    assert not (output_dir / "rollup.json").exists()  # single repo -> no rollup
    assert "Success!" in result.output


def test_single_repo_fail_on_with_graph_only_is_rejected(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--output", str(output_dir), "--graph-only", "--fail-on", "high"],
    )

    assert result.exit_code != 0
    assert "--fail-on requires LLM scanning" in result.output


def test_to_without_from_is_rejected(git_repo: Path, tmp_path: Path):
    """--to alone isn't a diff of anything -- without this check it would be
    silently dropped, scanning uncommitted changes instead of the commit
    that was actually asked for."""
    output_dir = tmp_path / "out"
    result = runner.invoke(app, [str(git_repo), "--to", "HEAD", "--output", str(output_dir), "--graph-only"])

    assert result.exit_code != 0
    assert "--to requires --from" in result.output
    assert not output_dir.exists()  # rejected before any scan ran


def test_multiple_positional_paths_trigger_multi_repo_mode(git_repo: Path, tmp_path: Path):
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            str(git_repo), str(git_repo),
            "--from", "HEAD~1", "--to", "HEAD", "--output", str(output_dir), "--graph-only",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "rollup.json").exists()
    assert (output_dir / "rollup.html").exists()
    assert not (output_dir / "rollup.sarif").exists()  # --graph-only, nothing to convert
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

    result = runner.invoke(app, ["--repos-file", str(repos_file), "--output", str(output_dir), "--graph-only"])

    assert result.exit_code == 0, result.output
    assert (output_dir / "report.json").exists()
    assert not (output_dir / "rollup.json").exists()


def test_repos_file_with_multiple_entries_triggers_multi_repo_mode(git_repo: Path, tmp_path: Path):
    repos_file = tmp_path / "repos.txt"
    repos_file.write_text(f"{git_repo}\n# a comment\n\n{git_repo}\n")
    output_dir = tmp_path / "out"

    result = runner.invoke(app, ["--repos-file", str(repos_file), "--output", str(output_dir), "--graph-only"])

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

    result = runner.invoke(app, [str(git_repo), "--repos-file", str(repos_file), "--output", str(output_dir), "--graph-only"])

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
        [str(bad_repo), str(git_repo), "--output", str(output_dir), "--graph-only"],
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
        [*[str(r) for r in repos], "--repo-concurrency", "2", "--output", str(output_dir), "--graph-only"],
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
        [str(bad_repo), *[str(r) for r in good_repos], "--repo-concurrency", "2", "--output", str(output_dir), "--graph-only"],
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
            "--repo-concurrency", "2", "--stop-on-error", "--output", str(output_dir), "--graph-only",
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


def test_multi_repo_fail_on_with_graph_only_is_rejected(git_repo: Path, tmp_path: Path):
    result = runner.invoke(
        app,
        [str(git_repo), str(git_repo), "--output", str(tmp_path / "out"), "--graph-only", "--fail-on", "high"],
    )

    assert result.exit_code != 0
    assert "--fail-on requires LLM scanning" in result.output


def test_multi_repo_tokens_with_graph_only_is_silent(git_repo: Path, tmp_path: Path):
    """--tokens has nothing to report with --graph-only -- unlike --fail-on,
    there's no invalid combination here, it should just print nothing."""
    result = runner.invoke(
        app,
        [str(git_repo), str(git_repo), "--output", str(tmp_path / "out"), "--graph-only", "--tokens"],
    )

    assert result.exit_code == 0, result.output
    assert "Token usage" not in result.output
    assert "Tokens used" not in result.output


def test_multi_repo_tokens_sums_usage_across_repos(make_git_repo, tmp_path: Path):
    repo_a = make_git_repo("repo_a")
    repo_b = make_git_repo("repo_b")

    fake_usage = {
        "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
        "requests": 1, "requests_without_usage": 0, "nodes_scanned": 1, "errors": {}, "failed_nodes": {},
        "assessed_nodes": [], "skipped_nodes": {}, "notes_available": 0, "notes_used": 0, "lookups": {}, "lookups_made": 0,
    }

    with patch("zairo.scan.scan_graph_for_vulnerabilities", return_value=({}, fake_usage)):
        result = runner.invoke(
            app,
            [str(repo_a), str(repo_b), "--tokens", "--output", str(tmp_path / "out")],
        )

    assert result.exit_code == 0, result.output
    # 2 repos x fake_usage each -> summed totals
    assert "200 prompt" in result.output
    assert "40 completion" in result.output
    assert "240 total" in result.output
    assert "2 request(s)" in result.output


def test_head_relative_from_resolves_in_the_repo_not_the_to_worktree(git_repo: Path, tmp_path: Path):
    """--to is checked out into a temporary worktree, where HEAD means the
    --to commit. --from HEAD has to mean the repo's HEAD (here the initial
    commit), or the scan silently diffs --to against itself."""
    _git = lambda *a: subprocess.run(["git", *a], cwd=git_repo, check=True, capture_output=True)
    _git("branch", "feature")  # the vulnerable commit
    _git("checkout", "-q", "HEAD~1")  # HEAD is now the initial commit

    output_dir = tmp_path / "out"
    result = runner.invoke(
        app, [str(git_repo), "--from", "HEAD", "--to", "feature", "--graph-only", "--output", str(output_dir)],
    )

    assert result.exit_code == 0, result.output
    with open(output_dir / "report.json") as f:
        modified = {n["name"] for n in json.load(f)["symbols"] if n["status"] == "modified"}
    assert "vulnerable_exec" in modified


def test_unknown_from_ref_is_an_error(git_repo: Path, tmp_path: Path):
    """Not an empty diff that passes as "nothing changed"."""
    result = runner.invoke(
        app,
        [str(git_repo), "--from", "no-such-ref", "--to", "HEAD", "--graph-only", "--output", str(tmp_path / "out")],
    )

    assert result.exit_code != 0
    assert "doesn't name a commit" in result.output


def test_error_text_with_markup_like_brackets_prints_verbatim(git_repo: Path, tmp_path: Path):
    """Error messages (git's, a model provider's) are arbitrary text. One
    containing something like git's usage syntax "[/<m>]" must be printed
    as-is, not parsed as a Rich closing tag -- which used to crash the
    whole run instead of reporting the error."""
    with patch("zairo.cli.run_scan", side_effect=RuntimeError("bad option [/<m>]")):
        single = runner.invoke(app, [str(git_repo), "--graph-only", "--output", str(tmp_path / "single")])
        multi = runner.invoke(
            app, [str(git_repo), str(git_repo), "--graph-only", "--output", str(tmp_path / "multi")],
        )

    assert single.exit_code == 1
    assert "bad option [/<m>]" in single.output
    assert multi.exit_code == 1
    assert "bad option [/<m>]" in multi.output
    assert (tmp_path / "multi" / "rollup.json").exists()


def _scan_usage(failed_nodes: dict) -> dict:
    """What scan_graph_for_vulnerabilities returns as its second value."""
    errors = {}
    for message in failed_nodes.values():
        errors[message] = errors.get(message, 0) + 1
    return {
        "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "requests": 1,
        "requests_without_usage": 1, "nodes_scanned": len(failed_nodes) or 1,
        "errors": errors, "failed_nodes": failed_nodes, "assessed_nodes": [], "skipped_nodes": {},
        "notes_available": 0, "notes_used": 0, "lookups": {}, "lookups_made": 0,
    }


def test_fail_on_fails_an_incomplete_scan(git_repo: Path, tmp_path: Path):
    """Every node failing (e.g. a missing API key) finds nothing -- that's
    no evidence of safety, so --fail-on must not pass it."""
    usage = _scan_usage({"n1": "AuthenticationError: invalid API key"})
    with patch("zairo.scan.scan_graph_for_vulnerabilities", return_value=({}, usage)):
        result = runner.invoke(
            app,
            [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--fail-on", "high", "--output", str(tmp_path / "out")],
        )

    assert result.exit_code != 0
    assert "scan is incomplete" in result.output


def test_fail_on_passes_a_complete_clean_scan(git_repo: Path, tmp_path: Path):
    with patch("zairo.scan.scan_graph_for_vulnerabilities", return_value=({}, _scan_usage({}))):
        result = runner.invoke(
            app,
            [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--fail-on", "high", "--output", str(tmp_path / "out")],
        )

    assert result.exit_code == 0, result.output


def _finding(severity: str, introduced) -> dict:
    return {"title": f"{severity} thing", "severity": severity, "introduced_by_change": introduced}


def test_fail_on_fails_on_a_finding_the_change_introduced(git_repo: Path, tmp_path: Path):
    vulnerabilities = {"n1": [_finding("low", True), _finding("high", True)]}
    with patch("zairo.scan.scan_graph_for_vulnerabilities", return_value=(vulnerabilities, _scan_usage({}))):
        result = runner.invoke(
            app,
            [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--fail-on", "high", "--output", str(tmp_path / "out")],
        )

    assert result.exit_code == 1
    assert "Gate failed: this change introduces a 'high' severity finding (threshold: high)." in " ".join(result.output.split())


def test_fail_on_leaves_out_findings_the_change_did_not_introduce(git_repo: Path, tmp_path: Path):
    """Already there before the change, or not marked either way: reported,
    not gated on -- and the output says how many were left out."""
    vulnerabilities = {"n1": [_finding("critical", False), _finding("high", None), _finding("low", True)]}
    output_dir = tmp_path / "out"
    with patch("zairo.scan.scan_graph_for_vulnerabilities", return_value=(vulnerabilities, _scan_usage({}))):
        result = runner.invoke(
            app,
            [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--fail-on", "high", "--output", str(output_dir)],
        )

    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    assert "Gate failed" not in output
    assert "--fail-on left out 2 finding(s) at or above high that weren't marked as introduced by this change" in output
    sarif = json.loads((output_dir / "report.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == 3  # every finding is still reported


def test_multi_repo_fail_on_counts_only_introduced_findings(make_git_repo, tmp_path: Path):
    repo_a = make_git_repo("repo_a")
    repo_b = make_git_repo("repo_b")
    scans = iter([({"n1": [_finding("high", False)]}, _scan_usage({})), ({"n1": [_finding("high", True)]}, _scan_usage({}))])

    with patch("zairo.scan.scan_graph_for_vulnerabilities", side_effect=lambda *a, **kw: next(scans)):
        result = runner.invoke(app, [str(repo_a), str(repo_b), "--fail-on", "high", "--output", str(tmp_path / "out")])

    assert result.exit_code == 1
    output = " ".join(result.output.split())
    assert "the changes introduce a 'high' severity finding across all repos" in output
    assert "--fail-on left out 1 finding(s)" in output


def test_multi_repo_fail_on_fails_when_any_repo_scan_is_incomplete(make_git_repo, tmp_path: Path):
    repo_a = make_git_repo("repo_a")
    repo_b = make_git_repo("repo_b")
    usages = iter([_scan_usage({}), _scan_usage({"n1": "boom"})])

    with patch("zairo.scan.scan_graph_for_vulnerabilities", side_effect=lambda *a, **kw: ({}, next(usages))):
        result = runner.invoke(
            app,
            [str(repo_a), str(repo_b), "--fail-on", "high", "--output", str(tmp_path / "out")],
        )

    assert result.exit_code != 0
    assert "scan is incomplete" in result.output


def test_report_html_marks_what_the_scan_assessed(git_repo: Path, tmp_path: Path):
    """End to end: the scanner's assessed_nodes has to reach report.html,
    or every symbol scanned clean reads as "Not scanned"."""
    usage = _scan_usage({})
    usage["assessed_nodes"] = ["some-node-id"]
    output_dir = tmp_path / "out"
    with patch("zairo.scan.scan_graph_for_vulnerabilities", return_value=({}, usage)):
        result = runner.invoke(app, [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--output", str(output_dir)])

    assert result.exit_code == 0, result.output
    html = (output_dir / "report.html").read_text(encoding="utf-8")
    metadata = json.loads(re.search(r"const reportMeta = (.+);", html).group(1))
    assert metadata["scanned_symbol_ids"] == ["some-node-id"]


def test_reports_say_why_a_changed_symbol_was_not_scanned(git_repo: Path, tmp_path: Path):
    """End to end: the scanner's skip reasons have to reach the reports."""
    output_dir = tmp_path / "out"

    def scan(graph_data, *args, **kwargs):
        usage = _scan_usage({})
        usage["skipped_nodes"] = {n["id"]: "only comments or blank lines changed" for n in graph_data["nodes"] if n["name"] == "vulnerable_exec"}
        return {}, usage

    with patch("zairo.scan.scan_graph_for_vulnerabilities", side_effect=scan):
        result = runner.invoke(app, [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--output", str(output_dir)])

    assert result.exit_code == 0, result.output
    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    [node] = [n for n in report["symbols"] if n["name"] == "vulnerable_exec"]
    assert node["scan_skipped"] == "only comments or blank lines changed"


def test_depth_only_shapes_the_report_not_what_the_model_sees(git_repo: Path, tmp_path: Path):
    """End to end: at --depth 0 the report's graph is just the change, and
    the model still gets the changed function's caller."""
    git = lambda *a: subprocess.run(["git", *a], cwd=git_repo, check=True, capture_output=True)
    app_py = git_repo / "app.py"
    app_py.write_text("def helper(x):\n    return x\n\ndef caller(y):\n    return helper(y)\n")
    git("add", "app.py")
    git("commit", "-q", "-m", "add app")
    app_py.write_text("def helper(x):\n    return x + 1\n\ndef caller(y):\n    return helper(y)\n")
    git("commit", "-q", "-am", "change helper")
    fake_litellm = MagicMock()
    fake_litellm.completion.return_value.choices[0].message.content = '{"vulnerabilities": []}'
    fake_litellm.completion.return_value.usage = None
    output_dir = tmp_path / "out"

    with patch("zairo.llm_scanner.litellm", fake_litellm), patch("zairo.llm_scanner._ensure_litellm", return_value=fake_litellm):
        result = runner.invoke(app, [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--depth", "0", "--no-cache", "--output", str(output_dir)])

    assert result.exit_code == 0, result.output
    prompts = [_text(call.kwargs["messages"]) for call in fake_litellm.completion.call_args_list]
    [prompt] = [p for p in prompts if "Modified Function: helper" in p]
    assert "Caller: caller\n" in prompt
    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert "caller" not in {n["name"] for n in report["symbols"]}


def test_warm_up_takes_no_scan_options(tmp_path: Path):
    """--warm-up only writes notes: a scan option would be silently ignored."""
    result = runner.invoke(app, [str(tmp_path), "--warm-up", "--from", "HEAD~1", "--to", "HEAD", "--graph-only"])

    assert result.exit_code == 1
    assert "--warm-up only writes notes, so it can't take --from, --to, --graph-only" in result.output


def _fake_llm_writing_notes(calls: list) -> MagicMock:
    """Answers note requests with "note on <function name>" and scan
    requests with no findings, recording (model, prompt) in `calls`."""
    def complete(model, messages, max_tokens):
        prompt = _text(messages)
        calls.append((model, prompt))
        response = MagicMock()
        response.usage = None
        if prompt.startswith(NOTE_INSTRUCTIONS):
            labels = re.findall(r"^=== (F\d+): (\w+)", prompt, re.M)
            response.choices[0].message.content = json.dumps({label: {"does": f"note on {name}"} for label, name in labels})
        else:
            response.choices[0].message.content = '{"vulnerabilities": []}'
        return response

    fake_litellm = MagicMock()
    fake_litellm.completion.side_effect = complete
    return fake_litellm


def test_warm_up_only_writes_notes(git_repo: Path, tmp_path: Path):
    calls = []
    fake_litellm = _fake_llm_writing_notes(calls)
    output_dir = tmp_path / "out"

    with patch("zairo.llm_scanner.litellm", fake_litellm), patch("zairo.llm_scanner._ensure_litellm", return_value=fake_litellm):
        result = runner.invoke(app, [str(git_repo), "--warm-up", "--output", str(output_dir)])

    assert result.exit_code == 0, result.output
    assert "Writing notes for 1 function(s)" in result.output
    assert "Writing notes: 1/1" in result.output  # progress, as plain lines outside a terminal
    assert "1 note(s) written, 0 failed" in result.output
    assert all(prompt.startswith(NOTE_INSTRUCTIONS) for _model, prompt in calls)
    assert sorted(p.name for p in output_dir.iterdir()) == [".notes_cache.json"]  # no reports


def test_warm_up_fails_when_it_could_write_no_notes(git_repo: Path, tmp_path: Path):
    fake_litellm = MagicMock()
    fake_litellm.completion.side_effect = RuntimeError("AuthenticationError: no API key")

    with patch("zairo.llm_scanner.litellm", fake_litellm), patch("zairo.llm_scanner._ensure_litellm", return_value=fake_litellm):
        result = runner.invoke(app, [str(git_repo), "--warm-up", "--output", str(tmp_path / "out")])

    assert result.exit_code == 1
    assert "0 note(s) written, 1 failed" in result.output
    assert "AuthenticationError" in result.output


def test_scan_shows_progress(git_repo: Path, tmp_path: Path):
    fake_litellm = _fake_llm_writing_notes([])

    with patch("zairo.llm_scanner.litellm", fake_litellm), patch("zairo.llm_scanner._ensure_litellm", return_value=fake_litellm):
        result = runner.invoke(app, [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--output", str(tmp_path / "out")])

    assert result.exit_code == 0, result.output
    assert re.search(r"Scanning: (\d+)/\1\b", result.output)  # progress, as plain lines outside a terminal
    # No warm-up ran into this --output, and the scan says so.
    assert "No --warm-up notes in" in " ".join(result.output.split())


def test_warm_up_writes_notes_with_its_model_and_the_scan_reads_them(git_repo: Path, tmp_path: Path):
    """End to end: entry -> mid -> target, where target changed. The scan
    sees mid in full and entry through the note --warm-up wrote."""
    git = lambda *a: subprocess.run(["git", *a], cwd=git_repo, check=True, capture_output=True)
    lib = git_repo / "lib.py"
    lib.write_text("def entry(req):\n    return mid(req)\n\ndef mid(x):\n    return target(x)\n\ndef target(y):\n    return y\n")
    git("add", "lib.py")
    git("commit", "-q", "-m", "add lib")
    lib.write_text("def entry(req):\n    return mid(req)\n\ndef mid(x):\n    return target(x)\n\ndef target(y):\n    return run(y)\n")
    git("commit", "-q", "-am", "change target")
    calls = []
    fake_litellm = _fake_llm_writing_notes(calls)
    output_dir = tmp_path / "out"

    with patch("zairo.llm_scanner.litellm", fake_litellm), patch("zairo.llm_scanner._ensure_litellm", return_value=fake_litellm):
        warm = runner.invoke(app, [str(git_repo), "--warm-up", "--model", "cheap-model", "--output", str(output_dir)])
        scan = runner.invoke(app, [str(git_repo), "--from", "HEAD~1", "--to", "HEAD", "--model", "big-model", "--output", str(output_dir)])

    assert warm.exit_code == 0, warm.output
    assert scan.exit_code == 0, scan.output
    assert {model for model, prompt in calls if prompt.startswith(NOTE_INSTRUCTIONS)} == {"cheap-model"}
    [scan_prompt] = [prompt for model, prompt in calls if "Modified Function: target" in prompt]
    assert re.search(r"Callers of its callers:\n<<<REPO TEXT \w+>>>\n- entry \(calls mid\): does: note on entry", scan_prompt)
    # Notes on test.py's vulnerable_exec, entry, mid and target; only entry's
    # is needed -- mid is shown in full, target is the change.
    assert "Used 1 of 4 note(s) from an earlier --warm-up" in " ".join(scan.output.split())
