"""report.html in a real browser, with the network cut off: the page has to
load everything it runs on from itself, and draw the graph, the findings
and what the run didn't cover. Needs Playwright (pip install -e .[browser])
and its Chromium (python -m playwright install chromium), or an installed
Chrome; skipped without Playwright."""
from pathlib import Path

import pytest

from zairo.reporter import generate_reports

sync_api = pytest.importorskip("playwright.sync_api")


def _report(output_dir: Path) -> str:
    graph = {
        "nodes": [
            {"id": "app", "name": "app.py", "kind": "module", "file": "app.py", "start_line": 1, "end_line": 15,
             "status": "modified"},
            {"id": "app:upload", "name": "upload", "kind": "function", "file": "app.py", "start_line": 5,
             "end_line": 9, "status": "modified"},
            {"id": "app:save", "name": "save", "kind": "function", "file": "app.py", "start_line": 12,
             "end_line": 14, "status": "added"},
            {"id": "os:system", "name": "os.system", "kind": "proxy", "file": None, "start_line": None,
             "end_line": None, "status": "unchanged"},
        ],
        "edges": [
            {"source": "app", "target": "app:upload", "kind": "contains", "confidence": "certain", "lines": []},
            {"source": "app", "target": "app:save", "kind": "contains", "confidence": "certain", "lines": []},
            {"source": "app:upload", "target": "app:save", "kind": "calls", "confidence": "certain", "lines": [7]},
            {"source": "app:save", "target": "os:system", "kind": "calls", "confidence": "certain", "lines": [13]},
        ],
    }
    findings = {"app:save": [{
        "title": "Command injection in save", "description": "User input reaches os.system.", "impact": "RCE",
        "severity": "critical", "cwe": "CWE-78", "line": 13, "introduced_by_change": True, "confidence": "high",
    }]}
    _, html_path, _ = generate_reports(
        graph, str(output_dir), findings, repo_name="demo", assessed_nodes=["app:save"],
        failed_nodes={"app:upload": "RateLimitError: slow down"},
        changed_files=[{"path": "app.py", "outcome": "analyzed"}, {"path": "deploy.yaml", "outcome": "not_parsed"}],
        problems=[{"level": "warning", "message": "Couldn't find the repo's entry points (boom)."}],
    )
    return html_path


def _launch(playwright):
    try:
        return playwright.chromium.launch()
    except sync_api.Error:  # Playwright's own Chromium isn't installed: an installed Chrome does as well
        return playwright.chromium.launch(channel="chrome")


def test_report_renders_offline(tmp_path: Path):
    html_path = _report(tmp_path / "out")
    errors, fetched = [], []

    def offline(route):
        if route.request.url.startswith("file:"):
            route.continue_()
        else:
            fetched.append(route.request.url)
            route.abort()

    with sync_api.sync_playwright() as playwright:
        browser = _launch(playwright)
        try:
            page = browser.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.route("**/*", offline)
            page.goto(Path(html_path).as_uri())

            assert "Map could not load" not in page.inner_text("#canvas-state")
            page.wait_for_selector("#cy canvas", state="attached", timeout=10_000)
            assert (errors, fetched) == ([], [])
            assert page.is_hidden("#canvas-state")
            notice = " ".join(page.inner_text("#scan-notice").split())
            assert "Incomplete: 1 changed symbol could not be assessed" in notice
            assert "Warning: Couldn't find the repo's entry points (boom)." in notice
            assert "Not reviewed: 1 changed file zairo doesn’t parse: deploy.yaml" in notice

            page.click("#results .result-item")
            details = page.inner_text("#node-details")
            assert "Command injection in save" in details
            assert "app.py" in details
        finally:
            browser.close()
