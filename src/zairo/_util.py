import re
from typing import Any, Dict, List, Optional

# Test code isn't part of the shipped attack surface, so it's left out of
# the graph entirely: never a changed symbol, never pulled in as a caller
# of one -- and so never shown to the model, which would otherwise review
# test scaffolding as if it were exploitable production code, or see a
# well-tested function's test callers crowd out its real ones as context.
_TEST_DIR_NAMES = {'test', 'tests', '__tests__', 'spec', 'specs'}
_TEST_STEM_PREFIXES = ('test_', 'test-')
_TEST_STEM_SUFFIXES = ('_test', '-test', '.test', '_spec', '-spec', '.spec')


def is_test_file(rel_path: str) -> bool:
    """Whether a repo-relative path is test code, by its directories or its
    file name. Relative, so a repo that happens to live under a directory
    named "tests" isn't all test code."""
    parts = re.split(r'[/\\]', rel_path)
    if any(p.lower() in _TEST_DIR_NAMES for p in parts[:-1]):
        return True
    # Strip exactly one extension so "index.test.ts" -> "index.test" (still
    # matches the ".test" suffix) without over-stripping "test_utils.py".
    stem = re.sub(r'\.[a-zA-Z0-9]+$', '', parts[-1]).lower()
    return stem.startswith(_TEST_STEM_PREFIXES) or stem.endswith(_TEST_STEM_SUFFIXES)


def display_name(name: Any, limit: int = 60) -> str:
    """Collapses a node name to one short line for log display. Some graph
    nodes (e.g. Trailmark misparsing a chained expression like
    `.map(fn).filter(...)`) end up with a "name" that's actually a chunk of
    raw multi-line source text -- printing that verbatim floods the log."""
    text = " ".join(str(name).split())
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return text


# Ordered low -> high; index doubles as a comparable rank.
SEVERITY_LEVELS = ("low", "medium", "high", "critical")
# Fail-safe, not "typical": this is what an ungradeable finding gets treated
# as, including by --fail-on. Defaulting to something in the middle would
# mean a malformed/unparseable severity from the LLM -- which says nothing
# about how bad the underlying finding actually is -- could silently slip
# under a --fail-on high/critical gate. Worst-case is the only default that
# can't cause a real vulnerability to pass CI unnoticed; it costs a
# possible false alarm in the report instead, which a human reviewing it
# can still discount.
DEFAULT_SEVERITY = "critical"
_SEVERITY_RANK = {level: i for i, level in enumerate(SEVERITY_LEVELS)}


def normalize_severity(raw: Any) -> str:
    """Coerces a (possibly missing/garbled, since it comes from LLM output)
    severity value to one of SEVERITY_LEVELS, defaulting to DEFAULT_SEVERITY
    (the worst level, not a crash) for anything unrecognized -- a gating
    decision should degrade to fail-safe, not raise over a malformed field
    or silently downgrade a finding whose real severity is simply unknown."""
    sev = str(raw).strip().lower() if raw else ""
    return sev if sev in _SEVERITY_RANK else DEFAULT_SEVERITY


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, _SEVERITY_RANK[DEFAULT_SEVERITY])


def max_severity(vulnerabilities: Dict[str, List[Dict[str, Any]]]) -> Optional[str]:
    """Highest-ranked (already-normalized) severity across all findings, or
    None if there are none."""
    best = None
    for findings in vulnerabilities.values():
        for finding in findings:
            sev = normalize_severity(finding.get("severity"))
            if best is None or severity_rank(sev) > severity_rank(best):
                best = sev
    return best


CONFIDENCE_LEVELS = ("low", "medium", "high")


def normalize_confidence(raw: Any) -> Optional[str]:
    """One of CONFIDENCE_LEVELS -- how sure the model is a finding is real,
    kept apart from how bad it would be -- or None if it didn't give a
    usable one. Unlike severity there's no fail-safe value to fall back on:
    confidence gates nothing, and guessing one would only misstate how sure
    the model actually was."""
    value = str(raw).strip().lower() if raw else ""
    return value if value in CONFIDENCE_LEVELS else None


_CWE_DIGITS_RE = re.compile(r'(\d+)')


def normalize_cwe(raw: Any) -> Optional[str]:
    """Extracts a canonical "CWE-<n>" identifier from whatever form the LLM
    gave it in ("CWE-78", "cwe:78", "78", "CWE-078 - OS Command Injection"),
    or None if it didn't give a usable one. A stable per-category id (rather
    than a free-text title) is what lets a SARIF consumer like GitHub group
    recurring findings of the same kind under one rule instead of a new one
    every time the model phrases the title slightly differently."""
    if not raw:
        return None
    match = _CWE_DIGITS_RE.search(str(raw))
    if not match:
        return None
    return f"CWE-{int(match.group(1))}"
