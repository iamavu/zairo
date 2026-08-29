import re
from typing import Any, Dict, List, Optional


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
DEFAULT_SEVERITY = "medium"
_SEVERITY_RANK = {level: i for i, level in enumerate(SEVERITY_LEVELS)}


def normalize_severity(raw: Any) -> str:
    """Coerces a (possibly missing/garbled, since it comes from LLM output)
    severity value to one of SEVERITY_LEVELS, defaulting to DEFAULT_SEVERITY
    for anything unrecognized rather than raising -- a gating decision should
    degrade gracefully, not crash the scan over a malformed field."""
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
