from typing import Any


def display_name(name: Any, limit: int = 60) -> str:
    """Collapses a node name to one short line for log display. Some graph
    nodes (e.g. Trailmark misparsing a chained expression like
    `.map(fn).filter(...)`) end up with a "name" that's actually a chunk of
    raw multi-line source text -- printing that verbatim floods the log."""
    text = " ".join(str(name).split())
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return text
