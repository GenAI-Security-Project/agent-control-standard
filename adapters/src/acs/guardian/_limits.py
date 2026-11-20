"""Size checks the example Guardian and its OPA backend share, kept apart so the default path loads no OPA code."""
from __future__ import annotations

from typing import Any


def depth_exceeds(value: Any, limit: int) -> bool:
    """Whether value nests deeper than limit, checked without recursion, so it never hits the recursion limit."""
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > limit:
                return True
            stack.extend((child, depth + 1) for child in (node.values() if isinstance(node, dict) else node))
    return False
