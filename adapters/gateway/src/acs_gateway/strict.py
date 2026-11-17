"""JSON parsing that refuses a repeated object key at any depth.

Python keeps the last of two equal keys, and other parsers keep the first. A gateway that judged one copy while the
upstream or the client read the other would gate the wrong thing, so governed modes refuse repeated keys outright.
"""
from __future__ import annotations

import json
from typing import Any


class DuplicateKey(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(f"repeated JSON key {key!r}")
        self.key = key


def loads_recording(text: str | bytes) -> tuple[Any, str | None]:
    """json.loads in one pass that also returns the first repeated key, or None. When a key repeats, the last copy is
    kept, as Python reads it. Raises ValueError for text that isn't JSON."""
    first: list[str] = []

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: dict[str, Any] = {}
        for key, value in items:
            if key in seen and not first:
                first.append(key)
            seen[key] = value
        return seen

    value = json.loads(text, object_pairs_hook=pairs)
    return value, first[0] if first else None


def loads_strict(text: str | bytes) -> Any:
    """json.loads, raising DuplicateKey on a repeated key anywhere in the document. Built on loads_recording, so the
    gateway has one duplicate-tracking parser."""
    value, repeated = loads_recording(text)
    if repeated is not None:
        raise DuplicateKey(repeated)
    return value


def repeated_key(text: Any) -> str | None:
    """The first repeated key in a JSON string, or None. A non-string or a string that isn't JSON has none."""
    if not isinstance(text, (str, bytes)):
        return None
    try:
        return loads_recording(text)[1]
    except (ValueError, RecursionError):
        return None
