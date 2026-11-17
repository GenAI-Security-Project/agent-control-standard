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


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise DuplicateKey(key)
        seen[key] = value
    return seen


def loads_strict(text: str | bytes) -> Any:
    """json.loads, raising DuplicateKey on a repeated key anywhere in the document."""
    return json.loads(text, object_pairs_hook=_pairs)


def repeated_key(text: Any) -> str | None:
    """The first repeated key in a JSON string, or None. A non-string or a string that isn't JSON has none."""
    if not isinstance(text, (str, bytes)):
        return None
    try:
        loads_strict(text)
    except DuplicateKey as e:
        return e.key
    except (ValueError, RecursionError):
        return None
    return None
