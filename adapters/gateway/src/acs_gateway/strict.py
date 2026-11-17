"""JSON parsing that refuses a repeated object key at any depth.

Python keeps the last of two equal keys, and other parsers keep the first. A gateway that judged one copy while the
upstream or the client read the other would gate the wrong thing, so governed modes refuse repeated keys outright.
"""
from __future__ import annotations

import json
import re
from typing import Any

_SURROGATE_ESCAPE = re.compile(r"\\u[dD][89a-fA-F][0-9a-fA-F]{2}")


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


def has_lone_surrogate(value: Any) -> bool:
    """Whether any string in a parsed JSON value, keys included, holds a lone surrogate, which UTF-8 can't encode and
    RFC 8785 can't sign. Walks iteratively, so nesting depth can't exhaust the stack."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


def request_has_lone_surrogate(body: dict[str, Any]) -> bool:
    """Whether a request body holds a lone surrogate anywhere the gateway refuses one.

    A function_call_output's output is exempt: it is tool data an attacker can plant, so it is gated per result
    (it can't be signed, so its step is refused) rather than refusing the whole request every turn. A call's
    arguments are JSON text, so a surrogate escaped inside them is found by parsing them too.
    """
    items = body.get("input")
    rest = {k: v for k, v in body.items() if k != "input"}
    if has_lone_surrogate(rest):
        return True
    for item in items if isinstance(items, list) else [items]:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            # Every key and every other field is still checked, only the output's content is exempt.
            if has_lone_surrogate({k: v for k, v in item.items() if k != "output"}):
                return True
            continue
        if has_lone_surrogate(item):
            return True
        arguments = item.get("arguments") if isinstance(item, dict) and item.get("type") == "function_call" else None
        # Parsed only when the text holds a surrogate escape (\uD800 to \uDFFF), the one way a lone surrogate can
        # hide in JSON text past the string walk above, so ordinary arguments are still parsed once per request.
        if isinstance(arguments, str) and _SURROGATE_ESCAPE.search(arguments):
            try:
                if has_lone_surrogate(loads_recording(item["arguments"])[0]):
                    return True
            except (ValueError, RecursionError):
                pass
    return False
