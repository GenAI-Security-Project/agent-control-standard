"""The one way the example Guardian and its OPA backend write a value that came from a request into a log line.

Kept apart from both modules so each can import it without loading the other.
"""
from __future__ import annotations

from typing import Any


def log_value(value: Any, width: int = 8) -> str:
    """The repr of a string cut to width, so no request byte can start a new line or emit an escape sequence.

    Anything else is logged only as its type name, never as a full repr.
    """
    return repr(value[:width]) if isinstance(value, str) else f"<{type(value).__name__}>"
