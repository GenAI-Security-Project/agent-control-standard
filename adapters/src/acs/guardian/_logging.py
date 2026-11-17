"""The one way the example Guardian and its OPA backend write a value that came from a request into a log line.

Kept apart from both modules so each can import it without loading the other.
"""
from __future__ import annotations

import re
from typing import Any


# C0 and C1 controls, DEL, and the Unicode line and paragraph separators: everything that can end a log line or
# start a terminal escape sequence.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _escape(match: re.Match) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def log_value(value: Any, width: int = 8) -> str:
    """A string cut to width with its control characters escaped, so no request byte can start a new line or emit
    an escape sequence. Only control characters change, so a value that already carries escaped text, such as a
    message built with !r, is escaped once, not twice. Anything else is logged only as its type name.
    """
    if not isinstance(value, str):
        return f"<{type(value).__name__}>"
    return _CONTROL.sub(_escape, value[:width])
