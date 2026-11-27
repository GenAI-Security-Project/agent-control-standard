"""How the lab CLI reports: one line per check, and the A.11 exit codes (issue #588, LAB-15).

Every check prints one line starting DONE or NOT YET:. Exit 0 means pass, 1 not yet, 2 the environment is broken.
Text that came from a log, a model or a file passes through escape() first, so a terminal control sequence in it
prints as visible escapes and never acts on the attendee's terminal (issue #468).
"""
from __future__ import annotations

import sys

EXIT_PASS, EXIT_NOT_YET, EXIT_BROKEN = 0, 1, 2

# Bidirectional and zero-width marks reorder or hide what a reader sees, so they are escaped like control bytes.
_INVISIBLE = {*range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2066, 0x206A), 0xFEFF}


def escape(text: str) -> str:
    """text with every C0 and C1 control, DEL and invisible mark shown as an escape. Newline and tab stay."""
    out = []
    for ch in text:
        code = ord(ch)
        if ch in "\n\t":
            out.append(ch)
        elif code < 0x20 or 0x7F <= code < 0xA0:
            out.append(f"\\x{code:02x}")
        elif code in _INVISIBLE or 0xD800 <= code < 0xE000:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def done(message: str) -> None:
    print(f"DONE: {escape(message)}")


def not_yet(message: str) -> None:
    print(f"NOT YET: {escape(message)}")


def info(message: str) -> None:
    """A line that isn't a check result, such as a fingerprint or a table row."""
    print(escape(message))


def warn(message: str) -> None:
    print(escape(message), file=sys.stderr)
