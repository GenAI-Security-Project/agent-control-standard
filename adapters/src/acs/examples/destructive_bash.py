"""The example Guardian's toy policy: commands that destroy a filesystem or a disk."""
from __future__ import annotations

import re

from acs.client import audit_event


DESTRUCTIVE_BASH_PATTERNS: tuple[re.Pattern, ...] = (
    # rm with r and f in one flag token (-rf, -vrf), then a path at /, ~ or $HOME.
    re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|--recursive\s+--force|--force\s+--recursive)\b.*?\s+(/|~|\$HOME)", re.IGNORECASE),
    re.compile(r"\brm\s+(-rf|-fr|--recursive\s+--force|--force\s+--recursive)\s+(/|~|\$HOME)(\s|$)", re.IGNORECASE),
    # r and f as separate flag tokens in any order; the lookaheads scan only the flags before the path.
    re.compile(r"\brm(?=(?:\s+-[a-zA-Z-]+)*\s+-(?:[a-zA-Z]*r|-recursive\b))(?=(?:\s+-[a-zA-Z-]+)*\s+-(?:[a-zA-Z]*f|-force\b))(?:\s+-[a-zA-Z-]+)+\s+(/|~|\$HOME)", re.IGNORECASE),
    re.compile(r"\brm\s+.*--no-preserve-root\b", re.IGNORECASE),
    re.compile(r"\bmkfs(\.\w+)?\s+", re.IGNORECASE),
    re.compile(r"\bdd\s+.*\bof=/dev/", re.IGNORECASE),
    re.compile(r":\(\)\s*\{"),
    re.compile(r">\s*/dev/(sd[a-z]|nvme|hd[a-z]|disk)", re.IGNORECASE),
    # The path ends at whitespace, not at a word boundary, because no boundary
    # sits between `/` or `~` and the space after it.
    re.compile(r"\bfind\s+(/|~|\$HOME)\S*\s.*-delete\b", re.IGNORECASE),
    re.compile(r"\bfind\s+(/|~|\$HOME)\S*\s.*-exec\s+rm\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+(-R\s+)?[0-7]*7{2,}[0-7]*\s+(/etc|/usr|/bin|/sbin)", re.IGNORECASE),
)


# Longer input is not a shell command, or is a regex-DoS attempt.
DESTRUCTIVE_SCAN_MAX_LEN = 8 * 1024


def scan_destructive_bash_safely(cmd: str, *, max_len: int = DESTRUCTIVE_SCAN_MAX_LEN):
    """None when nothing matches, the matching pattern, or "input_too_large", which the caller must not treat as safe."""
    if len(cmd) > max_len:
        audit_event("destructive_scan_skipped_oversized",
                    cmd_length=len(cmd), max_len=max_len)
        return "input_too_large"
    for pat in DESTRUCTIVE_BASH_PATTERNS:
        if pat.search(cmd):
            return pat
    return None


def matches_destructive_bash(cmd: str) -> str | re.Pattern | None:
    """None when safe, the matching pattern, or "too_large", which the caller must treat as suspicious."""
    if len(cmd) > DESTRUCTIVE_SCAN_MAX_LEN:
        return "too_large"
    for pat in DESTRUCTIVE_BASH_PATTERNS:
        if pat.search(cmd):
            return pat
    return None
