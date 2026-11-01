"""The example Guardian's toy policy: commands that destroy a filesystem or a disk, found with bounded regex scans."""
from __future__ import annotations

import re

from acs.client import audit_event


# ----- Destructive-Bash regex set -----

DESTRUCTIVE_BASH_PATTERNS: tuple[re.Pattern, ...] = (
    # `rm` + a flag token containing both r and f with other letters
    # anywhere (-rf, -rfv, -vrf, ...), then a path starting `/`, `~`,
    # or `$HOME`; the trailing [a-zA-Z]* keeps `-rfv` matching.
    re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|--recursive\s+--force|--force\s+--recursive)\b.*?\s+(/|~|\$HOME)", re.IGNORECASE),
    re.compile(r"\brm\s+(-rf|-fr|--recursive\s+--force|--force\s+--recursive)\s+(/|~|\$HOME)(\s|$)", re.IGNORECASE),
    # Recursive and force given as separate flag tokens in any order (`rm -r -f /`,
    # `rm -f -R ~`). The lookaheads only scan the flag tokens before the path.
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


# Maximum command string length to scan with destructive-pattern regexes.
# Real shell commands are tiny; longer inputs are either non-shell data
# routed through the wrong tool or a regex-DoS attempt.
DESTRUCTIVE_SCAN_MAX_LEN = 8 * 1024  # 8 KiB

# ----- Bounded regex scanning (defends against regex DoS / input bombing) -----

def scan_destructive_bash_safely(cmd: str, *, max_len: int = DESTRUCTIVE_SCAN_MAX_LEN):
    """Run destructive-pattern regex scanning ONLY if cmd is below max_len.

    Returns:
      None — command is short and matched no destructive pattern
      a re.Pattern — command matched (caller decides what to do)
      "input_too_large" — command exceeds max_len; caller MUST treat as
        suspicious and MUST NOT silently allow (skipping the scan is
        not the same as the scan returning "safe").

    Scans with DESTRUCTIVE_BASH_PATTERNS above, the one canonical pattern set.
    """
    if len(cmd) > max_len:
        audit_event("destructive_scan_skipped_oversized",
                    cmd_length=len(cmd), max_len=max_len)
        return "input_too_large"
    for pat in DESTRUCTIVE_BASH_PATTERNS:
        if pat.search(cmd):
            return pat
    return None


def matches_destructive_bash(cmd: str) -> str | re.Pattern | None:
    """Returns:
      None         — safe (no destructive pattern matched)
      re.Pattern   — a destructive pattern matched
      "too_large"  — input exceeds the regex-scan cap; caller MUST treat
                     as suspicious (we don't know if it's destructive).

    The 8 KiB cap defends against regex DoS via crafted huge commands.
    """
    if len(cmd) > DESTRUCTIVE_SCAN_MAX_LEN:
        return "too_large"
    for pat in DESTRUCTIVE_BASH_PATTERNS:
        if pat.search(cmd):
            return pat
    return None
