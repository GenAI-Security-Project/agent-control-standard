"""Holds the FinBot lab's text to its claims ledger (issue #587, LAB-14).

Version 1.0.0. Owner: ACS lab maintainers.

The ledger (CLAIMS.md) is Markdown for people with three fenced machine blocks. This module parses it and
scans a tree. It is stdlib only so the root test suite and the lab wrapper can both load it by path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ID_ROW = re.compile(r"^\|\s*([CN]-\d{2})\s*\|", re.M)
SIGN_HEADER = "| Signed by | Date | Commit |"
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SHA = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class Ledger:
    ids: frozenset[str]
    banned: tuple[str, ...]
    triggers: tuple[str, ...]
    exclude: tuple[str, ...]
    signed: bool


def _block(text: str, tag: str) -> tuple[str, ...]:
    match = re.search(rf"^```{tag}\n(.*?)^```", text, re.S | re.M)
    if not match:
        raise ValueError(f"the ledger has no {tag} block")
    lines = tuple(ln.strip() for ln in match.group(1).splitlines() if ln.strip())
    if not lines:
        raise ValueError(f"the ledger's {tag} block is empty")
    return lines


def _signed(text: str) -> bool:
    lines = text.splitlines()
    if SIGN_HEADER not in lines:
        raise ValueError(f"the ledger's sign-off table lacks the header {SIGN_HEADER!r}")
    rows = [ln for ln in lines[lines.index(SIGN_HEADER) + 2:] if ln.startswith("|")]
    if len(rows) != 1:
        raise ValueError("the ledger's sign-off table must hold exactly one row")
    cells = [c.strip() for c in rows[0].strip().strip("|").split("|")]
    if len(cells) != 3:
        raise ValueError("the sign-off row must have three cells")
    name, date, sha = cells
    if (date and not DATE.fullmatch(date)) or (sha and not SHA.fullmatch(sha)):
        raise ValueError("the sign-off row holds a malformed date or commit")
    return bool(name and date and sha)


def load_ledger(path: Path) -> Ledger:
    """Parse the ledger. Raises OSError when unreadable and ValueError when malformed."""
    text = Path(path).read_text(encoding="utf-8")
    return Ledger(
        ids=frozenset(ID_ROW.findall(text)),
        banned=_block(text, "claims-banned"),
        triggers=_block(text, "claims-triggers"),
        exclude=_block(text, "claims-exclude"),
        signed=_signed(text),
    )
