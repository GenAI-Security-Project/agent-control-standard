"""Tests for the FinBot lab claims ledger and the check that holds lab text to it (issue #587, LAB-14).

Version 1.0.0. Owner: ACS lab maintainers.
"""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LABS_FINBOT = ROOT / "labs" / "finbot"
LEDGER = LABS_FINBOT / "CLAIMS.md"
MODULE = LABS_FINBOT / "cli" / "lab_claims.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("lab_claims", MODULE)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves string annotations through sys.modules, so register before executing.
    sys.modules["lab_claims"] = module
    spec.loader.exec_module(module)
    return module


lab_claims = _load_module()


def _section(name: str) -> str:
    text = LEDGER.read_text(encoding="utf-8")
    match = re.search(rf"^## {re.escape(name)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    assert match, f"CLAIMS.md has no '## {name}' section"
    return match.group(1)


def _rows(section: str) -> list[list[str]]:
    rows = []
    for line in section.splitlines():
        if line.startswith("|") and not re.match(r"^\|[\s|:]*-[\s|:-]*$", line):
            rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows[1:]


# ---------------------------------------------------------------- Task 1: the ledger


def test_ids_unique_and_sequential():
    for letter, name in (("C", "Claims"), ("N", "Not claimed")):
        ids = [r[0] for r in _rows(_section(name))]
        assert ids == [f"{letter}-{n:02d}" for n in range(1, len(ids) + 1)]
        assert len(ids) >= 12


SECTION_12_CAN_SAY = [
    "1450fc4", "FIPS 204", "forged decision", "shared HMAC key", "ClientHello", "Two of nineteen",
    "N attempts", "fixed neutral reply", "fails closed", "committed outcome", "Release 0.1.5",
    "build team's machines",
]
SECTION_12_CANT_SAY = [
    "can't tell a control exists", "attributable", "revocation is solved", "record is complete",
    "downgrade is fully prevented", "ACS-Core conformant", "stops a given attack", "reproduces a live model",
    "0.2.0 is released", "Agent Governance Toolkit", "ACS-Crypto", "outside the build team",
]


def test_section_12_rows_present():
    claims = _section("Claims")
    missing = [k for k in SECTION_12_CAN_SAY if k not in claims]
    assert not missing, f"Claims table lost section 12 rows: {missing}"
    not_claimed = _section("Not claimed")
    missing = [k for k in SECTION_12_CANT_SAY if k not in not_claimed]
    assert not missing, f"Not claimed table lost section 12 rows: {missing}"


def test_issue_claims_present():
    claims = _section("Claims")
    for key in ("v0.1.0 schemas", "on_decision_failure", "interoperability", "macOS and Linux only"):
        assert key in claims, f"Claims table lacks the claim holding {key!r}"


def test_machine_blocks_parse():
    ledger = lab_claims.load_ledger(LEDGER)
    assert ledger.banned and ledger.triggers and ledger.exclude
    assert "C-01" in ledger.ids and "N-12" in ledger.ids


def test_sign_off_row_shape():
    lines = [ln for ln in _section("Sign-off").splitlines() if ln.startswith("|")]
    assert lines[0] == "| Signed by | Date | Commit |"
    rows = [c for c in _rows(_section("Sign-off"))]
    assert len(rows) == 1 and len(rows[0]) == 3
    name, date, sha = rows[0]
    assert name == "" or name
    assert date == "" or re.fullmatch(r"\d{4}-\d{2}-\d{2}", date)
    assert sha == "" or re.fullmatch(r"[0-9a-f]{40}", sha)
