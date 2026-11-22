"""Tests for the FinBot lab claims ledger and the check that holds lab text to it (issue #587, LAB-14).

Version 1.6.0. Owner: ACS lab maintainers.
"""

import concurrent.futures
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
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
    "fixed neutral reply", "fails closed", "committed outcome", "Release 0.1.5",
]
SECTION_12_CANT_SAY = [
    "hidden from the agent", "attributable", "revocation is solved", "record is complete",
    "downgrade is fully prevented", "ACS-Core conformant", "reproduces a live model",
    "0.2.0 is released", "Agent Governance Toolkit", "ACS-Crypto",
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
    assert lines[0] == "| Signed by | Date | Commit | Ledger sha256 |"
    rows = [c for c in _rows(_section("Sign-off"))]
    assert len(rows) == 1 and len(rows[0]) == 4
    name, date, sha, digest = rows[0]
    assert name == "" or name
    assert digest == "" or re.fullmatch(r"[0-9a-f]{64}", digest)
    assert date == "" or re.fullmatch(r"\d{4}-\d{2}-\d{2}", date)
    assert sha == "" or re.fullmatch(r"[0-9a-f]{40}", sha)


# ---------------------------------------------------------------- Task 2: the checker


@pytest.fixture
def tree(tmp_path):
    """A scanned directory and a copy of the real ledger beside it, outside the scanned tree."""
    root = tmp_path / "lab"
    root.mkdir()
    ledger = tmp_path / "CLAIMS.md"
    ledger.write_text(LEDGER.read_text(encoding="utf-8"), encoding="utf-8")
    return root, ledger


def _scan(tree, files: dict[str, str | bytes]):
    root, ledger = tree
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            path.write_bytes(body)
        else:
            path.write_text(body, encoding="utf-8")
    return lab_claims.scan(root, lab_claims.load_ledger(ledger))


def _kinds(findings):
    return sorted(f.kind for f in findings)


def test_planted_banned_phrase_fails(tree):
    findings = _scan(tree, {"a.md": "The lab is ACS-Core conformant.\n"})
    assert "banned" in _kinds(findings)
    assert findings[0].line == 1 and findings[0].path == "a.md"


def test_planted_unlisted_claim_fails(tree):
    findings = _scan(tree, {"a.md": "ACS prevents every exfiltration.\n"})
    assert _kinds(findings) == ["unledgered"]


def test_unknown_marker_id_fails(tree):
    findings = _scan(tree, {"a.md": "Fine text. <!-- claim:C-99 -->\n"})
    assert _kinds(findings) == ["unknown_id"]


def test_marked_claim_passes(tree):
    assert _scan(tree, {"a.md": "ACS prevents every exfiltration. <!-- claim:C-03 -->\n"}) == []


def test_banned_phrase_allowed_with_n_marker(tree):
    assert _scan(tree, {"a.md": "The stack isn't ACS-Core conformant. <!-- claim:N-06 -->\n"}) == []


def test_banned_phrase_with_c_marker_still_fails(tree):
    findings = _scan(tree, {"a.md": "The stack is ACS-Core conformant. <!-- claim:C-03 -->\n"})
    assert "banned" in _kinds(findings)


def test_ledger_is_not_scanned(tree):
    root, ledger = tree
    copy = root / "CLAIMS.md"
    copy.write_text(ledger.read_text(encoding="utf-8"), encoding="utf-8")
    assert lab_claims.scan(root, lab_claims.load_ledger(ledger)) == []
    # With an exclusion list that doesn't name it, the ledger file is still skipped by identity.
    bare = lab_claims.Ledger(ids=frozenset({"C-01"}), banned=("ACS-Crypto",), triggers=("prove",), exclude=("zz",),
                             signed=False)
    assert lab_claims.scan(root, bare, ledger_path=copy) == []


def test_exclusions_honored(tree):
    assert _scan(tree, {"state/run/a.md": "ACS-Core conformant\n", "x/y/z.lock": "ACS-Core conformant\n"}) == []


def test_phrase_split_across_wrapped_lines_fails(tree):
    findings = _scan(tree, {"a.md": "The lab is acs-core\nConformant, they said.\n"})
    assert "banned" in _kinds(findings)
    assert findings[0].line == 1


def test_word_boundary(tree):
    assert _scan(tree, {"a.md": "pagtest and AGTs\n"}) == []
    assert "banned" in _kinds(_scan(tree, {"b.md": "The AGT project.\n"}))


def test_triggers_skip_fenced_code(tree):
    assert _scan(tree, {"a.md": "```\nlab verify\n```\n"}) == []
    assert "banned" in _kinds(_scan(tree, {"b.md": "```\nACS-Core conformant\n```\n"}))


def test_trigger_matches_word_start_only(tree):
    assert _scan(tree, {"a.md": "We improve things and approve plans.\n"}) == []


def test_non_markdown_is_checked_per_line(tree):
    # Round 4: code is no longer scanned, so the per-line path is plain text.
    findings = _scan(tree, {"a.txt": "fine\nACS-Crypto here\n"})
    assert [(f.kind, f.line) for f in findings] == [("banned", 2)]


def test_scan_outside_repo_skips_binaries(tree):
    findings = _scan(tree, {
        "clip.mp4": b"ACS-Core conformant",
        "blob.txt": b"ACS-Core conformant\x00\x01",
        "latin.md": "Caf\xe9 is ACS-Core conformant\n".encode("latin-1"),
    })
    # Round 2 of the final review: a prose file that isn't UTF-8 is named as undecodable, not read with holes.
    assert findings == []
    root, ledger = tree
    skips = lab_claims._scan(root, lab_claims.load_ledger(ledger), None)[2]
    assert sorted((f.path, f.kind) for f in skips) == [("blob.txt", "undecodable"), ("latin.md", "undecodable")]


def test_symlink_not_followed(tree):
    root, ledger = tree
    outside = ledger.parent / "outside"
    outside.mkdir()
    (outside / "a.md").write_text("ACS-Core conformant\n", encoding="utf-8")
    (root / "link").symlink_to(outside, target_is_directory=True)
    (root / "flink.md").symlink_to(outside / "a.md")
    assert lab_claims.scan(root, lab_claims.load_ledger(ledger)) == []


def test_finding_text_is_escaped(tree):
    findings = _scan(tree, {"a.md": "ACS-Core conformant ‮\x1b[31m\n"})
    assert findings and "‮" not in findings[0].text and "\x1b" not in findings[0].text


def test_windows_named_as_supported_fails(tree):
    assert "banned" in _kinds(_scan(tree, {"a.md": "The lab supports Windows.\n"}))
    # The first call's file stays in the tree, so only b.md is judged here.
    assert [f for f in _scan(tree, {"b.md": "Windows is untested. <!-- claim:C-16 -->\n"}) if f.path == "b.md"] == []


def _sign(ledger, text=None):
    """Sign a ledger copy the way Rock would: the digest covers everything above the sign-off section."""
    body = text if text is not None else ledger.read_text(encoding="utf-8")
    digest = lab_claims.ledger_digest(body)
    ledger.write_text(body.replace("| | | | |", f"| Rock Lambros | 2026-11-30 | {'a' * 40} | {digest} |"),
                      encoding="utf-8")


def test_require_signed(tree, capsys):
    root, ledger = tree
    (root / "ok.md").write_text("Plain text.\n", encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "NOT YET" in capsys.readouterr().out
    # Signed and with every row confirmed, the gate opens.
    _sign(ledger, ledger.read_text(encoding="utf-8").replace("Unconfirmed:", "Confirmed:"))
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 0
    assert capsys.readouterr().out.startswith("DONE: lab text holds to the ledger (1 files)")


def test_require_signed_refuses_unconfirmed_rows(tree, capsys):
    root, ledger = tree
    _sign(ledger)
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    out = capsys.readouterr().out
    for row in ("C-08",):
        assert f"unconfirmed {row}" in out
    assert "unsigned" not in out
    # Without the flag the same ledger is fine, since CI runs before Rock decides.
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 0


def test_unconfirmed_rows_parsed(tree):
    _, ledger = tree
    assert lab_claims.load_ledger(ledger).unconfirmed == ("C-08",)


def test_main_exit_codes(tree, tmp_path):
    root, ledger = tree
    assert lab_claims.main([str(tmp_path / "missing"), "--ledger", str(ledger)]) == 2
    bad = tmp_path / "bad.md"
    bad.write_text("# no blocks\n", encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(bad)]) == 2
    (root / "a.md").write_text("ACS-Core conformant\n", encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 1


# ---------------------------------------------------------------- Task 3: the lab directory in CI


def test_lab_text_holds_to_the_ledger(capsys):
    code = lab_claims.main([str(LABS_FINBOT), "--ledger", str(LEDGER)])
    out = capsys.readouterr().out
    assert code == 0, out


# ---------------------------------------------------------------- Fix round 2


@pytest.mark.parametrize("body", [
    "The lab is **ACS-Core** conformant.\n",
    "The lab is ACS-Core *conformant*.\n",
    "The lab is `ACS-Core` conformant.\n",
    "The lab is [ACS-Core](x) conformant.\n",
    "The lab is ACS-Co**re conformant**.\n",
    "The lab is ACS\u2013Core conformant.\n",
    "The lab is ACS\u2011Core conformant.\n",
    "The lab is ACS-Core\u200b conformant.\n",
    "The agent can\u2019t tell a control exists.\n",
    "The lab is ACS-Core&nbsp;conformant.\n",
    "The lab is ACS-Core\u00a0conformant.\n",
    "The lab is \uff21CS-Core conformant.\n",
    "THE LAB IS ACS-CORE CONFORMANT.\n",
    "The lab is ~~ACS-Core~~ conformant.\n",
    "The lab is ACS-Core conformant. <!-- claim:C-03 -->\n",
    "The lab is **ACS-Core** conformant. <!-- claim:C-03 -->\n",
])
def test_banned_phrase_survives_markup(tree, body):
    assert "banned" in _kinds(_scan(tree, {"a.md": body}))


def test_markup_does_not_hide_a_trigger(tree):
    assert _kinds(_scan(tree, {"a.md": "ACS **guarantees** safety.\n"})) == ["unledgered"]
    split = [f for f in _scan(tree, {"b.md": "Decisions are signed\nwith ML-DSA-65.\n"}) if f.path == "b.md"]
    assert [f.kind for f in split] == ["unledgered"]


def test_honest_negative_survives_markup(tree):
    assert _scan(tree, {"a.md": "The stack isn\u2019t **ACS-Core** conformant. <!-- claim:N-06 -->\n"}) == []


def test_marker_in_a_comment_counts(tree):
    # A marker counts only from a real comment node, with or without spaces inside the delimiters.
    assert _scan(tree, {"a.md": "ACS guarantees nothing. <!--claim:C-03-->\n"}) == []


def test_marker_clears_only_its_list_item(tree):
    findings = _scan(tree, {"a.md": "- The stack isn't AGT. <!-- claim:N-10 -->\n- The stack is ACS-Core conformant.\n"
                                    "- ACS guarantees safety.\n"})
    assert sorted((f.line, f.kind) for f in findings) == [(2, "banned"), (3, "unledgered")]


def test_marker_clears_only_its_table_row(tree):
    body = "| a | b |\n|---|---|\n| ok | <!-- claim:N-06 --> |\n| The lab is ACS-Core conformant | x |\n"
    assert [(f.line, f.kind) for f in _scan(tree, {"a.md": body})] == [(4, "banned")]


def test_marker_clears_only_its_heading(tree):
    findings = _scan(tree, {"a.md": "# ACS guarantees safety\nNext line. <!-- claim:C-03 -->\n"})
    assert [(f.line, f.kind) for f in findings] == [(1, "unledgered")]


def test_wrapped_list_item_stays_one_unit(tree):
    assert _scan(tree, {"a.md": "- The stack isn't ACS-Core\n  conformant. <!-- claim:N-06 -->\n"}) == []


def test_windows_is_a_trigger(tree):
    assert _kinds(_scan(tree, {"a.md": "Run it on Windows.\n"})) == ["unledgered"]


def test_windows_mention_with_marker_passes(tree):
    root, ledger = tree
    (root / "b.md").write_text("Windows is untested. <!-- claim:C-16 -->\n", encoding="utf-8")
    assert lab_claims.scan(root, lab_claims.load_ledger(ledger)) == []


def test_fifo_does_not_hang(tree):
    import os
    root, ledger = tree
    os.mkfifo(root / "pipe.md")
    (root / "a.md").write_text("Plain.\n", encoding="utf-8")
    assert lab_claims.scan(root, lab_claims.load_ledger(ledger)) == []


def test_unclosed_fence_is_code_to_the_end(tree):
    # Round 8: CommonMark, and so GitHub, runs an unclosed fence to the end of the file. Triggers are exempt in code,
    # and a banned phrase is still caught.
    assert _scan(tree, {"a.md": "```\nx\n\nACS guarantees every attack is stopped.\n"}) == []
    assert _kinds(_scan(tree, {"b.md": "```\nx\n\nThe lab is ACS-Core conformant.\n"})) == ["banned"]


def test_fence_closes_only_on_its_own_marker(tree):
    # A backtick line doesn't close a tilde fence, so the trigger after it is still inside the code block.
    assert _scan(tree, {"a.md": "~~~\n```\nACS guarantees safety.\n"}) == []
    assert _kinds(_scan(tree, {"b.md": "~~~\n```\n~~~\nACS guarantees safety.\n"})) == ["unledgered"]


def test_file_count_counts_scanned_files_only(tree, capsys):
    root, ledger = tree
    (root / "a.md").write_text("Plain.\n", encoding="utf-8")
    (root / "clip.mp4").write_bytes(b"x\x00")
    # A prose file that isn't text fails the run since the final review (test_r1_*), so only a non-prose binary here.
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 0
    assert "(1 files)" in capsys.readouterr().out


def _evidence_ledger(tree, evidence_cell: str) -> Path:
    root, ledger = tree
    text = ledger.read_text(encoding="utf-8").replace("Unconfirmed:", "Confirmed:")
    text = re.sub(r"(\| C-15 \| [^|]*\| )[^|]*(\|)", lambda m: m.group(1) + evidence_cell + " " + m.group(2), text)
    _sign(ledger, text)
    return ledger


@pytest.mark.parametrize("cell", ["", "TBD", "todo", "TODO later"])
def test_sign_gate_refuses_empty_or_placeholder_evidence(tree, capsys, cell):
    root, _ = tree
    ledger = _evidence_ledger(tree, cell)
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "unconfirmed C-15" in capsys.readouterr().out


def test_sign_gate_matches_unconfirmed_in_any_case(tree, capsys):
    root, _ = tree
    ledger = _evidence_ledger(tree, "UNCONFIRMED until the cut")
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "unconfirmed C-15" in capsys.readouterr().out
    ledger = _evidence_ledger(tree, "Not yet unconfirmed")
    assert "C-15" in lab_claims.load_ledger(ledger).unconfirmed


def test_sign_gate_refuses_a_ledger_with_no_claim_rows(tree, capsys):
    root, ledger = tree
    text = "\n".join(ln for ln in ledger.read_text(encoding="utf-8").splitlines() if not ln.startswith("| C-"))
    _sign(ledger, text)
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "no_claims" in capsys.readouterr().out


def test_cells_honor_escaped_pipes(tree):
    root, ledger = tree
    before = ledger.read_text(encoding="utf-8")
    text = before.replace("| `labs/finbot/compose.yaml:48-57`", "| ok a\\| b `labs/finbot/compose.yaml:48-57`", 1)
    assert text != before
    ledger.write_text(text, encoding="utf-8")
    # An escaped pipe keeps the evidence cell whole, so its first path is still read as evidence.
    assert ("C-01", "labs/finbot/compose.yaml") in lab_claims.load_ledger(ledger).evidence


def test_edit_after_signing_reads_as_unsigned(tree, capsys):
    root, ledger = tree
    _sign(ledger, ledger.read_text(encoding="utf-8").replace("Unconfirmed:", "Confirmed:"))
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 0
    capsys.readouterr()
    ledger.write_text(ledger.read_text(encoding="utf-8").replace("macOS and Linux only", "every platform"),
                      encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "changed after it was signed" in capsys.readouterr().out


def test_edit_below_the_digest_boundary_keeps_the_signature(tree):
    root, ledger = tree
    _sign(ledger, ledger.read_text(encoding="utf-8").replace("Unconfirmed:", "Confirmed:"))
    ledger.write_text(ledger.read_text(encoding="utf-8").replace("The signer fills in", "The signer will fill in"),
                      encoding="utf-8")
    assert lab_claims.load_ledger(ledger).signed


def test_digest_flag_prints_the_digest(tree, capsys):
    root, ledger = tree
    assert lab_claims.main(["--ledger", str(ledger), "--digest"]) == 0
    assert capsys.readouterr().out.strip() == lab_claims.ledger_digest(ledger.read_text(encoding="utf-8"))


def test_ledger_truth_rows():
    claims = _section("Claims")
    rows = {r[0]: r for r in _rows(claims)}
    assert "4 of the 7" in _section("Not claimed") and "sessionEnd" in rows["C-06"][1] + rows["C-06"][2]
    assert "enforce" in rows["C-09"][1] and "shadow" in (rows["C-09"][1] + rows["C-09"][3]).lower()
    assert "enforce" in rows["C-14"][1]
    # The pin is lab verify's, from .env, and the compose file sets none, so the gateway and the viewer run unpinned.
    assert "can pin" in rows["C-03"][1] and "unconfirmed" not in rows["C-03"][2].lower()
    assert "`labs/finbot/modules/checks/evidence.py:231-251`" in rows["C-03"][2] and "check no fingerprint" in rows["C-03"][2]
    assert "_response_signing.py" in rows["C-02"][2]
    assert "digest" in _section("What the tests enforce and what only a reader catches")
    assert "plain-text file" in _section("What the tests enforce and what only a reader catches")


# ---------------------------------------------------------------- Fix round 3


def test_n_marker_excuses_only_its_own_phrases(tree):
    body = "The lab isn't ACS-Core conformant and isn't FIPS 140 validated. <!-- claim:N-06 -->\n"
    findings = _scan(tree, {"a.md": body})
    assert [(f.kind, f.line) for f in findings] == [("banned", 1)]
    both = "The lab isn't ACS-Core conformant and isn't FIPS 140 validated. <!-- claim:N-06 claim:N-13 -->\n"
    assert [f for f in _scan(tree, {"b.md": both}) if f.path == "b.md"] == []


def test_n_marker_for_another_row_does_not_excuse(tree):
    assert "banned" in _kinds(_scan(tree, {"a.md": "The stack is ACS-Core conformant. <!-- claim:N-01 -->\n"}))


def test_every_not_claimed_row_names_banned_phrases(tree):
    root, ledger = tree
    loaded = lab_claims.load_ledger(ledger)
    named = dict(loaded.excuses)
    # A retired row keeps its id and names no phrase (Rock, 2026-11-22).
    not_claimed = [i for i in loaded.ids if i.startswith("N-") and i not in ("N-07", "N-12")]
    assert sorted(named) == sorted(not_claimed)
    assert all(phrases for phrases in named.values())
    banned = {p.lower() for p in loaded.banned}
    assert all(p.lower() in banned for phrases in named.values() for p in phrases)


def test_ledger_with_an_unmapped_not_claimed_row_is_unreadable(tree, tmp_path):
    root, ledger = tree
    ledger.write_text(ledger.read_text(encoding="utf-8").replace("N-06: ", "N-99: ", 1), encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 2


def test_plain_text_marker_does_not_mark(tree):
    assert "banned" in _kinds(_scan(tree, {"a.md": "The lab is ACS-Core conformant. claim:N-06\n"}))
    assert [f.kind for f in _scan(tree, {"b.md": "ACS guarantees safety. claim:C-03\n"}) if f.path == "b.md"] == [
        "unledgered"]


def test_plain_text_marker_id_is_not_checked(tree):
    assert _scan(tree, {"a.md": "Write markers as claim:C-99 in a comment.\n"}) == []


@pytest.mark.parametrize("name,body", [
    ("a.md", "The lab is <b>ACS-Core</b> conformant.\n"),
    ("b.md", "The lab is ACS-<i>Core</i> conformant.\n"),
    ("c.html", "<p>The lab is <b>ACS-Core</b> conformant.</p>\n"),
    ("d.html", "<p>ACS-<span class=\"x\">Core</span> conformant</p>\n"),
    ("e.md", "The lab is <a href=\"x\">ACS-Core</a> conformant.\n"),
])
def test_html_tags_do_not_hide_a_banned_phrase(tree, name, body):
    assert "banned" in _kinds(_scan(tree, {name: body}))


def test_html_tags_do_not_hide_a_trigger(tree):
    assert _kinds(_scan(tree, {"a.html": "<p>ACS <em>prevents</em> leaks.</p>\n"})) == ["unledgered"]


def test_comment_text_is_still_matched(tree):
    assert "banned" in _kinds(_scan(tree, {"a.md": "<!-- The lab is ACS-Core conformant -->\n"}))


# ---------------------------------------------------------------- Fix round 4: match rendered text
#
# Every reviewer probe from rounds 1 to 3 is a case here. Markdown is rendered with Python-Markdown and both
# Markdown and HTML are read as the HTML a person sees, so the parser decides fences, escapes and comments.

MARK_C = " <!-- claim:C-13 -->"

CAUGHT = [
    # Round 1 and 2 probes.
    ("bold_split.md", "The lab is **ACS-Core** conformant.\n"),
    ("ital.md", "The lab is ACS-Core *conformant*.\n"),
    ("code.md", "The lab is `ACS-Core` conformant.\n"),
    ("link.md", "The lab is [ACS-Core](x) conformant.\n"),
    ("intraword.md", "The lab is ACS-Co**re conformant**.\n"),
    ("endash.md", "The lab is ACS–Core conformant.\n"),
    ("space.md", "The lab is ACS Core conformant.\n"),
    ("zwsp.md", "The lab is ACS-Core​ conformant.\n"),
    ("curly.md", "The agent can’t tell a control exists.\n"),
    ("html_split.html", "<p>The lab is ACS-Core\nconformant</p>\n"),
    ("html_entity.html", "<p>The lab is ACS-Core&nbsp;conformant</p>\n"),
    ("anyN.md", "The lab is ACS-Core conformant and FIPS 140 validated. <!-- claim:N-01 -->\n"),
    ("visible_marker.md", "The lab is ACS-Core conformant. claim:N-06\n"),
    # Round 8: CommonMark runs an unclosed fence to the end of the file, so GitHub shows the rest as code. A banned
    # phrase there is still caught (test_unclosed_fence_is_code_to_the_end).
    ("lower_marker.md", "ACS guarantees safety. <!-- claim:c-03 -->\n"),
    ("heading.md", "# ACS guarantees safety\nNext line. <!-- claim:C-03 -->\n"),
    ("wrapped.md", "The lab is ACS-Core\n  conformant.\n"),
    ("trig_split.md", "Decisions are signed\nwith ML-DSA-65.\n"),
    ("unicode_hyphen.md", "The lab is ACS‑Core conformant.\n"),
    ("fullwidth.md", "The lab is ＡCS-Core conformant.\n"),
    ("py_split.txt", "x = 'ACS-Core '\\\n    'conformant'\n"),
    ("win1.md", "The lab is supported on Windows.\n"),
    ("win2.md", "Windows support: yes.\n"),
    ("win3.md", "It also runs fine on Windows 11.\n"),
    ("bold_C.md", "The lab is **ACS-Core** conformant. <!-- claim:C-13 -->\n"),
    ("agt_em.md", "Benchmarked with the Agent *Governance* Toolkit.\n"),
    ("invis.md", "The control is invisible to the *agent*.\n"),
    ("indep.md", "The lab was independently **tested**.\n"),
    ("prod.md", "The gateway is production-*ready*.\n"),
    ("stops.md", "ACS stops **attacks**.\n"),
    ("html_agt.html", "<p>Works with the Agent Governance\nToolkit</p>\n"),
    ("html_win.html", "<li>The lab runs on\nWindows</li>\n"),
    ("md_win_em.md", "The lab runs on *Windows*.\n"),
    ("revocation.md", "Revocation is *solved*.\n"),
    ("blocks.md", "The Guardian blocks **every** exfiltration.\n"),
    # Round 3 probes: normalization.
    ("nested_em.md", "The lab is ***ACS-Core*** conformant.\n"),
    ("nested_em2.md", "The lab is **_ACS-Core_** ~~not~~ conformant.\n"),
    ("ent_dec.md", "The lab is ACS&#45;Core conformant.\n"),
    ("ent_hex_letter.md", "The lab is &#x41;CS-Core conformant.\n"),
    ("ent_shy.md", "The lab is ACS-Co&shy;re conformant.\n"),
    ("ent_zwsp.md", "Production&ZeroWidthSpace;-ready gateway.\n"),
    ("ent_hyphen.md", "The lab is ACS&hyphen;Core conformant.\n"),
    ("ref_link.md", "The lab is [ACS-Core][1] conformant.\n\n[1]: https://example.com\n"),
    ("ref_short.md", "The lab is [ACS-Core] conformant.\n\n[ACS-Core]: https://example.com\n"),
    ("ref_collapsed.md", "The lab is [ACS-Core][] conformant.\n\n[ACS-Core]: https://example.com\n"),
    ("link_title_parens.md", "The lab is [ACS-Core](https://x.example/a_(b)) conformant.\n"),
    ("image_alt.md", "The lab is ![ACS-Core](x.png) conformant.\n"),
    ("autolink.md", "Pinned at <https://example.com> and production-ready.\n"),
    ("tag_split.md", "The lab is ACS-Co<span></span>re conformant.\n"),
    ("tag_wrap.md", "The lab is ACS-Co<b>re</b> conformant.\n"),
    ("tag_attr_gt.md", "The lab is ACS-Co<span title=\"a>b\">re conformant.\n"),
    ("br_join.md", "Works with the Agent Governance<br>Toolkit.\n"),
    ("br_join.html", "<p>Works with the Agent Governance<br>Toolkit</p>\n"),
    ("td_join.html", "<td>production</td><td>-ready</td>\n"),
    ("md_escape_dash.md", "The lab is ACS\\-Core conformant.\n"),
    ("md_escape_prod.md", "The gateway is production\\-ready.\n"),
    ("md_escape_dot.md", "Version 0\\.2\\.0 is released.\n"),
    ("md_escape_apos.md", "The agent can\\'t tell a control exists.\n"),
    ("combining_cgj.md", "The gateway is produc͏tion-ready.\n"),
    ("variation_sel.md", "The gateway is produc️tion-ready.\n"),
    ("hangul_filler.md", "The lab is ACS-Coreㅤconformant.\n"),
    ("trig_cgj.md", "ACS gua͏rantees safety.\n"),
    ("trig_vs.md", "ACS gua️rantees safety.\n"),
    # Round 3 probes: fences, units and markers.
    ("fence_marker.md", "```\nThe lab is ACS-Core conformant. <!-- claim:N-06 -->\n```\n"),
    ("fence_indented4.md", "Intro.\n\n    ```\nACS guarantees every attack is stopped.\n\n    ```\n"),
    ("fence_shorter_close.md", "````\n```\n````\nACS guarantees safety.\n"),
    ("quote_list.md", "> - Keys are verified. <!-- claim:C-03 -->\n> - ACS guarantees safety.\n"),
    ("html_list.md", "<ul>\n<li>Keys are verified. <!-- claim:C-03 --></li>\n<li>ACS guarantees safety.</li>\n</ul>\n"),
    ("quote_table.md", "> | a | b |\n> |---|---|\n> | ok <!-- claim:C-03 --> | x |\n> | ACS guarantees safety | y |\n"),
    ("R1_other_phrase.md", "The lab is ACS-Core conformant and production-ready. <!-- claim:N-06 -->\n"),
    ("R1_two_markers_one_comment.md", "Not ACS-Core conformant or FIPS 140 validated. <!-- claim:N-06 claim:N-01 -->\n"),
    ("R2_code_span.md", "The lab is ACS-Core conformant. `<!-- claim:N-06 -->`\n"),
    ("R2_escaped_comment.md", "The lab is ACS-Core conformant. \\<!-- claim:N-06 -->\n"),
    ("R2_entity_comment.md", "The lab is ACS-Core conformant. &lt;!-- claim:N-06 --&gt;\n"),
    ("R2_code_span_c.md", "ACS guarantees safety. `<!-- claim:C-03 -->`\n"),
    ("R3_comment_hides.md", "<!--\n\nFinBot is production-ready.\n\n-->\n"),
    ("R3_marker_comment_holds_phrase.md", "Keys are verified. <!-- claim:C-03 production-ready -->\n"),
    ("win_bare.md", "Windows.\n"),
    ("win_lower.md", "the windows build.\n"),
    # Round 3 probes: a banned phrase the old normalizer missed, with a claim marker added for the trigger.
    ("ref_link_c.md", "The lab is [ACS-Core][1] conformant." + MARK_C + "\n\n[1]: https://example.com\n"),
    ("ref_short_c.md", "The lab is [ACS-Core] conformant." + MARK_C + "\n\n[ACS-Core]: https://example.com\n"),
    ("link_parens_c.md", "The lab is [ACS-Core](https://x.example/a_(b)) conformant." + MARK_C + "\n"),
    ("tag_attr_gt_c.md", "The lab is ACS-Co<span title=\"a>b\">re conformant." + MARK_C + "\n"),
    ("md_escape_dash_c.md", "The lab is ACS\\-Core conformant." + MARK_C + "\n"),
    ("cgj_c.md", "The lab is ACS-Co͏re conformant." + MARK_C + "\n"),
    ("vs16_c.md", "The lab is ACS-Co️re conformant." + MARK_C + "\n"),
    ("hangul_filler_c.md", "The lab is ACS-Coreㅤconformant." + MARK_C + "\n"),
    ("braille_blank_c.md", "The lab is ACS-Core⠀conformant." + MARK_C + "\n"),
    ("md_escape_fips.md", "The signer is FIPS\\-validated.\n"),
    ("ref_link_agt.md", "Compared with [AGT][1].\n\n[1]: https://example.com\n"),
    ("ref_link_prod.md", "The gateway is [production-ready][1].\n\n[1]: https://example.com\n"),
    ("ref_link_zenity.md", "Built with [Zenity][z] in mind.\n\n[z]: https://example.com\n"),
]


@pytest.mark.parametrize("name,body", CAUGHT, ids=[c[0] for c in CAUGHT])
def test_reviewer_probe_is_caught(tree, name, body):
    assert _scan(tree, {name: body}), f"{name} passed the check"


PASSES = [
    ("R1_own_phrase.md", "The lab doesn't claim to be ACS-Core conformant. <!-- claim:N-06 -->\n"),
    ("R1_both_rows.md", "Not ACS-Core conformant or FIPS 140 validated. <!-- claim:N-06 claim:N-13 -->\n"),
    ("R3_escaped_lt.md", "The value is 3 &lt; 4 and we verify it. <!-- claim:C-03 -->\n"),
    ("plain_lt.md", "When a < b the loop exits.\n"),
    ("legit.md", "The gateway forwards requests.\n"),
    # R2 ruling (round 3): an id written as plain text is ordinary text and isn't checked, so the reviewer's
    # R2_unknown_plain probe passes by decision.
    ("R2_unknown_plain.md", "Ordinary. claim:N-99\n"),
    ("indented_code.md", "Run this.\n\n    lab verify --all\n"),
    ("html_pre.html", "<pre>lab verify --all</pre>\n"),
    ("snake_case.md", "Set `on_decision_failure` to deny.\n"),
    # Round 8, I-B: an escaped underscore renders as signed_with, one identifier, so no trigger starts inside it.
    ("trig_escape.md", "Decisions are signed\\_with ML-DSA.\n"),
]


@pytest.mark.parametrize("name,body", PASSES, ids=[c[0] for c in PASSES])
def test_honest_text_passes(tree, name, body):
    assert [f for f in _scan(tree, {name: body}) if f.path == name] == []


def test_marker_on_the_next_line_is_its_own_block(tree):
    # A line that opens with a comment is an HTML block in CommonMark, so it doesn't mark the line above.
    findings = _scan(tree, {"a.md": "ACS guarantees safety.\n<!-- claim:C-03 -->\n"})
    assert _kinds(findings) == ["unledgered"]


def test_markdown_finding_points_at_its_source_line(tree):
    findings = _scan(tree, {"a.md": "Intro.\n\nSecond paragraph.\n\n- one\n- The lab is ACS-Core conformant.\n"})
    assert [(f.kind, f.line) for f in findings] == [("banned", 6)]


def test_html_finding_points_at_its_source_line(tree):
    findings = _scan(tree, {"a.html": "<html>\n<body>\n<p>Fine.</p>\n<p>The lab is\nACS-Core conformant.</p>\n"})
    assert [(f.kind, f.line) for f in findings] == [("banned", 4)]


def test_script_and_style_in_html_are_not_scanned(tree):
    # Round 4 ruling: code makes no claim to attendees, and script or style in a page is code.
    body = "<script>\nconst b = 'ACS-Crypto verified';\n</script>\n<style>/* ACS-Crypto */</style>\n<p>Fine.</p>\n"
    assert _scan(tree, {"a.html": body}) == []


def _confirmed(ledger: Path) -> str:
    return ledger.read_text(encoding="utf-8").replace("Unconfirmed:", "Confirmed:")


@pytest.mark.parametrize("cell", ["-", "N/A", "n/a", "**TBD**", "Pending", "none", "`todo`", "_Pending_"])
def test_sign_gate_refuses_placeholder_words_in_markup(tree, capsys, cell):
    root, _ = tree
    ledger = _evidence_ledger(tree, cell)
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "unconfirmed C-15" in capsys.readouterr().out


def test_sign_gate_reads_unconfirmed_through_an_entity(tree, capsys):
    root, _ = tree
    ledger = _evidence_ledger(tree, "Un&shy;confirmed until the cut")
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "unconfirmed C-15" in capsys.readouterr().out


SIGN_TABLE = "| Signed by | Date | Commit | Ledger sha256 |"


def test_claim_row_below_the_sign_off_is_refused(tree):
    root, ledger = tree
    text = _confirmed(ledger)
    _sign(ledger, text)
    row = "| C-17 | The Guardian guarantees every attack is stopped. | Rock. | None. |\n\n"
    ledger.write_text(ledger.read_text(encoding="utf-8").replace(SIGN_TABLE, row + SIGN_TABLE), encoding="utf-8")
    (root / "x.md").write_text("The Guardian guarantees every attack is stopped. <!-- claim:C-17 -->\n")
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 2


def test_ledger_block_below_the_sign_off_is_refused(tree):
    root, ledger = tree
    ledger.write_text(ledger.read_text(encoding="utf-8") + "\n```claims-exclude\n**\n```\n", encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 2


@pytest.mark.parametrize("block", ["claims-not-claimed", "claims-banned", "claims-triggers", "claims-exclude"])
def test_duplicate_ledger_block_is_refused(tree, block):
    root, ledger = tree
    hidden = f"<!--\n```{block}\nN-01: AGT\n```\n-->\n\n"
    ledger.write_text(_confirmed(ledger).replace("## Claims\n", hidden + "## Claims\n", 1), encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 2


def test_hidden_not_claimed_block_cannot_excuse_after_signing(tree):
    root, ledger = tree
    hidden = "<!--\n```claims-not-claimed\n" + "\n".join(
        "N-01: production-ready" if i == 1 else f"N-{i:02d}: AGT" for i in range(1, 14)) + "\n```\n-->\n\n"
    _sign(ledger, _confirmed(ledger).replace("## Claims\n", hidden + "## Claims\n", 1))
    (root / "x.md").write_text("FinBot is production-ready. <!-- claim:N-01 -->\n", encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 2


def test_duplicate_ledger_id_is_refused(tree):
    root, ledger = tree
    row = "| C-16 | The lab supports macOS and Linux only. Windows is untested. | Rock, 2026-11-17. | x |\n"
    ledger.write_text(ledger.read_text(encoding="utf-8").replace("\n## Not claimed", row + "\n## Not claimed"),
                      encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 2


def test_recomputed_digest_is_named_as_reader_only():
    # The digest has no key, so an editor who recomputes it passes the gate. The ledger says a reader catches that.
    reader = _section("What the tests enforce and what only a reader catches").split("Only a reader catches")[1]
    assert "recomputed" in reader and "obfuscat" in reader
    assert "without recomputing" in _section("Sign-off")


def test_c02_limits_say_when_answers_stay_on_hmac():
    limits = {r[0]: r for r in _rows(_section("Claims"))}["C-02"][3]
    assert " then " not in limits and "While signing is off" in limits


# ---------------------------------------------------------------- Fix round 4: prose only

CODE_FILES = ["a.py", "a.rego", "a.sh", "a.js", "a.css", "a.yaml", "a.yml", "a.json", "a.ps1", "a.toml"]


@pytest.mark.parametrize("name", CODE_FILES)
def test_code_file_is_not_scanned(tree, name):
    assert _scan(tree, {name: "ACS-Crypto is verified.\n"}) == []


@pytest.mark.parametrize("name", ["a.md", "a.html", "a.txt"])
def test_prose_file_is_scanned(tree, name):
    assert "banned" in _kinds(_scan(tree, {name: "The lab is ACS-Crypto ready.\n"}))


def test_scanned_types_are_one_explicit_allowlist():
    assert lab_claims.SCANNED == frozenset({".md", ".markdown", ".html", ".htm", ".txt"})


@pytest.mark.parametrize("name", ["tests/a.md", "viewer/tests/a.md", "cli/test/a.txt"])
def test_test_directories_are_not_scanned(tree, name):
    assert _scan(tree, {name: "The lab is ACS-Crypto ready.\n"}) == []


def test_ledger_exclusions_name_test_directories(tree):
    _, ledger = tree
    assert {"**/tests/**", "**/test/**"} <= set(lab_claims.load_ledger(ledger).exclude)


# ---------------------------------------------------------------- Fix round 5: where GitHub shows more

R5_CAUGHT = [
    # F1: a list right after a paragraph line starts a list on GitHub, so each item is its own unit.
    ("list_after_para.md", "What the lab shows:\n- The gateway can forge an allow.\n"
                           "- Decisions are signed with ML-DSA-65. <!-- claim:C-02 -->\n", "unledgered"),
    ("list_after_para_star.md", "Notes:\n* The gateway can forge an allow.\n* Signed with ML-DSA-65. <!-- claim:C-02 -->\n",
     "unledgered"),
    ("ol_after_para.md", "Steps:\n1. The lab fails closed.\n2. Decisions are signed with ML-DSA-65. <!-- claim:C-02 -->\n",
     "unledgered"),
    ("list_after_para_N10.md", "Notes:\n- ACS isn't compared with AGT. <!-- claim:N-10 -->\n"
                               "- The lab is ACS-Core conformant.\n", "banned"),
    ("list_after_para_N06.md", "Hooks:\n- It sends 4 of the 7 minimum hooks. <!-- claim:N-06 -->\n"
                               "- ACS interoperates with other agent stacks.\n", "banned"),
    ("list_after_para_star_N06.md", "Hooks:\n* It sends 4 of 7 hooks. <!-- claim:N-06 -->\n* Built with AGT.\n", "banned"),
    ("ol_after_para_N06.md", "Hooks:\n1. It sends 4 of 7 hooks. <!-- claim:N-06 -->\n2. Built with AGT.\n", "banned"),
    ("quote_list_after_para.md", "> Notes:\n> - The gateway can forge an allow.\n"
                                 "> - Signed with ML-DSA-65. <!-- claim:C-02 -->\n", "unledgered"),
]
for tag in ("<details>\n<summary>Notes</summary>\n", "<div align=\"center\">\n"):
    close = "</details>" if tag.startswith("<details") else "</div>"
    label = "details" if tag.startswith("<details") else "div"
    R5_CAUGHT += [
        # F2: Markdown inside a raw HTML block renders on GitHub after a blank line.
        (f"{label}_bold_agt.md", f"{tag}\nWe looked at the **Agent Governance** Toolkit.\n\n{close}\n", "banned"),
        (f"{label}_link.md", f"{tag}\nACS [interoperates](https://x) with other stacks.\n\n{close}\n", "banned"),
        (f"{label}_bold_core.md", f"{tag}\nThe lab is **ACS-Core** conformant.\n\n{close}\n", "banned"),
        (f"{label}_merge.md", f"{tag}\nSigned with ML-DSA-65. <!-- claim:C-02 -->\n\n"
                              f"The gateway can forge an allow.\n\n{close}\n", "unledgered"),
    ]


@pytest.mark.parametrize("name,body,kind", R5_CAUGHT, ids=[c[0] for c in R5_CAUGHT])
def test_round_5_github_reading_is_caught(tree, name, body, kind):
    assert kind in _kinds(_scan(tree, {name: body}))


R5_PASSES = [
    ("list_marked_items.md", "Notes:\n- The lab fails closed in enforce mode. <!-- claim:C-09 -->\n"
                             "- Signed with ML-DSA-65. <!-- claim:C-02 -->\n"),
    ("year_line.md", "The work began in\n2026. It continues.\n"),
    ("details_marked.md", "<details>\n<summary>Notes</summary>\n\nSigned with ML-DSA-65. <!-- claim:C-02 -->\n\n</details>\n"),
    ("fence_list.md", "```\nNotes:\n- verify it\n```\n"),
    ("fence_div.md", "```\n<div>\nverify\n</div>\n```\n"),
]


@pytest.mark.parametrize("name,body", R5_PASSES, ids=[c[0] for c in R5_PASSES])
def test_round_5_honest_text_passes(tree, name, body):
    assert [f for f in _scan(tree, {name: body}) if f.path == name] == []


def test_list_after_paragraph_points_at_each_item(tree):
    findings = _scan(tree, {"a.md": "Notes:\n- Fine. <!-- claim:C-02 -->\n- The lab fails closed.\n"})
    assert [(f.kind, f.line) for f in findings] == [("unledgered", 3)]


@pytest.mark.parametrize("name", ["a.markdown", "a.htm"])
def test_other_prose_spellings_are_scanned(tree, name):
    body = "<p>The lab is ACS-Crypto ready.</p>\n" if name.endswith(".htm") else "The lab is ACS-Crypto ready.\n"
    assert "banned" in _kinds(_scan(tree, {name: body}))


@pytest.mark.parametrize("cell", ["(TBD)", "TODO(rock)", "[TBD](x)", "TBC", "Not yet", "not yet checked",
                                  "To be confirmed", "Pending review", "?"])
def test_sign_gate_refuses_wrapped_placeholders(tree, capsys, cell):
    root, _ = tree
    ledger = _evidence_ledger(tree, cell)
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "unconfirmed C-15" in capsys.readouterr().out


def test_indented_claim_row_is_read(tree):
    _, ledger = tree
    text = ledger.read_text(encoding="utf-8").replace("| C-15 |", " | C-15 |", 1)
    ledger.write_text(text.replace("| No second implementation runs in the lab. |", "| Unconfirmed: x |"),
                      encoding="utf-8")
    assert "C-15" in lab_claims.load_ledger(ledger).unconfirmed


@pytest.mark.parametrize("opener,closer", [("````", "````"), ("~~~", "~~~"), ("   ```", "```")])
def test_other_fence_forms_of_a_ledger_block_count(tree, opener, closer):
    root, ledger = tree
    extra = f"{opener}claims-triggers\nzzz\n{closer}\n\n"
    ledger.write_text(ledger.read_text(encoding="utf-8").replace("## Claims\n", extra + "## Claims\n", 1),
                      encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 2


def test_tilde_block_below_the_sign_off_is_refused(tree):
    root, ledger = tree
    ledger.write_text(ledger.read_text(encoding="utf-8") + "\n~~~claims-banned\nfoo\n~~~\n", encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 2


def test_ledger_names_the_renderer_divergences():
    text = _section("What the tests enforce and what only a reader catches")
    assert "more text" not in text and "reads Markdown differently from GitHub" in text
    assert "lists" in text and "footnote" in text


# ---------------------------------------------------------------- Fix round 6: named fixes

C2 = "<!-- claim:C-02 -->"
N6 = "<!-- claim:N-06 -->"

R6_CAUGHT = [
    # I1: each suffix is read the way its renderer reads it, so a hard wrap can't split a phrase.
    ("wrap.markdown", "We compared the lab with the Agent\nGovernance Toolkit.\n", "banned"),
    ("wrap.htm", "<p>We compared the lab with the Agent\nGovernance Toolkit.</p>\n", "banned"),
    ("trig_wrap.markdown", "The gateway can\nforge an allow.\n", "unledgered"),
    ("trig_wrap.htm", "<p>The gateway can\nforge an allow.</p>\n", "unledgered"),
    # I2: a nested list after a paragraph line inside a list item is its own list on GitHub.
    ("nested4_ul_N06.md", f"- Check the hooks.\n\n    It isn't ACS-Core conformant. {N6}\n"
                          "    - The gateway is ACS-Core conformant.\n", "banned"),
    ("nested4_ol_N06.md", f"1. Check the hooks.\n\n    It sends 4 of the 7 minimum hooks. {N6}\n"
                          "    - The gateway is ACS-Core conformant.\n", "banned"),
    ("nested4_ol_C02_forge.md", f"1. Start the stack.\n\n    Signed with ML-DSA-65. {C2}\n"
                                "    - The gateway can forge an allow.\n", "unledgered"),
    # I3: table cells render their Markdown on GitHub, so each inner paragraph is its own unit.
    ("th_agt.md", "<table>\n<tr>\n<th>\n\nVs **Agent Governance** Toolkit\n\n</th>\n</tr>\n</table>\n", "banned"),
    ("td_N06.md", f"<table><tr>\n<td>\n\nIt isn't ACS-Core conformant. {N6}\n\n"
                  "The gateway is ACS-Core conformant.\n\n</td>\n</tr></table>\n", "banned"),
    ("html_td_marker.md", f"<table>\n<tr>\n<td>\n\nSigned with ML-DSA-65. {C2}\n\nThe gateway can forge an allow.\n\n"
                          "</td>\n</tr>\n</table>\n", "unledgered"),
    ("html_td_md.md", "<table>\n<tr>\n<td>\n\nWe looked at the **Agent Governance** Toolkit.\n\n</td>\n</tr>\n</table>\n",
     "banned"),
    # M1: emphasis marks Python-Markdown leaves as text in raw HTML don't split a phrase.
    ("summary_agt.md", "<details><summary>We compared with **Agent Governance** Toolkit</summary>\n\nBody.\n\n"
                       "</details>\n", "banned"),
    ("summary_code.md", "<details><summary>The lab is `ACS-Core` conformant</summary>\n\nBody.\n\n</details>\n", "banned"),
]


@pytest.mark.parametrize("name,body,kind", R6_CAUGHT, ids=[c[0] for c in R6_CAUGHT])
def test_round_6_github_reading_is_caught(tree, name, body, kind):
    assert kind in _kinds(_scan(tree, {name: body}))


R6_PASSES = [
    ("marked_wrap.markdown", f"Decisions are signed with ML-DSA-65,\nas the spec requires. {C2}\n"),
    ("marked.htm", f"<p>{C2}\nDecisions are signed with ML-DSA-65.</p>\n"),
    ("script.htm", "<script>\nconst secure = verify(x);\n</script>\n<p>Hello.</p>\n"),
    ("lazy_indent.md", "Run the stack\n    - or rather, start it.\n"),
]


@pytest.mark.parametrize("name,body", R6_PASSES, ids=[c[0] for c in R6_PASSES])
def test_round_6_honest_text_passes(tree, name, body):
    assert [f for f in _scan(tree, {name: body}) if f.path == name] == []


def test_markdown_and_html_suffixes_are_one_set_each():
    assert lab_claims.MARKDOWN_SUFFIXES == {".md", ".markdown"}
    assert lab_claims.HTML_SUFFIXES == {".html", ".htm"}
    assert lab_claims.MARKDOWN_SUFFIXES | lab_claims.HTML_SUFFIXES | {".txt"} == lab_claims.SCANNED


def test_ledger_sign_gate_names_every_placeholder():
    line = next(ln for ln in _section("What the tests enforce and what only a reader catches").splitlines()
                if "--require-signed" in ln).lower()
    words = set(lab_claims.PLACEHOLDER_LEAD) | {"n/a" if w == "n a" else w for w in lab_claims.PLACEHOLDER_WORDS}
    missing = sorted(w for w in words if w not in line)
    assert not missing, f"the sign-gate line doesn't name {missing}"




# ---------------------------------------------------------------- Fix round 6: the container-by-placement matrix
#
# Every container a lab page can hold prose in, crossed with every way an author places a phrase in it. Each case puts
# the phrase in its own unit, optionally beside a sibling unit whose marker would excuse the phrase if it reached it.
# Every combination here renders as visible prose on GitHub, so each must be caught, and no sibling marker may clear it.

# (kind, sentence parts) where the sentence is prefix + phrase + suffix. The hard wrap goes at the "|" in the phrase.
MATRIX_PHRASES = {
    "banned": ("We compared the lab with the ", "Agent|Governance Toolkit", "."),
    "trigger": ("The gateway can ", "|forge", " an allow."),
}
# The reverse direction: the same phrases said honestly, each carrying its own row's marker at the end.
HONEST_PHRASES = {
    "banned": ("The lab isn't benchmarked against the ", "Agent|Governance Toolkit", ". <!-- claim:N-10 -->"),
    "trigger": ("Anyone holding the HMAC key can ", "|forge", " an allow. <!-- claim:C-04 -->"),
}
# The sibling's marker excuses the banned phrase (N-10) or covers the trigger (C-02) if it reached the target unit.
# It sits after its sentence or, as an author may write it, before it.
MATRIX_SIBLINGS = {
    "banned": {"sibling": "The lab doesn't compare ACS with that toolkit. <!-- claim:N-10 -->",
               "sibling_first": "<!-- claim:N-10 --> The lab doesn't compare ACS with that toolkit."},
    "trigger": {"sibling": "Decisions are signed with ML-DSA-65. <!-- claim:C-02 -->",
                "sibling_first": "<!-- claim:C-02 --> Decisions are signed with ML-DSA-65."},
}
HONEST_SIBLINGS = {"none": None, "plain": "Read this first.",
                   "marked": "Decisions are signed with ML-DSA-65. <!-- claim:C-02 -->"}
MATRIX_EXPECT = {"banned": "banned", "trigger": "unledgered"}
CLAIM_COMMENT = re.compile(r"\s*<!-- claim:[A-Z]-\d+ -->")


def _place(parts: tuple[str, str, str], placement: str, html: bool) -> str:
    """The target sentence. A hard wrap is a newline, and containers indent it."""
    pre, phrase, post = parts
    whole = phrase.replace("|", " ").strip()
    if placement == "wrap":
        return pre.rstrip() + ("\n" if phrase.startswith("|") else " ") + phrase.replace("|", "\n").lstrip("\n") + post
    if placement == "fence":
        # A command in a fenced block carries no marker, since a marker in code doesn't count.
        return "```\n" + pre + whole + CLAIM_COMMENT.sub("", post) + "\n```"
    if placement == "marker_first":
        marker = CLAIM_COMMENT.search(post).group().strip()
        return f"{marker} {pre}{whole}{CLAIM_COMMENT.sub('', post)}"
    if html:
        wrapped = {"alone": whole, "emphasis": f"<strong>{whole}</strong>", "code": f"<code>{whole}</code>",
                   "link": f'<a href="https://example.com">{whole}</a>'}[placement]
    else:
        wrapped = {"alone": whole, "emphasis": f"**{whole}**", "code": f"`{whole}`",
                   "link": f"[{whole}](https://example.com)"}[placement]
    return pre + wrapped + post


def _indent(text: str, pad: str) -> str:
    """Indent every line after the first, so a hard wrap stays inside its container."""
    return text.replace("\n", "\n" + pad)


def _para(t, s):
    return (f"{s}\n\n" if s else "") + t + "\n"


def _list_after_para(indent):
    def build(t, s):
        pad = " " * indent
        sib = f"{pad}- {s}\n" if s else ""
        return f"Notes:\n{sib}{pad}- {_indent(t, pad + '  ')}\n"
    return build


def _nested_after_para(indent):
    # A list item whose own paragraph is followed by a nested list at this indent, the GitHub reading of I2.
    def build(t, s):
        outer = " " * (indent - 4)
        pad = " " * indent
        para = s or "Read this first."
        return f"{outer}- Start the stack.\n\n{pad}{para}\n{pad}- {_indent(t, pad + '  ')}\n"
    return build


def _deep(t, s):
    # A marker four or more columns past its item's content is paragraph text on GitHub (I-1).
    sib = f"    {s}\n\n" if s else ""
    return f"- Start.\n\n{sib}    Read this.\n            - {_indent(t, ' ' * 14)}\n"


def _nested(t, s):
    sib = f"    - {s}\n" if s else ""
    return f"- Outer item.\n{sib}    - {_indent(t, '      ')}\n"


def _quote(t, s):
    return (f"> {s}\n>\n" if s else "") + "> " + _indent(t, "> ") + "\n"


def _quote_list(t, s):
    sib = f"> - {s}\n" if s else ""
    return f"> Notes:\n{sib}> - {_indent(t, '>   ')}\n"


def _admonition(t, s):
    return (f"{s}\n\n" if s else "") + "!!! note\n    " + _indent(t, "    ") + "\n"


def _collapsible(t, s):
    return (f"{s}\n\n" if s else "") + '??? note "More"\n    ' + _indent(t, "    ") + "\n"


def _deflist(t, s):
    return (f"Guardian\n:   {s}\n\n" if s else "") + "Gateway\n:   " + _indent(t, "    ") + "\n"


def _task(t, s):
    sib = f"- [x] {s}\n" if s else ""
    return f"{sib}- [ ] {_indent(t, '      ')}\n"


def _footnote(t, s):
    sib = f"[^1]: {s}\n" if s else ""
    return f"Text.[^1][^2]\n\n{sib}[^2]: {_indent(t, '    ')}\n"


def _table(t, s):
    sib = f"| {s} | x |\n" if s else ""
    return f"| A | B |\n|---|---|\n{sib}| {t} | y |\n"


def _md_html(tag):
    # Raw HTML in a Markdown file, with the blank lines GitHub needs to render the Markdown inside it.
    def build(t, s):
        if tag == "summary":
            return f"<details>\n<summary>{t}</summary>\n\n{s or 'Body.'}\n\n</details>\n"
        # The sibling is a second paragraph in the same element, which GitHub shows as its own paragraph.
        inner = (f"\n{s}\n" if s else "") + f"\n{t}\n\n"
        if tag in ("td", "th"):
            return f"<table>\n<tr>\n<{tag}>\n{inner}</{tag}>\n</tr>\n</table>\n"
        if tag == "li":
            return f"<ul>\n<li>\n{inner}</li>\n</ul>\n"
        head = "<details>\n<summary>More</summary>\n" if tag == "details" else f"<{tag}>\n"
        close = "</details>" if tag == "details" else f"</{tag}>"
        return head + inner + close + "\n"
    return build


def _html_file(tag):
    def build(t, s):
        if tag == "summary":
            return f"<details><summary>{t}</summary><p>{s or 'Body.'}</p></details>\n"
        if tag in ("td", "th"):
            row = "<tr><{0}>{1}</{0}></tr>\n"
            return "<table>\n" + (row.format(tag, s) if s else "") + row.format(tag, t) + "</table>\n"
        if tag == "li":
            return "<ul>\n" + (f"<li>{s}</li>\n" if s else "") + f"<li>{t}</li>\n</ul>\n"
        if tag == "details":
            unit = "<details>\n<summary>More</summary>\n{}\n</details>\n"
            return (unit.format(s) if s else "") + unit.format(t)
        return (f"<{tag}>{s}</{tag}>\n" if s else "") + f"<{tag}>{t}</{tag}>\n"
    return build


MD_CONTAINERS = {
    "paragraph": _para,
    "list_after_para_0": _list_after_para(0),
    "list_after_para_2": _list_after_para(2),
    "list_after_para_3": _list_after_para(3),
    "list_after_para_4": _nested_after_para(4),
    "list_after_para_6": _nested_after_para(6),
    "list_deep": _deep,
    "nested_list": _nested,
    "blockquote": _quote,
    "blockquote_list": _quote_list,
    "admonition": _admonition,
    "collapsible": _collapsible,
    "definition_list": _deflist,
    "task_list": _task,
    "footnote": _footnote,
    "table_cell": _table,
}
HTML_TAGS = ("details", "summary", "div", "section", "p", "td", "th", "li")
MD_CONTAINERS.update({f"html_{tag}": _md_html(tag) for tag in HTML_TAGS})
HTML_CONTAINERS = {f"html_{tag}": _html_file(tag) for tag in HTML_TAGS}
MATRIX_PLACEMENTS = ("alone", "wrap", "emphasis", "code", "link", "fence")
HONEST_PLACEMENTS = MATRIX_PLACEMENTS + ("marker_first",)
# A GFM table row ends at the newline, so a hard wrap can't sit inside a Markdown table cell.
MATRIX_IMPOSSIBLE = {("table_cell", "wrap")}
# A fenced block is code on GitHub only where GitHub reads the fence: in Markdown containers it renders, and inside
# raw HTML after a blank line. GitHub doesn't render admonitions, collapsibles or definition lists, so a fence there is
# paragraph text, and a fence can't sit in a table cell, a footnote line, a summary, an over-indented line, after a
# task box or in a page.
FENCE_CONTAINERS = {"paragraph", "list_after_para_0", "list_after_para_2", "list_after_para_3", "list_after_para_4",
                    "list_after_para_6", "nested_list", "blockquote", "blockquote_list", "html_details",
                    "html_div", "html_section", "html_p", "html_td", "html_th", "html_li"}
# Triggers are exempt in code by design, so a fence catches only a banned phrase, and an honest fence holds a trigger.
FENCE_KIND = {"catch": "banned", "honest": "trigger"}


def _applies(direction: str, suffix: str, cname: str, placement: str, kind: str) -> bool:
    if (cname, placement) in MATRIX_IMPOSSIBLE:
        return False
    if placement == "fence":
        return suffix in (".md", ".markdown") and cname in FENCE_CONTAINERS and kind == FENCE_KIND[direction]
    return True


def _matrix(direction: str) -> list[tuple[str, str, str]]:
    phrases = MATRIX_PHRASES if direction == "catch" else HONEST_PHRASES
    placements = MATRIX_PLACEMENTS if direction == "catch" else HONEST_PLACEMENTS
    cases = []
    for suffixes, containers, html in (((".md", ".markdown"), MD_CONTAINERS, False),
                                       ((".html", ".htm"), HTML_CONTAINERS, True)):
        for suffix in suffixes:
            for cname, build in containers.items():
                for placement in placements:
                    for kind, parts in phrases.items():
                        if not _applies(direction, suffix, cname, placement, kind):
                            continue
                        siblings = ({"alone": None, **MATRIX_SIBLINGS[kind]} if direction == "catch"
                                    else HONEST_SIBLINGS)
                        for sname, sibling in siblings.items():
                            body = build(_place(parts, placement, html), sibling)
                            cases.append((f"{cname}-{placement}-{kind}-{sname}{suffix}", body, MATRIX_EXPECT[kind]))
    return cases


MATRIX = _matrix("catch")
HONEST_MATRIX = _matrix("honest")
MATRIX_LEDGER = lab_claims.load_ledger(LEDGER)


def test_matrix_size():
    print(f"container-by-placement matrix: {len(MATRIX)} catch cases, {len(HONEST_MATRIX)} honest cases")
    # Pinned, so a change that drops a container or a placement shows here.
    assert (len(MATRIX), len(HONEST_MATRIX)) == (2004, 2388)
    assert len({c[0] for c in MATRIX}) == len(MATRIX) and len({c[0] for c in HONEST_MATRIX}) == len(HONEST_MATRIX)


@pytest.mark.parametrize("name,body,kind", MATRIX, ids=[c[0] for c in MATRIX])
def test_matrix_phrase_is_caught(tmp_path, name, body, kind):
    (tmp_path / name).write_text(body, encoding="utf-8")
    findings = lab_claims.scan(tmp_path, MATRIX_LEDGER)
    target = lab_claims._key(MATRIX_PHRASES["banned" if kind == "banned" else "trigger"][1].replace("|", " "))
    # The finding must be the target's own unit, so a stray finding on the sibling can't stand in for a miss.
    hits = [f for f in findings if f.kind == kind and target in lab_claims._key(f.text)]
    assert hits, f"{name} passed the check:\n{body}\n{findings}"


@pytest.mark.parametrize("name,body,kind", HONEST_MATRIX, ids=[c[0] for c in HONEST_MATRIX])
def test_matrix_honest_text_passes(tmp_path, name, body, kind):
    (tmp_path / name).write_text(body, encoding="utf-8")
    findings = lab_claims.scan(tmp_path, MATRIX_LEDGER)
    assert findings == [], f"{name} failed the check:\n{body}"


def test_ledger_names_the_reader_for_each_suffix():
    text = " ".join(_section("What the tests enforce and what only a reader catches").split())
    assert "`.md` and `.markdown` render as Markdown" in text
    assert "`.html` and `.htm` parse as HTML" in text


# ---------------------------------------------------------------- Fix round 7: GitHub's list, fence and marker rules

C4 = "<!-- claim:C-04 -->"
N10 = "<!-- claim:N-10 -->"

R7_CAUGHT = [
    # I-1: a marker four or more columns past its item's content is paragraph text on GitHub, not a nested list.
    ("deep_trigger.md", "- Start.\n\n    Read this.\n            - The gateway can forge an allow.\n", "unledgered"),
    ("deep_banned.md", "- Start.\n\n    Read this.\n            - The lab is ACS-Core conformant.\n", "banned"),
    # I-1: a bullet does interrupt paragraph text, so on GitHub the marker sits in a nested item of its own.
    ("item_para_dash.md", f"- Item.\n\n  Decisions are signed with ML-DSA-65 -\n  - the spec says so. {C2}\n", "unledgered"),
    ("item_para_star.md", f"- Item.\n\n    Decisions are signed with ML-DSA-65\n    * as specified. {C2}\n", "unledgered"),
    # I-2: a banned phrase stays banned inside a fence in a list.
    ("fence_banned.md", "1. Note:\n\n   ```\n   AGT\n   ```\n", "banned"),
    # I-3: a leading marker binds to its own sentence, so it can't reach a sibling paragraph.
    ("marker_first_sibling.md", f"{C2} Decisions are signed with ML-DSA-65.\n\nThe gateway can forge an allow.\n",
     "unledgered"),
]


@pytest.mark.parametrize("name,body,kind", R7_CAUGHT, ids=[c[0] for c in R7_CAUGHT])
def test_round_7_github_reading_is_caught(tree, name, body, kind):
    assert kind in _kinds(_scan(tree, {name: body}))


R7_PASSES = [
    # I-1: only a bullet or 1. starts a list after paragraph text, and an ordered marker past 1 stays text.
    ("nested_year.md", f"- Start the stack.\n\n    Decisions were signed with ML-DSA-65 in December\n    2026. {C2}\n"),
    ("nested_year_ol.md", f"1. Start the stack.\n\n    Decisions were signed with ML-DSA-65 in December\n    2026. {C2}\n"),
    ("item2_year.md", f"- Decisions were signed with ML-DSA-65 in December\n  2026. {C2}\n"),
    ("nested_item_year.md", f"- Outer.\n    - Decisions were signed with ML-DSA-65 in December\n      2026. {C2}\n"),
    ("nested_para_paren.md", f"- Start.\n\n    Decisions are signed with ML-DSA-65, see step\n    2) for the key. {C2}\n"),
    ("year_banned_marked.md", f"- Start.\n\n    We compared the lab with the Agent Governance Toolkit in\n    2026. {N10}\n"),
    # I-2: a fence inside a list item or a block quote is code, where triggers are exempt.
    ("ol_fence.md", "1. Check the run:\n\n   ```bash\n   ./lab.sh verify\n   ```\n"),
    ("ul_fence.md", "- Check the run:\n\n  ```\n  lab verify --all\n  ```\n"),
    ("ul_fence_tight.md", "- Check the run:\n  ```\n  lab verify --all\n  ```\n"),
    ("quote_fence.md", "> ```\n> lab verify\n> ```\n"),
    ("nested_fence.md", "1. Outer.\n    - Inner:\n\n      ```\n      lab verify\n      ```\n"),
    ("fence_list_lines.md", "1. Check:\n\n   ```\n   - verify it\n   2026. verify\n   ```\n"),
    # I-3: a marker before its sentence on the same line binds to it.
    ("marker_first.md", f"{C2} Decisions are signed with ML-DSA-65.\n"),
    ("marker_first_wrap.md", f"{C2} Decisions are signed\nwith ML-DSA-65.\n"),
    ("quote_marker_first.md", f"> {C2} Decisions are signed with ML-DSA-65.\n"),
    ("item_marker_first.md", f"- {C2} Decisions are signed with ML-DSA-65.\n"),
    # m-3: raw HTML with no blank line renders no Markdown on GitHub, so its text is one unit.
    ("div_marker_line.md", f'<div align="center">\n{C2}\nDecisions are signed with ML-DSA-65.\n</div>\n'),
    ("p_multiline.md", f"<p>\nDecisions are signed\nwith ML-DSA-65. {C2}\n</p>\n"),
    # m-2: a raw HTML row with no blank lines is one unit, as a GFM row is.
    ("td_marker_other_cell.md", f"<table>\n<tr>\n<td>Decisions are signed with ML-DSA-65.</td>\n<td>{C2}</td>\n"
                                "</tr>\n</table>\n"),
    # m-1: an intraword underscore isn't emphasis, so window_size doesn't read as Windows.
    ("snake_window.md", "Set `window_size` to 8.\n"),
    ("snake_window.txt", "Set window_size to 8.\n"),
    ("snake_window.html", "<p>Set <code>window_size</code> to 8.</p>\n"),
    ("snake_window_raw.md", "<details><summary>Set window_size to 8</summary>\n\nBody.\n\n</details>\n"),
]


@pytest.mark.parametrize("name,body", R7_PASSES, ids=[c[0] for c in R7_PASSES])
def test_round_7_honest_text_passes(tree, name, body):
    assert [f for f in _scan(tree, {name: body}) if f.path == name] == []


def test_unledgered_finding_says_where_a_marker_goes(tree, capsys):
    root, ledger = tree
    (root / "a.md").write_text("The gateway can forge an allow.\n", encoding="utf-8")
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 1
    out = capsys.readouterr().out
    assert "before or after the sentence on the same line" in out


def test_ledger_says_where_a_marker_goes():
    head = LEDGER.read_text(encoding="utf-8").split("## Claims", 1)[0]
    assert "before or after the sentence on the same line" in " ".join(head.split())


def test_every_cited_evidence_path_exists():
    ledger = lab_claims.load_ledger(LEDGER)
    assert ledger.evidence, "the ledger cites no evidence path"
    missing = [(row, p) for row, p in ledger.evidence if not (ROOT / p).exists()]
    assert not missing, f"evidence paths missing from the tree: {missing}"


def test_evidence_paths_skip_text_after_unconfirmed():
    ledger = lab_claims.load_ledger(LEDGER)
    assert ("C-11", "version.txt") in ledger.evidence
    assert ("C-02", "adapters/src/acs/core/_mldsa.py") in ledger.evidence
    assert not any(p in ("acs-lab-keys/1", "acs.lab.replay_miss") for _, p in ledger.evidence)


def test_sign_gate_refuses_a_missing_evidence_path(tree, capsys):
    root, _ = tree
    ledger = _evidence_ledger(tree, "`adapters/src/acs/core/_nothing_here.py` (gone).")
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "missing_evidence C-15 adapters/src/acs/core/_nothing_here.py" in capsys.readouterr().out


def test_viewer_evidence_cites_the_viewer_on_this_tree():
    # LAB-13's viewer is on the lab branch, so C-04 cites it as evidence, with nothing left pending.
    rows = {r[0]: r for r in _rows(_section("Claims"))}
    assert "unconfirmed" not in " ".join(rows["C-04"]).lower()
    for path in ("labs/finbot/viewer/verify.py:142-147", "labs/finbot/viewer/model.py:885-891",
                 "labs/finbot/viewer/model.py:920-942"):
        assert f"`{path}`" in rows["C-04"][2], path
    # m-6: the viewer checks each answer's signature and leaves the chain to lab verify.
    assert "keys only" in rows["C-04"][2] and "lab verify" in rows["C-04"][2]


def test_reader_only_list_names_admonitions_with_a_blank_line():
    # Round 8: CommonMark reads an admonition body after a blank line as code, as GitHub does, so the ledger says the
    # two agree rather than naming it as reader-only.
    text = " ".join(_section("What the tests enforce and what only a reader catches").split())
    assert "admonition body after a blank line is a code block on GitHub and to the check alike" in text


# ---------------------------------------------------------------- Fix round 8: a CommonMark parser

FORGE = "The gateway can forge an allow."
SIGNED = f"Decisions are signed with ML-DSA-65. {C2}"

R8_CAUGHT = [
    # I-A: a marker binds only to the sentences on its own source line, before or after it.
    ("lead_next_line.md", f"{C2} Decisions are signed with ML-DSA-65.\n{FORGE}\n", "unledgered"),
    ("lead_after_forge.md", f"{FORGE}\n{C2} Decisions are signed with ML-DSA-65.\n", "unledgered"),
    ("lead_mid.md", f"Read this first.\n{C2} Decisions are signed with ML-DSA-65.\n{FORGE}\n", "unledgered"),
    ("lead_wrap_claim.md", f"{C4} Anyone holding the HMAC key can\nforge an allow.\n", "unledgered"),
    ("trail_line_2.md", f"{FORGE}\n{SIGNED}\n", "unledgered"),
    ("trail_line_2_item.md", f"- {FORGE}\n  {SIGNED}\n", "unledgered"),
    ("trail_line_2_banned.md", f"The lab is ACS-Core conformant.\nIt isn't ACS-Core conformant. {N6}\n", "banned"),
    ("trail_line_2.txt", f"{FORGE}\n{SIGNED}\n", "unledgered"),
    # m-1: a tab-indented nested item after paragraph text is a nested item of its own.
    ("tab_para_then_item_sib.md", f"- Start the stack.\n\n\t{SIGNED}\n\t- {FORGE}\n", "unledgered"),
    # m-2: a changed ordered delimiter starts a new list, and an unprefixed year leaves the quote.
    ("ordered_delim_change.md", f"1. {SIGNED}\n2) {FORGE}\n", "unledgered"),
    ("quote_list_lazy_year.md", f"> 1. Decisions were signed with ML-DSA-65 in December\n2026. {C2}\n", "unledgered"),
    # I-B: an underscore that isn't between two letters or digits still reads as a space.
    ("emph_raw_banned.md", "<details><summary>We compared ACS with _AGT_ here</summary>\n\nBody.\n\n</details>\n",
     "banned"),
    ("emph_md_trigger.md", "Decisions are _signed with_ ML-DSA-65.\n", "unledgered"),
    ("emph_txt_trigger.txt", "Decisions are _signed with_ ML-DSA-65.\n", "unledgered"),
    ("snake_prose_trigger.md", "The gateway can forge_an allow.\n", "unledgered"),
    ("underscore_forge.md", "The gateway can _forge_ an allow.\n", "unledgered"),
    ("underscore_forge.txt", "The gateway can _forge_ an allow.\n", "unledgered"),
    ("txt_emph.txt", "The lab is _ACS-Core conformant_.\n", "banned"),
    ("code_fips.md", "Signing follows `FIPS 204`.\n", "unledgered"),
]


@pytest.mark.parametrize("name,body,kind", R8_CAUGHT, ids=[c[0] for c in R8_CAUGHT])
def test_round_8_overclaim_is_caught(tree, name, body, kind):
    assert kind in _kinds(_scan(tree, {name: body}))


R8_PASSES = [
    # I-A: a marker binds to every sentence on its own line, and a marker can sit beside inline HTML or another marker.
    ("lead_then_inline_html.md", f"{C2} <strong>Decisions are signed with ML-DSA-65.</strong>\n"),
    ("lead_two_markers.md", f"{C2} {C4} Decisions are signed with ML-DSA-65 and a holder can forge an allow.\n"),
    ("lead_two_sentences.md", f"{C2} Decisions are signed with ML-DSA-65. Read the key document.\n"),
    ("trail_two_sentences.md", f"Read the key document. Decisions are signed with ML-DSA-65. {C2}\n"),
    ("wrapped_sentence.md", f"Anyone holding the HMAC key can\nforge an allow. {C4}\n"),
    # I-C: an indented code block inside a step is code, where triggers are exempt.
    ("item_indented_code_2.md", "- Check the run:\n\n      ./lab.sh verify\n"),
    ("item_indented_code_3.md", "1. Check the run:\n\n       ./lab.sh verify\n"),
    ("nested_indented_code.md", "1. Outer.\n   - Check the run:\n\n         ./lab.sh verify\n"),
    # m-1: tabs expand to stops of four, as in CommonMark.
    ("tab_fence_in_step.md", "1. Check the run:\n\n\t```bash\n\t./lab.sh verify\n\t```\n"),
    ("tab_year_wrap.md", f"- Start.\n\n\tDecisions were signed with ML-DSA-65 in December\n\t2026. {C2}\n"),
    # m-2: lazy continuation keeps a quote's paragraph together.
    ("quote_lazy.md", f"> Decisions are signed\nwith ML-DSA-65. {C2}\n"),
]


@pytest.mark.parametrize("name,body", R8_PASSES, ids=[c[0] for c in R8_PASSES])
def test_round_8_honest_text_passes(tree, name, body):
    assert [f for f in _scan(tree, {name: body}) if f.path == name] == []


# I-B: real lab identifiers. An underscore between two letters or digits is part of the word, so no trigger starts
# inside an identifier, in prose or in inline code.
IDENTIFIER_SENTENCES = {
    "fail_closed_reason": "A refused session shows {session_refused_fail_closed} in the audit log.",
    "decision_failure": "When the Guardian is down, the reason reads {decision_failure_fail_closed}.",
    "keyring_verified": "The {keyring_verified} column names the key the viewer used.",
    "response_verified": "The {response_verified} field sits next to the method name.",
    "acs_verify": "Run {acs_verify} from the viewer directory.",
    "provenance": "The {policy_requires_provenance} rule is off in this lab.",
    "require_signed_with": "Pass {require_signed} with a value of true to refuse HMAC sessions.",
}


def _identifier_cases():
    cases = []
    for key, template in IDENTIFIER_SENTENCES.items():
        for form, md, html_code in (("prose", "{}", "{}"), ("code", "`{}`", "<code>{}</code>")):
            text = re.sub(r"\{([^}]*)\}", lambda m: md.format(m.group(1)), template)
            page = re.sub(r"\{([^}]*)\}", lambda m: html_code.format(m.group(1)), template)
            cases += [(f"{key}_{form}.md", text + "\n"), (f"{key}_{form}.txt", text + "\n"),
                      (f"{key}_{form}.html", f"<p>{page}</p>\n")]
    return cases


@pytest.mark.parametrize("name,body", _identifier_cases(), ids=[c[0] for c in _identifier_cases()])
def test_identifier_underscores_join_words(tree, name, body):
    assert [f for f in _scan(tree, {name: body}) if f.path == name] == []


def test_markdown_renders_with_markdown_it_only():
    source = MODULE.read_text(encoding="utf-8")
    assert "markdown_it" in source
    assert not re.search(r"^\s*(?:import|from)\s+(?:markdown|pymdownx)\b", source, re.M)


def test_markdown_it_is_pinned_once_in_the_lock():
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    pins = re.findall(r'"markdown-it-py==([\d.]+)"', project)
    assert len(pins) == 1, "pyproject.toml must pin markdown-it-py to one exact version"
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert re.search(rf'name = "markdown-it-py"\nversion = "{re.escape(pins[0])}"', lock)


def test_scan_refuses_without_markdown_it(tree, monkeypatch):
    root, ledger = tree
    (root / "a.md").write_text("Plain.\n", encoding="utf-8")
    monkeypatch.setattr(lab_claims, "markdown_it", None)
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 2


def test_ledger_says_inline_code_needs_a_marker():
    head = " ".join(LEDGER.read_text(encoding="utf-8").split("## Claims", 1)[0].split())
    assert "trigger inside inline code needs a marker" in head


def test_ledger_says_a_marker_binds_to_its_own_line():
    head = " ".join(LEDGER.read_text(encoding="utf-8").split("## Claims", 1)[0].split())
    assert "never clears a sentence on another line" in head


def test_ledger_names_the_commonmark_reader():
    text = " ".join(_section("What the tests enforce and what only a reader catches").split())
    assert "markdown-it-py" in text and "CommonMark" in text
    assert "Python-Markdown" not in text and "superfences" not in text


@pytest.mark.parametrize("token", ["adapters/guardian-go/main.go", "labs/finbot/viewer/static/app.ts",
                                   "crates/a/b/c/lib.rs", "docs/", "a/b/c/d/e/"])
def test_evidence_paths_cover_more_suffixes_and_depths(token):
    paths, _ = lab_claims._evidence(f"| C-01 | Claim. | `{token}` (here). | None. |\n")
    assert paths == (("C-01", token),)


def test_evidence_says_which_tokens_it_skips(tree, capsys):
    root, ledger = tree
    _, skipped = lab_claims._evidence("| C-01 | Claim. | `acs-lab-keys/1` and `adapters/benchmarks` (here). | x |\n")
    assert skipped == (("C-01", "acs-lab-keys/1"), ("C-01", "adapters/benchmarks"))
    lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"])
    assert "skipped C-13 acs-lab-keys/1" in capsys.readouterr().out


# ---------------------------------------------------------------- Fix round 8: GitHub's reading, recorded
#
# pandoc's gfm reader is a CommonMark implementation. It rendered every Markdown matrix layout and every reviewer
# probe from rounds 6 and 7, and the check's own walker and matcher read the result. Those readings are committed in
# GITHUB_FIXTURE, and the check must agree with each one. CI has no pandoc, so only the drift test calls it, and only
# where pandoc is installed.

GITHUB_FIXTURE = ROOT / "tests" / "fixtures" / "lab_claims_github.json"
PANDOC = shutil.which("pandoc")
# Source line breaks in prose carry lab_claims.LINE, as the check's own renderer emits them, so a marker binds the
# same way in both readings.
PANDOC_FILTER = """
local LINE = utf8.char(0xE000)
function SoftBreak() return pandoc.RawInline("html", LINE .. "\\n") end
function LineBreak() return pandoc.RawInline("html", "<br />" .. LINE .. "\\n") end
function RawInline(el)
  if el.format == "html" then el.text = el.text:gsub("\\n", LINE .. "\\n") end
  return el
end
"""


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def _kinds_of(units) -> list[str]:
    banned = lab_claims._phrase_regex(MATRIX_LEDGER.banned, whole_word=True)
    triggers = lab_claims._phrase_regex(MATRIX_LEDGER.triggers, whole_word=False)
    excused = {row: frozenset(lab_claims._key(p) for p in phrases) for row, phrases in MATRIX_LEDGER.excuses}
    return sorted(k for u in units for k, _ in lab_claims._check(u, ".md", MATRIX_LEDGER, banned, triggers, excused))


def _github_reading(body: str, filter_path: str) -> list[str]:
    page = subprocess.run([PANDOC, "-f", "gfm", "-t", "html", "--wrap=preserve", "--lua-filter", filter_path],
                          input=body, capture_output=True, text=True, check=True, timeout=60).stdout
    return _kinds_of(lab_claims._walk(page))


def _check_reading(body: str) -> list[str]:
    units = lab_claims._units(body, ".md")
    return _kinds_of(units)


def _markdown_matrix() -> dict[str, str]:
    return {name: body for name, body, _ in MATRIX + HONEST_MATRIX if name.endswith(".md")}


def _load_fixture() -> dict:
    return json.loads(GITHUB_FIXTURE.read_text(encoding="utf-8"))


def _regenerate(fixture: dict, tmp_path: Path) -> dict:
    """GitHub's reading of every recorded case, from pandoc. Probe bodies come from the fixture itself."""
    filter_path = tmp_path / "lines.lua"
    filter_path.write_text(PANDOC_FILTER, encoding="utf-8")
    bodies = {name: entry["body"] for name, entry in fixture["probes"].items()}
    bodies.update(_markdown_matrix())
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        readings = dict(zip(bodies, pool.map(lambda b: _github_reading(b, str(filter_path)), bodies.values())))
    return {
        "probes": {name: {"body": bodies[name], "github": readings[name]} for name in fixture["probes"]},
        "matrix": {name: {"sha": _digest(bodies[name]), "github": readings[name]} for name in _markdown_matrix()},
    }


GITHUB = _load_fixture() if GITHUB_FIXTURE.exists() else {"probes": {}, "matrix": {}}


def test_github_fixture_covers_every_markdown_layout():
    assert GITHUB["probes"], "the fixture records no reviewer probe"
    assert set(GITHUB["matrix"]) == set(_markdown_matrix())
    stale = [n for n, body in _markdown_matrix().items() if GITHUB["matrix"][n]["sha"] != _digest(body)]
    assert not stale, f"matrix layouts changed since the fixture was recorded: {stale[:5]}"


@pytest.mark.parametrize("name", sorted(GITHUB["probes"]))
def test_probe_reads_as_github_does(name):
    entry = GITHUB["probes"][name]
    assert _check_reading(entry["body"]) == entry["github"], entry["body"]


@pytest.mark.parametrize("name", sorted(GITHUB["matrix"]))
def test_matrix_layout_reads_as_github_does(name):
    assert _check_reading(_markdown_matrix()[name]) == GITHUB["matrix"][name]["github"], name


# The regeneration takes minutes. LAB_CLAIMS_SKIP_PANDOC=1 skips it on a machine that has pandoc, for a quick run.
@pytest.mark.skipif(PANDOC is None or os.environ.get("LAB_CLAIMS_SKIP_PANDOC") == "1",
                    reason="pandoc isn't installed or LAB_CLAIMS_SKIP_PANDOC=1, so the fixture isn't regenerated")
def test_github_fixture_has_not_drifted(tmp_path):
    assert _regenerate(GITHUB, tmp_path) == GITHUB, "pandoc's reading changed: rerun the fixture recording"


# ---------------------------------------------------------------- Fix round 9: marker binding by line everywhere

R9_CAUGHT = [
    # I-1: a sentence ends at . ! or ? followed by any run of closing quotes or brackets.
    ("closer_straight.md", f'A checked row reads "verified." {C4}\n{FORGE}\n', "unledgered"),
    ("closer_curly.md", f"A checked row reads “verified.” {C4}\n{FORGE}\n", "unledgered"),
    ("closer_reverse.md", f'The gateway can forge an allow, and the row reads "failed."\n'
                          f"A checked row reads verified. {C4}\n", "unledgered"),
    ("closer_paren.md", f"Decisions are signed with ML-DSA-65. (The library follows FIPS 204.) {C2}\n{FORGE}\n",
     "unledgered"),
    ("closer_paren_before.md", f"{FORGE}\n(The library follows FIPS 204.) {C2}\n", "unledgered"),
    ("closer_brace.md", f"Decisions are signed with ML-DSA-65.}} {C2}\n{FORGE}\n", "unledgered"),
    # I-2: in HTML a marker clears only the sentences on its own source line.
    ("p_two_lines.html", f"<p>{SIGNED}\n{FORGE}</p>\n", "unledgered"),
    ("p_two_lines_lead.html", f"<p>{C2} Decisions are signed with ML-DSA-65.\n{FORGE}</p>\n", "unledgered"),
    ("p_center.md", f'<p align="center">\n{SIGNED}\n{FORGE}\n</p>\n', "unledgered"),
    ("div_spans.html", f"<div><span>{SIGNED}</span>\n<span>{FORGE}</span></div>\n", "unledgered"),
    ("div_label_button.md", f"<div>\n<label>{SIGNED}</label>\n<button>{FORGE}</button>\n</div>\n", "unledgered"),
    ("li_two_lines.html", f"<ul><li>{SIGNED}\n{FORGE}</li></ul>\n", "unledgered"),
    ("td_two_cells.html", f"<table><tr><td>{SIGNED}</td>\n<td>{FORGE}</td></tr></table>\n", "unledgered"),
    ("td_two_lines.html", f"<table><tr><td>{SIGNED}\n{FORGE}</td></tr></table>\n", "unledgered"),
    ("br_lines.html", f"<p>{SIGNED}<br>\n{FORGE}</p>\n", "unledgered"),
    ("alone_then_two.html", f"<div>\n{C2}\nDecisions are signed with ML-DSA-65.\n{FORGE}\n</div>\n", "unledgered"),
    ("alone_after_forge.html", f"<div>\n{FORGE}\n{C2}\nDecisions are signed with ML-DSA-65.\n</div>\n",
     "unledgered"),
    # m-5: elements a browser draws as blocks are units of their own.
    ("center_pair.html", f"<div><center>{SIGNED}</center><center>{FORGE}</center></div>\n", "unledgered"),
    ("menu_pair.html", f"<div><menu>{SIGNED}</menu><menu>{FORGE}</menu></div>\n", "unledgered"),
    # m-2: an indented paragraph after a blank line continues a footnote, as prose.
    ("footnote_para.md", "Signing is on.[^1]\n\n[^1]: See the key document.\n\n    The gateway can forge an allow.\n",
     "unledgered"),
]


@pytest.mark.parametrize("name,body,kind", R9_CAUGHT, ids=[c[0] for c in R9_CAUGHT])
def test_round_9_overclaim_is_caught(tree, name, body, kind):
    findings = _scan(tree, {name: body})
    assert kind in _kinds(findings), findings
    # The finding names the unmarked sentence, never the marked one.
    assert all("ML-DSA-65" not in f.text or "forge" in f.text for f in findings), findings


R9_PASSES = [
    # A marker alone on its line binds the next non-blank line's sentences.
    ("alone_next_line.html", f"<div>\n{C2}\n\nDecisions are signed with ML-DSA-65.\n</div>\n"),
    ("alone_next_line_p.html", f"<p>{C2}\nDecisions are signed with ML-DSA-65.</p>\n"),
    # A marker alone in a table cell binds its row, as a GFM row on one line does.
    ("cell_alone.md", f"<table>\n<tr>\n<td>Decisions are signed with ML-DSA-65.</td>\n<td>{C2}</td>\n</tr>\n</table>\n"),
    ("cell_alone.html", f"<table><tr><td>Decisions are signed with ML-DSA-65.</td>\n<td> {C2} </td></tr></table>\n"),
    # Every sentence on the marker's own line, in a page.
    ("one_line_two.html", f"<p>Read the key document. Decisions are signed with ML-DSA-65. {C2}</p>\n"),
    ("wrapped.html", f"<p>Anyone holding the HMAC key can\nforge an allow. {C4}</p>\n"),
    ("closer_honest.md", f'A forged row reads "failed." {C4}\nRead the key document.\n'),
    ("footnote_para_marked.md", f"Signing is on.[^1]\n\n[^1]: See the key document.\n\n    {SIGNED}\n"),
]


@pytest.mark.parametrize("name,body", R9_PASSES, ids=[c[0] for c in R9_PASSES])
def test_round_9_honest_text_passes(tree, name, body):
    assert [f for f in _scan(tree, {name: body}) if f.path == name] == []


# The binding matrix. It doesn't use the pandoc fixtures, which record how a source is read but run the check's own
# binder. Each case holds one marked claim and one unmarked overclaim on the line before or after the marker's line,
# and asserts which sentence is cleared and which is reported.
BIND_ENDINGS = {
    "period": "Decisions are signed with ML-DSA-65.",
    "straight_quote": 'A checked row says the decision was "signed with ML-DSA-65."',
    "curly_quote": "A checked row says the decision was “signed with ML-DSA-65.”",
    "paren": "(Decisions are signed with ML-DSA-65.)",
    # Round 10: a no-break space after the period, as pasted text carries it.
    "nbsp": "Decisions are signed with ML-DSA-65.\u00a0",
    # Round 11: invisible format characters after the period, as copied text carries them.
    **{f"invisible_{ord(ch):04x}": f"Decisions are signed with ML-DSA-65.{ch}" for ch in "\u200b\u200c\u200d\u2060\ufeff\u00ad"},
}
BIND_POSITIONS = ("trail", "lead", "alone")


def _bind_lines(claim: str, position: str, before: bool) -> list[str]:
    if position == "trail":
        lines = [f"{claim} {C2}"]
    elif position == "lead":
        lines = [f"{C2} {claim}"]
    else:
        lines = [C2, claim]
    return [FORGE] + lines if before else lines + [FORGE]


# (name, suffix, builder, positions it applies to). A Markdown prose container reads a marker alone on its line as an
# HTML block of its own, which marks nothing, so "alone" applies only where the lines sit inside raw HTML.
BIND_CONTAINERS = [
    ("paragraph", (".md",), lambda ls: "\n".join(ls) + "\n", ("trail", "lead")),
    ("list_item", (".md",), lambda ls: "- " + "\n  ".join(ls) + "\n", ("trail", "lead")),
    ("blockquote", (".md",), lambda ls: "> " + "\n> ".join(ls) + "\n", ("trail", "lead")),
    ("p", (".md", ".html"), lambda ls: "<p>\n" + "\n".join(ls) + "\n</p>\n", BIND_POSITIONS),
    ("p_center", (".md", ".html"), lambda ls: '<p align="center">\n' + "\n".join(ls) + "\n</p>\n", BIND_POSITIONS),
    ("div", (".md", ".html"), lambda ls: "<div>\n" + "\n".join(ls) + "\n</div>\n", BIND_POSITIONS),
    ("br", (".md", ".html"), lambda ls: "<p>" + "<br>\n".join(ls) + "</p>\n", BIND_POSITIONS),
    ("spans", (".md", ".html"), lambda ls: "<div>" + "\n".join(f"<span>{x}</span>" for x in ls) + "</div>\n",
     ("trail", "lead")),
    ("li", (".html",), lambda ls: "<ul><li>" + "\n".join(ls) + "</li></ul>\n", BIND_POSITIONS),
    ("td_lines", (".md", ".html"), lambda ls: "<table><tr><td>" + "\n".join(ls) + "</td></tr></table>\n",
     BIND_POSITIONS),
    ("td_cells", (".md", ".html"),
     lambda ls: "<table><tr>" + "\n".join(f"<td>{x}</td>" for x in ls) + "</tr></table>\n", ("trail", "lead")),
]


def _binding_matrix():
    cases = []
    for cname, suffixes, build, positions in BIND_CONTAINERS:
        for suffix in suffixes:
            for position in positions:
                for ending, claim in BIND_ENDINGS.items():
                    for before in (True, False):
                        side = "before" if before else "after"
                        body = build(_bind_lines(claim, position, before))
                        cases.append((f"{cname}-{position}-{ending}-{side}{suffix}", body))
    return cases


BINDING_MATRIX = _binding_matrix()


def test_binding_matrix_size():
    assert len(BINDING_MATRIX) == 1034 and len({n for n, _ in BINDING_MATRIX}) == len(BINDING_MATRIX)


def _binding_holds(tmp_path: Path, name: str, body: str) -> str:
    """Empty when the marked claim is cleared and the neighboring overclaim is reported, else what went wrong."""
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    findings = lab_claims.scan(tmp_path, MATRIX_LEDGER)
    path.unlink()
    if [f.kind for f in findings] != ["unledgered"] or "forge" not in findings[0].text \
            or "ML-DSA-65" in findings[0].text or "claim:" in findings[0].text:
        return f"reported {findings}"
    # Both directions, read off the binder itself: the claim's sentence carries C-02 and the overclaim's carries none.
    # The report alone can't show the first when the overclaim comes first, since only one finding is kept per unit.
    pieces = [p for u in lab_claims._units(body, Path(name).suffix) for p in lab_claims._sentences(u)]
    claim = [m for t, m in pieces if "ML-DSA-65" in t]
    forge = [m for t, m in pieces if "forge" in t]
    if not claim or not all("C-02" in m for m in claim):
        return f"claim not cleared {pieces}"
    if not forge or any(forge):
        return f"overclaim bound {pieces}"
    return ""


@pytest.mark.parametrize("name,body", BINDING_MATRIX, ids=[c[0] for c in BINDING_MATRIX])
def test_marker_binds_only_its_own_line(tmp_path, name, body):
    problem = _binding_holds(tmp_path, name, body)
    assert not problem, f"{name}:\n{body}\n{problem}"


@pytest.mark.parametrize("mutant", ["binds_nothing", "binds_everything"])
def test_binding_matrix_catches_a_broken_binder(tmp_path, monkeypatch, mutant):
    # Minor 1: each half of the matrix, before and after, fails against a binder that binds nothing or everything.
    real = lab_claims._sentences

    def broken(unit):
        every = tuple(i for _, i, _ in unit.marks) or unit.markers
        return [(t, () if mutant == "binds_nothing" else every) for t, _ in real(unit)]

    # A Markdown line that opens with a marker is an HTML block, a unit apart from the overclaim, so no binder can
    # join them there: paragraph-lead and blockquote-lead, 11 endings, both sides. Every other case puts the marker and
    # the overclaim in one unit, where only the binder decides.
    shared = [(n, b) for n, b in BINDING_MATRIX
              if any("forge" in u.text and u.marks for u in lab_claims._units(b, Path(n).suffix))]
    assert len(shared) == len(BINDING_MATRIX) - 44
    monkeypatch.setattr(lab_claims, "_sentences", broken)
    for side in ("before", "after"):
        survivors = [n for n, b in shared if f"-{side}." in n and not _binding_holds(tmp_path, n, b)]
        assert not survivors, f"{mutant}: {len(survivors)} {side} cases still pass, such as {survivors[:3]}"


def test_fixture_probe_names_are_pinned():
    # m-1: the drift test regenerates from the fixture's own probe list, so a dropped probe shows only here.
    assert len(GITHUB["probes"]) == 207 + len([c for c in R9_CAUGHT + R9_PASSES if c[0].endswith(".md")])


def test_ledger_says_fixtures_check_reading_not_binding():
    text = " ".join(_section("What the tests enforce and what only a reader catches").split())
    assert "how the source is read, not how markers bind" in text
    assert "with no closing punctuation" in text


def test_pandoc_drift_test_has_a_switch():
    head = Path(__file__).read_text(encoding="utf-8").split("def test_github_fixture_has_not_drifted", 1)[0]
    assert "LAB_CLAIMS_SKIP_PANDOC" in head.rsplit("@pytest.mark.skipif", 1)[-1]


# ---------------------------------------------------------------- Fix round 10: Unicode spaces and finding text

NBSP = "\u00a0"
R10_CAUGHT = [
    # I-1: a no-break or other Unicode space after a marked sentence doesn't bind the next line's overclaim.
    ("ctrl_plain.md", f"{SIGNED}\n{FORGE}\n"),
    ("nbsp_before_marker.md", f"Decisions are signed with ML-DSA-65.{NBSP}{C2}\n{FORGE}\n"),
    ("gdocs_nbsp_space.md", f"Decisions are signed with ML-DSA-65.{NBSP} {C2}\n{FORGE}\n"),
    ("trailing_nbsp.md", f"{SIGNED}{NBSP}\n{FORGE}\n"),
    ("lead_marker_trailing_nbsp.md", f"{C2} Decisions are signed with ML-DSA-65.{NBSP}\n{FORGE}\n"),
    ("thin_space.md", f"Decisions are signed with ML-DSA-65.\u2009{C2}\n{FORGE}\n"),
    ("narrow_nbsp.md", f"Decisions are signed with ML-DSA-65.\u202f{C2}\n{FORGE}\n"),
    ("html_entity.html", f"<p>Decisions are signed with ML-DSA-65.&nbsp; {C2}\n{FORGE}</p>\n"),
    ("html_entity_md.md", f"Decisions are signed with ML-DSA-65.&nbsp; {C2}\n{FORGE}\n"),
    ("list_item.md", f"- Decisions are signed with ML-DSA-65.{NBSP}{C2}\n  {FORGE}\n"),
    ("td_html.html", f"<table><tr><td>Decisions are signed with ML-DSA-65.&nbsp;{C2}\n{FORGE}</td></tr></table>\n"),
    ("closer_quote_nbsp.md", f'A checked row reads "verified."{NBSP}{C4}\n{FORGE}\n'),
]


@pytest.mark.parametrize("name,body", R10_CAUGHT, ids=[c[0] for c in R10_CAUGHT])
def test_round_10_unicode_space_does_not_widen_a_marker(tree, name, body):
    findings = _scan(tree, {name: body})
    assert [f.kind for f in findings] == ["unledgered"], findings
    assert "forge" in findings[0].text and "verified" not in findings[0].text and "ML-DSA" not in findings[0].text


def test_finding_text_never_quotes_a_marker(tree):
    # Minor 2: the split falls before a trailing comment, so the next sentence opened with the marker's text.
    findings = _scan(tree, {"a.md": f"{SIGNED}\n{FORGE}\n", "b.html": f"<p>{SIGNED}\n{FORGE}</p>\n",
                            "c.md": f"The gateway can forge an allow. {C4} {C2}\n"})
    assert findings and all("claim:" not in f.text for f in findings), findings


def test_ledger_says_a_marker_cell_binds_its_row():
    head = " ".join(LEDGER.read_text(encoding="utf-8").split("## Claims", 1)[0].split())
    assert "a marker alone in a table cell binds its row, every cell of it" in head


def test_reader_only_list_names_the_round_10_parks():
    text = " ".join(_section("What the tests enforce and what only a reader catches").split())
    for phrase in ("footnote reference or a `<sup>`", "line break inside a start tag", "fail loudly"):
        assert phrase in text, phrase


# ---------------------------------------------------------------- Fix round 11: invisible characters and line ends

INVISIBLE = "\u200b\u200c\u200d\u2060\ufeff\u00ad"


def _r11_layouts():
    cases = []
    for ch in INVISIBLE:
        tag = f"{ord(ch):04x}"
        after_period = f"Decisions are signed with ML-DSA-65.{ch}{C2}"
        line_end = f"{SIGNED}{ch}"
        for where, line in (("after_period", after_period), ("line_end", line_end)):
            for side, lines in (("after", [line, FORGE]), ("before", [FORGE + ch, line])):
                text = "\n".join(lines)
                cases += [(f"{tag}-{where}-{side}.md", text + "\n"), (f"{tag}-{where}-{side}.txt", text + "\n"),
                          (f"{tag}-{where}-{side}.html", f"<p>{text}</p>\n")]
    return cases


R11_INVISIBLE = _r11_layouts()


@pytest.mark.parametrize("name,body", R11_INVISIBLE, ids=[c[0] for c in R11_INVISIBLE])
def test_invisible_character_does_not_widen_a_marker(tree, name, body):
    findings = _scan(tree, {name: body})
    assert [f.kind for f in findings] == ["unledgered"], findings
    assert "forge" in findings[0].text and "ML-DSA" not in findings[0].text, findings


def test_invisible_character_inside_a_sentence_keeps_it_whole(tree):
    body = f"Decisions are signed\u200b with ML-DSA-65 {C2}\nas FIPS 204 says.\n"
    assert _scan(tree, {"a.md": body, "b.html": f"<p>{body}</p>\n"}) == []


R11_SEPARATORS = [(f"{name}{suffix}", sep) for name, sep in (("u2028", "\u2028"), ("u2029", "\u2029"),
                                                              ("u0085", "\u0085"), ("lone_cr", "\r"))
                  for suffix in (".md", ".html", ".txt")]


@pytest.mark.parametrize("name,sep", R11_SEPARATORS, ids=[c[0] for c in R11_SEPARATORS])
def test_unicode_and_cr_line_separators_break_lines(tree, name, sep):
    text = f"{SIGNED}{sep}{FORGE}"
    body = f"<p>{text}</p>\n" if name.endswith(".html") else text + "\n"
    root, _ = tree
    (root / name).write_bytes(body.encode("utf-8"))
    findings = lab_claims.scan(root, lab_claims.load_ledger(tree[1]))
    assert [f.kind for f in findings] == ["unledgered"], findings
    assert "forge" in findings[0].text and "ML-DSA" not in findings[0].text, findings
    # A plain-text line is its own unit, so its pointer is the overclaim's own line. A rendered unit points at its
    # first line, as before this round.
    assert not name.endswith(".txt") or findings[0].line == 2, findings


R11_COMMENT_QUOTES = [
    ("in_marker.md", "Keys are verified. <!-- claim:C-03 stops attacks -->\n", "stops attacks"),
    ("in_marker.txt", "Keys are verified. <!-- claim:C-03 stops attacks -->\n", "stops attacks"),
    ("in_marker.html", "<p>Keys are verified. <!-- claim:C-03 stops attacks --></p>\n", "stops attacks"),
    ("alone.md", "<!-- claim:C-02 independently tested -->\n", "independently tested"),
    ("alone_p.html", "<p><!-- claim:C-02 independently tested --></p>\n", "independently tested"),
    ("wrapped.md", "Keys are verified. <!-- claim:C-03\nstops attacks -->\nMore text here.\n", "stops attacks"),
    ("not_claimed.md", "Not claimed. <!-- claim:N-02 AGT -->\n", "AGT"),
]


@pytest.mark.parametrize("name,body,phrase", R11_COMMENT_QUOTES, ids=[c[0] for c in R11_COMMENT_QUOTES])
def test_banned_phrase_in_a_marker_comment_is_quoted(tree, name, body, phrase):
    findings = [f for f in _scan(tree, {name: body}) if f.kind == "banned"]
    assert findings and all(phrase in f.text and f.text.strip() for f in findings), findings
    assert all("claim:" not in f.text for f in findings), findings


# ---------------------------------------------------------------- Final review: the check never skips silently

def _main(tree, *extra):
    root, ledger = tree
    return lab_claims.main([str(root), "--ledger", str(ledger), *extra])


OVERCLAIM = "The lab supports Windows and is production-ready.\n"


@pytest.mark.parametrize("encoding,bom", [("utf-8", b"\xef\xbb\xbf"), ("utf-16-le", b"\xff\xfe"),
                                          ("utf-16-be", b"\xfe\xff"), ("utf-32-le", b"\xff\xfe\x00\x00"),
                                          ("utf-32-be", b"\x00\x00\xfe\xff")])
def test_r1_a_byte_order_mark_file_is_decoded_and_scanned(tree, capsys, encoding, bom):
    root, _ = tree
    (root / "README.md").write_bytes(bom + OVERCLAIM.encode(encoding))
    assert _main(tree) == 1
    out = capsys.readouterr().out
    assert "README.md:1 banned" in out and "(0 files)" not in out


def test_r1_an_undecodable_prose_file_is_named_and_fails(tree, capsys):
    root, _ = tree
    (root / "README.md").write_bytes(OVERCLAIM.encode("utf-16-le"))
    assert _main(tree) == 2
    out = capsys.readouterr().out
    assert "SKIPPED: README.md" in out and "DONE" not in out


def test_r1_a_non_prose_binary_is_still_not_scanned(tree, capsys):
    root, _ = tree
    (root / "clip.mp4").write_bytes(b"\x00\x01ACS-Core conformant")
    (root / "a.md").write_text("Plain.\n", encoding="utf-8")
    assert _main(tree, ) == 0


@pytest.mark.parametrize("token,path", [
    ("adapters/src/acs/core/_nothing_here.py:12", "adapters/src/acs/core/_nothing_here.py"),
    ("adapters/src/acs/core/_nothing_here.py:12-30", "adapters/src/acs/core/_nothing_here.py"),
    ("docs/nothing_here.md#section", "docs/nothing_here.md"),
    ("adapters/nothing@v1/x.py", "adapters/nothing@v1/x.py"),
    ("adapters/no+thing~1/x.py", "adapters/no+thing~1/x.py"),
    ("NOTHING.MD", "NOTHING.MD"),
])
def test_r2_evidence_with_a_line_or_anchor_is_checked(tree, capsys, token, path):
    paths, _ = lab_claims._evidence(f"| C-01 | Claim. | `{token}` (here). | None. |\n")
    assert paths == (("C-01", path),)
    root, _ = tree
    ledger = _evidence_ledger(tree, f"`{token}` (gone).")
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert f"missing_evidence C-15 {path}" in capsys.readouterr().out


def test_r2_a_cited_line_in_a_real_file_passes():
    ledger = lab_claims.Ledger(ids=frozenset(), banned=(), triggers=(), exclude=(), signed=True,
                               evidence=(("C-01", "labs/finbot/cli/lab_claims.py"),))
    assert lab_claims.missing_evidence(ledger, ROOT) == []
    paths, _ = lab_claims._evidence("| C-01 | x | `labs/finbot/cli/lab_claims.py:10` | y |\n")
    assert paths == (("C-01", "labs/finbot/cli/lab_claims.py"),)


def test_r3_an_unlistable_directory_is_named(tree, capsys):
    root, _ = tree
    (root / "sub").mkdir()
    (root / "sub" / "a.md").write_text(OVERCLAIM, encoding="utf-8")
    (root / "sub").chmod(0)
    try:
        if os.access(root / "sub", os.R_OK):
            pytest.skip("running as a user who can list any directory")
        # Named on every run, and a failure only at the sign gate, as for any skip that isn't an unreadable prose file.
        code = _main(tree)
        out = capsys.readouterr().out
        assert "SKIPPED: sub" in out and code == 0
        assert _main(tree, "--require-signed") == 2
    finally:
        (root / "sub").chmod(0o755)


def test_r3_a_symlinked_prose_file_is_named_and_fails_the_sign_gate(tree, capsys):
    root, ledger = tree
    outside = ledger.parent / "outside"
    outside.mkdir()
    (outside / "a.md").write_text(OVERCLAIM, encoding="utf-8")
    (root / "README.md").symlink_to(outside / "a.md")
    (root / "docs").symlink_to(outside, target_is_directory=True)
    assert _main(tree) == 0
    out = capsys.readouterr().out
    assert "SKIPPED: README.md" in out and "SKIPPED: docs" in out
    assert _main(tree, "--require-signed") == 2


def test_r4_evidence_paths_match_case_exactly(tmp_path):
    (tmp_path / "adapters" / "gateway").mkdir(parents=True)
    (tmp_path / "adapters" / "gateway" / "README.md").write_text("x\n", encoding="utf-8")
    ledger = lab_claims.Ledger(ids=frozenset(), banned=(), triggers=(), exclude=(), signed=True,
                               evidence=(("C-01", "Adapters/Gateway/readme.md"), ("C-02", "adapters/gateway/README.md"),
                                         ("C-03", "adapters/Gateway/"), ("C-04", "adapters/gateway/")))
    assert lab_claims.missing_evidence(ledger, tmp_path) == [("C-01", "Adapters/Gateway/readme.md"),
                                                             ("C-03", "adapters/Gateway/")]


def test_r5_a_claim_row_without_a_leading_pipe_is_read(tree):
    _, ledger = tree
    text = ledger.read_text(encoding="utf-8").replace(
        "| C-16 |", "C-18 | A claim. | Unconfirmed: nothing yet. | None. |\n| C-16 |", 1)
    ledger.write_text(text, encoding="utf-8")
    parsed = lab_claims.load_ledger(ledger)
    assert "C-18" in parsed.ids and "C-18" in parsed.unconfirmed


def test_r5_a_row_inside_a_fenced_example_is_not_an_id(tree):
    _, ledger = tree
    example = "```text\n| C-99 | example | `x.py` | none |\n```\n\n## Claims\n"
    ledger.write_text(ledger.read_text(encoding="utf-8").replace("## Claims\n", example, 1), encoding="utf-8")
    parsed = lab_claims.load_ledger(ledger)
    assert "C-99" not in parsed.ids and ("C-99", "x.py") not in parsed.evidence


def test_r6_an_unexpected_error_exits_2(tree, capsys, monkeypatch):
    root, _ = tree
    (root / "a.md").write_text("Plain.\n", encoding="utf-8")

    def boom(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(lab_claims, "_units", boom)
    assert _main(tree) == 2
    err = capsys.readouterr().err
    assert err.startswith("ERROR:") and len(err.strip().splitlines()) == 1


def test_r7_source_line_pointer_stays_linear(tree):
    import time
    root, _ = tree
    (root / "a.md").write_text("".join(f"&#65;bc paragraph {i}.\n\n" for i in range(8000)), encoding="utf-8")
    start = time.perf_counter()
    lab_claims.scan(root, lab_claims.load_ledger(tree[1]))
    # Round 11 took about 20 s on this shape, and a bounded search takes well under one.
    assert time.perf_counter() - start < 5


def test_r7_an_oversize_prose_file_is_named_and_fails(tree, capsys, monkeypatch):
    root, _ = tree
    monkeypatch.setattr(lab_claims, "MAX_BYTES", 64)
    (root / "a.md").write_text("Plain words. " * 10, encoding="utf-8")
    assert _main(tree) == 2
    assert "SKIPPED: a.md" in capsys.readouterr().out


def test_ledger_names_what_the_check_skips():
    text = " ".join(_section("What the tests enforce and what only a reader catches").split())
    assert "never skips a file silently" in text and "symlink" in text


def test_r7_pointer_reaches_past_a_long_code_block(tree):
    # The bounded search starts its window after the previous unit, so a long code block doesn't hide the next line.
    body = "Intro.\n\n```\n" + "x = 1\n" * 300 + "```\n\nThe lab is ACS-Core conformant.\n"
    assert [(f.kind, f.line) for f in _scan(tree, {"a.md": body})] == [("banned", 306)]


# ---------------------------------------------------------------- Final review, round 2

def test_r8_a_windows_1252_file_is_named_and_fails(tree, capsys):
    root, _ = tree
    (root / "a.md").write_bytes("The lab is production–ready.\n".encode("cp1252"))
    assert _main(tree) == 2
    out = capsys.readouterr().out
    assert "SKIPPED: a.md undecodable" in out and "DONE" not in out


def test_r8_nul_bytes_after_the_first_8_kib_fail_the_run(tree, capsys):
    root, _ = tree
    head = ("Plain words here. " * 600).encode("utf-8")
    assert len(head) > lab_claims.SNIFF_BYTES
    (root / "a.md").write_bytes(head + OVERCLAIM.encode("utf-16-le"))
    assert _main(tree) == 2
    assert "SKIPPED: a.md undecodable" in capsys.readouterr().out


def test_r9_a_crash_while_the_ledger_loads_exits_2(tree, capsys, monkeypatch):
    def boom(path):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(lab_claims, "load_ledger", boom)
    assert _main(tree) == 2
    err = capsys.readouterr().err
    assert err.startswith("ERROR:") and len(err.strip().splitlines()) == 1


def test_r10_an_unlistable_scan_root_exits_2(tree, capsys):
    root, _ = tree
    (root / "a.md").write_text(OVERCLAIM, encoding="utf-8")
    root.chmod(0o311)
    try:
        if os.access(root, os.R_OK):
            pytest.skip("running as a user who can list any directory")
        assert _main(tree) == 2
        out = capsys.readouterr().out
        assert "SKIPPED: . unlistable" in out and "DONE" not in out
    finally:
        root.chmod(0o755)


def test_r11_an_excluded_directory_is_never_entered(tree, capsys):
    root, _ = tree
    (root / "state" / "secrets").mkdir(parents=True)
    (root / "state" / "secrets" / "a.md").write_text(OVERCLAIM, encoding="utf-8")
    (root / "state" / "secrets").chmod(0)
    try:
        if os.access(root / "state" / "secrets", os.R_OK):
            pytest.skip("running as a user who can list any directory")
        assert _main(tree) == 0
        assert "SKIPPED" not in capsys.readouterr().out
        assert _main(tree, "--require-signed") == 1
    finally:
        (root / "state" / "secrets").chmod(0o755)


@pytest.mark.parametrize("name", ["README", "guide.rst", "guide.adoc", "guide.mdx"])
def test_r12_other_prose_names_are_scanned_as_plain_text(tree, name):
    findings = _scan(tree, {name: OVERCLAIM})
    assert [(f.path, f.kind) for f in findings] == [(name, "banned")]


def test_r12_a_suffixless_file_that_is_not_a_readme_is_not_scanned(tree):
    assert _scan(tree, {"Makefile": OVERCLAIM, "LICENSE": OVERCLAIM}) == []


def test_r13_an_evidence_path_with_a_space_is_checked(tree, capsys):
    paths, _ = lab_claims._evidence("| C-01 | x | `docs/my file.md` and `my notes.txt` | y |\n")
    assert paths == (("C-01", "docs/my file.md"), ("C-01", "my notes.txt"))
    root, _ = tree
    ledger = _evidence_ledger(tree, "`docs/no such file.md` (gone).")
    assert lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"]) == 1
    assert "missing_evidence C-15 docs/no such file.md" in capsys.readouterr().out


def test_ledger_header_says_test_directories_are_never_scanned():
    head = " ".join(LEDGER.read_text(encoding="utf-8").split("## Claims", 1)[0].split())
    assert "directories named `tests` or `test` are never scanned" in head.lower()


# ---------------------------------------------------------------- Ledger bypass reword


def test_c17_claims_the_agent_cannot_bypass_the_guardian(tree):
    _, ledger = tree
    parsed = lab_claims.load_ledger(ledger)
    assert "C-17" in parsed.ids and "C-17" not in parsed.unconfirmed
    rows = {r[0]: r for r in _rows(_section("Claims"))}
    assert rows["C-17"][1].startswith("FinBot can't bypass the Guardian.")
    assert "ClientTokenGate" in rows["C-17"][2]
    assert "hooks in C-06" in rows["C-17"][3]


def test_c17_is_confirmed_by_the_network_and_the_token():
    # Rock, 2026-11-22: finbot-net is internal, so the network itself keeps FinBot off any model but the gateway.
    evidence = {r[0]: r for r in _rows(_section("Claims"))}["C-17"][2]
    assert "unconfirmed" not in evidence.lower()
    for path in ("labs/finbot/compose.yaml:69-71", "labs/finbot/compose.yaml:332-333", "labs/finbot/compose.yaml:329-330",
                 "labs/finbot/compose.yaml:166-171", "labs/finbot/compose.yaml:63",
                 "adapters/gateway/src/acs_gateway/app.py:1479-1511", "labs/finbot/cli/commands.py:147-148",
                 "labs/finbot/images/smoke.sh:126-156"):
        assert f"`{path}`" in evidence, path


def test_c08_cites_the_viewer_and_leaves_capture_open():
    evidence = {r[0]: r for r in _rows(_section("Claims"))}["C-08"][2]
    cited, pending = evidence.split("Unconfirmed", 1)
    assert "`labs/finbot/viewer/model.py:962-965`" in cited and "`labs/finbot/viewer/static/app.js:131-136`" in cited
    assert "`replay miss: recorded neutral reply`" in cited
    assert "LAB-16" in pending and "recorded model" in pending and "viewer" not in pending
    assert ("C-08", "labs/finbot/viewer/model.py") in lab_claims.load_ledger(LEDGER).evidence


def test_c01_names_where_each_finbot_default_lives():
    # Each changed default is named with its file and line at 1450fc4, and the row is confirmed from that.
    row = {r[0]: r for r in _rows(_section("Claims"))}["C-01"]
    assert "unconfirmed" not in " ".join(row).lower()
    for needle in ("finbot/config.py line 102", "Dockerfile line 35", "docker-compose.yml lines 11-13",
                   "finbot/core/llm/openai_client.py line 29"):
        assert needle in row[2], needle
    assert "60, the default in finbot/config.py" in row[1] and "3, the default in the app stage" in row[1]


def test_c07_is_retired_and_no_rule_asks_for_an_attempt_count():
    # Rock, 2026-11-22: the clips state no attempt count. The id stays so nothing renumbers.
    row = {r[0]: r for r in _rows(_section("Claims"))}["C-07"]
    assert row[1] == "Retired 2026-11-22." and row[2] == "Rock, 2026-11-22."
    assert "C-07" not in lab_claims.load_ledger(LEDGER).unconfirmed
    text = LEDGER.read_text(encoding="utf-8")
    assert "N attempts" not in text and "attempt count." not in text.replace("state an attempt count.", "")


def test_n01_leads_with_the_bypass_claim_not_hiding():
    rows = {r[0]: r for r in _rows(_section("Not claimed"))}
    assert rows["N-01"][1] == "That the control is hidden from the agent."
    assert "can't bypass it (C-17)" in rows["N-01"][2]


def test_hidden_from_the_agent_is_banned_and_excused_only_by_n01(tree):
    line = "The control is hidden from the agent.{}\n"
    assert "banned" in _kinds(_scan(tree, {"a.md": line.format("")}))
    assert "banned" in _kinds(_scan(tree, {"b.md": line.format(" <!-- claim:N-02 -->")}))
    assert [f for f in _scan(tree, {"c.md": line.format(" <!-- claim:N-01 -->")}) if f.path == "c.md"] == []
    # The two earlier N-01 phrases stay excused.
    kept = "It is invisible to the agent. <!-- claim:N-01 -->\n"
    assert [f for f in _scan(tree, {"d.md": kept}) if f.path == "d.md"] == []


def test_ledger_holds_no_disclosures_section():
    # Rock, 2026-11-22: the disclaimers are cut. The neutral deny line stays as demo content in the guides.
    assert "## Disclosures" not in LEDGER.read_text(encoding="utf-8")


def test_n07_and_n12_are_retired_and_excuse_nothing():
    # Rock, 2026-11-22: both non-claims are cut. The ids stay so nothing renumbers, and their phrases stay banned with
    # no row left to excuse them.
    rows = {r[0]: r for r in _rows(_section("Not claimed"))}
    for row in ("N-07", "N-12"):
        assert rows[row][1] == "Retired 2026-11-22." and rows[row][2] == "Rock, 2026-11-22.", row
    ledger = lab_claims.load_ledger(LEDGER)
    assert "N-07" not in dict(ledger.excuses) and "N-12" not in dict(ledger.excuses)
    for phrase in ("stops attacks", "blocks every", "tested by attendees", "independently tested"):
        assert phrase in ledger.banned, phrase


def test_a_retired_not_claimed_row_needs_no_phrase_line(tree):
    root, ledger = tree
    text = ledger.read_text(encoding="utf-8")
    ledger.write_text(text.replace("| N-02 | That requests are attributable. |", "| N-02 | Retired 2026-11-22. |", 1)
                      .replace("N-02: attributable\n", "", 1), encoding="utf-8")
    parsed = lab_claims.load_ledger(ledger)
    assert "N-02" in parsed.ids and "N-02" not in dict(parsed.excuses)
    # A retired row excuses nothing, so its old phrase now fails wherever it appears, and so does its marker.
    (root / "x.md").write_text("Requests are attributable. <!-- claim:N-02 -->\n", encoding="utf-8")
    assert sorted(f.kind for f in lab_claims.scan(root, parsed)) == ["banned", "retired_id"]


def test_a_retired_not_claimed_row_cannot_keep_a_phrase_line(tree):
    _, ledger = tree
    text = ledger.read_text(encoding="utf-8")
    ledger.write_text(text.replace("| N-02 | That requests are attributable. |", "| N-02 | Retired 2026-11-22. |", 1),
                      encoding="utf-8")
    with pytest.raises(ValueError, match="retired"):
        lab_claims.load_ledger(ledger)


# ---------------------------------------------------------------- Retired rows, review round 4


@pytest.mark.parametrize("row", ["N-07", "C-07"])
def test_a_marker_for_a_retired_row_ledgers_nothing(tree, row):
    # I2: a retired id stays in the ledger so nothing renumbers, but a marker naming it backs no claim.
    findings = _scan(tree, {"a.md": f"ACS guarantees the agent cannot get around the gateway. <!-- claim:{row} -->\n"})
    kinds = _kinds(findings)
    assert "retired_id" in kinds and "unledgered" in kinds, findings


def test_a_marker_for_a_retired_row_fails_even_on_plain_text(tree):
    findings = _scan(tree, {"a.md": "The lab has seven modules. <!-- claim:N-12 -->\n"})
    assert _kinds(findings) == ["retired_id"], findings


def test_the_sign_gate_names_a_retired_claim_row(tree, capsys):
    # I3: a live row rewritten into retired form never reads as confirmed. The gate names it as retired.
    root, ledger = tree
    text = ledger.read_text(encoding="utf-8")
    start = text.index("| C-09 |")
    end = text.index("\n", start)
    ledger.write_text(text[:start] + "| C-09 | Retired 2026-11-22. | Rock, 2026-11-22. | None. |" + text[end:],
                      encoding="utf-8")
    parsed = lab_claims.load_ledger(ledger)
    assert "C-09" in parsed.retired and "C-09" not in parsed.unconfirmed
    lab_claims.main([str(root), "--ledger", str(ledger), "--require-signed"])
    assert "retired C-09" in capsys.readouterr().out


@pytest.mark.parametrize("cell", ["Retired 2026-11-22: Release 0.1.5 adds signing.", "Retired 2026-11-22",
                                  "Retired on 2026-11-22.", "retired 2026-11-22."])
def test_a_retired_row_holds_only_the_retirement_line(tree, cell):
    # A retired row can't carry a claim beside the retirement, so anything but the exact form is refused.
    _, ledger = tree
    text = ledger.read_text(encoding="utf-8")
    start = text.index("| C-09 |")
    end = text.index("\n", start)
    ledger.write_text(text[:start] + f"| C-09 | {cell} | Rock, 2026-11-22. | None. |" + text[end:], encoding="utf-8")
    with pytest.raises(ValueError, match="Retired YYYY-MM-DD"):
        lab_claims.load_ledger(ledger)


def test_the_ledger_retires_c07_c12_n07_and_n12_in_the_exact_form():
    rows = {r[0]: r for name in ("Claims", "Not claimed") for r in _rows(_section(name))}
    for row in ("C-07", "C-12", "N-07", "N-12"):
        assert rows[row][1] == "Retired 2026-11-22." and rows[row][2] == "Rock, 2026-11-22.", row
    assert set(lab_claims.load_ledger(LEDGER).retired) == {"C-07", "C-12", "N-07", "N-12"}


def test_c11_cites_the_release_version():
    row = {r[0]: r for r in _rows(_section("Claims"))}["C-11"]
    assert "unconfirmed" not in " ".join(row).lower()
    assert ("C-11", "version.txt") in lab_claims.load_ledger(LEDGER).evidence
