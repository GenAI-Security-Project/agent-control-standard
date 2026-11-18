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
    findings = _scan(tree, {"a.py": "# fine\n# ACS-Crypto here\n"})
    assert [(f.kind, f.line) for f in findings] == [("banned", 2)]


def test_scan_outside_repo_skips_binaries(tree):
    findings = _scan(tree, {
        "clip.mp4": b"ACS-Core conformant",
        "blob.txt": b"ACS-Core conformant\x00\x01",
        "latin.md": "Caf\xe9 is ACS-Core conformant\n".encode("latin-1"),
    })
    assert [f.path for f in findings] == ["latin.md"]


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
    for row in ("C-01", "C-03", "C-07", "C-08", "C-11", "C-12"):
        assert f"unconfirmed {row}" in out
    assert "unsigned" not in out
    # Without the flag the same ledger is fine, since CI runs before Rock decides.
    assert lab_claims.main([str(root), "--ledger", str(ledger)]) == 0


def test_unconfirmed_rows_parsed(tree):
    _, ledger = tree
    assert lab_claims.load_ledger(ledger).unconfirmed == ("C-01", "C-03", "C-07", "C-08", "C-11", "C-12")


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


def test_marker_in_a_comment_is_read_from_raw_text(tree):
    # The comment is stripped from the matching copy, but the marker inside it still counts.
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


def test_unclosed_fence_is_a_finding(tree):
    findings = _scan(tree, {"a.md": "```\nx\n\nACS guarantees every attack is stopped.\n"})
    assert "unclosed_fence" in _kinds(findings)


def test_fence_closes_only_on_its_own_marker(tree):
    findings = _scan(tree, {"a.md": "~~~\n```\nACS guarantees safety.\n"})
    assert "unclosed_fence" in _kinds(findings)


def test_file_count_counts_scanned_files_only(tree, capsys):
    root, ledger = tree
    (root / "a.md").write_text("Plain.\n", encoding="utf-8")
    (root / "clip.mp4").write_bytes(b"x")
    (root / "blob.txt").write_bytes(b"x\x00")
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
    text = ledger.read_text(encoding="utf-8").replace(
        "| Unconfirmed: the lab compose file (LAB-15)", "| ok a\\| b Unconfirmed: the lab compose file (LAB-15)", 1)
    ledger.write_text(text, encoding="utf-8")
    assert "C-01" in lab_claims.load_ledger(ledger).unconfirmed


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
    assert "can pin" in rows["C-03"][1] and "unconfirmed" in rows["C-03"][2].lower()
    assert "_response_signing.py" in rows["C-02"][2]
    assert "digest" in _section("What the tests enforce and what only a reader catches")
    assert "non-Markdown" in _section("What the tests enforce and what only a reader catches")


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
    not_claimed = [i for i in loaded.ids if i.startswith("N-")]
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
