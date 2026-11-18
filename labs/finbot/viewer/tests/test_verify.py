"""The verify mark: acs-verify's verdict on each session's whole transcript, shown row by row (issue #586).

A row reads verified only when acs.testing.verify, run over the whole session file, accepts the session and the row's
answer carries a signature it checked. ML-DSA-65 response signing, the key document, and the request hash are lab
conventions (issues #316, #460, #13). Several tests come from the fix round 1 review probes.
"""
from __future__ import annotations

import datetime
import json
import os
import sys
import time

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa",
                    reason="the pqc extra is not installed: uv run --extra pqc")

from acs.core import derive_session_key, sign_with_key  # noqa: E402
from lab_lines import (  # noqa: E402
    HMAC_KEY_ID,
    HMAC_SECRET,
    SESSION_A,
    SESSION_B,
    LabLogs,
    answer,
    decision_key,
    error_answer,
    request,
    sign_hmac,
    tool_request,
)
from model import Model  # noqa: E402
from verify import VERIFY_MARKS, KeySource, load_keys  # noqa: E402


@pytest.fixture
def key(tmp_path):
    return decision_key(tmp_path / "decision-keys")


@pytest.fixture
def keys(key):
    return KeySource({"ACS_GUARDIAN_KEYS": str(key.document_path)})


def marks(logs: LabLogs, keys) -> list[tuple]:
    model = Model(logs.transcript_dir, logs.audit_file, keys)
    model.refresh()
    return [(r.tool or r.method, r.decision, r.verify) for r in sorted(model.rows_after(0), key=lambda r: r.id)]


def stamp(moment: datetime.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def resign(req: dict, session_id: str = SESSION_A) -> dict:
    req["params"].pop("signature", None)
    return sign_with_key(req, derive_session_key(HMAC_SECRET, session_id), key_id=HMAC_KEY_ID)


def test_marks_are_the_six_words():
    assert VERIFY_MARKS == ("verified", "warning", "failed", "not_checked", "unsigned", "no_answer")


def test_genuine_session_verifies(tmp_path, key, keys):
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("rm")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, key.sign(answer(b, "deny"), b))
    assert marks(logs, keys) == [("echo", "allow", "verified"), ("rm", "deny", "verified")]


def test_flipped_decision_fails_its_row_and_stops_the_session(tmp_path, key, keys):
    logs = LabLogs(tmp_path)
    a, b, c = tool_request("echo"), tool_request("rm"), tool_request("ls")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    flipped = key.sign(answer(b, "deny"), b)
    flipped["result"]["decision"] = "allow"
    logs.pair(b, flipped)
    logs.pair(c, key.sign(answer(c, "allow"), c))
    # acs-verify fails the session at the flipped answer, so no row in the session reads verified.
    assert marks(logs, keys) == [("echo", "allow", "not_checked"), ("rm", "allow", "failed"),
                                 ("ls", "allow", "not_checked")]


def test_response_bound_to_another_request_fails(tmp_path, key, keys):
    logs = LabLogs(tmp_path)
    req, other = tool_request("echo"), tool_request("echo")
    relayed = key.sign(answer(other, "allow"), other)
    relayed["id"], relayed["result"]["request_id"] = req["id"], req["params"]["request_id"]
    logs.pair(req, relayed)
    assert marks(logs, keys) == [("echo", "allow", "failed")]


def test_duplicate_pair_fails(tmp_path, key, keys):
    # Probe G: a signed pair copied again later in the same file, a replayed decision.
    logs = LabLogs(tmp_path)
    a, b = tool_request("transfer_funds"), tool_request("read_balance")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, key.sign(answer(b, "deny"), b))
    first_two = logs.transcript().read_bytes().splitlines()[:2]
    with logs.transcript().open("ab") as f:
        f.write(b"\n".join(first_two) + b"\n")
    got = marks(logs, keys)
    assert got[-1] == ("transfer_funds", "allow", "failed")
    assert "verified" not in [m for _, _, m in got]


def test_pair_pasted_from_another_session_fails(tmp_path, key, keys):
    # Probe H: a genuine pair from session B written into session A's file.
    logs = LabLogs(tmp_path)
    x = tool_request("echo")
    logs.pair(x, key.sign(answer(x, "allow"), x))
    y = tool_request("wire_money", session_id=SESSION_B)
    with logs.transcript().open("ab") as f:
        f.write(json.dumps({"dir": "req", "envelope": y}).encode() + b"\n")
        f.write(json.dumps({"dir": "resp", "envelope": key.sign(answer(y, "allow"), y)}).encode() + b"\n")
    assert marks(logs, keys) == [("echo", "allow", "not_checked"), ("wire_money", "allow", "failed")]


def test_forged_cause_on_a_signed_answer_fails(tmp_path, key, keys):
    # Probe F: only decision_timeout may sit on a signed answer.
    logs = LabLogs(tmp_path)
    c = tool_request("pay")
    logs.transcript_dir.mkdir(parents=True)
    with logs.transcript().open("ab") as f:
        f.write(json.dumps({"dir": "req", "envelope": c}).encode() + b"\n")
        f.write(json.dumps({"dir": "resp", "envelope": key.sign(answer(c, "allow"), c),
                            "cause": "upstream_429"}).encode() + b"\n")
    assert marks(logs, keys) == [("pay", "allow", "failed")]


def test_discards_line_that_is_not_next_to_its_answer_fails_only_itself(tmp_path, key, keys):
    # Probe E and round 2 M3: a discards line must follow the answer it marks. One that doesn't fails the session at
    # its own row, and never paints the earlier genuine answer it names as failed.
    logs = LabLogs(tmp_path)
    a, b = tool_request("transfer_funds"), tool_request("read_balance")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, key.sign(answer(b, "deny"), b))
    logs.resp(SESSION_A, None, cause="decision_timeout", discards=a["params"]["request_id"])
    assert marks(logs, keys) == [("transfer_funds", "allow", "not_checked"), ("read_balance", "deny", "not_checked"),
                                 ("withheld", None, "failed")]
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    first = min(model.rows_after(0), key=lambda r: r.id)
    # The stray line doesn't get to call the earlier answer withheld either.
    assert "withheld" not in (first.note or "")


def test_adjacent_discards_line_keeps_the_answer_verified(tmp_path, key, keys):
    logs = LabLogs(tmp_path)
    a = tool_request("echo")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.resp(SESSION_A, None, cause="decision_timeout", discards=a["params"]["request_id"])
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    row, claim = sorted(model.rows_after(0), key=lambda r: r.id)
    assert (row.decision, row.verify) == ("allow", "verified")
    assert "withheld" in row.note
    # The discards line is the gateway's unsigned claim, a row of its own.
    assert (claim.method, claim.verify) == ("withheld", "unsigned")


def test_hmac_session_is_never_verified(tmp_path, keys):
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, sign_hmac(answer(req, "allow")))
    assert marks(logs, keys) == [("echo", "allow", "not_checked")]
    assert marks(logs, None) == [("echo", "allow", "not_checked")]


def test_hmac_answer_after_mldsa_answers_fails(tmp_path, key, keys):
    # The session's first signed answer is ML-DSA-65, so acs-verify checks every answer under the key document.
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("rm")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, sign_hmac(answer(b, "allow")))
    assert marks(logs, keys)[1] == ("rm", "allow", "failed")


def test_unsigned_answer_in_an_mldsa_session_fails(tmp_path, key, keys):
    # M7: only ping and the -32004 for an unknown key_id may go unsigned (specification section 10).
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("rm")
    logs.pair(a, key.sign(answer(a, "deny"), a))
    logs.pair(b, answer(b, "allow"))
    assert marks(logs, keys) == [("echo", "deny", "not_checked"), ("rm", "allow", "failed")]


def test_unsigned_key_id_refusal_reads_unsigned(tmp_path, key, keys):
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("rm")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    # The refused request names a key_id the Guardian holds no secret for, which is when it sends this unsigned error.
    b["params"].pop("signature")
    b = sign_with_key(b, derive_session_key(HMAC_SECRET, SESSION_A), key_id="rotated-away")
    logs.pair(b, error_answer(b, -32004, "SIGNATURE_INVALID"))
    assert marks(logs, keys) == [("echo", "allow", "verified"), ("rm", None, "unsigned")]


def test_no_keys_reads_not_checked(tmp_path, key):
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, key.sign(answer(req, "allow"), req))
    assert marks(logs, None) == [("echo", "allow", "not_checked")]
    assert load_keys({}) is None
    assert KeySource({}).current() is None


def test_unreadable_key_document_reads_as_no_keys(tmp_path):
    bad = tmp_path / "keys.json"
    bad.write_text("{}", encoding="utf-8")
    assert load_keys({"ACS_GUARDIAN_KEYS": str(bad)}) is None
    assert load_keys({"ACS_GUARDIAN_KEYS": str(tmp_path / "missing.json")}) is None


def test_unanswered_reads_no_answer(tmp_path, key, keys):
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("rm")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, None, cause="transport_failure")
    assert marks(logs, keys) == [("echo", "allow", "verified"), ("rm", None, "no_answer")]


def test_key_pin_from_the_gateways_settings_is_honored(tmp_path, key):
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, key.sign(answer(req, "allow"), req))
    pinned = KeySource({"ACS_GUARDIAN_KEYS": str(key.document_path), "ACS_GUARDIAN_KEY_ID": "lab-guardian-1"})
    assert marks(logs, pinned)[0][2] == "verified"
    wrong = KeySource({"ACS_GUARDIAN_KEYS": str(key.document_path),
                       "ACS_GUARDIAN_KEY_FINGERPRINT": "sha256:" + "0" * 64})
    assert marks(logs, wrong)[0][2] == "failed"


def test_backdated_entry_under_a_revoked_key_reads_warning(tmp_path, key):
    # I4, probe C2: the key document revokes the key now, and the entry claims a time before that. acs-verify passes
    # it with a warning, since whoever holds a stolen key chooses the timestamp. The viewer shows the warning.
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, key.sign(answer(req, "allow"), req))
    time.sleep(0.05)
    document = key.document
    document["revoked"] = [{"key_id": "lab-guardian-1",
                            "revoked_at": stamp(datetime.datetime.now(datetime.timezone.utc))}]
    revoked = tmp_path / "revoked.json"
    revoked.write_text(json.dumps(document), encoding="utf-8")
    os.chmod(revoked, 0o644)
    model = Model(logs.transcript_dir, None, KeySource({"ACS_GUARDIAN_KEYS": str(revoked)}))
    model.refresh()
    [row] = model.rows_after(0)
    assert row.verify == "warning"
    assert "revokes it" in row.note


def test_key_document_change_is_picked_up(tmp_path, key):
    # I4: the document is read again when it changes, and every session is judged again under it.
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, key.sign(answer(req, "allow"), req))
    live = tmp_path / "live.json"
    live.write_text(json.dumps(key.document), encoding="utf-8")
    os.chmod(live, 0o644)
    source = KeySource({"ACS_GUARDIAN_KEYS": str(live)})
    model = Model(logs.transcript_dir, None, source)
    model.refresh()
    [row] = model.rows_after(0)
    assert row.verify == "verified"
    other = decision_key(tmp_path / "other-keys")
    live.write_text(json.dumps(other.document), encoding="utf-8")
    os.utime(live, ns=(1, 1))
    model.refresh()
    [changed] = model.rows_after(row.seq)
    assert changed.id == row.id and changed.verify == "failed"


def test_session_too_long_for_the_viewer_reads_not_checked(tmp_path, key, keys, monkeypatch):
    import model as model_module
    monkeypatch.setattr(model_module, "MAX_SESSION_LINES", 4)
    logs = LabLogs(tmp_path)
    for tool in ("a", "b", "c"):
        req = tool_request(tool)
        logs.pair(req, key.sign(answer(req, "allow"), req))
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    got = model.rows_after(0)
    assert [r.verify for r in got] == ["not_checked"] * 3
    assert "lab verify" in got[0].note


def test_a_session_the_real_example_guardian_signed_verifies_row_by_row(tmp_path, monkeypatch):
    """Pins the viewer to the Guardian's real signing path and acs-verify's real verdicts, not to these fixtures."""
    from conftest import REPO_ROOT
    sys.path.insert(0, str(REPO_ROOT / "adapters" / "tests" / "guardian"))
    from acs_verify_helpers import record_session, start_guardian, stop_guardian

    run = start_guardian(tmp_path, monkeypatch, mldsa=True)
    try:
        transcript = record_session(run)
    finally:
        stop_guardian(run)
    source = KeySource({"ACS_GUARDIAN_KEYS": str(run.key_document_path)})

    def rows_for(records):
        logs = LabLogs(tmp_path / f"lab-{len(list(tmp_path.iterdir()))}")
        logs.transcript_dir.mkdir(parents=True)
        logs.transcript(run.session_id).write_text("\n".join(
            r if isinstance(r, str) else json.dumps(r) for r in records) + "\n", encoding="utf-8")
        model = Model(logs.transcript_dir, None, source)
        model.refresh()
        return model.rows_after(0)

    got = [(r.method, r.decision, r.verify, r.algorithm) for r in rows_for(transcript)]
    assert got == [("handshake/hello", None, "verified", "ML-DSA-65"),
                   ("steps/sessionStart", "allow", "verified", "ML-DSA-65"),
                   ("steps/toolCallRequest", "allow", "verified", "ML-DSA-65"),
                   ("steps/toolCallRequest", "deny", "verified", "ML-DSA-65"),
                   ("steps/sessionEnd", "allow", "verified", "ML-DSA-65")], got
    records = [json.loads(line) for line in transcript]
    deny = next(i for i, r in enumerate(records) if r["dir"] == "resp"
                and (r["envelope"].get("result") or {}).get("decision") == "deny")
    records[deny]["envelope"]["result"]["decision"] = "allow"
    assert [r.verify for r in rows_for(records)] == ["not_checked", "not_checked", "not_checked", "failed",
                                                     "not_checked"]
    # An HMAC-signed allow in place of the deny, correct under the session key the agent side holds, fails: the
    # session is ML-DSA-65 and acs-verify never takes HMAC beside a key document (specification section 8.6).
    records = [json.loads(line) for line in transcript]
    forged = records[deny]["envelope"]
    forged["result"].pop("signature")
    forged["result"]["decision"] = "allow"
    sign_with_key(forged, derive_session_key(run.hmac_secret, run.session_id), key_id="lab-guardian-1")
    assert [(r.verify, r.algorithm) for r in rows_for(records)][3] == ("failed", "HMAC-SHA256")


def test_entry_past_the_keys_validity_fails(tmp_path, key, keys):
    # Probe D: a request timestamp after the key's not_after.
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    req["params"]["timestamp"] = "2099-01-01T00:00:00.000Z"
    req = resign(req)
    logs.pair(req, key.sign(answer(req, "allow"), req))
    assert marks(logs, keys) == [("echo", "allow", "failed")]


def test_entry_after_a_revocation_fails(tmp_path, key):
    # Probe C1: the key document revoked the key before the request's own time.
    document = key.document
    document["revoked"] = [{"key_id": "lab-guardian-1", "revoked_at": stamp(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1))}]
    revoked = tmp_path / "revoked.json"
    revoked.write_text(json.dumps(document), encoding="utf-8")
    os.chmod(revoked, 0o644)
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, key.sign(answer(req, "allow"), req))
    assert marks(logs, KeySource({"ACS_GUARDIAN_KEYS": str(revoked)})) == [("echo", "allow", "failed")]


# Fix round 2


def test_rows_a_replaced_file_no_longer_holds_are_dropped(tmp_path, key, keys):
    # M1, round 3 F1: a file cut shorter or replaced is read again from the start. Rows it no longer holds are
    # dropped, sent to the page once as gone, and never judged again.
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("wire_money")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, key.sign(answer(b, "deny"), b))
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    old = [r.id for r in model.rows_after(0)]
    assert [r.verify for r in model.rows_after(0)] == ["verified", "verified"]
    seq = model.last_seq
    kept = logs.transcript().read_bytes().splitlines(keepends=True)[:2]
    replacement = logs.transcript().with_suffix(".new")
    replacement.write_bytes(b"".join(kept))
    os.replace(replacement, logs.transcript())
    model.refresh()
    assert [(r.tool, r.verify) for r in model.rows_after(0)] == [("echo", "verified")]
    page, _, _ = model.page(seq)
    assert sorted(r.id for r in page if r.gone) == old
    other = decision_key(tmp_path / "other")
    keys._path = str(other.document_path)
    model.refresh()
    assert [r.id for r in model.rows_after(0) if r.id in old] == []


# Fix round 3: a verified mark comes only from bytes on disk at judge time (F1, probes p7 and p8).


def flip_deny(path) -> None:
    """Probe p7 d: the signed deny becomes DENY in place, same size, same inode, with the old mtime put back."""
    before = os.stat(path)
    data = bytearray(path.read_bytes())
    at = data.find(b'"deny"')
    data[at + 1:at + 5] = b"DENY"
    with path.open("r+b") as f:
        f.write(bytes(data))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert os.stat(path).st_size == before.st_size and os.stat(path).st_ino == before.st_ino


def test_a_deleted_file_drops_its_rows(tmp_path, key, keys):
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("wire_money")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, key.sign(answer(b, "deny"), b))
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    seq = model.last_seq
    os.unlink(logs.transcript())
    model.refresh()
    assert model.rows_after(0) == []
    assert all(r.gone for r in model.page(seq)[0]) and len(model.page(seq)[0]) == 2


def test_a_deleted_file_is_not_judged_again_after_a_key_change(tmp_path, key):
    # Probe p8 b2: before round 3 a key change judged the deleted session again from lines held in memory.
    live = tmp_path / "live.json"
    live.write_text(json.dumps(key.document), encoding="utf-8")
    os.chmod(live, 0o644)
    logs = LabLogs(tmp_path)
    a = tool_request("echo")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    model = Model(logs.transcript_dir, None, KeySource({"ACS_GUARDIAN_KEYS": str(live)}))
    model.refresh()
    os.unlink(logs.transcript())
    model.refresh()
    document = key.document
    document["note"] = "rewritten"
    live.write_text(json.dumps(document), encoding="utf-8")
    os.utime(live, ns=(1, 1))
    for _ in range(2):
        model.refresh()
    assert model.rows_after(0) == []


def test_a_same_size_edit_in_place_is_read_again_from_disk(tmp_path, key, keys):
    # Probe p7 d: no new inode, no new size, the old mtime. The bytes on disk no longer verify, so no row says so.
    logs = LabLogs(tmp_path)
    a, b, c = tool_request("echo"), tool_request("wire_money"), tool_request("read_balance")
    for req, decision in ((a, "allow"), (b, "deny"), (c, "allow")):
        logs.pair(req, key.sign(answer(req, decision), req))
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    assert {r.verify for r in model.rows_after(0)} == {"verified"}
    flip_deny(logs.transcript())
    model.refresh()
    got = [(r.tool, r.decision, r.verify) for r in sorted(model.rows_after(0), key=lambda r: r.id)]
    assert got == [("echo", "allow", "not_checked"), ("wire_money", "DENY", "failed"),
                   ("read_balance", "allow", "not_checked")]


def test_an_edit_then_a_genuine_append_is_still_caught(tmp_path, key, keys):
    # Probe p8 d2: the file grows after the edit, which before round 3 judged the stale lines held in memory.
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("wire_money")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, key.sign(answer(b, "deny"), b))
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    flip_deny(logs.transcript())
    c = tool_request("read_balance")
    logs.pair(c, key.sign(answer(c, "allow"), c))
    model.refresh()
    marks_now = {r.tool: r.verify for r in model.rows_after(0)}
    assert marks_now == {"echo": "not_checked", "wire_money": "failed", "read_balance": "not_checked"}


def test_a_copied_file_fails_without_a_key_document(tmp_path, key):
    # Round 3 N1: the file name check runs whatever the session's mode.
    logs = LabLogs(tmp_path)
    a = tool_request("echo")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.transcript(SESSION_B).write_bytes(logs.transcript().read_bytes())
    model = Model(logs.transcript_dir, None, None)
    model.refresh()
    copied = [r for r in model.rows_after(0) if r.session_id == SESSION_B]
    assert [r.verify for r in copied] == ["failed"]
    assert "session_file_mismatch" in copied[0].note


def test_a_discards_line_after_a_ping_answer_marks_nothing_withheld(tmp_path, key, keys):
    # Round 3 N2: only a signed step answer with no cause can be withheld, acs-verify's rule.
    logs = LabLogs(tmp_path)
    a = tool_request("echo")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    ping = request("system/ping", {})
    logs.pair(ping, {"jsonrpc": "2.0", "id": ping["id"], "result": {"request_id": ping["params"]["request_id"]}})
    logs.resp(SESSION_A, None, cause="decision_timeout", discards=ping["params"]["request_id"])
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    pinged = next(r for r in model.rows_after(0) if r.method == "system/ping")
    claim = next(r for r in model.rows_after(0) if r.method == "withheld")
    assert "withheld" not in (pinged.note or "")
    assert claim.verify == "failed"


def test_a_file_named_for_another_session_fails(tmp_path, key, keys):
    # M2: genuine pairs copied into a file named for another session. Every signature checks, the name doesn't.
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("read_balance")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, key.sign(answer(b, "allow"), b))
    logs.transcript(SESSION_B).write_bytes(logs.transcript().read_bytes())
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    copied = sorted((r for r in model.rows_after(0) if r.session_id == SESSION_B), key=lambda r: r.id)
    original = [r for r in model.rows_after(0) if r.session_id == SESSION_A]
    assert [r.verify for r in copied] == ["failed", "not_checked"]
    assert "session_file_mismatch" in copied[0].note
    assert {r.verify for r in original} == {"verified"}


def test_judging_is_budgeted_across_polls(tmp_path, key, keys, monkeypatch):
    # M4: a poll judges sessions until its budget runs out and leaves the rest to later polls. With no budget it
    # still judges one session, so every session is judged in the end.
    import model as model_module
    monkeypatch.setattr(model_module, "JUDGE_BUDGET_S", 0.0)
    logs = LabLogs(tmp_path)
    sessions = [SESSION_A, SESSION_B, "33333333-3333-4333-8333-333333333333"]
    for session_id in sessions:
        req = tool_request("echo", session_id=session_id)
        logs.pair(req, key.sign(answer(req, "allow"), req))
    model = Model(logs.transcript_dir, None, keys)
    seen = []
    for _ in range(3):
        model.refresh()
        seen.append(sum(r.verify == "verified" for r in model.rows_after(0)))
    assert seen == [1, 2, 3]


def test_a_key_change_greys_sessions_waiting_to_be_judged_again(tmp_path, key, keys, monkeypatch):
    # M4: a changed key document is judged in again a session at a time. A session still waiting shows no mark from
    # the old document.
    import model as model_module
    logs = LabLogs(tmp_path)
    for session_id in (SESSION_A, SESSION_B):
        req = tool_request("echo", session_id=session_id)
        logs.pair(req, key.sign(answer(req, "allow"), req))
    live = tmp_path / "live.json"
    live.write_text(json.dumps(key.document), encoding="utf-8")
    os.chmod(live, 0o644)
    model = Model(logs.transcript_dir, None, KeySource({"ACS_GUARDIAN_KEYS": str(live)}))
    model.refresh()
    assert [r.verify for r in model.rows_after(0)] == ["verified", "verified"]
    monkeypatch.setattr(model_module, "JUDGE_BUDGET_S", 0.0)
    other = decision_key(tmp_path / "other-keys")
    live.write_text(json.dumps(other.document), encoding="utf-8")
    os.utime(live, ns=(1, 1))
    model.refresh()
    got = {r.session_id: r for r in model.rows_after(0)}
    assert sorted(r.verify for r in got.values()) == ["failed", "not_checked"]
    waiting = next(r for r in got.values() if r.verify == "not_checked")
    assert "judging again" in waiting.note


# Fix round 4


def test_a_session_past_the_cap_is_never_read_or_hashed_again(tmp_path, key, keys, monkeypatch):
    # I-1: once a session passes the cap, the tail stops and a judge reads nothing from disk, so a poll costs the
    # same however large the file grows.
    import model as model_module
    monkeypatch.setattr(model_module, "MAX_SESSION_LINES", 4)
    logs = LabLogs(tmp_path)
    for tool in ("a", "b", "c"):
        req = tool_request(tool)
        logs.pair(req, key.sign(answer(req, "allow"), req))
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    session = model._sessions[SESSION_A]
    assert session.too_long
    stopped_at = session.tail._offset

    def no_disk(self):
        raise AssertionError("a session past the cap was read from disk")

    monkeypatch.setattr(model_module.LogTail, "disk_lines", no_disk)
    for tool in ("d", "e", "f"):
        req = tool_request(tool)
        logs.pair(req, key.sign(answer(req, "allow"), req))
        model.refresh()
    assert session.tail._offset == stopped_at
    assert {r.verify for r in model.rows_after(0)} == {"not_checked"}


def test_a_session_past_the_cap_replaced_by_a_short_file_starts_over(tmp_path, key, keys, monkeypatch):
    import model as model_module
    monkeypatch.setattr(model_module, "MAX_SESSION_LINES", 4)
    logs = LabLogs(tmp_path)
    for tool in ("a", "b", "c"):
        req = tool_request(tool)
        logs.pair(req, key.sign(answer(req, "allow"), req))
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    assert model._sessions[SESSION_A].too_long
    fresh = tool_request("only")
    replacement = logs.transcript().with_suffix(".new")
    replacement.write_bytes(b"")
    os.replace(replacement, logs.transcript())
    logs.pair(fresh, key.sign(answer(fresh, "allow"), fresh))
    model.refresh()
    assert [(r.tool, r.verify) for r in model.rows_after(0)] == [("only", "verified")]


def test_a_session_that_leaves_the_newest_listing_is_forgotten(tmp_path, key, keys, monkeypatch):
    # I-2a, probe p10: a followed file that falls out of the newest MAX_SESSIONS is no longer stat'ed, so its rows
    # go, as for a deleted file, rather than keep marks nothing checks again.
    import time as time_module
    import model as model_module
    monkeypatch.setattr(model_module, "MAX_SESSIONS", 3)
    logs = LabLogs(tmp_path)
    a, b = tool_request("echo"), tool_request("wire_money")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, key.sign(answer(b, "deny"), b))
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    assert {r.verify for r in model.rows_after(0)} == {"verified"}
    for number in range(3):
        time_module.sleep(0.01)
        (logs.transcript_dir / f"newer{number}.jsonl").write_bytes(b"")
    model.refresh()
    assert [r for r in model.rows_after(0) if r.session_id == SESSION_A] == []
    assert SESSION_A not in model._sessions
    assert {"session_id": SESSION_A, "why": "the file is no longer among the newest followed"}.items() <= \
        model.drops()[-1].items()


def test_dropped_rows_are_announced(tmp_path, key, keys):
    # Round 4 minor: a drop names the file and why, so rows never vanish without a word.
    logs = LabLogs(tmp_path)
    a = tool_request("echo")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    os.unlink(logs.transcript())
    model.refresh()
    [drop] = model.drops()
    assert drop["session_id"] == SESSION_A
    assert drop["why"] == "the file left the transcript directory"
    flip = LabLogs(tmp_path / "flip")
    b = tool_request("wire_money")
    flip.pair(b, key.sign(answer(b, "deny"), b))
    model = Model(flip.transcript_dir, None, keys)
    model.refresh()
    flip_deny(flip.transcript())
    model.refresh()
    assert model.drops()[-1]["why"] == "the file no longer holds the bytes read before, so it is read again"


# Fix round 5


def test_a_drop_names_only_a_gateway_shaped_file(tmp_path, key, keys):
    # M-B, probe p16: a file name can hold text that reads as another session and another reason. Only a name shaped
    # like the gateway's (str(uuid.UUID(session_id))) is shown. Any other reads as a transcript file.
    logs = LabLogs(tmp_path)
    a = tool_request("echo")
    logs.pair(a, key.sign(answer(a, "allow"), a))
    crafted = logs.transcript_dir / (f"x: the file left the transcript directory. Rows dropped for session {SESSION_A}: "
                                     "the file no longer holds the bytes read before, so it is read again.jsonl")
    crafted.write_bytes(logs.transcript().read_bytes())
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    os.unlink(crafted)
    os.unlink(logs.transcript())
    model.refresh()
    drops = {d["why"]: d for d in model.drops()}
    named = [d["session_id"] for d in model.drops()]
    assert named.count(SESSION_A) == 1
    assert None in named
    assert all(d["session_id"] in (None, SESSION_A) for d in drops.values())
    assert model.drop_count == 2
