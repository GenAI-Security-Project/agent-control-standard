"""The viewer's log reader: escaping, incremental tails, and one row per governed step (issue #586)."""
from __future__ import annotations

import os

from lab_lines import SESSION_A, SESSION_B, LabLogs, answer, tool_request
from model import LogTail, Model, escape_text


def rows(model: Model, after: int = 0):
    model.refresh()
    return model.rows_after(after)


def test_terminal_control_bytes_are_escaped(tmp_path):
    assert escape_text("send\x1b[2J\x07") == "send\\x1b[2J\\x07"
    assert escape_text("a\u202eb\u200bc\ufeff\x85\x7f") == "a\\u{202e}b\\u{200b}c\\u{feff}\\x85\\x7f"
    assert escape_text("x\ud800y\n\t\r") == "x\\u{d800}y\\n\\t\\r"
    # A literal backslash is escaped too, so a log can't print text that reads as one of our escapes.
    assert escape_text("\\x1b") == "\\\\x1b"

    logs = LabLogs(tmp_path)
    req = tool_request("send\x1b[2J\x07")
    logs.pair(req, answer(req, "deny", reasoning="fine \u202e txt.exe", reason_codes=["\x1b]0;owned\x07"]))
    [row] = rows(Model(logs.transcript_dir, None, None))
    assert row.tool == "send\\x1b[2J\\x07"
    assert row.reason_codes == ["\\x1b]0;owned\\x07"]
    for value in (row.tool, row.method, *row.reason_codes):
        assert not any(ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f or c == "\u202e" for c in value)


def test_partial_line_waits_for_newline(tmp_path):
    path = tmp_path / "log.jsonl"
    path.write_bytes(b'{"a": 1}\n{"b"')
    tail = LogTail(path)
    assert tail.read_new() == [b'{"a": 1}']
    assert tail.read_new() == []
    with path.open("ab") as f:
        f.write(b': 2}\n')
    assert tail.read_new() == [b'{"b": 2}']
    assert tail.read_new() == []


def test_bad_line_becomes_one_unreadable_row(tmp_path):
    logs = LabLogs(tmp_path)
    logs.transcript_dir.mkdir(parents=True)
    path = logs.transcript()
    path.write_bytes(b"\xff\xfe\x1b\nnot json\n")
    req = tool_request("echo")
    logs.pair(req, answer(req, "allow"))
    got = rows(Model(logs.transcript_dir, None, None))
    # Two bad lines in a row are one row with a count (fix round 1, I5), shown from the first line's bytes.
    assert [r.method for r in got] == ["unreadable", "steps/toolCallRequest"]
    assert got[0].note == "\\xff\\xfe\\x1b (2 unreadable lines)"
    assert got[1].decision == "allow"
    # A readable line ends the run, so the next bad line starts a row of its own.
    with path.open("ab") as f:
        f.write(b"not json\n")
    model = Model(logs.transcript_dir, None, None)
    assert [r.note for r in rows(model) if r.method == "unreadable"] == ["\\xff\\xfe\\x1b (2 unreadable lines)",
                                                                          "not json"]


def test_req_resp_pair_gives_one_row(tmp_path):
    logs = LabLogs(tmp_path)
    req = tool_request("finmail__send_email")
    logs.pair(req, answer(req, "deny", reason_codes=["external_recipient"]))
    [row] = rows(Model(logs.transcript_dir, None, None))
    assert (row.session_id, row.method, row.tool, row.decision, row.reason_codes) == (
        SESSION_A, "steps/toolCallRequest", "finmail__send_email", "deny", ["external_recipient"])
    assert row.t == req["params"]["timestamp"]
    assert row.verify == "unsigned"


def test_unanswered_request_reads_no_answer(tmp_path):
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, None, cause="transport\x1bfailure")
    [row] = rows(Model(logs.transcript_dir, None, None))
    assert (row.verify, row.note, row.decision) == ("no_answer", "transport\\x1bfailure", None)


def test_audit_joins_by_request_id(tmp_path):
    logs = LabLogs(tmp_path)
    req = tool_request("finmail__send_email")
    rid = req["params"]["request_id"]
    logs.pair(req, answer(req, "deny", reason_codes=["external_recipient"]))
    model = Model(logs.transcript_dir, logs.audit_file, None)
    [row] = rows(model)
    # Shadow forwards the call, so the decision that counts here is the Guardian's.
    logs.audit("shadow_decision", session_id=SESSION_A, epoch=0, method="steps/toolCallRequest",
               tool="finmail__send_email", call_id="c1", request_id=rid, decision="allow",
               guardian_decision="deny", reason_codes=["external_recipient"], cause=None, failure_class=None)
    [updated] = rows(model, row.seq)
    assert updated.id == row.id and updated.seq > row.seq
    # The decision column keeps the signed answer's decision. The audit line adds what the gateway did.
    assert (updated.decision, updated.applied, updated.mode, updated.conflict) == ("deny", "allow", "shadow", False)
    assert updated.note == "shadow: the gateway forwarded the call"


def test_audit_line_read_before_its_transcript_line_still_joins(tmp_path):
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.audit("decision_applied", session_id=SESSION_A, epoch=0, method="steps/toolCallRequest", tool="echo",
               call_id="c1", request_id=req["params"]["request_id"], decision="deny", guardian_decision="allow",
               reason_codes=None, cause="response_signature_invalid", failure_class="signature_invalid")
    model = Model(logs.transcript_dir, logs.audit_file, None)
    assert rows(model) == []
    logs.pair(req, answer(req, "allow"))
    [row] = rows(model)
    assert (row.decision, row.applied, row.conflict) == ("allow", "deny", False)
    assert row.note == "gateway applied deny (response_signature_invalid)"


def test_new_session_file_is_picked_up(tmp_path):
    logs = LabLogs(tmp_path)
    first = tool_request("echo")
    logs.pair(first, answer(first, "allow"))
    model = Model(logs.transcript_dir, None, None)
    [row] = rows(model)
    second = tool_request("echo", session_id=SESSION_B)
    logs.pair(second, answer(second, "allow"))
    [new] = rows(model, row.seq)
    assert new.session_id == SESSION_B


# The gateway's newer lines (adapters/gateway/README.md, "Records"), each written by the gateway's own writer.


def test_discards_line_marks_the_answer_before_it(tmp_path):
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, answer(req, "allow"))
    logs.resp(SESSION_A, None, cause="decision_timeout", discards=req["params"]["request_id"])
    row, claim = sorted(rows(Model(logs.transcript_dir, None, None)), key=lambda r: r.id)
    assert row.decision == "allow"
    assert row.note == "the gateway withheld this answer and denied the step (decision_timeout)"
    # The discards line is a row of its own, the gateway's unsigned claim (fix round 2, M3).
    assert (claim.method, claim.decision, claim.verify) == ("withheld", None, "unsigned")
    assert claim.note == "the gateway says it withheld the answer above and denied the step (decision_timeout)"


def test_late_answer_keeps_its_envelope_and_says_it_was_withheld(tmp_path):
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, answer(req, "allow"), cause="decision_timeout")
    [row] = rows(Model(logs.transcript_dir, None, None))
    assert row.decision == "allow"
    assert row.note == "the answer came late and the gateway withheld it (decision_timeout)"


def test_body_that_is_no_answer_reads_no_answer(tmp_path):
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    logs.pair(req, {"detail": "slow down"}, cause="http_429_error")
    [row] = rows(Model(logs.transcript_dir, None, None))
    assert (row.verify, row.note, row.decision) == ("no_answer", "http_429_error", None)


def test_session_end_is_a_row(tmp_path):
    from lab_lines import request
    logs = LabLogs(tmp_path)
    end = request("steps/sessionEnd", {"reason": "user_exit"})
    logs.pair(end, answer(end, "allow"))
    [row] = rows(Model(logs.transcript_dir, None, None))
    assert (row.method, row.tool) == ("steps/sessionEnd", None)


# Fix round 1: a forged audit line never rewrites the signed decision (probes I and J).


def test_forged_audit_line_never_rewrites_the_signed_decision(tmp_path):
    logs = LabLogs(tmp_path)
    d, e = tool_request("delete_all"), tool_request("delete_more")
    logs.pair(d, answer(d, "deny", reason_codes=["destructive"]))
    logs.pair(e, answer(e, "deny", reason_codes=["destructive"]))
    logs.audit("decision_applied", session_id=SESSION_A, request_id=d["params"]["request_id"], decision="allow")
    logs.audit("shadow_decision", session_id=SESSION_A, request_id=e["params"]["request_id"], decision="allow",
               guardian_decision="allow")
    first, second = rows(Model(logs.transcript_dir, logs.audit_file, None))
    assert (first.decision, first.applied, first.conflict) == ("deny", "allow", True)
    assert first.note == "conflict: the gateway applied allow, the signed answer says deny"
    assert (second.decision, second.applied, second.conflict) == ("deny", "allow", True)
    assert second.note == "conflict: the audit line says the Guardian said allow, the signed answer says deny"


def test_waiting_audit_lines_are_keyed_by_session_and_request(tmp_path):
    # M8: a request_id is unique within a session only, so an audit line for another session never joins this row.
    logs = LabLogs(tmp_path)
    req = tool_request("echo")
    rid = req["params"]["request_id"]
    logs.audit("decision_applied", session_id=SESSION_B, epoch=0, method=req["method"], tool="echo",
               call_id="c1", request_id=rid, decision="deny", guardian_decision="deny", reason_codes=None,
               cause=None, failure_class=None)
    model = Model(logs.transcript_dir, logs.audit_file, None)
    model.refresh()
    logs.pair(req, answer(req, "allow"))
    [row] = rows(model)
    assert (row.decision, row.applied, row.note) == ("allow", None, None)


# Fix round 1: bounds (I5). A junk or very long log must not grow memory or a poll without limit.


def test_a_run_of_unreadable_lines_is_one_row(tmp_path):
    logs = LabLogs(tmp_path)
    logs.transcript_dir.mkdir(parents=True)
    logs.transcript().write_bytes(b"x\n" * 200_000)
    model = Model(logs.transcript_dir, None, None)
    for _ in range(3):
        model.refresh()
    [row] = model.rows_after(0)
    assert row.method == "unreadable"
    # 200000 lines is past the lines the viewer holds for acs-verify, so the session also says to run lab verify.
    assert row.note == ("x (200000 unreadable lines) | this session is too long for the viewer to judge. "
                        "Run lab verify on it")


def test_rows_kept_are_capped_and_the_oldest_go_first(tmp_path, monkeypatch):
    import model as model_module
    monkeypatch.setattr(model_module, "MAX_ROWS", 3)
    logs = LabLogs(tmp_path)
    for tool in [f"t{i}" for i in range(5)]:
        req = tool_request(tool)
        logs.pair(req, answer(req, "allow"))
    assert [r.tool for r in rows(Model(logs.transcript_dir, None, None))] == ["t2", "t3", "t4"]


def test_one_answer_holds_a_bounded_page(tmp_path, monkeypatch):
    import model as model_module
    monkeypatch.setattr(model_module, "MAX_ROWS_PER_ANSWER", 2)
    logs = LabLogs(tmp_path)
    for tool in ("a", "b", "c", "d", "e"):
        req = tool_request(tool)
        logs.pair(req, answer(req, "allow"))
    model = Model(logs.transcript_dir, None, None)
    model.refresh()
    seen, after = [], 0
    while True:
        page, after, more = model.page(after)
        seen += [r.tool for r in page]
        if not more:
            break
    assert seen == ["a", "b", "c", "d", "e"]
    assert model.page(after) == ([], after, False)


def test_session_files_tracked_are_capped(tmp_path, monkeypatch):
    import model as model_module
    monkeypatch.setattr(model_module, "MAX_SESSIONS", 2)
    logs = LabLogs(tmp_path)
    sessions = ["33333333-3333-4333-8333-33333333333" + str(i) for i in range(4)]
    for number, session_id in enumerate(sessions):
        req = tool_request("echo", session_id=session_id)
        logs.pair(req, answer(req, "allow"))
        os.utime(logs.transcript(session_id), ns=((number + 1) * 10**9, (number + 1) * 10**9))
    got = rows(Model(logs.transcript_dir, None, None))
    assert sorted(r.session_id for r in got) == sessions[2:]
