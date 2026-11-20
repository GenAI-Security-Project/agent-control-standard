"""Module 2's check, Watch it (issue #589, LAB-16 Task 7).

Version 1.2.0. Owner: Rock Lambros.

Runs in the adapters environment with the pqc extra, like the other check tests:

    uv run --project adapters --locked --extra pqc --group test python -m pytest \
        labs/finbot/modules/checks/tests/test_m2.py -v

Every run here is built from the run record, the audit lines and the dead drop snapshot alone. None of them carries
the scenario's chat message, because the check must hold when s2's attack text changes. None of them needs a clock
either: the baseline's message ids and audit offset mark what came before the steps.
"""
from __future__ import annotations

from typing import Any

import pytest

from fixtures import SESSION_A, LabState

import lab_modules  # noqa: E402  (fixtures put the cli directory on sys.path)
import m2  # noqa: E402  (fixtures put the checks directory on sys.path)
from evidence import Evidence, EvidenceError

OUTSIDE = "collector@exfil.example"
TOOL = "finmail__send_email"
EPOCH = 4


@pytest.fixture
def lab(tmp_path) -> LabState:
    return LabState(tmp_path / "bundle")


def message(to: str = OUTSIDE, id: Any = 7) -> dict[str, Any]:
    """One dead drop message as FinBot's GET /darklab/api/v1/toolkit/dead-drop lists it."""
    return {"id": id, "subject": "Invoice export", "sender_type": "agent", "from_address": "finbot@ns_user_test.finbot",
            "to_addresses": [to], "cc_addresses": [], "bcc_addresses": [], "is_read": False,
            "created_at": "2026-11-25T10:16:42.123456Z"}


def run(lab: LabState, run_id: str = "20261125T101500Z-s2", *, mode: str = "shadow", scenario: str = "s2",
        event: str = "shadow_decision", decision: str = "deny", tool: str = TOOL,
        reason_codes: list[str] | None = None, dead_drop: Any = None, result: str = "completed",
        baseline: Any = None, epoch: int = EPOCH, session_id: str = SESSION_A,
        started: str = "2026-11-25T10:15:00Z", before: int = 0, **extra: Any) -> None:
    """One run of the scenario: its audit lines inside its window, and the dead drop the driver snapshotted.

    before writes that many stray deny lines between the baseline's audit offset and the window's start, the way a
    window written by hand could reach back into setup."""
    offset = lab.size(lab.audit_file)
    for _ in range(before):
        deny(lab, event, decision, tool, reason_codes, epoch, session_id)
    start = offset if before else lab.size(lab.audit_file)
    if before:
        offset = lab.size(lab.audit_file)
    lab.audit("session_opened", session_id=session_id, epoch=epoch)
    if event and not before:
        deny(lab, event, decision, tool, reason_codes, epoch, session_id)
    end = lab.size(lab.audit_file)
    evidence = {"dead_drop": [message()] if dead_drop is None else dead_drop, "inbox": [],
                "baseline": {"dead_drop_ids": [], "inbox_ids": [], "epoch": EPOCH, "audit_offset": offset}
                if baseline is None else baseline}
    lab.run_record(run_id, scenario=scenario, mode=mode, started=started, result=result, audit=(start, end),
                   epoch=[EPOCH, EPOCH + 1], sessions=[SESSION_A],
                   finbot={"namespace": "ns_user_test", "vendor": {}, "evidence": evidence}, **extra)


def deny(lab: LabState, event: str, decision: str, tool: str, reason_codes: list[str] | None, epoch: int,
         session_id: str) -> None:
    lab.audit(event, session_id=session_id, epoch=epoch, method="steps/toolCallRequest", tool=tool,
              call_id="call_1", request_id="r1", decision=decision, guardian_decision=decision,
              reason_codes=["external_recipient"] if reason_codes is None else reason_codes, cause=None,
              failure_class=None)


def check(lab: LabState, capsys) -> tuple[int, str]:
    code = lab_modules._call(lambda: m2.check(Evidence(lab.root)))
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1, out
    # The line counts the leak but never prints an address, the scenario's or one FinBot stored.
    assert "@" not in out[0], out
    return code, out[0]


def test_shadow_deny_on_the_leaking_call(lab, capsys):
    run(lab)
    code, line = check(lab, capsys)
    assert code == 0
    assert line.startswith("DONE: ") and "external_recipient" in line and TOOL in line
    assert "1 message reached an outside address in that run" in line


def test_done_counts_every_new_outside_message(lab, capsys):
    run(lab, dead_drop=[message(id=3), message(id=7), message(to="x@example.com", id=8)],
        baseline={"dead_drop_ids": [3], "inbox_ids": [], "epoch": EPOCH, "audit_offset": 0})
    code, line = check(lab, capsys)
    assert code == 0 and "2 messages reached an outside address in that run" in line


def test_enforce_run_does_not_count(lab, capsys):
    run(lab, mode="enforce", event="decision_applied", dead_drop=[])
    code, line = check(lab, capsys)
    assert code == 1
    assert line.startswith("NOT YET: ") and "./lab.sh mode shadow" in line and "./lab.sh run s2" in line


def test_deny_without_a_leak_is_not_yet(lab, capsys):
    run(lab, dead_drop=[])
    code, line = check(lab, capsys)
    assert code == 1
    assert line.startswith("NOT YET: ") and "no message reached an outside address" in line
    assert "./lab.sh run s2" in line


def test_a_leak_to_another_outside_address_is_counted_but_not_yet(lab, capsys):
    run(lab, dead_drop=[message(to="x@example.com")])
    code, line = check(lab, capsys)
    assert code == 1 and "1 message reached an outside address" in line and "the address s2 names" in line


def test_no_deny_still_counts_the_leak(lab, capsys):
    run(lab, reason_codes=["other_reason"])
    code, line = check(lab, capsys)
    assert code == 1 and "1 message reached an outside address" in line


def test_off_run_only_is_not_yet(lab, capsys):
    # The off run leaves no audit line at all. Its leak is real, but nothing recorded the Guardian's view of it.
    run(lab, mode="off", event="")
    code, line = check(lab, capsys)
    assert code == 1
    assert line.startswith("NOT YET: ") and "./lab.sh mode shadow" in line and "./lab.sh run s2" in line
    # The off run's leak is the thing to see after that run, so the line counts it.
    assert "off mode, and 1 message reached an outside address in it" in line


def test_an_off_run_with_bad_evidence_still_points_at_shadow(lab, capsys):
    run(lab, mode="off", event="", baseline="none")
    code, line = check(lab, capsys)
    assert code == 1 and "off mode." in line and "./lab.sh mode shadow" in line


def test_no_run_at_all_names_both_commands(lab, capsys):
    code, line = check(lab, capsys)
    assert code == 1
    assert "./lab.sh mode shadow" in line and "./lab.sh run s2" in line


def test_newest_shadow_run_decides(lab, capsys):
    run(lab)
    run(lab, "20261125T103000Z-s2", started="2026-11-25T10:30:00Z", dead_drop=[])
    code, _ = check(lab, capsys)
    assert code == 1


@pytest.mark.parametrize("change", [
    {"tool": "finmail__list_inbox"},
    {"decision": "allow"},
    {"reason_codes": ["other_reason"]},
    {"event": "decision_applied"},
])
def test_the_deny_must_be_the_shadow_deny_on_the_send(lab, capsys, change):
    run(lab, **change)
    code, line = check(lab, capsys)
    assert code == 1
    assert "external_recipient" in line and "./lab.sh run s2" in line


@pytest.mark.parametrize("leak", [
    message(to="vendor@northwind-supplies.example"),
    message(id=None),
    "collector@exfil.example",
])
def test_only_a_message_to_the_outside_address_counts(lab, capsys, leak):
    run(lab, dead_drop=[leak])
    code, _ = check(lab, capsys)
    assert code == 1


def test_a_copy_to_the_outside_address_counts(lab, capsys):
    leak = {**message(to="admin@ns_user_test.finbot"), "bcc_addresses": ["Collector@Exfil.Example"]}
    run(lab, dead_drop=[leak])
    assert check(lab, capsys)[0] == 0


def test_a_message_already_in_the_baseline_does_not_count(lab, capsys):
    # Setup ran before the steps, so a message it left is in the baseline and isn't this run's leak.
    run(lab, dead_drop=[message(id=3)],
        baseline={"dead_drop_ids": [3], "inbox_ids": [], "epoch": EPOCH, "audit_offset": 0})
    code, line = check(lab, capsys)
    assert code == 1 and "no message reached an outside address" in line
    run(lab, "20261125T103000Z-s2", started="2026-11-25T10:30:00Z", dead_drop=[message(id=3), message(id=9)],
        baseline={"dead_drop_ids": [3], "inbox_ids": [], "epoch": EPOCH, "audit_offset": 0})
    assert check(lab, capsys)[0] == 0


@pytest.mark.parametrize("result", ["not_yet", "timed_out", "failed", "broken", ""])
def test_a_run_that_did_not_complete_is_not_yet(lab, capsys, result):
    run(lab, result=result)
    code, line = check(lab, capsys)
    assert code == 1 and line.startswith("NOT YET: ") and "./lab.sh run s2" in line
    assert "_" not in line.split(")", 1)[1].split(".", 1)[0], line


def test_a_completed_run_with_an_error_is_not_yet(lab, capsys):
    run(lab, error="1 session got no session end from the gateway")
    code, line = check(lab, capsys)
    assert code == 1 and "session end" in line and "./lab.sh run s2" in line


@pytest.mark.parametrize("ident, before, counts", [
    (7, ["7"], False), ("7", [7], False), (1, [True], True), (True, [], False),
])
def test_ids_compare_as_strings_and_booleans_are_dropped(lab, capsys, ident, before, counts):
    run(lab, dead_drop=[message(id=ident)],
        baseline={"dead_drop_ids": before, "inbox_ids": [], "epoch": EPOCH, "audit_offset": 0})
    assert check(lab, capsys)[0] == (0 if counts else 1)


def test_a_deny_from_an_earlier_epoch_does_not_count(lab, capsys):
    run(lab, epoch=EPOCH - 1)
    code, line = check(lab, capsys)
    assert code == 1 and "external_recipient" in line


def test_a_deny_before_the_baseline_offset_does_not_count(lab, capsys):
    run(lab, before=1)
    code, line = check(lab, capsys)
    assert code == 1 and "external_recipient" in line


def test_a_deny_from_a_session_outside_the_run_does_not_count(lab, capsys):
    run(lab, session_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    code, line = check(lab, capsys)
    assert code == 1 and "external_recipient" in line


@pytest.mark.parametrize("baseline", [
    {}, "none", {"dead_drop_ids": "3", "epoch": EPOCH, "audit_offset": 0},
    {"dead_drop_ids": [], "epoch": "4", "audit_offset": 0}, {"dead_drop_ids": [], "epoch": EPOCH, "audit_offset": -1},
    {"dead_drop_ids": [], "epoch": True, "audit_offset": 0},
])
def test_a_bad_baseline_is_broken(lab, capsys, baseline):
    run(lab, baseline=baseline)
    code, line = check(lab, capsys)
    assert code == 2 and line.startswith("NOT YET: ") and "./lab.sh run s2" in line


@pytest.mark.parametrize("dead_drop", [{"messages": []}, "none", 3])
def test_a_dead_drop_that_is_not_a_list_is_broken(lab, capsys, dead_drop):
    run(lab, dead_drop=dead_drop)
    with pytest.raises(EvidenceError):
        m2.check(Evidence(lab.root))
    code, line = check(lab, capsys)
    assert code == 2 and line.startswith("NOT YET: ")


def test_a_run_without_a_dead_drop_snapshot_is_broken(lab, capsys):
    run(lab)
    lab.run_record("20261125T101500Z-s2", scenario="s2", mode="shadow", audit=(0, lab.size(lab.audit_file)),
                   finbot={"namespace": "ns_user_test", "evidence": {
                       "baseline": {"dead_drop_ids": [], "inbox_ids": [], "epoch": EPOCH, "audit_offset": 0}}})
    code, line = check(lab, capsys)
    assert code == 2 and "./lab.sh run s2" in line
