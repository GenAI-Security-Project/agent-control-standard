"""Module 3's check, Stop it (issue #589, LAB-16 Task 8).

Runs in the adapters environment with the pqc extra, like every module check test:

    uv run --project adapters --locked --extra pqc --group test python -m pytest \
        labs/finbot/modules/checks/tests/test_m3.py -v

Every run here is built from audit lines and FinBot snapshots alone. None of it carries s2's chat message, because
the check must judge a run by its decisions and its evidence, never by the attack text.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from fixtures import SESSION_A, SESSION_B, LabState

import lab_modules  # noqa: E402  (the CLI's dispatcher, for the exit code a broken record gets)
import m3  # noqa: E402  (fixtures put the checks directory on sys.path)
from evidence import Evidence, EvidenceError

SEND = "finmail__send_email"
STARTER = "1" * 64
SOLUTION = "2" * 64
OUTSIDE_MAIL = {"id": 1, "to_addresses": ["someone@outside.example"], "subject": "filing",
                "created_at": "2026-11-25T10:15:30Z"}
VENDOR_MAIL = {"id": 2, "inbox_type": "vendor", "to_addresses": ["ap@vendor.example"], "subject": "payment notice",
               "created_at": "2026-11-25T10:20:30Z"}


@pytest.fixture
def lab(tmp_path) -> LabState:
    return LabState(tmp_path / "bundle")


Decision = tuple[str, list[str]] | tuple[str, list[str], str]
KEEP: Any = object()


def _decide(lab: LabState, session: str, epoch: int, mode: str, decisions: list[Decision]) -> None:
    for n, (decision, codes, *tool) in enumerate(decisions):
        event = "decision_applied" if mode == "enforce" else "shadow_decision"
        lab.audit(event, session_id=session, epoch=epoch, method="steps/toolCallRequest", tool=tool[0] if tool else SEND,
                  call_id=f"call_{epoch}_{n}", request_id=None, decision=decision, guardian_decision=decision,
                  reason_codes=codes, cause=None, failure_class=None)


def _run(lab: LabState, scenario: str, minute: int, *, decisions: list[Decision], policy: str = SOLUTION,
         mode: str = "enforce", dead_drop: list[Any] | None = None, inbox: list[Any] | None = None,
         result: str = "completed", setup: list[Decision] | None = None, old_ids: dict[str, list[Any]] | None = None,
         decision_session: str | None = None, baseline: Any = KEEP) -> str:
    """One driver run: decisions under the steps' epoch after the baseline, then the record with FinBot's snapshot.

    setup puts decisions from scenario setup under the epoch before, ahead of the baseline offset but inside the
    audit window. The driver opens its window after setup, so only a crafted record looks like this (review I1).
    old_ids lists messages that were already there when the baseline was read.
    """
    session = SESSION_A if scenario == "s2" else SESSION_B
    start = lab.size(lab.audit_file)
    if setup:
        _decide(lab, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", minute - 1, mode, setup)
    offset = lab.size(lab.audit_file)
    lab.audit("session_opened", session_id=session, epoch=minute)
    _decide(lab, decision_session or session, minute, mode, decisions)
    end = lab.size(lab.audit_file)
    run_id = f"20261125T10{minute:02d}00Z-{scenario}"
    old_ids = old_ids or {}
    evidence: dict[str, Any] = {"dead_drop": dead_drop or [], "reply": "I couldn't complete that action."}
    if scenario == "s3":
        evidence["inbox"] = inbox or []
    evidence["baseline"] = {"dead_drop_ids": old_ids.get("dead_drop", []), "inbox_ids": old_ids.get("inbox", []),
                            "epoch": minute, "audit_offset": offset}
    if baseline is not KEEP:
        evidence["baseline"] = baseline
        if baseline is None:
            del evidence["baseline"]
    lab.run_record(run_id, scenario=scenario, mode=mode, started=f"2026-11-25T10:{minute:02d}:00Z",
                   audit=(start, end), sessions=[session], policy_sha256=policy, result=result,
                   epoch=[minute, minute + 1],
                   finbot={"namespace": "ns_user_test", "vendor": {}, "evidence": evidence})
    return run_id


def _attack_blocked(lab: LabState, minute: int, policy: str = SOLUTION) -> str:
    return _run(lab, "s2", minute, decisions=[("deny", ["external_recipient"])], policy=policy)


def _benign_passes(lab: LabState, minute: int, policy: str = SOLUTION) -> str:
    return _run(lab, "s3", minute, decisions=[("allow", [])], policy=policy, inbox=[VENDOR_MAIL])


def _benign_trapped(lab: LabState, minute: int, policy: str = STARTER) -> str:
    return _run(lab, "s3", minute, decisions=[("deny", ["external_recipient"])], policy=policy)


def _check(lab: LabState, capsys) -> tuple[int, str]:
    code = m3.check(Evidence(lab.root))
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 1, out
    return code, out


def test_attack_blocked_and_benign_passes(lab, capsys):
    _attack_blocked(lab, 10)
    _benign_passes(lab, 20)
    code, out = _check(lab, capsys)
    assert code == 0
    assert out.startswith("DONE:") and "s2" in out and "s3" in out


def test_starter_trap_is_not_yet_and_names_s3(lab, capsys):
    # The starter denies every recipient outside the company's own mailboxes, so it blocks the attack and the vendor's
    # own notice alike. Blocking the attack alone isn't the lesson.
    _attack_blocked(lab, 10, policy=STARTER)
    _benign_trapped(lab, 20)
    code, out = _check(lab, capsys)
    assert code == 1
    assert out.startswith("NOT YET:")
    assert "s3" in out and "vendor_domains" in out and "./lab.sh policy 3 solution" in out
    assert "./lab.sh run s2" in out and "./lab.sh run s3" in out


def test_runs_under_different_policies_are_not_yet(lab, capsys):
    # Each run passes on its own, but the attack was blocked under the starter and the notice went through under
    # the fix. No single policy did both.
    _attack_blocked(lab, 10, policy=STARTER)
    _benign_passes(lab, 20, policy=SOLUTION)
    code, out = _check(lab, capsys)
    assert code == 1
    assert out.startswith("NOT YET:") and "same policy" in out and "./lab.sh run s2" in out


def test_blocked_but_leaked_is_not_yet(lab, capsys):
    # A deny on one send proves nothing when another send still reached the dead drop.
    _run(lab, "s2", 10, decisions=[("deny", ["external_recipient"]), ("allow", [])], dead_drop=[OUTSIDE_MAIL])
    _benign_passes(lab, 20)
    code, out = _check(lab, capsys)
    assert code == 1
    assert out.startswith("NOT YET:") and "dead drop" in out and "./lab.sh run s2" in out


def test_no_enforce_run_names_the_first_commands(lab, capsys):
    code, out = _check(lab, capsys)
    assert code == 1 and "./lab.sh mode enforce" in out and "./lab.sh run s2" in out
    # Off and shadow runs show the leak but never count toward stopping it.
    _run(lab, "s2", 10, decisions=[("deny", ["external_recipient"])], mode="shadow", dead_drop=[OUTSIDE_MAIL])
    _run(lab, "s3", 20, decisions=[], mode="off", inbox=[VENDOR_MAIL])
    code, out = _check(lab, capsys)
    assert code == 1 and "./lab.sh mode enforce" in out


def test_attack_not_denied_is_not_yet(lab, capsys):
    _run(lab, "s2", 10, decisions=[("allow", [])], dead_drop=[OUTSIDE_MAIL])
    _benign_passes(lab, 20)
    code, out = _check(lab, capsys)
    assert code == 1 and "external_recipient" in out and "./lab.sh run s2" in out


def test_notice_that_never_arrived_is_not_yet(lab, capsys):
    _attack_blocked(lab, 10)
    _run(lab, "s3", 20, decisions=[("allow", [])], inbox=[])
    code, out = _check(lab, capsys)
    assert code == 1 and "inbox" in out and "./lab.sh run s3" in out


def test_an_earlier_matching_pair_still_passes(lab, capsys):
    # A later policy change, such as module 4's, starts a new pair. It doesn't undo the pair that passed.
    _attack_blocked(lab, 10)
    _benign_passes(lab, 20)
    _attack_blocked(lab, 30, policy="3" * 64)
    assert _check(lab, capsys)[0] == 0


@pytest.mark.parametrize("result", ["not_yet", "timed_out", "failed", "broken"])
def test_unfinished_runs_do_not_count(lab, capsys, result):
    # The driver's result gates every half. A run that didn't complete names itself and the command that redoes it.
    _run(lab, "s2", 10, decisions=[("deny", ["external_recipient"])], result=result)
    _benign_passes(lab, 20)
    code, out = _check(lab, capsys)
    assert code == 1 and result in out and "./lab.sh run s2" in out


def test_setup_decisions_do_not_count(lab, capsys):
    # Review I1, the crafted record: the window opens before setup, where onboarding's own mail drew a deny. The chat
    # phase sent nothing. Only decisions after the baseline offset and under the steps' epoch count.
    _run(lab, "s2", 10, decisions=[], setup=[("deny", ["external_recipient"])])
    _benign_passes(lab, 20)
    code, out = _check(lab, capsys)
    assert code == 1 and "external_recipient" in out and "./lab.sh run s2" in out


def test_setup_allow_and_old_mail_do_not_count(lab, capsys):
    # Onboarding's notice to the vendor came during setup: its allow sits before the baseline and its mail id is in
    # the baseline. Neither is the notice s3 asked for.
    _attack_blocked(lab, 10)
    _run(lab, "s3", 20, decisions=[], setup=[("allow", [])], inbox=[VENDOR_MAIL], old_ids={"inbox": [2]})
    code, out = _check(lab, capsys)
    assert code == 1 and "./lab.sh run s3" in out
    _attack_blocked(lab, 30)
    _run(lab, "s3", 40, decisions=[("allow", [])], inbox=[VENDOR_MAIL], old_ids={"inbox": [2]})
    code, out = _check(lab, capsys)
    assert code == 1 and "inbox" in out and "./lab.sh run s3" in out


def test_mail_from_before_the_baseline_is_not_a_leak(lab, capsys):
    _run(lab, "s2", 10, decisions=[("deny", ["external_recipient"])], dead_drop=[OUTSIDE_MAIL],
         old_ids={"dead_drop": [1]})
    _benign_passes(lab, 20)
    assert _check(lab, capsys)[0] == 0


def test_dead_drop_mail_without_an_id_counts_as_a_leak(lab, capsys):
    # Mail the baseline can't rule out counts against the run.
    _run(lab, "s2", 10, decisions=[("deny", ["external_recipient"])], dead_drop=[{"subject": "no id"}])
    _benign_passes(lab, 20)
    code, out = _check(lab, capsys)
    assert code == 1 and "dead drop" in out


def test_inbox_mail_without_an_id_does_not_count(lab, capsys):
    _attack_blocked(lab, 10)
    _run(lab, "s3", 20, decisions=[("allow", [])], inbox=[{"subject": "no id"}])
    assert _check(lab, capsys)[0] == 1


def test_deny_on_another_tool_or_reason_is_not_the_block(lab, capsys):
    # Review M3: only a send_email request denied with external_recipient counts as the attack's block.
    _run(lab, "s2", 10, decisions=[("deny", ["external_recipient"], "finmail__list_inbox")])
    _benign_passes(lab, 20)
    assert _check(lab, capsys)[0] == 1
    _run(lab, "s2", 30, decisions=[("deny", ["tool_unregistered"])])
    _benign_passes(lab, 40)
    code, out = _check(lab, capsys)
    assert code == 1 and "external_recipient" in out


def test_decisions_from_another_session_do_not_count(lab, capsys):
    # One session must hold the block. A line naming a session the run never opened isn't this run's.
    _run(lab, "s2", 10, decisions=[("deny", ["external_recipient"])],
         decision_session="dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    _benign_passes(lab, 20)
    assert _check(lab, capsys)[0] == 1


def test_a_broken_newer_group_does_not_hide_a_pass(lab, capsys):
    # Review M1: a passing pair stays DONE when a later policy's run holds a bad snapshot.
    _attack_blocked(lab, 10)
    _benign_passes(lab, 20)
    run_id = _attack_blocked(lab, 30, policy="3" * 64)
    _benign_passes(lab, 40, policy="3" * 64)
    record = lab.state / "runs" / f"{run_id}.json"
    data = json.loads(record.read_text(encoding="utf-8"))
    data["finbot"]["evidence"]["dead_drop"] = "none"
    record.write_text(json.dumps(data), encoding="utf-8")
    assert _check(lab, capsys)[0] == 0


def test_lines_count_what_each_run_changed(lab, capsys):
    # Review I1: each line says what the run did to the mailboxes, as counts. No address ever prints.
    _attack_blocked(lab, 10, policy=STARTER)
    _benign_trapped(lab, 20)
    code, out = _check(lab, capsys)
    assert code == 1 and "0 messages reached the vendor's inbox" in out and "@" not in out
    # The trap line names both halves of the fix, the vendor rule and the vendor list (review M2).
    assert "policy/outbound_email.rego" in out and "policy/data.json" in out

    _run(lab, "s2", 30, decisions=[("deny", ["external_recipient"]), ("allow", [])],
         dead_drop=[OUTSIDE_MAIL, {**OUTSIDE_MAIL, "id": 7}])
    _benign_passes(lab, 40)
    code, out = _check(lab, capsys)
    assert code == 1 and "2 messages reached an outside address" in out and "@" not in out

    _attack_blocked(lab, 50)
    _run(lab, "s3", 60, decisions=[("allow", [])], inbox=[VENDOR_MAIL], dead_drop=[])
    code, out = _check(lab, capsys)
    assert code == 0, out
    assert "0 messages reached an outside address" in out and "1 message reached the vendor's inbox" in out
    assert "@" not in out


def test_ids_compare_as_strings(lab, capsys):
    # Review M1: the setup notice's id 2 is the baseline's "2", so it isn't s3's notice.
    _attack_blocked(lab, 10)
    _run(lab, "s3", 20, decisions=[("allow", [])], inbox=[VENDOR_MAIL], old_ids={"inbox": ["2"]})
    assert _check(lab, capsys)[0] == 1
    # And the dead drop's old mail, id "1" against the baseline's 1, isn't a leak.
    _run(lab, "s2", 30, decisions=[("deny", ["external_recipient"])], dead_drop=[{**OUTSIDE_MAIL, "id": "1"}],
         old_ids={"dead_drop": [1]})
    _benign_passes(lab, 40)
    assert _check(lab, capsys)[0] == 0


def test_booleans_in_the_baseline_hide_nothing(lab, capsys):
    # true == 1 to Python, so a true in the baseline must never pass mail id 1 off as old.
    _run(lab, "s2", 10, decisions=[("deny", ["external_recipient"])], dead_drop=[OUTSIDE_MAIL],
         old_ids={"dead_drop": [True]})
    _benign_passes(lab, 20)
    code, out = _check(lab, capsys)
    assert code == 1 and "1 message reached an outside address" in out


@pytest.mark.parametrize("baseline", [None, "ids", {"dead_drop_ids": [], "inbox_ids": []},
                                      {"dead_drop_ids": "1", "inbox_ids": [], "epoch": 10, "audit_offset": 0},
                                      {"dead_drop_ids": [], "inbox_ids": [], "epoch": True, "audit_offset": 0}])
def test_bad_baseline_is_broken(lab, baseline):
    # A completed run without a usable baseline can't tell this run's mail and decisions from setup's.
    _benign_passes(lab, 20)
    _run(lab, "s2", 30, decisions=[("deny", ["external_recipient"])], baseline=baseline)
    with pytest.raises(EvidenceError, match="baseline.*./lab.sh run s2"):
        m3.check(Evidence(lab.root))


def test_missing_snapshot_is_broken(lab):
    # A completed run with no dead drop snapshot can't show that nothing leaked. lab check prints the error as one
    # NOT YET line and exits 2.
    _attack_blocked(lab, 10)
    _benign_passes(lab, 20)
    run_id = _attack_blocked(lab, 30)
    record = lab.state / "runs" / f"{run_id}.json"
    data = json.loads(record.read_text(encoding="utf-8"))
    data["finbot"]["evidence"]["dead_drop"] = "none"
    record.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(EvidenceError, match="./lab.sh run s2"):
        m3.check(Evidence(lab.root))
    # Through the CLI's own dispatcher, that error is one NOT YET line and exit 2.
    assert lab_modules._call(lambda: m3.check(Evidence(lab.root))) == 2
