"""Module 4's check, Ask a human (issue #589, LAB-16 Task 9).

Version 1.1.0. Owner: Rock Lambros.

Runs in the adapters environment with the pqc extra, like every module check test:

    uv run --project adapters --locked --extra pqc --group test python -m pytest \
        labs/finbot/modules/checks/tests/test_m4.py -v

Each run here writes the audit lines the gateway writes for a held call (ask_pending, ask_resolved, then
decision_applied for the same call) and the FinBot snapshot the driver copies into the run record.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from fixtures import BUNDLE, SESSION_A, SESSION_B, LabState

import lab_modules  # noqa: E402  (the CLI's dispatcher, for the exit code a broken record gets)
import m4  # noqa: E402  (fixtures put the checks directory on sys.path)
from evidence import Evidence, EvidenceError

TRANSFER = "finstripe__create_transfer"
REQUEST = "steps/toolCallRequest"
SOLUTION = "4" * 64
OTHER_POLICY = "5" * 64
PAID = {"id": 1, "invoice_id": 1, "vendor_id": 1, "transfer_id": "tr_1", "amount": 7500.0, "currency": "USD",
        "status": "completed", "created_at": "2026-11-25T10:15:30Z"}
KEEP: Any = object()

# One held call: what the approver did, what the gateway applied, and what the Guardian said on the resend.
APPROVED = ("approved", "allow", "allow")
REJECTED = ("rejected", "deny", None)
TIMED_OUT = ("timed_out", "deny", None)
ABANDONED = ("abandoned", "deny", None)
APPROVED_THEN_DENIED = ("approved", "deny", "deny")
CAUSES = {"rejected": "ask_rejected", "timed_out": "ask_timeout", "abandoned": "client_disconnected"}


@pytest.fixture
def lab(tmp_path) -> LabState:
    return LabState(tmp_path / "bundle")


def _hold(lab: LabState, session: str, epoch: int, call_id: str, held: tuple[str, str, str | None]) -> None:
    """The three lines the gateway writes for one held transfer, in its order (adapters/gateway/README.md, Audit)."""
    outcome, decision, guardian = held
    lab.audit("ask_pending", session_id=session, call_id=call_id, tool=TRANSFER, request_id=f"ask-{call_id}",
              approver="lab-approver", question="Approve a transfer of 7500?", deadline_s=240, remaining_s=239.0)
    approved = outcome == "approved"
    lab.audit("ask_resolved", session_id=session, call_id=call_id, tool=TRANSFER, ask_request_id=f"ask-{call_id}",
              approver="lab-approver", deadline_s=240, outcome=outcome, waited_s=3.2, resent=approved,
              request_id=f"resend-{call_id}" if approved else None, guardian_decision=guardian, decision=decision,
              cause=None if decision == "allow" else (CAUSES.get(outcome) or "guardian_deny"))
    lab.audit("decision_applied", session_id=session, epoch=epoch, method=REQUEST, tool=TRANSFER, call_id=call_id,
              request_id=f"resend-{call_id}" if approved else f"ask-{call_id}", decision=decision,
              guardian_decision=guardian or "ask", reason_codes=[], cause=None, failure_class=None)


def _allow(lab: LabState, session: str, epoch: int, call_id: str) -> None:
    """A transfer the Guardian allowed with no ask, as it does under the threshold or under the starter."""
    lab.audit("decision_applied", session_id=session, epoch=epoch, method=REQUEST, tool=TRANSFER, call_id=call_id,
              request_id=f"req-{call_id}", decision="allow", guardian_decision="allow", reason_codes=[], cause=None,
              failure_class=None)


def _run(lab: LabState, minute: int, holds: list[tuple[str, str, str | None]], *, transfers: Any = KEEP,
         policy: str = SOLUTION, mode: str = "enforce", result: str = "completed", scenario: str = "s4a",
         unasked: int = 0, before_baseline: list[tuple[str, str, str | None]] | None = None,
         hold_session: str | None = None, baseline: Any = KEEP) -> str:
    """One driver run of s4a. transfers defaults to the 7500 payment when a hold was approved, else to none.

    before_baseline writes held calls ahead of the baseline's audit offset but inside the window, which only a crafted
    record holds, since the driver opens its window after setup.
    """
    session = SESSION_A
    start = lab.size(lab.audit_file)
    for n, held in enumerate(before_baseline or []):
        _hold(lab, session, minute - 1, f"setup_{minute}_{n}", held)
    offset = lab.size(lab.audit_file)
    lab.audit("session_opened", session_id=session, epoch=minute)
    for n, held in enumerate(holds):
        _hold(lab, hold_session or session, minute, f"call_{minute}_{n}", held)
    for n in range(unasked):
        _allow(lab, session, minute, f"plain_{minute}_{n}")
    end = lab.size(lab.audit_file)
    if transfers is KEEP:
        transfers = [PAID] if any(h[0] == "approved" and h[1] == "allow" for h in holds) else []
    evidence: dict[str, Any] = {"invoice": {"id": 1, "status": "submitted"}, "transfers": transfers,
                                "baseline": {"dead_drop_ids": [], "inbox_ids": [], "epoch": minute,
                                             "audit_offset": offset}}
    if transfers is None:
        del evidence["transfers"]
    if baseline is not KEEP:
        evidence["baseline"] = baseline
    run_id = f"20261125T10{minute:02d}00Z-{scenario}"
    lab.run_record(run_id, scenario=scenario, mode=mode, started=f"2026-11-25T10:{minute:02d}:00Z",
                   audit=(start, end), sessions=[session], policy_sha256=policy, result=result,
                   epoch=[minute, minute + 1],
                   finbot={"namespace": "ns_user_test", "vendor": {}, "evidence": evidence})
    return run_id


def _check(lab: LabState, capsys) -> tuple[int, str]:
    code = m4.check(Evidence(lab.root))
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 1, out
    return code, out


def _not_yet(lab: LabState, capsys) -> str:
    code, out = _check(lab, capsys)
    assert code == 1, out
    assert out.startswith("NOT YET:") and "./lab.sh " in out, out
    return out


# ---------------------------------------------------------------------------------------------------------------------
# The four tests the plan names
# ---------------------------------------------------------------------------------------------------------------------

def test_one_approved_one_rejected(lab, capsys):
    approved = _run(lab, 10, [APPROVED])
    rejected = _run(lab, 20, [REJECTED])
    code, out = _check(lab, capsys)
    assert code == 0, out
    assert out.startswith("DONE:") and approved in out and rejected in out


def test_rejected_first_then_approved_also_passes(lab, capsys):
    _run(lab, 10, [REJECTED])
    _run(lab, 20, [APPROVED])
    assert _check(lab, capsys)[0] == 0


def test_two_approvals_is_not_yet(lab, capsys):
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [APPROVED])
    out = _not_yet(lab, capsys)
    assert "reject" in out and "--answer reject" in out


def test_two_rejections_is_not_yet(lab, capsys):
    _run(lab, 10, [REJECTED])
    _run(lab, 20, [REJECTED])
    out = _not_yet(lab, capsys)
    assert "--answer approve" in out


@pytest.mark.parametrize("other", [REJECTED, TIMED_OUT], ids=["rejected", "timed out"])
def test_timeout_counts_as_rejected_not_as_approved(lab, capsys, other):
    # D-043: an ask nobody answers denies. A timeout is the rejected half, never the approved one.
    _run(lab, 10, [TIMED_OUT])
    _run(lab, 20, [other])
    out = _not_yet(lab, capsys)
    assert "--answer approve" in out


def test_approved_and_timed_out_passes(lab, capsys):
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [TIMED_OUT])
    assert _check(lab, capsys)[0] == 0


def test_timeout_with_a_transfer_is_not_approved(lab, capsys):
    # A transfer that shows up in a run whose only ask timed out went through some other way. It is neither half.
    _run(lab, 10, [TIMED_OUT], transfers=[PAID])
    _run(lab, 20, [REJECTED])
    _not_yet(lab, capsys)


def test_approved_without_transfer_is_not_yet(lab, capsys):
    _run(lab, 10, [APPROVED], transfers=[])
    _run(lab, 20, [REJECTED])
    out = _not_yet(lab, capsys)
    assert "7500" in out


# ---------------------------------------------------------------------------------------------------------------------
# Other ways a run could look like the lesson without being it
# ---------------------------------------------------------------------------------------------------------------------

def test_approval_the_guardian_then_denied_is_not_approved(lab, capsys):
    # D-043: the Guardian's decision on the resend is the only thing that releases the call.
    _run(lab, 10, [APPROVED_THEN_DENIED], transfers=[])
    _run(lab, 20, [REJECTED])
    out = _not_yet(lab, capsys)
    assert "--answer approve" in out


def test_wrong_amount_is_not_the_payment(lab, capsys):
    _run(lab, 10, [APPROVED], transfers=[{**PAID, "amount": 750.0}])
    _run(lab, 20, [REJECTED])
    assert "7500" in _not_yet(lab, capsys)


def test_failed_transfer_is_not_the_payment(lab, capsys):
    _run(lab, 10, [APPROVED], transfers=[{**PAID, "status": "failed"}])
    _run(lab, 20, [REJECTED])
    _not_yet(lab, capsys)


def test_amount_written_as_a_flag_is_not_the_payment(lab, capsys):
    # bool is an int to Python, and True == 1, so a crafted amount must not pass as a number.
    _run(lab, 10, [APPROVED], transfers=[{**PAID, "amount": True}])
    _run(lab, 20, [REJECTED])
    _not_yet(lab, capsys)


def test_rejected_but_paid_is_not_yet(lab, capsys):
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [REJECTED], transfers=[PAID])
    out = _not_yet(lab, capsys)
    assert "reject" in out


def test_rejected_run_with_a_split_payment_is_not_yet(lab, capsys):
    # Two smaller transfers under the threshold get past an amount rule. Any transfer in the rejected run fails, and
    # the line names the split and a rerun, since the rule itself is fine (review M5).
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [REJECTED], unasked=2, transfers=[{**PAID, "amount": 3750.0}, {**PAID, "id": 2, "amount": 3750.0}])
    out = _not_yet(lab, capsys)
    assert "smaller transfers" in out and "./lab.sh run s4a --answer reject" in out
    assert "policy 4 solution" not in out


def test_rejected_run_with_a_transfer_and_no_decision_is_not_yet(lab, capsys):
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [REJECTED], transfers=[{**PAID, "amount": 3750.0}])
    out = _not_yet(lab, capsys)
    assert "no gateway decision" in out and "./lab.sh run s4a --answer reject" in out


def test_rejected_run_with_an_unasked_allowed_transfer_is_not_yet(lab, capsys):
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [REJECTED], unasked=1, transfers=[])
    _not_yet(lab, capsys)


def test_approved_run_with_an_unasked_allowed_transfer_is_not_yet(lab, capsys):
    # The 7500 could be the transfer the Guardian allowed with no ask, so the approval proves nothing about it.
    _run(lab, 10, [APPROVED], unasked=1)
    _run(lab, 20, [REJECTED])
    _not_yet(lab, capsys)


def test_completed_with_an_error_does_not_count(lab, capsys):
    # The driver stores completed with a null error only when it printed DONE (review M1).
    _run(lab, 10, [APPROVED])
    rejected = _run(lab, 20, [REJECTED])
    record = lab.state / "runs" / f"{rejected}.json"
    data = json.loads(record.read_text(encoding="utf-8"))
    data["error"] = "1 model call had no recording in replay"
    record.write_text(json.dumps(data), encoding="utf-8")
    out = _not_yet(lab, capsys)
    assert "with an error" in out and "./lab.sh run s4a" in out


def test_extra_transfer_with_no_decision_is_not_yet(lab, capsys):
    # Every transfer in the approved run must have the gateway's allow behind it (review M4).
    _run(lab, 10, [APPROVED], transfers=[PAID, {**PAID, "id": 2, "amount": 99999.0}])
    _run(lab, 20, [REJECTED])
    assert "exactly one" in _not_yet(lab, capsys)


def test_two_approved_transfers_is_not_yet(lab, capsys):
    _run(lab, 10, [APPROVED, APPROVED], transfers=[PAID, {**PAID, "id": 2}])
    _run(lab, 20, [REJECTED])
    _not_yet(lab, capsys)


def test_call_id_reused_across_sessions_is_not_paired(lab, capsys):
    # An approval whose own call the gateway denied in one session, and an unasked allow under the same call id in
    # another, don't make an approved call (review M3).
    start = lab.size(lab.audit_file)
    lab.audit("session_opened", session_id=SESSION_A, epoch=10)
    lab.audit("session_opened", session_id=SESSION_B, epoch=10)
    lab.audit("ask_resolved", session_id=SESSION_B, call_id="call_x", tool=TRANSFER, ask_request_id="ask-x",
              approver="lab-approver", deadline_s=240, outcome="approved", waited_s=3.2, resent=True,
              request_id="resend-x", guardian_decision="allow", decision="allow", cause=None)
    lab.audit("decision_applied", session_id=SESSION_B, epoch=10, method=REQUEST, tool=TRANSFER, call_id="call_x",
              request_id="resend-x", decision="deny", guardian_decision="deny", reason_codes=[], cause=None,
              failure_class=None)
    _allow(lab, SESSION_A, 10, "call_x")
    end = lab.size(lab.audit_file)
    evidence = {"transfers": [PAID], "baseline": {"dead_drop_ids": [], "inbox_ids": [], "epoch": 10,
                                                 "audit_offset": start}}
    lab.run_record("20261125T1010Z-s4a", scenario="s4a", started="2026-11-25T10:10:00Z", audit=(start, end),
                   sessions=[SESSION_A, SESSION_B], policy_sha256=SOLUTION, epoch=[10, 11],
                   finbot={"namespace": "ns_user_test", "vendor": {}, "evidence": evidence})
    _run(lab, 20, [REJECTED])
    _not_yet(lab, capsys)


def test_abandoned_counts_as_neither(lab, capsys):
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [ABANDONED])
    out = _not_yet(lab, capsys)
    assert "--answer reject" in out


def test_starter_never_asks(lab, capsys):
    # Under the starter every transfer goes through with no ask.
    _run(lab, 10, [], unasked=1, transfers=[PAID])
    out = _not_yet(lab, capsys)
    assert "payment_threshold.rego" in out and "./lab.sh policy 4 solution" in out


def test_runs_under_different_policies_are_not_yet(lab, capsys):
    _run(lab, 10, [APPROVED], policy=SOLUTION)
    _run(lab, 20, [REJECTED], policy=OTHER_POLICY)
    out = _not_yet(lab, capsys)
    assert "same policy" in out


def test_older_pair_under_one_policy_still_passes(lab, capsys):
    # Module 5 changes the policy later. A new policy starts a new pair without undoing this one.
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [REJECTED])
    _run(lab, 30, [], policy=OTHER_POLICY, unasked=1, transfers=[PAID])
    assert _check(lab, capsys)[0] == 0


def test_bad_policy_hash_does_not_count(lab, capsys):
    _run(lab, 10, [APPROVED], policy="")
    _run(lab, 20, [REJECTED], policy="")
    _not_yet(lab, capsys)


@pytest.mark.parametrize("mode", ["shadow", "off"])
def test_runs_outside_enforce_do_not_count(lab, capsys, mode):
    _run(lab, 10, [APPROVED], mode=mode)
    _run(lab, 20, [REJECTED], mode=mode)
    out = _not_yet(lab, capsys)
    assert "./lab.sh mode enforce" in out


@pytest.mark.parametrize("result", ["not_yet", "timed_out", "failed", "broken"])
def test_unfinished_run_does_not_count(lab, capsys, result):
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [REJECTED], result=result)
    out = _not_yet(lab, capsys)
    assert "./lab.sh run s4a" in out


def test_s4b_does_not_count(lab, capsys):
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [REJECTED], scenario="s4b")
    _not_yet(lab, capsys)


def test_ask_from_another_session_does_not_count(lab, capsys):
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [REJECTED], hold_session=SESSION_B)
    _not_yet(lab, capsys)


def test_ask_before_the_baseline_does_not_count(lab, capsys):
    # A held call ahead of the baseline's offset belongs to setup, not to the run's steps.
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [], before_baseline=[REJECTED])
    _not_yet(lab, capsys)


def test_no_run_names_the_first_command(lab, capsys):
    out = _not_yet(lab, capsys)
    assert "./lab.sh mode enforce" in out and "./lab.sh run s4a" in out


def test_one_run_line_is_one_line(lab, capsys):
    _run(lab, 10, [APPROVED])
    _not_yet(lab, capsys)


# ---------------------------------------------------------------------------------------------------------------------
# Broken records and fixed facts
# ---------------------------------------------------------------------------------------------------------------------

def test_missing_transfer_snapshot_is_broken(lab):
    _run(lab, 10, [APPROVED], transfers=None)
    with pytest.raises(EvidenceError, match="./lab.sh run s4a"):
        m4.check(Evidence(lab.root))
    assert lab_modules._call(lambda: m4.check(Evidence(lab.root))) == 2


def test_missing_baseline_is_broken(lab):
    _run(lab, 10, [APPROVED], baseline=None)
    with pytest.raises(EvidenceError, match="baseline"):
        m4.check(Evidence(lab.root))


def test_broken_older_group_does_not_block_a_pass(lab, capsys):
    # A broken record in a group that can't pass never hides a group that does (module 3 review M1).
    _run(lab, 5, [APPROVED], policy=OTHER_POLICY, transfers=None)
    _run(lab, 10, [APPROVED])
    _run(lab, 20, [REJECTED])
    assert _check(lab, capsys)[0] == 0


def test_amount_matches_the_scenario():
    facts = json.loads((BUNDLE / "scenarios" / "s4a.json").read_text(encoding="utf-8"))["facts"]
    assert m4.AMOUNT == facts["amount"]
    assert m4.SCENARIO == "s4a"
