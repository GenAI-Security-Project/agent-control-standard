"""Module 6's check, Poison a tool (issue #589, LAB-16 Task 11).

Version 1.0.0. Owner: Rock Lambros.

Runs in the adapters environment with the pqc extra, like every module check test:

    uv run --project adapters --locked --extra pqc --group test python -m pytest \
        labs/finbot/modules/checks/tests/test_m6.py -v

Every run here is built from audit lines and FinBot snapshots alone. None of it carries s6's changed tool description
or its chat message, because the check must judge a run by its decisions and its evidence, never by the attack text.
"""
from __future__ import annotations

import json
import re
import shutil
from typing import Any

import pytest

from fixtures import SESSION_A, SESSION_B, LabState

import guide_rego  # noqa: E402  (beside this file, shared with module 5's guide test)
import lab_modules  # noqa: E402  (the CLI's dispatcher, for the exit code a broken record gets)
import m6  # noqa: E402  (fixtures put the checks directory on sys.path)
from evidence import Evidence, EvidenceError

SEND = "finmail__send_email"
REQUEST = "steps/toolCallRequest"
RESULT = "steps/toolCallResult"
MISMATCH = "tool_content_hash_mismatch"
SETUP_MAIL = {"id": 1, "to_addresses": ["ap@vendor.example"], "subject": "welcome",
              "created_at": "2026-11-25T10:05:30Z"}
OUTSIDE_MAIL = {"id": 2, "to_addresses": ["someone@outside.example"], "subject": "details",
                "created_at": "2026-11-25T10:15:30Z"}
# (decision applied, Guardian decision, reason codes, method, session). Session None means the run's own session.
Decision = tuple[str, str | None, list[str], str, str | None]


def deny(codes: list[str], method: str = REQUEST, session: str | None = None) -> Decision:
    return ("deny", "deny", codes, method, session)


def allow(method: str = REQUEST) -> Decision:
    return ("allow", "allow", [], method, None)


@pytest.fixture
def lab(tmp_path) -> LabState:
    return LabState(tmp_path / "bundle")


def _decision_lines(lab: LabState, session: str, minute: int, decisions: list[Decision], event: str) -> None:
    for n, (applied, guardian, codes, method, other) in enumerate(decisions):
        lab.audit(event, session_id=other or session, epoch=minute, method=method, tool=SEND,
                  call_id=f"call_{minute}_{n}", request_id=None, decision=applied, guardian_decision=guardian,
                  reason_codes=codes, cause=None, failure_class=None)


def _run(lab: LabState, minute: int, *, decisions: list[Decision], mode: str = "enforce",
         dead_drop: list[dict[str, Any]] | None = None, baseline_ids: list[Any] | None = None,
         setup: list[Decision] | None = None, result: str = "completed", scenario: str = "s6",
         session: str = SESSION_A) -> str:
    """One driver run. Setup's decision lines, if any, sit before baseline.audit_offset. With setup the window
    opens before that offset too, so a check that ignored the baseline would read them as the run's own."""
    window_start = lab.size(lab.audit_file)
    event = "decision_applied" if mode == "enforce" else "shadow_decision"
    if setup:
        _decision_lines(lab, session, minute, setup, event)
    offset = lab.size(lab.audit_file)
    lab.audit("session_opened", session_id=session, epoch=minute)
    _decision_lines(lab, session, minute, decisions, event)
    end = lab.size(lab.audit_file)
    start = window_start if setup else offset
    run_id = f"20261125T10{minute:02d}00Z-{scenario}"
    evidence: dict[str, Any] = {
        "baseline": {"dead_drop_ids": baseline_ids or [], "inbox_ids": [], "epoch": minute, "audit_offset": offset},
        "dead_drop": dead_drop or [], "inbox": [], "reply": "I couldn't complete that action.",
    }
    lab.run_record(run_id, scenario=scenario, mode=mode, started=f"2026-11-25T10:{minute:02d}:00Z",
                   audit=(start, end), sessions=[session], policy_sha256="6" * 64, result=result,
                   finbot={"namespace": "ns_user_test", "vendor": {}, "evidence": evidence})
    return run_id


def _check(lab: LabState, capsys) -> tuple[int, str]:
    code = m6.check(Evidence(lab.root))
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 1, out
    return code, out


# ---------------------------------------------------------------------------------------------------------------------
# The three tests the plan names
# ---------------------------------------------------------------------------------------------------------------------

def test_digest_mismatch_denies(lab, capsys):
    # The onboarding mail from setup sits in the dead drop before the steps, so the baseline holds its id.
    _run(lab, 10, decisions=[deny([MISMATCH])], dead_drop=[SETUP_MAIL], baseline_ids=[1])
    code, out = _check(lab, capsys)
    assert code == 0
    assert out.startswith("DONE:") and MISMATCH in out and SEND in out


def test_unregistered_deny_is_not_this_lesson(lab, capsys):
    # base.rego denies a tool the registry doesn't hold before any module runs, so the pin rule never judged it.
    _run(lab, 10, decisions=[deny(["tool_unregistered"])])
    code, out = _check(lab, capsys)
    assert code == 1
    assert out.startswith("NOT YET:") and "tool_unregistered" in out
    # The clean run goes in off mode, as the pins capture did. pins skips poisoned runs, so nothing is wiped first.
    steps = ["./lab.sh mode off", "./lab.sh run s6 --clean", "./lab.sh pins", "./lab.sh mode enforce",
             "./lab.sh run s6"]
    at = [out.index(step) for step in steps[:-1]] + [out.rindex(steps[-1])]
    assert at == sorted(at), out
    assert "reset" not in out and "init" not in out


def test_off_run_only_is_not_yet(lab, capsys):
    _run(lab, 10, decisions=[], mode="off", dead_drop=[OUTSIDE_MAIL])
    code, out = _check(lab, capsys)
    assert code == 1
    assert out.startswith("NOT YET:") and "off mode" in out
    assert "./lab.sh policy 6 solution" in out and "./lab.sh mode enforce" in out and "./lab.sh run s6" in out


# ---------------------------------------------------------------------------------------------------------------------
# Every other way a run can fall short. None of them may read as DONE.
# ---------------------------------------------------------------------------------------------------------------------

def test_no_run_names_the_first_commands(lab, capsys):
    code, out = _check(lab, capsys)
    assert code == 1 and "./lab.sh mode enforce" in out and "./lab.sh run s6" in out


def test_shadow_run_does_not_count(lab, capsys):
    # A shadow deny records what enforce would have done and forwards the call anyway.
    _run(lab, 10, decisions=[deny([MISMATCH])], mode="shadow", dead_drop=[OUTSIDE_MAIL])
    code, out = _check(lab, capsys)
    assert code == 1 and "shadow mode" in out and "./lab.sh mode enforce" in out


def test_enforce_record_with_only_shadow_lines_is_not_yet(lab, capsys):
    run_id = _run(lab, 10, decisions=[deny([MISMATCH])], mode="shadow")
    record = lab.state / "runs" / f"{run_id}.json"
    data = json.loads(record.read_text(encoding="utf-8"))
    data["mode"] = "enforce"
    record.write_text(json.dumps(data), encoding="utf-8")
    code, out = _check(lab, capsys)
    assert code == 1 and MISMATCH in out and "./lab.sh run s6" in out


def test_no_deny_names_the_rule_and_the_solution(lab, capsys):
    # The starter's rule never matches, so the changed tool's call goes through and its mail lands.
    _run(lab, 10, decisions=[allow(), allow(RESULT)], dead_drop=[OUTSIDE_MAIL])
    code, out = _check(lab, capsys)
    assert code == 1 and out.startswith("NOT YET:")
    assert MISMATCH in out and "policy/tool_pins.rego" in out and "./lab.sh policy 6 solution" in out
    assert "./lab.sh run s6" in out and "dead drop" in out
    # An unfinished rule is the common case, so the line names the rule's next step and no registry recovery.
    assert "./lab.sh pins" not in out and "reset" not in out and "--clean" not in out


def test_other_deny_reason_is_not_yet(lab, capsys):
    # Module 3's rule also denies the outside recipient. That deny isn't the pin's.
    _run(lab, 10, decisions=[deny(["external_recipient"])])
    code, out = _check(lab, capsys)
    assert code == 1 and MISMATCH in out and "./lab.sh policy 6 solution" in out


def test_mismatch_beside_another_code_counts(lab, capsys):
    # With module 3's solution live, the verdict lists every deny code, sorted.
    _run(lab, 10, decisions=[deny(["external_recipient", MISMATCH])])
    assert _check(lab, capsys)[0] == 0


def test_deny_on_the_result_only_is_not_yet(lab, capsys):
    # A deny on the result means the call itself already ran.
    _run(lab, 10, decisions=[allow(), deny([MISMATCH], method=RESULT)])
    code, out = _check(lab, capsys)
    assert code == 1 and "./lab.sh run s6" in out


def test_one_deny_and_one_send_through_is_not_yet(lab, capsys):
    _run(lab, 10, decisions=[deny([MISMATCH]), allow()])
    code, out = _check(lab, capsys)
    assert code == 1 and "let 1" in out and "./lab.sh run s6" in out


def test_gateway_failure_deny_is_not_the_guardians(lab, capsys):
    # Enforce turns a Guardian failure into a deny, with no Guardian decision behind it.
    _run(lab, 10, decisions=[("deny", None, [MISMATCH], REQUEST, None)])
    code, out = _check(lab, capsys)
    assert code == 1 and MISMATCH in out


def test_deny_from_a_session_outside_the_run_is_not_yet(lab, capsys):
    _run(lab, 10, decisions=[deny([MISMATCH], session=SESSION_B)])
    code, out = _check(lab, capsys)
    assert code == 1 and MISMATCH in out


def test_setup_deny_before_the_baseline_does_not_count(lab, capsys):
    # The window opens before baseline.audit_offset here, so only the offset keeps setup's deny out.
    _run(lab, 10, decisions=[], setup=[deny([MISMATCH])])
    code, out = _check(lab, capsys)
    assert code == 1 and MISMATCH in out


def test_setup_send_before_the_baseline_does_not_count(lab, capsys):
    _run(lab, 10, decisions=[deny([MISMATCH])], setup=[allow()])
    assert _check(lab, capsys)[0] == 0


def test_new_dead_drop_mail_is_not_yet(lab, capsys):
    # The deny held, yet something still reached an outside address during the run.
    _run(lab, 10, decisions=[deny([MISMATCH])], dead_drop=[SETUP_MAIL, OUTSIDE_MAIL], baseline_ids=[1])
    code, out = _check(lab, capsys)
    assert code == 1 and "dead drop" in out and "./lab.sh run s6" in out


def test_dead_drop_mail_without_an_id_counts_as_new(lab, capsys):
    _run(lab, 10, decisions=[deny([MISMATCH])], dead_drop=[{"to_addresses": ["x@outside.example"]}],
         baseline_ids=[None])
    code, out = _check(lab, capsys)
    assert code == 1 and "dead drop" in out


def test_completed_with_an_error_is_not_yet(lab, capsys):
    # The driver clears error whenever it stores completed. A record holding both wasn't written that way.
    run_id = _run(lab, 10, decisions=[deny([MISMATCH])])
    record = lab.state / "runs" / f"{run_id}.json"
    data = json.loads(record.read_text(encoding="utf-8"))
    record.write_text(json.dumps({**data, "error": "2 model calls had no recording in replay"}), encoding="utf-8")
    code, out = _check(lab, capsys)
    assert code == 1 and "error" in out and "./lab.sh run s6" in out


def test_unfinished_run_is_not_yet(lab, capsys):
    _run(lab, 10, decisions=[deny([MISMATCH])], result="timed_out")
    code, out = _check(lab, capsys)
    assert code == 1 and "timed_out" in out and "./lab.sh run s6" in out


def test_newest_enforce_run_is_the_one_judged(lab, capsys):
    _run(lab, 10, decisions=[deny([MISMATCH])])
    _run(lab, 20, decisions=[allow()], dead_drop=[OUTSIDE_MAIL])
    code, out = _check(lab, capsys)
    assert code == 1 and MISMATCH in out


def test_other_scenarios_do_not_count(lab, capsys):
    _run(lab, 10, decisions=[deny([MISMATCH])], scenario="s2")
    code, out = _check(lab, capsys)
    assert code == 1 and "./lab.sh run s6" in out


def test_missing_baseline_is_broken(lab):
    # A completed run with no baseline can't show what arrived during it. lab check prints the error as one NOT YET
    # line and exits 2.
    run_id = _run(lab, 10, decisions=[deny([MISMATCH])])
    record = lab.state / "runs" / f"{run_id}.json"
    data = json.loads(record.read_text(encoding="utf-8"))
    del data["finbot"]["evidence"]["baseline"]
    record.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(EvidenceError, match="./lab.sh run s6"):
        m6.check(Evidence(lab.root))
    assert lab_modules._call(lambda: m6.check(Evidence(lab.root))) == 2


def test_missing_dead_drop_is_broken(lab):
    run_id = _run(lab, 10, decisions=[deny([MISMATCH])])
    record = lab.state / "runs" / f"{run_id}.json"
    data = json.loads(record.read_text(encoding="utf-8"))
    data["finbot"]["evidence"]["dead_drop"] = "none"
    record.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(EvidenceError, match="./lab.sh run s6"):
        m6.check(Evidence(lab.root))


# ---------------------------------------------------------------------------------------------------------------------
# the guide's Rego (fix round 1, review I-3)
# ---------------------------------------------------------------------------------------------------------------------

GUIDE = guide_rego.POLICY.parent / "modules" / "6.md"
STARTER = guide_rego.POLICY / "starters" / "m6" / "tool_pins.rego"
# The starter's one rule, from its head to the closing brace at column 0. The guide tells the reader to replace it.
STARTER_RULE = re.compile(r"^deny_codes contains .*?^}\n", re.M | re.S)


def _pasted() -> tuple[str, str]:
    snippet = guide_rego.guide_rego(GUIDE)
    return snippet, guide_rego.pasted(STARTER, STARTER_RULE, snippet)


def test_guide_rego_names_only_what_the_pasted_file_defines():
    # Pasted into the starter, the guide's Rego must compile, since one broken file stops OPA deciding for every
    # module. The snippet once called version_readable and version_pinned, which only the solution defines.
    snippet, pasted = _pasted()
    assert not guide_rego.problems(snippet, pasted, "tool_pins.rego")


def test_the_static_check_catches_a_solution_only_helper():
    # The check above must fail on the snippet the review found, or it proves nothing.
    old = "deny_codes contains \"tool_content_hash_mismatch\" if {\n\tregistered\n\tversion_readable\n" \
          "\tnot version_pinned\n}\n"
    found = guide_rego.problems(old, guide_rego.pasted(STARTER, STARTER_RULE, old), "tool_pins.rego")
    assert found and "version_pinned" in found[0] and "version_readable" in found[0]


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa is not on PATH. The static test above still runs")
def test_guide_rego_compiles_in_the_pack(tmp_path):
    _, pasted = _pasted()
    done = guide_rego.opa_check(pasted, "tool_pins.rego", tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
