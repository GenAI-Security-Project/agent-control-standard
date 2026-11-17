import pytest

from conftest import NEUTRAL, call_item, finbot_request, response_body, transcript_lines

DENIED = response_body(call_item("bash", {"command": "rm -rf /"}, "call_1"))


def run(client, upstream):
    upstream.reply(DENIED)
    return client.post("/v1/responses", json=finbot_request()).json()


def test_shadow_records_the_deny_and_forwards_the_call(gateway, guardian, upstream, audit, tmp_path):
    reply = run(gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian), upstream)
    assert reply == DENIED
    shadow = [e for e in audit() if e["acs_audit_event"] == "shadow_decision"]
    assert [(e["tool"], e["decision"], e["guardian_decision"]) for e in shadow] == [("bash", "deny", "deny")]
    assert [e for e in audit() if e["acs_audit_event"] == "decision_applied"] == []
    assert any(line["envelope"].get("method") == "steps/toolCallRequest" for line in transcript_lines(tmp_path))


def test_the_same_scenario_leaves_no_record_off_a_record_in_shadow_and_a_block_in_enforce(
        gateway, guardian, upstream, audit, tmp_path):
    off = run(gateway(ACS_LAB_MODE="off"), upstream)
    assert off == DENIED and audit() == [] and transcript_lines(tmp_path) == []
    shadow = run(gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian), upstream)
    assert shadow == DENIED
    enforce = run(gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian), upstream)
    assert enforce["output"][0]["content"][0]["text"] == NEUTRAL


def boom(*args, **kwargs):
    raise RuntimeError("gateway bug")


def test_shadow_forwards_unchanged_when_gating_itself_fails(gateway, guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="shadow", ACS_GUARDIAN_URL=guardian)
    client.app.state.gateway._gate_call = boom
    reply = run(client, upstream)
    assert reply == DENIED
    assert [e["phase"] for e in audit() if e["acs_audit_event"] == "gateway_step_error"] == ["output"]


def test_enforce_fails_closed_when_gating_itself_fails(gateway, guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.app.state.gateway._gate_call = boom
    upstream.reply(DENIED)
    response = client.post("/v1/responses", json=finbot_request())
    assert response.status_code == 500
    assert "rm -rf" not in response.text and "bash" not in response.text
    assert [e["phase"] for e in audit() if e["acs_audit_event"] == "gateway_step_error"] == ["output"]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_a_fault_in_the_pre_pass_follows_the_mode(gateway, guardian, upstream, audit, mode):
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=guardian)
    client.app.state.gateway._refuse_input = boom
    response = client.post("/v1/responses", json=finbot_request())
    assert response.status_code == (200 if mode == "shadow" else 500)
    assert [e["phase"] for e in audit() if e["acs_audit_event"] == "gateway_step_error"] == ["pre_pass"]
