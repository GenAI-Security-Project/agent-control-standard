"""ASK through the approver page (LAB-08, issue #581): the approver answers, the Guardian decides, and silence denies."""
from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from conftest import NEUTRAL, call_item, finbot_request, response_body, transcript_lines

ANSWER_FIELD = "x_acs_lab_ask_answer"


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def approver(client: Any, *choices: str) -> threading.Thread:
    """A person at the approver page: answers each listed call in turn, one choice per call."""
    approvals = client.app.state.gateway.approvals

    def run() -> None:
        answered: set[str] = set()
        end = time.monotonic() + 10
        while len(answered) < len(choices) and time.monotonic() < end:
            for item in approvals.pending():
                if item.ask_id not in answered:
                    assert approvals.answer(item.ask_id, choices[len(answered)])
                    answered.add(item.ask_id)
            time.sleep(0.01)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def enforce(gateway, harness_guardian, **env: str) -> Any:
    guardian_env = {k: v for k, v in env.items() if k.startswith("HARNESS_")}
    gateway_env = {k: v for k, v in env.items() if not k.startswith("HARNESS_")}
    mode = gateway_env.pop("ACS_LAB_MODE", "enforce")
    return gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=harness_guardian(**guardian_env),
                   ACS_GATEWAY_APPROVER_PORT="8090", **gateway_env)


def tool_requests(tmp_path) -> list[dict[str, Any]]:
    return [line["envelope"]["params"] for line in transcript_lines(tmp_path)
            if line["dir"] == "req" and line["envelope"]["method"] == "steps/toolCallRequest"]


def test_an_approved_ask_delivers_the_call_once_the_guardian_allows_the_resend(gateway, harness_guardian, upstream,
                                                                              audit, tmp_path):
    call = call_item("ask_tool", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client = enforce(gateway, harness_guardian)
    thread = approver(client, "approve")
    response = client.post("/v1/responses", json=finbot_request())
    thread.join()
    assert response.json()["output"] == [call]
    first, resent = tool_requests(tmp_path)
    assert ANSWER_FIELD not in first["payload"]
    assert resent["payload"][ANSWER_FIELD] == {"ask_request_id": first["request_id"], "answer": "approve",
                                               "approver": {"type": "human", "id": "lab-approver"},
                                               "assurance": "declared"}
    assert {k: v for k, v in resent["payload"].items() if k != ANSWER_FIELD} == first["payload"]
    assert resent["request_id"] != first["request_id"]
    pending = events(audit, "ask_pending")
    assert [(p["request_id"], p["tool"]) for p in pending] == [(first["request_id"], "ask_tool")]
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["ask_request_id"], r["request_id"], r["guardian_decision"], r["decision"])
            for r in resolved] == [("approved", first["request_id"], resent["request_id"], "allow", "allow")]
    applied = events(audit, "decision_applied")
    assert [(a["decision"], a["guardian_decision"], a["request_id"]) for a in applied] == [
        ("allow", "allow", resent["request_id"])]


def test_a_rejected_ask_blocks_the_call(gateway, harness_guardian, upstream, audit, tmp_path):
    upstream.reply(response_body(call_item("ask_tool", {"vendor_id": 7}, "call_1")))
    client = enforce(gateway, harness_guardian)
    thread = approver(client, "reject")
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    thread.join()
    assert [i["type"] for i in output] == ["message"] and output[0]["content"][0]["text"] == NEUTRAL
    assert tool_requests(tmp_path)[1]["payload"][ANSWER_FIELD]["answer"] == "reject"
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["decision"]) for r in resolved] == [("rejected", "deny")]


def test_one_approve_and_one_reject_give_matching_outcomes_and_two_audit_entries(gateway, harness_guardian, upstream,
                                                                                audit):
    client = enforce(gateway, harness_guardian)
    outcomes = []
    for choice, run in (("approve", "Pay vendor 7"), ("reject", "Pay vendor 8")):
        upstream.reply(response_body(call_item("ask_tool", {"run": run}, f"call_{choice}")))
        thread = approver(client, choice)
        output = client.post("/v1/responses", json=finbot_request(user=run)).json()["output"]
        thread.join()
        outcomes.append(output[0]["type"])
    assert outcomes == ["function_call", "message"]
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["decision"]) for r in resolved] == [("approved", "allow"), ("rejected", "deny")]


def test_approval_releases_nothing_when_the_guardian_denies_the_resend(gateway, harness_guardian, upstream, audit):
    upstream.reply(response_body(call_item("ask_deny_tool", {}, "call_1")))
    client = enforce(gateway, harness_guardian)
    thread = approver(client, "approve")
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    thread.join()
    assert output[0]["content"][0]["text"] == NEUTRAL
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["guardian_decision"], r["decision"]) for r in resolved] == [("approved", "deny", "deny")]


def test_no_answer_before_the_guardians_timeout_denies_without_a_resend(gateway, harness_guardian, upstream, audit,
                                                                       tmp_path):
    upstream.reply(response_body(call_item("ask_tool", {}, "call_1")))
    client = enforce(gateway, harness_guardian, HARNESS_ASK_TIMEOUT_S="1")
    started = time.monotonic()
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert 0.9 <= time.monotonic() - started < 3
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert len(tool_requests(tmp_path)) == 1
    assert client.app.state.gateway.approvals.pending() == []
    resolved = events(audit, "ask_resolved")
    assert [(r["outcome"], r["decision"]) for r in resolved] == [("timed_out", "deny")]
    assert events(audit, "decision_applied")[0]["cause"] == "ask_timeout"


def test_two_asks_in_one_response_share_one_deadline(gateway, harness_guardian, upstream, audit):
    upstream.reply(response_body(call_item("ask_tool", {"n": 1}, "call_1"), call_item("ask_tool", {"n": 2}, "call_2")))
    # The Guardian asks for 60 s each. The cap stands in for 240 s, and both calls must fit inside one of it.
    client = enforce(gateway, harness_guardian, ACS_GATEWAY_ASK_MAX_S="1")
    started = time.monotonic()
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    elapsed = time.monotonic() - started
    assert elapsed < 1.8, elapsed
    assert output[0]["content"][0]["text"] == NEUTRAL
    resolved = events(audit, "ask_resolved")
    assert [r["outcome"] for r in resolved] == ["timed_out", "timed_out"]
    assert resolved[0]["deadline_s"] == resolved[1]["deadline_s"] == 1


def test_a_second_ask_waits_only_for_what_is_left_of_the_first(gateway, harness_guardian, upstream, audit):
    calls = [call_item("ask_tool", {"n": 1}, "call_1"), call_item("ask_tool", {"n": 2}, "call_2")]
    upstream.reply(response_body(*calls))
    client = enforce(gateway, harness_guardian, ACS_GATEWAY_ASK_MAX_S="1.5")
    approvals = client.app.state.gateway.approvals

    def first_only() -> None:
        # Answer the first call late, then never the second.
        end = time.monotonic() + 5
        while not approvals.pending() and time.monotonic() < end:
            time.sleep(0.01)
        time.sleep(0.9)
        approvals.answer(approvals.pending()[0].ask_id, "approve")

    thread = threading.Thread(target=first_only, daemon=True)
    thread.start()
    started = time.monotonic()
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    elapsed = time.monotonic() - started
    thread.join()
    assert elapsed < 2.3, elapsed
    assert output == [calls[0]]
    assert [r["outcome"] for r in events(audit, "ask_resolved")] == ["approved", "timed_out"]


def test_without_the_approver_page_an_ask_denies_as_before(gateway, harness_guardian, upstream, audit):
    upstream.reply(response_body(call_item("ask_tool", {}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian())
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    assert events(audit, "ask_pending") == [] and events(audit, "ask_resolved") == []


def test_shadow_records_the_ask_and_delivers(gateway, harness_guardian, upstream, audit, tmp_path):
    call = call_item("ask_tool", {}, "call_1")
    upstream.reply(response_body(call))
    client = enforce(gateway, harness_guardian, ACS_LAB_MODE="shadow")
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output == [call]
    assert len(tool_requests(tmp_path)) == 1
    assert events(audit, "ask_pending") == []
    assert [(e["guardian_decision"], e["decision"]) for e in events(audit, "shadow_decision")] == [("ask", "deny")]


@pytest.mark.parametrize("details", [None, {}, {"approver": {"type": "human", "id": "a"}, "question": "q"},
                                     {"approver": {"type": "human", "id": "a"}, "question": "q",
                                      "timeout_seconds": 0},
                                     {"approver": {"type": "human", "id": "a"}, "question": "q",
                                      "timeout_seconds": True},
                                     {"approver": {"type": "human"}, "question": "q", "timeout_seconds": 5},
                                     {"approver": {"type": "human", "id": "a"}, "question": 3, "timeout_seconds": 5}])
def test_unusable_ask_details_are_refused(details):
    from acs_gateway.app import ask_settings

    assert ask_settings(details) is None


def test_usable_ask_details_are_read():
    from acs_gateway.app import ask_settings

    assert ask_settings({"approver": {"type": "human", "id": "lab-approver"}, "question": "Pay?",
                         "timeout_seconds": 30}) == ("Pay?", "lab-approver", 30)


def _streamed(client: Any) -> list[dict[str, Any]]:
    from streams import decode

    with client.stream("POST", "/v1/responses", json={**finbot_request(), "stream": True}) as response:
        return decode(b"".join(response.iter_bytes()))


def _streamed_calls(received: list[dict[str, Any]]) -> list[str]:
    return [e["item"]["call_id"] for e in received
            if e["type"] == "response.output_item.done" and e["item"]["type"] == "function_call"]


def test_a_streamed_ask_is_held_and_released_after_approval(gateway, harness_guardian, upstream, audit):
    from conftest import SSE
    from streams import encode, stream_events

    upstream.reply(SSE(encode(stream_events(call_item("ask_tool", {"vendor_id": 7}, "call_1")))))
    client = enforce(gateway, harness_guardian)
    thread = approver(client, "approve")
    received = _streamed(client)
    thread.join()
    assert _streamed_calls(received) == ["call_1"]
    assert [(r["outcome"], r["decision"]) for r in events(audit, "ask_resolved")] == [("approved", "allow")]


def test_two_streamed_asks_share_one_deadline(gateway, harness_guardian, upstream, audit):
    from conftest import SSE
    from streams import encode, stream_events

    upstream.reply(SSE(encode(stream_events(call_item("ask_tool", {"n": 1}, "call_1"),
                                            call_item("ask_tool", {"n": 2}, "call_2")))))
    client = enforce(gateway, harness_guardian, ACS_GATEWAY_ASK_MAX_S="1")
    started = time.monotonic()
    received = _streamed(client)
    assert time.monotonic() - started < 1.8
    assert _streamed_calls(received) == []
    assert [r["outcome"] for r in events(audit, "ask_resolved")] == ["timed_out", "timed_out"]
