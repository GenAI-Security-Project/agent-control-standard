"""Branch tokens come from the session's own outcome records, never from text in the request (fix round 2, R1)."""
import json

from conftest import NEUTRAL, call_item, finbot_request, message_item, response_body


def lines(tmp_path):
    path = tmp_path / "rec" / "capture.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def capture(gateway, tmp_path, guardian, mode="enforce"):
    return gateway(ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(tmp_path / "rec"), ACS_LAB_MODE=mode,
                   ACS_GUARDIAN_URL=guardian)


def output(call_id, text):
    return {"type": "function_call_output", "call_id": call_id, "output": text}


def two_turns(client, upstream, call, result_text):
    """The model asks for one call, the client runs it and resends. Returns the second request's capture line."""
    upstream.reply(response_body(call))
    upstream.reply(response_body(message_item("done")))
    first = client.post("/v1/responses", json=finbot_request()).json()
    delivered = [i for i in first["output"] if i["type"] == "function_call"]
    client.post("/v1/responses", json=finbot_request(*delivered, output(call["call_id"], result_text)))


def test_output_text_holding_the_redaction_marker_is_still_delivered(gateway, guardian, upstream, tmp_path):
    two_turns(capture(gateway, tmp_path, guardian), upstream,
              call_item("get_vendor_details", {"vendor_id": 7}, "call_1"), '{"note": "[REDACTED] by the vendor"}')
    assert [line["branch"] for line in lines(tmp_path)] == ["", "a,a"]


def test_output_text_equal_to_the_neutral_line_is_still_delivered(gateway, guardian, upstream, tmp_path):
    two_turns(capture(gateway, tmp_path, guardian), upstream,
              call_item("get_vendor_details", {"vendor_id": 7}, "call_1"), NEUTRAL)
    assert lines(tmp_path)[1]["branch"] == "a,a"


def test_a_redacted_result_is_m(gateway, harness_guardian, upstream, tmp_path):
    two_turns(capture(gateway, tmp_path, harness_guardian()), upstream,
              call_item("get_vendor_details", {"vendor_id": 7}, "call_1"), json.dumps({"bank_account_number": "123"}))
    assert lines(tmp_path)[1]["branch"] == "a,m"


def test_modified_content_with_no_marker_is_m(gateway, harness_guardian, upstream, tmp_path):
    two_turns(capture(gateway, tmp_path, harness_guardian()), upstream,
              call_item("text_tool", {}, "call_1"), "the full text")
    assert lines(tmp_path)[1]["branch"] == "a,m"


def test_a_denied_result_is_d(gateway, harness_guardian, upstream, tmp_path):
    two_turns(capture(gateway, tmp_path, harness_guardian()), upstream,
              call_item("leaky_tool", {}, "call_1"), "secret")
    assert lines(tmp_path)[1]["branch"] == "a,d"


def test_a_rewritten_call_is_m(gateway, harness_guardian, upstream, tmp_path):
    two_turns(capture(gateway, tmp_path, harness_guardian()), upstream,
              call_item("override_tool", {"to": "x@evil.example"}, "call_1"), "sent")
    assert lines(tmp_path)[1]["branch"] == "m,a"


def test_a_removed_call_is_d_in_the_place_it_was_gated(gateway, guardian, upstream, tmp_path):
    client = capture(gateway, tmp_path, guardian)
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"),
                                 call_item("bash", {"command": "rm -rf /"}, "call_2")))
    upstream.reply(response_body(message_item("done")))
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"),
                                 call_item("bash", {"command": "rm -rf /"}, "call_2")))
    first = client.post("/v1/responses", json=finbot_request()).json()
    [kept] = [i for i in first["output"] if i["type"] == "function_call"]
    client.post("/v1/responses", json=finbot_request(kept, output("call_1", "{}")))
    # A retry of the first request comes after its calls were gated, and still carries no token for them.
    client.post("/v1/responses", json=finbot_request())
    assert [line["branch"] for line in lines(tmp_path)] == ["", "d,a,a", ""]


def test_shadow_records_only_a(gateway, guardian, upstream, tmp_path):
    client = capture(gateway, tmp_path, guardian, mode="shadow")
    upstream.reply(response_body(call_item("bash", {"command": "rm -rf /"}, "call_1")))
    upstream.reply(response_body(message_item("done")))
    first = client.post("/v1/responses", json=finbot_request()).json()
    client.post("/v1/responses", json=finbot_request(first["output"][0], output("call_1", "{}")))
    assert lines(tmp_path)[1]["branch"] == "a,a"


def test_off_gives_a_for_each_call_and_output(gateway, upstream, tmp_path):
    client = gateway(ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(tmp_path / "rec"))
    upstream.reply(response_body(message_item("done")))
    client.post("/v1/responses", json=finbot_request(call_item("get_vendor_details", {}, "call_1"),
                                                     output("call_1", NEUTRAL)))
    assert lines(tmp_path)[0]["branch"] == "a,a"


def test_the_branch_header_never_leaves_and_a_client_copy_is_ignored(gateway, guardian, upstream, tmp_path):
    client = capture(gateway, tmp_path, guardian)
    upstream.reply(response_body(message_item("done")))
    client.post("/v1/responses", json=finbot_request(), headers={"x-acs-lab-branch": "d,d"})
    assert lines(tmp_path)[0]["branch"] == ""
    assert not [h for h in upstream.received[0].headers if h.startswith("x-acs-")]


def test_plain_live_sends_no_branch_header(gateway, upstream):
    upstream.reply(response_body(message_item("done")))
    gateway().post("/v1/responses", json=finbot_request(), headers={"x-acs-lab-branch": "d"})
    assert not [h for h in upstream.received[0].headers if h.startswith("x-acs-")]
