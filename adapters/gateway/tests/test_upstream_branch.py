"""Branch tokens come from the session's own outcome records, never from text in the request (fix round 2, R1)."""
import json

from conftest import NEUTRAL, SSE, call_item, finbot_request, message_item, response_body
from streams import encode, stream_events

from acs_gateway.sessions import conversation_key
from acs_gateway.upstream import session_branch


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


def test_a_call_removed_from_a_stream_takes_its_branch_token(gateway, guardian, upstream):
    """Rehearsal R7: a streamed answer places its removed calls by the same rule as a whole answer, so the next
    request's branch keeps the d."""
    upstream.reply(SSE(encode(stream_events(call_item("bash", {"command": "rm -rf /"}, "call_bash")))))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    streamed = {**finbot_request(), "stream": True}
    with client.stream("POST", "/v1/responses", json=streamed) as r:
        b"".join(r.iter_bytes())
    session = client.app.state.gateway.sessions.peek(conversation_key(streamed))
    assert session is not None and session.calls["call_bash"].outcome == "removed"
    assert session_branch(session, finbot_request({"role": "user", "content": "And then?"})) == "d"


def test_the_whole_answer_path_gives_the_same_d(gateway, guardian, upstream):
    """The control for the test above: the same removal answered whole."""
    upstream.reply(response_body(call_item("bash", {"command": "rm -rf /"}, "call_bash")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    body = finbot_request()
    client.post("/v1/responses", json=body)
    session = client.app.state.gateway.sessions.peek(conversation_key(body))
    assert session_branch(session, finbot_request({"role": "user", "content": "And then?"})) == "d"


def test_a_streamed_reply_sends_the_same_branch_header_as_a_whole_one(gateway, guardian, upstream, tmp_path):
    """The header capture and replay key on, for the conversation test_a_removed_call_is_d_in_the_place_it_was_gated
    runs whole, with its first reply streamed."""
    client = capture(gateway, tmp_path, guardian)
    upstream.reply(SSE(encode(stream_events(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"),
                                            call_item("bash", {"command": "rm -rf /"}, "call_2")))))
    upstream.reply(response_body(message_item("done")))
    with client.stream("POST", "/v1/responses", json={**finbot_request(), "stream": True}) as r:
        b"".join(r.iter_bytes())
    kept = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    client.post("/v1/responses", json=finbot_request(kept, output("call_1", "{}")))
    assert lines(tmp_path)[-1]["branch"] == "d,a,a"


def test_a_retry_that_fails_mid_stream_keeps_the_completed_attempts_d(gateway, guardian, upstream, tmp_path):
    """A stream that never reaches response.completed places nothing, as the whole answer notes nothing on an error
    exit, so the d from the attempt that completed survives on the next request's branch."""
    client = capture(gateway, tmp_path, guardian)
    calls = (call_item("get_vendor_details", {"vendor_id": 7}, "call_1"),
             call_item("bash", {"command": "rm -rf /"}, "call_2"))
    upstream.reply(SSE(encode(stream_events(*calls))))
    # The retry's upstream stops before its terminal event.
    upstream.reply(SSE(encode(stream_events(*calls)[:-1])))
    upstream.reply(response_body(message_item("done")))
    for _ in range(2):
        with client.stream("POST", "/v1/responses", json={**finbot_request(), "stream": True}) as r:
            b"".join(r.iter_bytes())
    client.post("/v1/responses", json=finbot_request(calls[0], output("call_1", "{}")))
    assert lines(tmp_path)[-1]["branch"] == "d,a,a"


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


def test_a_retry_whose_first_reply_was_removed_replays_with_the_same_branch(gateway, guardian, upstream, tmp_path,
                                                                           audit):
    """Fix round 3, CR3-1: the client keeps only the retry's reply, so only that reply's removed calls count."""
    client = capture(gateway, tmp_path, guardian)
    upstream.reply(response_body(call_item("bash", {"command": "rm -rf /"}, "call_1")))
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_2"),
                                 call_item("bash", {"command": "rm -rf /"}, "call_3")))
    upstream.reply(response_body(message_item("done")))
    client.post("/v1/responses", json=finbot_request())
    kept_reply = client.post("/v1/responses", json=finbot_request()).json()
    [kept] = [i for i in kept_reply["output"] if i["type"] == "function_call"]
    captured_end = client.post("/v1/responses", json=finbot_request(kept, output("call_2", "{}"))).json()
    assert lines(tmp_path)[2]["branch"] == "d,a,a"

    # Fix round 4, I-1: replay serves the reply the client kept, the last matching line, and the client follows up
    # on exactly what replay served, so the whole conversation must match the capture.
    replay = gateway(ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"), ACS_LAB_MODE="enforce",
                     ACS_GUARDIAN_URL=guardian)
    served = replay.post("/v1/responses", json=finbot_request()).json()
    assert replay.post("/v1/responses", json=finbot_request()).json() == served
    assert served["output"] == kept_reply["output"]
    calls = [i for i in served["output"] if i["type"] == "function_call"]
    follow_up = finbot_request(*calls, *(output(c["call_id"], "{}") for c in calls))
    replayed_end = replay.post("/v1/responses", json=follow_up).json()
    assert replayed_end["output"] == captured_end["output"]
    assert replayed_end["output"][0]["content"][0]["text"] == "done"
    assert not [e for e in audit() if e["acs_audit_event"] == "replay_miss"]


def test_a_tampered_resend_replaced_by_the_neutral_line_is_d(gateway, guardian, upstream, tmp_path):
    """Fix round 3, CR3-2: the token says what the model received for this request."""
    client = capture(gateway, tmp_path, guardian)
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    upstream.reply(response_body(message_item("first")))
    upstream.reply(response_body(message_item("second")))
    client.post("/v1/responses", json=finbot_request())
    client.post("/v1/responses", json=finbot_request(call, output("call_1", '{"v": 1}')))
    client.post("/v1/responses", json=finbot_request(call, output("call_1", '{"v": 2}')))
    assert [line["branch"] for line in lines(tmp_path)] == ["", "a,a", "a,d"]


def test_a_history_call_with_no_record_counts_as_delivered(gateway, guardian, upstream, tmp_path):
    """Fix round 3, CR3-8: after an epoch bump the session never saw the call, and off would say a."""
    for mode in ("shadow", "enforce"):
        rec = tmp_path / mode
        client = gateway(ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(rec), ACS_LAB_MODE=mode,
                         ACS_GUARDIAN_URL=guardian)
        call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
        upstream.reply(response_body(call))
        upstream.reply(response_body(message_item("done")))
        client.post("/v1/responses", json=finbot_request())
        client.app.state.gateway.bump_epoch()
        client.post("/v1/responses", json=finbot_request(call, output("call_1", "{}")))
        branches = [json.loads(line)["branch"] for line in (rec / "capture.jsonl").read_text().splitlines()]
        assert branches == ["", "a,a"], mode


def test_plain_live_sends_no_branch_header(gateway, upstream):
    upstream.reply(response_body(message_item("done")))
    gateway().post("/v1/responses", json=finbot_request(), headers={"x-acs-lab-branch": "d"})
    assert not [h for h in upstream.received[0].headers if h.startswith("x-acs-")]


def test_a_retry_that_overtakes_its_first_attempt_keeps_the_retrys_branch(gateway, guardian, upstream, tmp_path,
                                                                         audit):
    """Final review I-1: the client gave up on a slow first attempt and retried. The first attempt finishes last, but
    the client kept the retry's reply, so capture records the retry's reply and the retry's removed call, and replay
    follows the same conversation with no miss."""
    import threading
    import time

    client = capture(gateway, tmp_path, guardian)
    upstream.reply(response_body(message_item("abandoned")), delay=1.0)
    retry_reply = response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_2"),
                                call_item("bash", {"command": "rm -rf /"}, "call_3"))
    upstream.reply(retry_reply)
    upstream.reply(response_body(message_item("done")))
    got: dict[str, dict] = {}

    def send(name, delay):
        time.sleep(delay)
        got[name] = client.post("/v1/responses", json=finbot_request()).json()

    threads = [threading.Thread(target=send, args=("first", 0)), threading.Thread(target=send, args=("retry", 0.3))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert got["first"]["output"][0]["content"][0]["text"] == "abandoned"
    [kept] = [i for i in got["retry"]["output"] if i["type"] == "function_call"]
    captured_end = client.post("/v1/responses", json=finbot_request(kept, output("call_2", "{}"))).json()
    assert [line["branch"] for line in lines(tmp_path)] == ["", "d,a,a"]

    replay = gateway(ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"), ACS_LAB_MODE="enforce",
                     ACS_GUARDIAN_URL=guardian)
    served = replay.post("/v1/responses", json=finbot_request()).json()
    assert served["output"] == got["retry"]["output"]
    calls = [i for i in served["output"] if i["type"] == "function_call"]
    replayed_end = replay.post("/v1/responses",
                               json=finbot_request(*calls, *(output(c["call_id"], "{}") for c in calls))).json()
    assert replayed_end["output"] == captured_end["output"]
    assert not [e for e in audit() if e["acs_audit_event"] == "replay_miss"]


def test_a_streamed_retry_that_overtakes_its_first_attempt_keeps_the_retrys_branch(gateway, guardian, upstream,
                                                                                  tmp_path):
    """The stream path of the test above: a stream places its calls once it completes, so the abandoned stream
    completing last must not take the retry's removed call out of the branch."""
    import threading
    import time

    client = capture(gateway, tmp_path, guardian)
    upstream.reply(SSE(encode(stream_events(message_item("abandoned")))), delay=1.0)
    kept = call_item("get_vendor_details", {"vendor_id": 7}, "call_2")
    upstream.reply(SSE(encode(stream_events(kept, call_item("bash", {"command": "rm -rf /"}, "call_3")))))
    upstream.reply(response_body(message_item("done")))
    streamed = {**finbot_request(), "stream": True}

    def send(delay):
        time.sleep(delay)
        with client.stream("POST", "/v1/responses", json=streamed) as r:
            b"".join(r.iter_bytes())

    threads = [threading.Thread(target=send, args=(d,)) for d in (0, 0.3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    client.post("/v1/responses", json=finbot_request(kept, output("call_2", "{}")))
    assert [line["branch"] for line in lines(tmp_path)] == ["", "d,a,a"]
