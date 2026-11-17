"""Replay: answers from recordings, with no network and no credentials (issue #579, A.8, PREMORTEM P2 and P11)."""
import json
import socket

import pytest

from conftest import NEUTRAL, call_item, finbot_request, message_item, response_body

USER_A, USER_B = "user_AbCdEfGh-_123456", "user_ZyXwVuTs_-987654"
NS_A, NS_B = "ns_" + USER_A, "ns_" + USER_B


def system(ns: str) -> str:
    return f"You are FinBot. Internal mail goes to admin@{ns}.finbot."


def output(call_id: str, text: str = '{"ok": true}') -> dict:
    return {"type": "function_call_output", "call_id": call_id, "output": text}


def history(n: int) -> list[dict]:
    items = []
    for i in range(n):
        items += [call_item("get_vendor_details", {"vendor_id": i}, f"call_{i}"), output(f"call_{i}")]
    return items


def line(step: int, response, *, branch: str = "", stream: bool = False, match: str = "Pay vendor 7",
         ids: tuple = ()) -> dict:
    return {"scenario": "s1", "match": match, "turn": 1, "step": step, "branch": branch, "stream": stream, "ids": list(ids),
            "response": response}


def write(directory, *lines, name="s1.jsonl"):
    directory.mkdir(exist_ok=True)
    (directory / name).write_text("".join(json.dumps(item) + "\n" for item in lines))


@pytest.fixture
def no_network(monkeypatch):
    """Any socket connect fails the test, so replay is shown to make no network call."""
    def refuse(*args, **kwargs):
        raise AssertionError("replay opened a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def replay(gateway, tmp_path, **env):
    return gateway(ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"), **env)


def miss_events(audit):
    return [e for e in audit() if e["acs_audit_event"] == "replay_miss"]


def test_a_recording_replays_into_a_new_namespace_with_no_network(gateway, upstream, tmp_path, no_network):
    write(tmp_path / "rec", line(0, response_body(message_item("Mailed admin@ns_{{acs:user:1}}.finbot")), ids=["user:1"]))
    client = replay(gateway, tmp_path)
    response = client.post("/v1/responses", json=finbot_request(system=system(NS_B)))
    assert response.status_code == 200
    assert response.json()["output"][0]["content"][0]["text"] == f"Mailed admin@{NS_B}.finbot"
    assert upstream.received == []


def test_the_step_comes_from_the_request_not_from_how_many_requests_came_before(gateway, upstream, tmp_path, no_network):
    write(tmp_path / "rec", line(0, response_body(message_item("step zero"))),
          line(2, response_body(message_item("step two")), branch="a,a,a,a"))
    client = replay(gateway, tmp_path)
    text = lambda r: r.json()["output"][0]["content"][0]["text"]  # noqa: E731
    assert text(client.post("/v1/responses", json=finbot_request(*history(2)))) == "step two"
    for _ in range(3):
        # FinBot's SDK and agent runner retry, and each retry must stay on step 0.
        assert text(client.post("/v1/responses", json=finbot_request())) == "step zero"
    assert text(client.post("/v1/responses", json=finbot_request(*history(2)))) == "step two"


def test_a_byte_identical_retry_gets_the_same_answer(gateway, tmp_path, no_network):
    write(tmp_path / "rec", line(0, response_body(message_item("cached"))))
    client = replay(gateway, tmp_path)
    raw = json.dumps(finbot_request()).encode()
    first = client.post("/v1/responses", content=raw, headers={"content-type": "application/json"})
    second = client.post("/v1/responses", content=raw, headers={"content-type": "application/json"})
    assert first.content == second.content
    transport = client.app.state.gateway.http._transport
    # The answer is a pure function of the request and the gateway's branch tokens, so nothing is cached (CR8).
    assert not hasattr(transport, "cache")


def test_off_mode_reads_a_neutral_output_as_delivered(gateway, tmp_path, no_network):
    write(tmp_path / "rec", line(1, response_body(message_item("after allow")), branch="a,a"),
          line(1, response_body(message_item("after deny")), branch="a,d"))
    client = replay(gateway, tmp_path)
    denied = finbot_request(call_item("get_vendor_details", {}, "call_0"), output("call_0", NEUTRAL))
    assert client.post("/v1/responses", json=denied).json()["output"][0]["content"][0]["text"] == "after allow"


def test_a_miss_returns_the_recorded_neutral_line_and_is_audited(gateway, tmp_path, audit, no_network):
    write(tmp_path / "rec", line(0, response_body(message_item("only step zero"))))
    client = replay(gateway, tmp_path)
    reply = client.post("/v1/responses", json=finbot_request(*history(1))).json()
    assert reply["id"] == "resp_replay_miss"
    assert [(i["type"], i["content"][0]["text"]) for i in reply["output"]] == [("message", NEUTRAL)]
    assert [(e["cause"], e["step"], e["branch"], e["stream"]) for e in miss_events(audit)] == [
        ("no_recording", 1, "a,a", False)]


def test_an_unfillable_placeholder_is_a_miss(gateway, tmp_path, audit, no_network):
    write(tmp_path / "rec", line(0, response_body(message_item("Transfer {{acs:tr:1}} sent"))))
    reply = replay(gateway, tmp_path).post("/v1/responses", json=finbot_request()).json()
    assert reply["output"][0]["content"][0]["text"] == NEUTRAL
    assert [e["cause"] for e in miss_events(audit)] == ["placeholder_unfilled"]


@pytest.mark.parametrize("bad", [
    "not json",
    json.dumps({"scenario": "s1", "match": "(", "turn": 1, "step": 0, "branch": "", "stream": False, "ids": [], "response": {"output": []}}),
    json.dumps({"scenario": "s1", "match": "x", "turn": 1, "step": -1, "branch": "", "stream": False, "ids": [], "response": {"output": []}}),
    # Two outputs can't come with fewer than two tokens, so this line could never match (CR7).
    json.dumps({"scenario": "s1", "match": "x", "turn": 1, "step": 2, "branch": "a", "stream": False, "ids": [],
                "response": {"output": []}}),
    json.dumps({"scenario": "s1", "match": "x", "turn": 1, "step": 0, "branch": "q", "stream": False, "ids": [], "response": {"output": []}}),
    json.dumps({"scenario": "s1", "match": "x", "turn": 1, "step": 0, "branch": "", "stream": False, "ids": [], "response": {}}),
    json.dumps({"scenario": "s1", "match": "x", "turn": 1, "step": 0, "branch": "", "stream": True, "ids": [], "response": [{"event": 1}]}),
])
def test_a_malformed_recording_stops_startup(gateway, tmp_path, bad):
    (tmp_path / "rec").mkdir()
    (tmp_path / "rec" / "s1.jsonl").write_text(bad + "\n")
    with pytest.raises(ValueError, match="s1.jsonl:1"):
        replay(gateway, tmp_path)


def test_a_missing_recordings_dir_stops_startup(gateway, tmp_path):
    with pytest.raises(ValueError, match="ACS_RECORDINGS_DIR"):
        replay(gateway, tmp_path)


def test_a_streamed_request_replays_its_events_in_off_mode(gateway, tmp_path, no_network):
    item = message_item("streamed for ns_{{acs:user:1}}")
    events = [{"event": "response.output_text.delta", "data": {"type": "response.output_text.delta",
                                                               "delta": "streamed for ns_{{acs:user:1}}"}},
              {"event": "response.output_item.done", "data": {"type": "response.output_item.done", "item": item}}]
    write(tmp_path / "rec", line(0, events, stream=True, ids=["user:1"]))
    response = replay(gateway, tmp_path).post("/v1/responses", json={**finbot_request(system=system(NS_B)),
                                                                     "stream": True})
    assert response.headers["content-type"].startswith("text/event-stream")
    blocks = [b for b in response.text.split("\n\n") if b]
    assert blocks[0] == ("event: response.output_text.delta\ndata: "
                         + json.dumps({"type": "response.output_text.delta", "delta": f"streamed for {NS_B}"}))
    assert len(blocks) == 2


def test_replay_works_in_enforce_and_gates_the_recorded_call(gateway, guardian, tmp_path, audit):
    write(tmp_path / "rec", line(0, response_body(call_item("bash", {"command": "rm -rf /"}, "call_1"))))
    reply = replay(gateway, tmp_path, ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post(
        "/v1/responses", json=finbot_request()).json()
    assert reply["output"][0]["content"][0]["text"] == NEUTRAL
    applied = [e for e in audit() if e["acs_audit_event"] == "decision_applied"]
    assert [(e["tool"], e["decision"]) for e in applied] == [("bash", "deny")]
