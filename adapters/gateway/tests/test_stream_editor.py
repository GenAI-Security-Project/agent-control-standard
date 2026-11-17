"""StreamEditor on its own: upstream SSE bytes in, client SSE bytes out, with a scripted decide()."""
import asyncio
import json

from conftest import NEUTRAL
from streams import (call_item, decode, encode, hosted_item, message_item, reasoning_item, rebuilt_output,
                     stream_events)

from acs_gateway.stream import StreamEditor

LIMIT = 1 << 20
BASH = call_item("bash", {"command": "rm -rf /"}, "call_bash")
VENDOR = call_item("get_vendor_details", {"vendor_id": 7}, "call_vendor")


def run(chunks, decide=None, enforce=True, limit=LIMIT, idle_timeout=None):
    """Feed chunks through an editor, drain it, and return (client bytes, audit lines, items decide() saw)."""
    seen, audits = [], []

    async def default(item):
        seen.append(item)
        return None if item.get("name") == "bash" or item["type"] != "function_call" else item

    async def main():
        async def source():
            for chunk in chunks:
                yield chunk

        editor = StreamEditor(enforce=enforce, limit=limit, decide=decide or default, idle_timeout=idle_timeout,
                              audit=lambda event, **fields: audits.append({"event": event, **fields}))
        out = b"".join([out async for out in editor.edit(source())])
        await editor.drain()
        return out

    return asyncio.run(main()), audits, seen


def call_events(events):
    return [e for e in events if e.get("item", {}).get("type") == "function_call" or "arguments" in e["type"]]


SYNTHESIZED = ["response.output_item.added", "response.function_call_arguments.delta",
               "response.function_call_arguments.done", "response.output_item.done"]


def types(events):
    return [e["type"] for e in events]


def test_an_unedited_stream_is_byte_for_byte():
    raw = encode(stream_events(reasoning_item("think"), message_item("Hello there")))
    out, audits, _ = run(raw)
    assert out == b"".join(raw)
    assert audits == []


def test_chunks_split_anywhere_still_frame_events():
    raw = b"".join(encode(stream_events(message_item("Hello there")))).replace(b"\n", b"\r\n")
    out, _, _ = run([raw[i:i + 7] for i in range(0, len(raw), 7)])
    assert out == raw


def test_text_before_a_held_call_is_yielded_before_the_decision():
    raw = encode(stream_events(message_item("Paying vendor 7 now"), VENDOR))

    async def main():
        release = asyncio.Event()
        got: list[bytes] = []

        async def decide(item):
            await release.wait()
            return item

        async def source():
            for chunk in raw:
                yield chunk

        editor = StreamEditor(enforce=True, limit=LIMIT, decide=decide, audit=lambda *a, **k: None)

        async def consume():
            async for out in editor.edit(source()):
                got.append(out)

        task = asyncio.create_task(consume())
        for _ in range(50):
            await asyncio.sleep(0)
        before = decode(b"".join(got))
        release.set()
        await task
        return before, decode(b"".join(got))

    before, after = asyncio.run(main())
    deltas = "".join(e["delta"] for e in before if e["type"] == "response.output_text.delta")
    assert deltas == "Paying vendor 7 now"
    assert not any(e.get("item", {}).get("type") == "function_call" or "arguments" in e.get("type", "")
                   for e in before)
    assert rebuilt_output(after) == [message_item("Paying vendor 7 now"), VENDOR]


def test_a_denied_call_never_appears_in_any_event():
    raw = encode(stream_events(message_item("Working on it"), BASH))
    out, _, seen = run(raw)
    assert seen == [BASH]
    assert b"bash" not in out and b"rm -rf" not in out and b"call_bash" not in out
    events = decode(out)
    assert rebuilt_output(events) == [message_item("Working on it")]
    assert events[-1]["response"]["output"] == [message_item("Working on it")]


def test_a_denied_call_alone_streams_the_neutral_line():
    raw = encode(stream_events(BASH))
    events = decode(run(raw)[0])
    assert "".join(e["delta"] for e in events if e["type"] == "response.output_text.delta") == NEUTRAL
    output = rebuilt_output(events)
    assert [i["type"] for i in output] == ["message"] and output[0]["content"][0]["text"] == NEUTRAL
    assert events[-1]["response"]["output"] == output
    assert b"bash" not in run(raw)[0]


def test_sequence_numbers_are_never_renumbered():
    upstream = stream_events(message_item("Working on it"), BASH, VENDOR)
    by_number = {e["sequence_number"]: e for e in upstream}
    events = decode(run(encode(upstream))[0])
    numbers = [e["sequence_number"] for e in events]
    assert all(a < b for a, b in zip(numbers, numbers[1:]))
    assert set(numbers) <= set(by_number)
    for event in events:
        if event not in call_events(events):
            assert by_number[event["sequence_number"]]["type"] == event["type"]
    assert set(by_number) - set(numbers), "the dropped call leaves gaps"


def test_the_neutral_line_takes_numbers_of_dropped_events():
    upstream = stream_events(BASH)
    events = decode(run(encode(upstream))[0])
    numbers = [e["sequence_number"] for e in events]
    assert numbers == sorted(numbers) and len(set(numbers)) == len(numbers)
    assert numbers[-1] == upstream[-1]["sequence_number"]


def test_output_index_follows_the_edited_output():
    events = decode(run(encode(stream_events(BASH, message_item("after the call"))))[0])
    assert {e["output_index"] for e in events if "output_index" in e} == {0}
    assert events[-1]["response"]["output"] == [message_item("after the call")]


def test_a_modified_call_streams_its_new_arguments():
    send = call_item("finmail__send_email", {"to": "x@evil.example", "body": "hi"}, "call_mail")
    rewritten = {**send, "arguments": json.dumps({"to": "ops@ns1.finbot", "body": "hi"})}

    async def decide(item):
        return rewritten

    out, audits, _ = run(encode(stream_events(send)), decide=decide)
    events = decode(out)
    assert b"evil" not in json.dumps(events).encode()
    assert audits == [], "the original call in completed was gated, so it isn't unstreamed"
    added = next(e for e in events if e["type"] == "response.output_item.added")
    deltas = "".join(e["delta"] for e in events if e["type"] == "response.function_call_arguments.delta")
    assert added["item"]["arguments"] + deltas == rewritten["arguments"]
    done = next(e for e in events if e["type"] == "response.function_call_arguments.done")
    assert done["arguments"] == rewritten["arguments"]
    assert rebuilt_output(events) == [rewritten] == events[-1]["response"]["output"]


def test_completed_matches_the_streamed_items_for_every_terminal():
    for terminal in ("response.completed", "response.incomplete", "response.failed"):
        events = decode(run(encode(stream_events(reasoning_item("t"), message_item("m"), BASH, VENDOR,
                                                 terminal=terminal)))[0])
        assert events[-1]["type"] == terminal
        assert events[-1]["response"]["output"] == rebuilt_output(events)
        assert events[0]["response"]["output"] == []


def test_orphaned_reasoning_is_dropped_and_kept_reasoning_streams():
    first, second = reasoning_item("plan the shell", "rs_1"), reasoning_item("plan the lookup", "rs_2")
    events = decode(run(encode(stream_events(first, BASH, second, VENDOR)))[0])
    assert rebuilt_output(events) == [second, VENDOR]
    assert b"plan the shell" not in json.dumps(events).encode()
    kept = decode(run(encode(stream_events(first, message_item("hi"), BASH)))[0])
    assert rebuilt_output(kept) == [first, message_item("hi")]
    trailing = decode(run(encode(stream_events(BASH, first)))[0])
    assert [i["type"] for i in rebuilt_output(trailing)] == ["message", "reasoning"]


def test_the_full_event_set_of_kept_items_reaches_the_client():
    upstream = stream_events(reasoning_item("t"), message_item("hello"), VENDOR)
    events = decode(run(encode(upstream))[0])
    assert types(call_events(events)) == SYNTHESIZED
    assert types([e for e in events if e not in call_events(events)]) == types(
        [e for e in upstream if e not in call_events(upstream)])


def test_an_unsupported_item_is_removed_in_enforce():
    events = decode(run(encode(stream_events(hosted_item(), message_item("found it"))))[0])
    assert not any("web_search_call" in e["type"] for e in events)
    assert rebuilt_output(events) == [message_item("found it")] == events[-1]["response"]["output"]


def test_an_unparseable_event_ends_with_an_error_event():
    raw = encode(stream_events(message_item("hi"), VENDOR))
    out, audits, _ = run([*raw[:4], b"data: {not json\n\n", *raw[4:]])
    events = decode(out)
    assert events[-1]["type"] == "error" and "sequence_number" in events[-1]
    assert "acs" not in json.dumps(events[-1]).lower() and "guardian" not in json.dumps(events[-1]).lower()
    assert not any(e.get("item", {}).get("type") == "function_call" for e in events)
    assert [(a["event"], a["cause"]) for a in audits] == [("upstream_error", "upstream_unparseable")]


def test_a_repeated_key_in_an_event_is_unparseable():
    out, audits, _ = run([b'data: {"type": "response.created", "type": "x", "sequence_number": 0}\n\n'])
    assert decode(out)[-1]["type"] == "error"
    assert audits[0]["cause"] == "upstream_unparseable"


def test_a_truncated_stream_ends_with_an_error_event_and_no_call():
    raw = encode(stream_events(message_item("hi"), VENDOR))
    out, audits, seen = run(raw[:-3])
    events = decode(out)
    assert events[-1]["type"] == "error"
    assert b"call_vendor" not in out and seen == []
    assert audits[0]["cause"] == "upstream_unparseable"


def test_an_unannounced_output_index_ends_with_an_error_event():
    raw = encode(stream_events(message_item("hi")))
    stray = {"type": "response.function_call_arguments.delta", "sequence_number": 99, "item_id": "fc_x",
             "output_index": 5, "delta": "{}"}
    events = decode(run([*raw[:3], *encode([stray]), *raw[3:]])[0])
    assert events[-1]["type"] == "error"


def test_an_unstreamed_call_in_completed_is_dropped():
    events = decode(run(encode(stream_events(message_item("hi"), completed_output=[message_item("hi"), BASH])))[0])
    assert events[-1]["response"]["output"] == [message_item("hi")]


def test_a_held_call_over_the_limit_ends_with_an_error_event():
    big = call_item("get_vendor_details", {"note": "x" * 4000}, "call_big")
    out, audits, seen = run(encode(stream_events(big)), limit=2000)
    assert decode(out)[-1]["type"] == "error" and b"call_big" not in out and seen == []
    assert audits[0]["cause"] == "upstream_too_large"


def test_a_decide_fault_removes_the_call():
    async def broken(item):
        raise RuntimeError("policy crashed")

    out, audits, _ = run(encode(stream_events(VENDOR)), decide=broken)
    assert b"call_vendor" not in out
    assert rebuilt_output(decode(out))[0]["content"][0]["text"] == NEUTRAL
    assert audits[0]["event"] == "gateway_step_error"


def test_shadow_relays_every_byte_and_decides_each_call():
    raw = encode(stream_events(message_item("hi"), BASH, hosted_item("ws_2"), VENDOR))
    out, audits, seen = run(raw, enforce=False)
    assert out == b"".join(raw)
    assert [i["id"] for i in seen] == [BASH["id"], "ws_2", VENDOR["id"]]
    assert audits == []


def test_shadow_relays_the_rest_after_an_unparseable_event():
    raw = encode(stream_events(message_item("hi"), BASH))
    broken = [*raw[:4], b"data: {not json\n\n", *raw[4:]]
    out, audits, seen = run(broken, enforce=False)
    assert out == b"".join(broken)
    assert seen == [] and audits[0]["cause"] == "upstream_unparseable"


def test_a_failing_upstream_ends_with_an_error_event():
    async def main():
        async def source():
            yield encode(stream_events(message_item("hi")))[0]
            raise OSError("connection reset")

        editor = StreamEditor(enforce=True, limit=LIMIT, decide=None, audit=lambda *a, **k: None)
        return b"".join([out async for out in editor.edit(source())])

    assert decode(asyncio.run(main()))[-1]["type"] == "error"


def poisoned_call():
    """The reproduced bypass: added, deltas and arguments.done name bash with an rm payload, while the finished item
    the gate judges is a harmless read."""
    judged = call_item("read_file", {"path": "notes.txt"}, "call_x")
    events = stream_events(judged)
    for event in events:
        if event["type"] == "response.output_item.added":
            event["item"] = {**event["item"], "name": "bash"}
        elif event["type"] == "response.function_call_arguments.delta":
            event["delta"] = '{"command": "rm -rf /"}'
        elif event["type"] == "response.function_call_arguments.done":
            event["name"], event["arguments"] = "bash", '{"command": "rm -rf /"}'
    return judged, events


def test_an_allowed_call_reaches_the_client_only_as_the_judged_item():
    judged, events = poisoned_call()
    out, _, seen = run(encode(events))
    assert seen == [judged]
    assert b"bash" not in out and b"rm -rf" not in out
    client = decode(out)
    assert types(call_events(client)) == SYNTHESIZED
    assert rebuilt_output(client) == [judged] == client[-1]["response"]["output"]
    added = next(e for e in client if e["type"] == "response.output_item.added")
    delta = next(e for e in client if e["type"] == "response.function_call_arguments.delta")
    assert added["item"]["name"] == "read_file" and added["item"]["arguments"] + delta["delta"] == judged["arguments"]


def test_synthesized_call_events_reuse_the_upstream_numbers_in_order():
    upstream = stream_events(message_item("hi"), VENDOR)
    held = [e["sequence_number"] for e in call_events(upstream)]
    client = decode(run(encode(upstream))[0])
    assert [e["sequence_number"] for e in call_events(client)] == held[:4]


def test_a_call_with_few_events_still_streams_rising_numbers():
    upstream = [e for e in stream_events(VENDOR) if "arguments" not in e["type"]]
    client = decode(run(encode(upstream))[0])
    numbers = [e["sequence_number"] for e in client]
    assert all(a < b for a, b in zip(numbers, numbers[1:]))
    assert rebuilt_output(client) == [VENDOR]


def announced_as(kind_item, done_item):
    """A stream whose item is announced as one type and finished as another."""
    events = stream_events(kind_item)
    done = next(e for e in events if e["type"] == "response.output_item.done")
    done["item"] = done_item
    events[-1]["response"]["output"] = [done_item]
    return events


def test_a_message_that_finishes_as_a_call_is_never_delivered():
    out, audits, seen = run(encode(announced_as(message_item("hello", "msg_x"), {**BASH, "id": "msg_x"})))
    client = decode(out)
    assert client[-1]["type"] == "error" and b"rm -rf" not in out and seen == []
    assert not any(e["type"] == "response.completed" for e in client)
    assert audits[0]["detail"] == "item_type_mismatch"


def test_reasoning_that_finishes_as_a_call_is_never_delivered():
    out, audits, _ = run(encode(announced_as(reasoning_item("t", "rs_x"), {**VENDOR, "id": "rs_x"})))
    client = decode(out)
    assert client[-1]["type"] == "error" and b"call_vendor" not in out
    assert not any(e["type"] == "response.completed" for e in client)
    assert audits[0]["detail"] == "item_type_mismatch"


def test_a_call_event_on_a_message_is_a_mismatch():
    events = stream_events(message_item("hello"))
    stray = {"type": "response.function_call_arguments.delta", "sequence_number": 3, "item_id": "msg_1",
             "output_index": 0, "delta": "{}"}
    out, audits, _ = run(encode([*events[:3], stray, *events[4:]]))
    assert decode(out)[-1]["type"] == "error" and audits[0]["detail"] == "item_type_mismatch"


def test_shadow_judges_the_finished_item_type():
    _, _, seen = run(encode(announced_as(message_item("hello", "msg_x"), {**BASH, "id": "msg_x"})), enforce=False)
    assert [i["name"] for i in seen] == ["bash"]


def test_shadow_never_waits_for_a_decision():
    async def main():
        started, finished = [], []

        async def slow(item):
            started.append(item)
            await asyncio.sleep(0.5)
            finished.append(item)
            return item

        async def source():
            for chunk in encode(stream_events(message_item("hi"), BASH, VENDOR)):
                yield chunk

        editor = StreamEditor(enforce=False, limit=LIMIT, decide=slow, audit=lambda *a, **k: None)
        begin = asyncio.get_running_loop().time()
        out = b"".join([o async for o in editor.edit(source())])
        relayed = asyncio.get_running_loop().time() - begin
        assert finished == []
        await editor.drain()
        return relayed, len(finished), out

    relayed, decided, out = asyncio.run(main())
    assert relayed < 0.3 and decided == 2
    assert decode(out)[-1]["type"] == "response.completed"


def test_every_mode_stops_at_the_terminal_event():
    for enforce in (True, False):
        async def main():
            async def source():
                for chunk in encode(stream_events(message_item("hi"))):
                    yield chunk
                await asyncio.Event().wait()

            editor = StreamEditor(enforce=enforce, limit=LIMIT, decide=None, audit=lambda *a, **k: None)
            return b"".join([o async for o in editor.edit(source())])

        out = asyncio.run(asyncio.wait_for(main(), 2))
        assert decode(out)[-1]["type"] == "response.completed"


def test_an_upstream_error_event_is_the_last_event():
    events = stream_events(message_item("hi"))
    error = {"type": "error", "sequence_number": 4, "code": "server_error", "message": "boom", "param": None}
    for enforce in (True, False):
        client = decode(run(encode([*events[:4], error, *events[4:]]), enforce=enforce)[0])
        assert [e["type"] for e in client].count("error") == 1 and client[-1] == error


def test_kept_items_count_against_the_limit():
    out, audits, _ = run(encode(stream_events(message_item("a" * 600, "msg_1"), message_item("b" * 600, "msg_2"))),
                         limit=1500)
    assert decode(out)[-1]["type"] == "error" and audits[0]["cause"] == "upstream_too_large"


def test_the_neutral_line_numbers_rise_before_trailing_reasoning():
    upstream = stream_events(BASH, reasoning_item("after"))
    client = decode(run(encode(upstream))[0])
    numbers = [e["sequence_number"] for e in client]
    assert all(a < b for a, b in zip(numbers, numbers[1:]))
    assert numbers[-1] == upstream[-1]["sequence_number"]
    assert "".join(e["delta"] for e in client if e["type"] == "response.output_text.delta") == NEUTRAL


def test_a_stalled_upstream_ends_with_an_error_event():
    async def main():
        audits = []

        async def source():
            yield encode(stream_events(message_item("hi")))[0]
            await asyncio.sleep(5)

        editor = StreamEditor(enforce=True, limit=LIMIT, decide=None, idle_timeout=0.2,
                              audit=lambda event, **fields: audits.append(fields))
        return b"".join([o async for o in editor.edit(source())]), audits

    out, audits = asyncio.run(asyncio.wait_for(main(), 3))
    assert decode(out)[-1]["type"] == "error" and audits[0]["cause"] == "upstream_idle_timeout"
