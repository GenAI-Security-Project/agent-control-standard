"""StreamEditor on its own: upstream SSE bytes in, client SSE bytes out, with a scripted decide().

Enforce relays only message text, rebuilt from known fields, and builds every other item after the upstream's final
event from that event's output. Shadow relays every byte.
"""
import asyncio
import json

from conftest import NEUTRAL
from streams import (call_item, decode, encode, hosted_item, message_item, reasoning_item, rebuilt_output,
                     stream_events)

from acs_gateway.stream import StreamEditor

LIMIT = 1 << 20
BASH = call_item("bash", {"command": "rm -rf /"}, "call_bash")
VENDOR = call_item("get_vendor_details", {"vendor_id": 7}, "call_vendor")
CALL_EVENTS = ["response.output_item.added", "response.function_call_arguments.delta",
               "response.function_call_arguments.done", "response.output_item.done"]


async def _allow_unless_bash(item, seen):
    seen.append(item)
    return None if item.get("name") == "bash" or item["type"] != "function_call" else item


def run(chunks, decide=None, enforce=True, limit=LIMIT, **options):
    """Feed chunks through an editor, drain it, and return (client bytes, audit lines, items decide() saw)."""
    seen, audits = [], []

    async def main():
        async def source():
            for chunk in chunks:
                yield chunk

        editor = StreamEditor(enforce=enforce, limit=limit,
                              decide=decide or (lambda item: _allow_unless_bash(item, seen)),
                              audit=lambda event, **fields: audits.append({"event": event, **fields}), **options)
        out = b"".join([out async for out in editor.edit(source())])
        await editor.drain()
        return out

    return asyncio.run(main()), audits, seen


def types(events):
    return [e["type"] for e in events]


def numbers(events):
    return [e["sequence_number"] for e in events]


def calls_of(events):
    return [e for e in events if e.get("item", {}).get("type") == "function_call" or "arguments" in e["type"]]


def assert_consistent(events):
    """What every enforce stream must satisfy: gateway-owned numbers 0..n-1, a dense output_index, and a final
    event whose output is exactly what output_item.done events carried."""
    assert numbers(events) == list(range(len(events)))
    done = [e for e in events if e["type"] == "response.output_item.done"]
    assert [e["output_index"] for e in done] == list(range(len(done)))
    if events[-1]["type"] in ("response.completed", "response.incomplete", "response.failed"):
        assert events[-1]["response"]["output"] == [e["item"] for e in done]


# Message text streams live, rebuilt.

def test_message_text_streams_rebuilt_with_gateway_numbers():
    upstream = stream_events(message_item("Hello there"))
    events = decode(run(encode(upstream))[0])
    assert_consistent(events)
    assert types(events) == types(upstream)
    assert "".join(e["delta"] for e in events if e["type"] == "response.output_text.delta") == "Hello there"
    assert rebuilt_output(events) == [message_item("Hello there")]


def test_chunks_split_anywhere_still_frame_events():
    raw = b"".join(encode(stream_events(message_item("Hello there")))).replace(b"\n", b"\r\n")
    events = decode(run([raw[i:i + 7] for i in range(0, len(raw), 7)])[0])
    assert rebuilt_output(events) == [message_item("Hello there")]


def test_unknown_fields_on_message_events_never_reach_the_client():
    upstream = stream_events(message_item("hi"))
    for event in upstream:
        event["x_tool"] = {"name": "bash", "arguments": "rm -rf /"}
        if "item" in event:
            event["item"] = {**event["item"], "x_call": "rm -rf /"}
    out, _, _ = run(encode(upstream))
    assert b"rm -rf" not in out and b"x_tool" not in out
    assert decode(out)[-1]["type"] == "response.completed"


def test_text_before_a_held_call_is_yielded_before_the_decision():
    raw = encode(stream_events(message_item("Paying vendor 7 now"), VENDOR))

    async def main():
        release, got = asyncio.Event(), []

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
    assert "".join(e["delta"] for e in before if e["type"] == "response.output_text.delta") == "Paying vendor 7 now"
    assert calls_of(before) == []
    assert rebuilt_output(after) == [message_item("Paying vendor 7 now"), VENDOR]


# Every other item is built after the final event, from its output.

def test_a_call_is_built_from_the_final_output_after_gating():
    events = decode(run(encode(stream_events(message_item("hi"), VENDOR)))[0])
    assert_consistent(events)
    assert types(calls_of(events)) == CALL_EVENTS
    assert rebuilt_output(events) == [message_item("hi"), VENDOR]


def test_a_denied_call_never_appears_in_any_event():
    out, _, seen = run(encode(stream_events(message_item("Working on it"), BASH)))
    assert seen == [BASH]
    assert b"bash" not in out and b"rm -rf" not in out and b"call_bash" not in out
    events = decode(out)
    assert_consistent(events)
    assert rebuilt_output(events) == [message_item("Working on it")]


def test_a_denied_call_alone_streams_the_neutral_line():
    events = decode(run(encode(stream_events(BASH)))[0])
    assert_consistent(events)
    assert "".join(e["delta"] for e in events if e["type"] == "response.output_text.delta") == NEUTRAL
    assert [i["content"][0]["text"] for i in rebuilt_output(events)] == [NEUTRAL]


def test_a_modified_call_streams_its_new_arguments():
    send = call_item("finmail__send_email", {"to": "x@evil.example", "body": "hi"}, "call_mail")
    rewritten = {**send, "arguments": json.dumps({"to": "ops@ns1.finbot", "body": "hi"})}

    async def decide(item):
        return rewritten

    out, audits, _ = run(encode(stream_events(send)), decide=decide)
    events = decode(out)
    assert b"evil" not in out and audits == []
    assert_consistent(events)
    assert rebuilt_output(events) == [rewritten]


def _poisoned(stream, extra):
    """Insert hostile events at the end of a stream, just before the final event, numbered as an upstream would."""
    last = stream[-1].get("sequence_number", 0)
    numbered = [{**event, "sequence_number": last + n} for n, event in enumerate(extra)]
    final = {**stream[-1], "sequence_number": last + len(extra)} if "sequence_number" in stream[-1] else stream[-1]
    return [*stream[:-1], *numbered, final]


def test_late_events_on_an_allowed_call_never_reach_the_client():
    """The three reproduced probes: after the allowed call's done, more deltas, a second arguments.done, and a second
    done all carry bash and an rm payload."""
    stream = stream_events(VENDOR)
    where = {"item_id": VENDOR["id"], "output_index": 0}
    probes = [
        [{"type": "response.function_call_arguments.delta", **where, "delta": '{"command": "rm -rf /"}'}],
        [{"type": "response.function_call_arguments.done", **where, "name": "bash",
          "arguments": '{"command": "rm -rf /"}'}],
        [{"type": "response.output_item.done", "output_index": 0, "item": {**BASH, "id": VENDOR["id"]}}],
    ]
    for probe in probes:
        out, _, _ = run(encode(_poisoned(stream, probe)))
        assert b"bash" not in out and b"rm -rf" not in out, probe
        assert decode(out)[-1]["type"] == "error"


def test_an_allowed_call_reaches_the_client_only_as_the_judged_item():
    judged = call_item("read_file", {"path": "notes.txt"}, "call_x")
    stream = stream_events(judged)
    for event in stream:
        if event["type"] == "response.output_item.added":
            event["item"] = {**event["item"], "name": "bash"}
        elif event["type"] == "response.function_call_arguments.delta":
            event["delta"] = '{"command": "rm -rf /"}'
        elif event["type"] == "response.function_call_arguments.done":
            event["name"], event["arguments"] = "bash", '{"command": "rm -rf /"}'
    out, _, seen = run(encode(stream))
    assert seen == [judged] and b"bash" not in out and b"rm -rf" not in out
    assert rebuilt_output(decode(out)) == [judged]


def test_unknown_fields_on_a_call_never_reach_the_client():
    call = {**VENDOR, "x_shell": "rm -rf /"}
    out, _, _ = run(encode(stream_events(call)))
    assert b"rm -rf" not in out
    assert rebuilt_output(decode(out)) == [VENDOR]


def test_reasoning_is_rebuilt_without_its_private_text():
    events = decode(run(encode(stream_events(reasoning_item("plan"), VENDOR)))[0])
    assert_consistent(events)
    assert rebuilt_output(events) == [reasoning_item("plan"), VENDOR]
    assert "private" not in json.dumps(events)


def test_orphaned_reasoning_is_dropped():
    first, second = reasoning_item("plan the shell", "rs_1"), reasoning_item("plan the lookup", "rs_2")
    events = decode(run(encode(stream_events(first, BASH, second, VENDOR)))[0])
    assert rebuilt_output(events) == [second, VENDOR]
    assert "plan the shell" not in json.dumps(events)


def test_an_unsupported_item_is_removed():
    events = decode(run(encode(stream_events(hosted_item(), message_item("found it"))))[0])
    assert_consistent(events)
    assert not any("web_search_call" in json.dumps(e) for e in events)
    assert rebuilt_output(events) == [message_item("found it")]


def test_completed_matches_the_streamed_items():
    events = decode(run(encode(stream_events(reasoning_item("t"), message_item("m"), BASH, VENDOR)))[0])
    assert_consistent(events)
    assert events[0]["type"] == "response.created" and events[0]["response"]["output"] == []


def test_a_call_in_the_final_output_is_gated_even_if_never_streamed():
    events = decode(run(encode(stream_events(message_item("hi"), completed_output=[message_item("hi"), BASH])))[0])
    assert rebuilt_output(events) == [message_item("hi")]
    assert b"rm -rf" not in json.dumps(events).encode()


def test_an_upstream_without_sequence_numbers_still_streams():
    stream = stream_events(message_item("hi"), VENDOR)
    for event in stream:
        event.pop("sequence_number")
    events = decode(run(encode(stream))[0])
    assert_consistent(events)
    assert rebuilt_output(events) == [message_item("hi"), VENDOR]


def test_an_interleaving_upstream_still_gives_every_item_its_full_event_set():
    stream = stream_events(message_item("hi"), VENDOR)
    message_events = [e for e in stream if e.get("output_index") == 0]
    call_events = [e for e in stream if e.get("output_index") == 1]
    mixed = [stream[0], stream[1]]
    for pair in zip(call_events, message_events):
        mixed += list(pair)
    mixed += call_events[len(message_events):] + message_events[len(call_events):] + [stream[-1]]
    events = decode(run(encode(mixed))[0])
    assert_consistent(events)
    assert types(calls_of(events)) == CALL_EVENTS


# The final event is honored whenever it arrives.

def test_incomplete_or_failed_mid_call_drops_the_call_and_adds_the_neutral_line():
    for terminal in ("response.incomplete", "response.failed"):
        stream = stream_events(VENDOR, terminal=terminal)
        mid = [e for e in stream if e["type"] != "response.output_item.done"]
        events = decode(run(encode(mid))[0])
        assert_consistent(events)
        assert events[-1]["type"] == terminal
        assert [i["content"][0]["text"] for i in rebuilt_output(events)] == [NEUTRAL]


def test_an_upstream_error_mid_call_ends_the_stream_without_the_call():
    stream = stream_events(VENDOR)
    error = {"type": "error", "code": "server_error", "message": "boom", "param": None, "x": "rm -rf /"}
    out, _, seen = run(encode([*stream[:4], error]))
    events = decode(out)
    assert events[-1]["type"] == "error" and types(events).count("error") == 1
    assert b"call_vendor" not in out and b"rm -rf" not in out and seen == []


# Anything outside the allowlist ends the stream.

def test_an_event_outside_the_message_allowlist_ends_the_stream():
    stream = stream_events(message_item("hi"))
    stray = {"type": "response.output_text.annotation.added", "item_id": "msg_1", "output_index": 0,
             "content_index": 0, "annotation_index": 0, "annotation": {"type": "file_path"}}
    out, audits, _ = run(encode([*stream[:4], stray, *stream[4:]]))
    assert decode(out)[-1]["type"] == "error" and audits[0]["detail"] == "event_outside_allowlist"


def test_a_message_that_finishes_as_a_call_is_never_delivered():
    stream = stream_events(message_item("hello", "msg_x"))
    for event in stream:
        if event["type"] == "response.output_item.done":
            event["item"] = {**BASH, "id": "msg_x"}
    stream[-1]["response"]["output"] = [{**BASH, "id": "msg_x"}]
    out, audits, seen = run(encode(stream))
    assert decode(out)[-1]["type"] == "error" and b"rm -rf" not in out and seen == []
    assert not any(e["type"] == "response.completed" for e in decode(out))


def test_a_function_call_part_inside_a_message_ends_the_stream():
    item = message_item("hi")
    stream = stream_events(item)
    for event in stream:
        if event["type"] == "response.output_item.done":
            event["item"] = {**item, "content": [*item["content"], {"type": "function_call", "name": "bash",
                                                                    "arguments": "rm -rf /"}]}
    out, _, _ = run(encode(stream))
    assert decode(out)[-1]["type"] == "error" and b"rm -rf" not in out


def test_a_message_without_its_done_ends_the_stream():
    stream = [e for e in stream_events(message_item("hi")) if e["type"] != "response.output_item.done"]
    assert decode(run(encode(stream))[0])[-1]["type"] == "error"


def test_events_after_a_done_and_duplicates_end_the_stream():
    stream = stream_events(message_item("hi"), VENDOR)
    late = {"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0,
            "delta": "more", "logprobs": []}
    duplicate_index = {"type": "response.output_item.added", "output_index": 0, "item": message_item("again", "m2")}
    duplicate_id = {"type": "response.output_item.added", "output_index": 7, "item": message_item("again")}
    for extra in (late, duplicate_index, duplicate_id):
        assert decode(run(encode(_poisoned(stream, [extra])))[0])[-1]["type"] == "error", extra


def test_an_unknown_event_type_or_a_bad_final_event_ends_the_stream():
    stream = stream_events(message_item("hi"))
    unknown = {"type": "response.something_new", "detail": "rm -rf /"}
    assert decode(run(encode([*stream[:2], unknown, *stream[2:]]))[0])[-1]["type"] == "error"
    bad = [*stream[:-1], {"type": "response.completed", "response": {"output": "not a list"}}]
    assert decode(run(encode(bad))[0])[-1]["type"] == "error"
    bad_lifecycle = [{"type": "response.created", "response": "nope"}, *stream[1:]]
    assert decode(run(encode(bad_lifecycle))[0])[-1]["type"] == "error"


def test_an_unparseable_event_ends_with_an_error_event():
    raw = encode(stream_events(message_item("hi"), VENDOR))
    out, audits, _ = run([*raw[:4], b"data: {not json\n\n", *raw[4:]])
    events = decode(out)
    assert events[-1]["type"] == "error"
    assert "acs" not in json.dumps(events[-1]).lower() and "guardian" not in json.dumps(events[-1]).lower()
    assert calls_of(events) == []
    assert audits[0]["cause"] == "upstream_unparseable"


def test_a_truncated_stream_ends_with_an_error_event_and_no_call():
    out, audits, seen = run(encode(stream_events(message_item("hi"), VENDOR))[:-1])
    assert decode(out)[-1]["type"] == "error" and b"call_vendor" not in out and seen == []


# Limits and timers, enforce only.

def test_buffered_bytes_count_against_the_limit():
    stream = stream_events(VENDOR)
    where = {"item_id": VENDOR["id"], "output_index": 0}
    empties = [{"type": "response.function_call_arguments.delta", **where, "delta": ""}] * 300_000
    raw = encode([*stream[:3], *empties[:1], *stream[3:]])
    filler = encode(empties[:1])[0]
    out, audits, seen = run([*raw[:4], filler * 300_000, *raw[4:]])
    assert decode(out)[-1]["type"] == "error" and audits[0]["cause"] == "upstream_too_large" and seen == []


def test_a_decide_fault_removes_the_call():
    async def broken(item):
        raise RuntimeError("policy crashed")

    out, audits, _ = run(encode(stream_events(VENDOR)), decide=broken)
    assert b"call_vendor" not in out
    assert rebuilt_output(decode(out))[0]["content"][0]["text"] == NEUTRAL
    assert audits[0]["event"] == "gateway_step_error"


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


def test_a_stream_past_its_deadline_ends_with_an_error_event():
    async def main():
        audits = []

        async def source():
            for chunk in encode(stream_events(message_item("hi")))[:-1]:
                yield chunk
                await asyncio.sleep(0.1)

        editor = StreamEditor(enforce=True, limit=LIMIT, decide=None, idle_timeout=5, deadline=0.25,
                              audit=lambda event, **fields: audits.append(fields))
        return b"".join([o async for o in editor.edit(source())]), audits

    out, audits = asyncio.run(asyncio.wait_for(main(), 3))
    assert decode(out)[-1]["type"] == "error" and audits[0]["cause"] == "upstream_deadline"


def test_a_failing_upstream_ends_with_an_error_event():
    async def main():
        async def source():
            yield encode(stream_events(message_item("hi")))[0]
            raise OSError("connection reset")

        editor = StreamEditor(enforce=True, limit=LIMIT, decide=None, audit=lambda *a, **k: None)
        return b"".join([out async for out in editor.edit(source())])

    assert decode(asyncio.run(main()))[-1]["type"] == "error"


# Shadow relays byte for byte and records in the background.

def test_shadow_relays_every_byte_and_decides_each_call():
    raw = encode(stream_events(message_item("hi"), BASH, hosted_item("ws_2"), VENDOR))
    out, audits, seen = run(raw, enforce=False)
    assert out == b"".join(raw)
    assert [i["id"] for i in seen] == [BASH["id"], "ws_2", VENDOR["id"]]
    assert audits == []


def test_shadow_relays_what_follows_the_final_event_in_its_chunk():
    raw = b"".join(encode(stream_events(message_item("hi")))) + b"data: [DONE]\n\n"
    assert run([raw], enforce=False)[0] == raw


def test_shadow_has_no_idle_timeout_and_injects_nothing():
    raw = encode(stream_events(message_item("hi")))

    async def main():
        async def source():
            for chunk in raw:
                await asyncio.sleep(0.15)
                yield chunk

        editor = StreamEditor(enforce=False, limit=LIMIT, decide=None, idle_timeout=0.05,
                              audit=lambda *a, **k: None)
        return b"".join([o async for o in editor.edit(source())])

    assert asyncio.run(main()) == b"".join(raw)


def test_shadow_relays_the_rest_after_an_unparseable_event():
    raw = encode(stream_events(message_item("hi"), BASH))
    broken = [*raw[:4], b"data: {not json\n\n", *raw[4:]]
    out, audits, seen = run(broken, enforce=False)
    assert out == b"".join(broken) and seen == []


def test_shadow_judges_the_finished_item_type():
    stream = stream_events(message_item("hello", "msg_x"))
    for event in stream:
        if event["type"] == "response.output_item.done":
            event["item"] = {**BASH, "id": "msg_x"}
    assert [i["name"] for i in run(encode(stream), enforce=False)[2]] == ["bash"]


def test_shadow_never_waits_for_a_decision():
    async def main():
        finished = []

        async def slow(item):
            await asyncio.sleep(0.5)
            finished.append(item)
            return item

        async def source():
            for chunk in encode(stream_events(message_item("hi"), BASH, VENDOR)):
                yield chunk

        editor = StreamEditor(enforce=False, limit=LIMIT, decide=slow, audit=lambda *a, **k: None)
        begin = asyncio.get_running_loop().time()
        b"".join([o async for o in editor.edit(source())])
        relayed = asyncio.get_running_loop().time() - begin
        early = len(finished)
        await editor.drain()
        return relayed, early, len(finished)

    relayed, early, decided = asyncio.run(main())
    assert relayed < 0.3 and early == 0 and decided == 2


def test_shadow_caps_its_queued_decisions():
    calls = [call_item("get_vendor_details", {"vendor_id": n}, f"call_{n}") for n in range(5)]
    _, audits, seen = run(encode(stream_events(*calls)), enforce=False, queue_cap=2)
    assert len(seen) <= 3
    assert any(a["event"] == "shadow_decisions_dropped" for a in audits)


def test_abort_stops_the_recorder_even_when_drain_is_cancelled():
    async def main():
        async def endless(item):
            await asyncio.Event().wait()

        async def source():
            for chunk in encode(stream_events(VENDOR)):
                yield chunk

        editor = StreamEditor(enforce=False, limit=LIMIT, decide=endless, audit=lambda *a, **k: None)
        b"".join([o async for o in editor.edit(source())])
        drain = asyncio.create_task(editor.drain())
        await asyncio.sleep(0.05)
        drain.cancel()
        await editor.abort()
        return editor.recording

    assert asyncio.run(asyncio.wait_for(main(), 2)) is False
