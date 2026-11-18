"""Governed streaming: a Responses API event stream that reaches the client only as the gateway rebuilt it.

Issue #578, Appendix B WP2. In enforce, only message text streams live, and every event of it is rebuilt from an exact
allowlist of known fields. Every other item, function_call and reasoning included, is never relayed from upstream
events: they are only counted while the stream runs, and when the upstream's final event arrives the gateway takes
that event's output, gates each call, and builds each surviving item's events from the decided item. Upstream bytes
never reach the client in enforce, so no event the gateway didn't build can carry a call. The gateway numbers every
event it sends from its own counter, strictly rising, which P21 allows since FinBot reads only output_text.delta and
output_item.done, and output_index is the gateway's dense count, so response.completed lists exactly what was streamed.

Shadow relays the upstream byte for byte, injects nothing, and records decisions on a task of its own.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import re
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from starlette.responses import StreamingResponse

from acs_gateway.apply import item_type, message_part, neutral_message, rebuilt_message
from acs_gateway.strict import loads_recording

_LIFECYCLE = frozenset({"response.created", "response.in_progress", "response.queued"})
_TERMINAL = frozenset({"response.completed", "response.incomplete", "response.failed"})
_ADDED, _DONE = "response.output_item.added", "response.output_item.done"
# The only events of a message the client gets, each rebuilt from the fields named here.
_MESSAGE_EVENTS = frozenset({_ADDED, "response.content_part.added", "response.output_text.delta",
                             "response.output_text.done", "response.refusal.delta", "response.refusal.done",
                             "response.content_part.done", _DONE})
# Which announced part type each text event writes to.
_PART_OF = {"response.output_text.delta": "output_text", "response.output_text.done": "output_text",
            "response.refusal.delta": "refusal", "response.refusal.done": "refusal"}
# How long shadow keeps relaying after the final event, for trailing bytes such as data: [DONE] in a later chunk.
_SHADOW_TAIL_S = 1.0
_BOUNDARY = re.compile(rb"\r\n\r\n|\n\n|\r\r")
_LINES = re.compile(r"\r\n|\r|\n")
UNREADABLE = "The model service returned an unreadable response."
DEFAULT_QUEUE_CAP = 256


def error_event(sequence_number: int) -> bytes:
    """The Responses API's own stream error, so a client sees an ordinary model failure and nothing about ACS."""
    return _frame({"type": "error", "sequence_number": sequence_number, "code": "upstream_unreadable",
                   "message": UNREADABLE, "param": None})


def _frame(data: dict[str, Any]) -> bytes:
    # ASCII-escaped, so text holding a lone surrogate can't fail to encode, and a JSON reader gets it back unchanged.
    return f"event: {data['type']}\ndata: {json.dumps(data, ensure_ascii=True)}\n\n".encode("ascii")


class _Unreadable(Exception):
    def __init__(self, cause: str, detail: str) -> None:
        super().__init__(detail)
        self.cause, self.detail = cause, detail


def _refuse(detail: str) -> _Unreadable:
    return _Unreadable("upstream_unparseable", detail)


class _UpstreamFailed(Exception):
    """Reading the upstream failed, stalled or ran past its deadline, as distinct from a fault in the editor."""

    def __init__(self, cause: str) -> None:
        super().__init__(cause)
        self.cause = cause


def _parse(raw: bytes) -> dict[str, Any] | None:
    """One SSE event's data. None for a comment-only block or the [DONE] sentinel."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _refuse("event_not_utf8") from e
    lines = [line[5:].removeprefix(" ") for line in _LINES.split(text) if line.startswith("data:")]
    if not lines or lines == ["[DONE]"]:
        return None
    try:
        data, repeated = loads_recording("\n".join(lines))
    except (ValueError, RecursionError) as e:
        raise _refuse("event_not_json") from e
    if repeated is not None:
        raise _refuse("duplicate_json_key")
    if not isinstance(data, dict) or not isinstance(data.get("type"), str):
        raise _refuse("event_without_type")
    return data


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: Any, detail: str) -> str:
    if not isinstance(value, str):
        raise _refuse(detail)
    return value


def _message(item: Any) -> dict[str, Any]:
    """A message item rebuilt through the shared message-part allowlist (apply.message_part)."""
    if not isinstance(item, dict) or item.get("type") != "message":
        raise _refuse("item_type_mismatch")
    rebuilt = rebuilt_message(item)
    if rebuilt is None:
        raise _refuse("message_part_outside_allowlist")
    return rebuilt


def _usage(value: Any) -> dict[str, Any] | None:
    """Token counts only, so nothing but numbers rides in usage."""
    if not isinstance(value, dict):
        return None
    usage: dict[str, Any] = {k: value[k] for k in ("input_tokens", "output_tokens", "total_tokens")
                             if _int(value.get(k)) is not None}
    for details, key in (("input_tokens_details", "cached_tokens"), ("output_tokens_details", "reasoning_tokens")):
        if isinstance(value.get(details), dict) and _int(value[details].get(key)) is not None:
            usage[details] = {key: value[details][key]}
    return usage


def _envelope(response: dict[str, Any], output: list[dict[str, Any]]) -> dict[str, Any]:
    """The Response a rebuilt lifecycle or final event carries: only what a client needs, each field checked, and the
    gateway's own output. tools, metadata, instructions, text and reasoning never come back from the upstream."""
    rebuilt: dict[str, Any] = {k: response[k] for k in ("id", "object", "status", "model")
                               if isinstance(response.get(k), str)}
    if isinstance(response.get("created_at"), (int, float)) and not isinstance(response["created_at"], bool):
        rebuilt["created_at"] = response["created_at"]
    usage = _usage(response.get("usage"))
    if usage is not None:
        rebuilt["usage"] = usage
    if "error" in response:
        error = response["error"]
        rebuilt["error"] = ({"code": error.get("code") if isinstance(error.get("code"), str) else None,
                             "message": error.get("message") if isinstance(error.get("message"), str) else UNREADABLE}
                            if isinstance(error, dict) else None)
    rebuilt["output"] = output
    return rebuilt


def _call(item: dict[str, Any]) -> dict[str, Any]:
    """A function_call rebuilt from known keys of the decided item."""
    return {"type": "function_call", "id": _text(item.get("id"), "item_without_id"),
            "call_id": _text(item.get("call_id"), "call_without_call_id"),
            "name": _text(item.get("name"), "call_without_name"),
            "arguments": _text(item.get("arguments"), "call_without_arguments"), "status": "completed"}


def _reasoning(item: dict[str, Any]) -> dict[str, Any]:
    """A reasoning item rebuilt from known keys: its summary text and, when present, the encrypted content a
    reasoning model needs back on a resend. Private reasoning text never goes out."""
    parts = item.get("summary") if isinstance(item.get("summary"), list) else []
    summary = [{"type": "summary_text", "text": part["text"]} for part in parts
               if isinstance(part, dict) and part.get("type") == "summary_text" and isinstance(part.get("text"), str)]
    rebuilt = {"type": "reasoning", "id": _text(item.get("id"), "item_without_id"), "summary": summary}
    if isinstance(item.get("encrypted_content"), str):
        rebuilt["encrypted_content"] = item["encrypted_content"]
    return rebuilt


def _orphans(marked: list[Any]) -> set[int]:
    """Positions of reasoning items to drop. A run of reasoning belongs to the items after it up to the next run, and
    goes when every one of them was removed (None). A run with nothing after it stays."""
    dropped: set[int] = set()
    run: list[int] = []
    turn: list[Any] = []

    def close() -> None:
        if run and turn and all(item is None for item in turn):
            dropped.update(run)

    for position, item in enumerate(marked):
        if isinstance(item, dict) and item.get("type") == "reasoning":
            if turn:
                close()
                run, turn = [], []
            run.append(position)
        else:
            turn.append(item)
    close()
    return dropped


# Marks a message already streamed live when the final output is walked.
_STREAMED = object()


@dataclass
class _Item:
    kind: str
    item_id: str
    done: bool = False
    # A streamed message's dense output_index, and its rebuilt done item.
    client: int | None = None
    final: dict[str, Any] | None = None
    # A streamed message's announced parts, by content_index, and their types.
    parts: dict[int, str] = field(default_factory=dict)


@dataclass
class _Frames:
    """Splits SSE bytes into events. A read offset and a resumed search keep a long stream linear."""
    buffer: bytearray = field(default_factory=bytearray)
    start: int = 0
    scan: int = 0

    def feed(self, chunk: bytes) -> Iterator[bytes]:
        self.buffer += chunk
        while True:
            match = _BOUNDARY.search(self.buffer, max(self.start, self.scan - 3))
            if match is None:
                self.scan = len(self.buffer)
                break
            yield bytes(self.buffer[self.start:match.end()])
            self.start = self.scan = match.end()
        if self.start > len(self.buffer) // 2:
            del self.buffer[:self.start]
            self.scan -= self.start
            self.start = 0

    def pending(self) -> int:
        return len(self.buffer) - self.start


class StreamEditor:
    """Edits one upstream event stream for the client.

    decide(item) gets each function_call, and each item outside the output allowlist, from the upstream's final
    output, and returns the item to deliver or None to remove it. limit bounds the bytes enforce keeps, idle_timeout
    the wait for each upstream chunk and deadline the whole stream, all in enforce only. Shadow (enforce=False)
    relays every byte, keeps relaying after the final event until the upstream closes or stays silent for
    _SHADOW_TAIL_S, and queues decisions, at most queue_cap at once, for drain(). An upstream that keeps sending after
    the final event keeps a shadow relay going until it stops. A shadow editor given a deadline stops relaying when it
    passes, with nothing injected.
    """

    def __init__(self, *, enforce: bool, limit: int,
                 decide: Callable[[dict[str, Any]], Awaitable[dict[str, Any] | None]] | None,
                 audit: Callable[..., None], audit_fields: dict[str, Any] | None = None,
                 idle_timeout: float | None = None, deadline: float | None = None,
                 queue_cap: int = DEFAULT_QUEUE_CAP) -> None:
        self.enforce, self.limit, self.decide, self._audit = enforce, limit, decide, audit
        self.idle_timeout, self.deadline, self.queue_cap = idle_timeout, deadline, queue_cap
        self._fields = audit_fields or {}
        self._items: dict[int, _Item] = {}
        self._ids: set[str] = set()
        self._emitted: list[dict[str, Any]] = []
        self._seq = 0
        self._kept = 0
        self._finished = False
        self._queue: deque[dict[str, Any]] = deque()
        self._wake = asyncio.Event()
        self._closing = False
        self._recorder: asyncio.Task[None] | None = None

    @property
    def _mode(self) -> str:
        return "enforce" if self.enforce else "shadow"

    @property
    def recording(self) -> bool:
        return self._recorder is not None and not self._recorder.done()

    async def edit(self, chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        source = self._read(chunks)
        if not self.enforce:
            async for out in self._relay(source):
                yield out
            return
        frames = _Frames()
        try:
            async for chunk in source:
                for raw in frames.feed(chunk):
                    async for out in self._event(raw):
                        yield out
                    if self._finished:
                        return
                if frames.pending() > self.limit:
                    raise _Unreadable("upstream_too_large", "event_too_large")
            raise _refuse("stream_ended_early")
        except _Unreadable as e:
            self._audit("upstream_error", cause=e.cause, detail=e.detail, mode="enforce", stream=True, **self._fields)
            yield self._fail()
        except _UpstreamFailed as e:
            self._audit("upstream_error", cause=e.cause, mode="enforce", stream=True, **self._fields)
            yield self._fail()
        except Exception as e:  # noqa: BLE001
            # A fault in the editor itself. The stream ends cleanly rather than hanging or leaking an item.
            self._audit("gateway_step_error", phase="stream", mode="enforce", error=f"{type(e).__name__}: {e}",
                        **self._fields)
            yield self._fail()

    def _fail(self) -> bytes:
        self._finished = True
        return error_event(self._next())

    def _next(self) -> int:
        number, self._seq = self._seq, self._seq + 1
        return number

    def _emit(self, data: dict[str, Any]) -> bytes:
        return _frame({"type": data["type"], "sequence_number": self._next(),
                       **{k: v for k, v in data.items() if k != "type"}})

    def _keep(self, size: int) -> None:
        self._kept += size
        if self._kept > self.limit:
            raise _Unreadable("upstream_too_large", "kept_bytes_over_limit")

    async def _read(self, chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        """Upstream chunks under enforce's idle timeout and the deadline. Shadow gets no idle timeout."""
        loop = asyncio.get_running_loop()
        end = loop.time() + self.deadline if self.deadline is not None else None
        idle = self.idle_timeout if self.enforce else None
        iterator = chunks.__aiter__()
        while True:
            waits = [w for w in (idle, None if end is None else end - loop.time()) if w is not None]
            limit = min(waits) if waits else None
            try:
                chunk = await (iterator.__anext__() if limit is None else asyncio.wait_for(iterator.__anext__(),
                                                                                           max(limit, 0)))
            except StopAsyncIteration:
                return
            except asyncio.TimeoutError as e:
                past = end is not None and loop.time() >= end
                raise _UpstreamFailed("upstream_deadline" if past else "upstream_idle_timeout") from e
            except Exception as e:  # noqa: BLE001
                raise _UpstreamFailed("upstream_unreachable") from e
            yield chunk

    async def _relay(self, source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        """Shadow: every byte as it came, whatever the chunking, decisions queued. After the final event it keeps
        relaying until the upstream closes or stays silent for _SHADOW_TAIL_S, so a trailing data: [DONE] in a later
        chunk still goes out. A silent upstream releases the session lock after the tail. One that keeps sending after
        the final event holds it until it stops, since shadow has no overall deadline."""
        frames, reading = _Frames(), True
        try:
            async for chunk in source:
                yield chunk
                final = False
                if reading:
                    try:
                        for raw in frames.feed(chunk):
                            data = _parse(raw)
                            if data is None:
                                continue
                            item = data.get("item")
                            if data["type"] == _DONE and isinstance(item, dict) and item_type(item) not in (
                                    "message", "reasoning"):
                                self._record(item)
                            final = final or data["type"] in _TERMINAL or data["type"] == "error"
                        if frames.pending() > self.limit:
                            # An event that never ends can't be parsed within the limit. The bytes still relay, but
                            # nothing more is held for parsing.
                            raise _Unreadable("upstream_too_large", "event_too_large")
                    except _Unreadable as e:
                        # Shadow only observes, so it relays the rest ungated.
                        self._audit("upstream_error", cause=e.cause, detail=e.detail, mode="shadow", stream=True,
                                    **self._fields)
                        reading = False
                        frames.buffer.clear()
                if final:
                    async for chunk in self._tail(source):
                        yield chunk
                    return
        except _UpstreamFailed as e:
            # Nothing is injected. The relay ends where the upstream did.
            self._audit("upstream_error", cause=e.cause, mode="shadow", stream=True, **self._fields)

    @staticmethod
    async def _tail(source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        while True:
            try:
                yield await asyncio.wait_for(source.__anext__(), _SHADOW_TAIL_S)
            except (StopAsyncIteration, asyncio.TimeoutError, _UpstreamFailed):
                return

    def _record(self, item: dict[str, Any]) -> None:
        if self.decide is None:
            return
        if len(self._queue) >= self.queue_cap:
            self._audit("shadow_decisions_dropped", call_id=item.get("call_id"), queue_cap=self.queue_cap,
                        **self._fields)
            return
        self._queue.append(item)
        self._wake.set()
        if self._recorder is None:
            self._recorder = asyncio.get_running_loop().create_task(self._recording())

    async def _recording(self) -> None:
        """One task takes shadow decisions in order, so steps keep the session's order."""
        while True:
            while self._queue:
                await self._decided(self._queue.popleft())
            if self._closing:
                return
            self._wake.clear()
            await self._wake.wait()

    async def drain(self) -> None:
        """Wait for every queued shadow decision. The caller holds the session lock until this returns."""
        self._closing = True
        self._wake.set()
        if self._recorder is not None:
            await asyncio.shield(self._recorder)

    async def abort(self) -> None:
        """Stop the recorder and wait for it to end, so nothing runs on after the lock is released."""
        if self._recorder is not None and not self._recorder.done():
            self._recorder.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._recorder

    async def _decided(self, item: dict[str, Any]) -> dict[str, Any] | None:
        try:
            return await self.decide(item)
        except Exception as e:  # noqa: BLE001
            # Fail closed: a fault while gating removes the item in enforce, and shadow only records it.
            self._audit("gateway_step_error", phase="stream_output", mode=self._mode,
                        error=f"{type(e).__name__}: {e}", **self._fields)
            return None

    async def _event(self, raw: bytes) -> AsyncIterator[bytes]:
        data = _parse(raw)
        if data is None:
            return
        kind = data["type"]
        if kind in _LIFECYCLE:
            yield self._emit({"type": kind, "response": self._response(data, terminal=False)})
            return
        if kind == "error":
            # The upstream's own failure, rebuilt from known fields. Nothing buffered goes out.
            yield self._emit({"type": "error",
                              "code": data.get("code") if isinstance(data.get("code"), str) else None,
                              "message": data.get("message") if isinstance(data.get("message"), str) else UNREADABLE,
                              "param": data.get("param") if isinstance(data.get("param"), str) else None})
            self._finished = True
            return
        if kind in _TERMINAL:
            async for out in self._terminal(data):
                yield out
            self._finished = True
            return
        index = _int(data.get("output_index"))
        if index is None or not kind.startswith("response."):
            raise _refuse("unknown_event_type")
        if kind == _ADDED:
            for out in self._added(data, index, len(raw)):
                yield out
            return
        entry = self._items.get(index)
        if entry is None:
            raise _refuse("output_index_unannounced")
        if entry.done:
            raise _refuse("event_after_done")
        if entry.kind == "message":
            yield self._message_event(entry, data, len(raw))
            return
        # Any other item is only counted. The final event's output is what the gateway builds it from.
        self._keep(len(raw))
        if kind == _DONE:
            entry.done = True

    def _added(self, data: dict[str, Any], index: int, size: int) -> Iterator[bytes]:
        item = data.get("item")
        if not isinstance(item, dict) or not isinstance(item.get("type"), str):
            raise _refuse("event_without_item")
        item_id = _text(item.get("id"), "item_without_id")
        if index in self._items or item_id in self._ids:
            raise _refuse("item_repeated")
        self._keep(size)
        entry = _Item(item_type(item), item_id)
        self._items[index] = entry
        self._ids.add(item_id)
        if entry.kind == "message":
            entry.client = len(self._emitted)
            self._emitted.append({})
            yield self._emit({"type": _ADDED, "output_index": entry.client,
                              "item": {"type": "message", "id": item_id, "role": "assistant",
                                       "status": "in_progress", "content": []}})

    def _message_event(self, entry: _Item, data: dict[str, Any], size: int) -> bytes:
        kind = data["type"]
        if kind not in _MESSAGE_EVENTS:
            raise _refuse("event_outside_allowlist")
        where = {"output_index": entry.client}
        if kind == _DONE:
            final = _message(data.get("item"))
            if final["id"] != entry.item_id:
                raise _refuse("item_type_mismatch")
            self._keep(size)
            entry.done, entry.final = True, final
            self._emitted[entry.client] = final
            return self._emit({"type": _DONE, **where, "item": final})
        index = _int(data.get("content_index"))
        if data.get("item_id") != entry.item_id or index is None:
            raise _refuse("event_outside_allowlist")
        where = {"item_id": entry.item_id, **where, "content_index": index}
        if kind == "response.content_part.added":
            # A part's text starts empty, so the allowlist sees it with its text field filled in.
            part = data.get("part")
            kind_of = part.get("type") if isinstance(part, dict) else None
            rebuilt = message_part({"text": "", "refusal": "", **part} if isinstance(part, dict) else part)
            if rebuilt is None or index in entry.parts:
                raise _refuse("message_part_outside_allowlist")
            entry.parts[index] = kind_of
            return self._emit({"type": kind, **where, "part": rebuilt})
        announced = entry.parts.get(index)
        if kind == "response.content_part.done":
            rebuilt = message_part(data.get("part"))
            if rebuilt is None or rebuilt["type"] != announced:
                raise _refuse("event_outside_allowlist")
            return self._emit({"type": kind, **where, "part": rebuilt})
        # A text event writes to a part the client already has, of the same type, or the stream ends.
        if announced != _PART_OF[kind]:
            raise _refuse("event_outside_allowlist")
        if kind.endswith(".delta"):
            extra = {"logprobs": []} if announced == "output_text" else {}
            return self._emit({"type": kind, **where, "delta": _text(data.get("delta"), "delta_without_text"),
                               **extra})
        if announced == "output_text":
            return self._emit({"type": kind, **where, "text": _text(data.get("text"), "done_without_text"),
                               "logprobs": []})
        return self._emit({"type": kind, **where, "refusal": _text(data.get("refusal"), "done_without_text")})

    def _response(self, data: dict[str, Any], *, terminal: bool) -> dict[str, Any]:
        response = data.get("response")
        if not isinstance(response, dict):
            raise _refuse("final_event_without_response" if terminal else "lifecycle_without_response")
        return _envelope(response, [item for item in self._emitted if item])

    async def _terminal(self, data: dict[str, Any]) -> AsyncIterator[bytes]:
        """The upstream's final event: gate and build every item that isn't streamed text, then rebuild the event
        with exactly the items sent. On incomplete or failed, nothing buffered goes out."""
        response = data.get("response")
        output = response.get("output") if isinstance(response, dict) else None
        if not isinstance(output, list) or not all(isinstance(i, dict) and isinstance(i.get("type"), str)
                                                   for i in output):
            raise _refuse("final_event_without_output")
        if any(e.kind == "message" and not e.done for e in self._items.values()):
            raise _refuse("message_without_done")
        streamed = {e.item_id for e in self._items.values() if e.kind == "message"}
        # Positions in output order, each a built item, None for a removal, or _STREAMED.
        marked: list[Any] = []
        removed = False
        for item in output:
            if item["type"] == "message" and item.get("id") in streamed:
                marked.append(_STREAMED)
            elif data["type"] != "response.completed":
                marked.append(None)
                removed = True
            elif item["type"] == "message":
                marked.append(_message(item))
            elif item["type"] == "reasoning":
                marked.append(_reasoning(item))
            else:
                kept = await self._decided(item)
                built = _call(kept) if isinstance(kept, dict) and kept.get("type") == "function_call" else None
                marked.append(built)
                removed = removed or built is None
        if data["type"] != "response.completed" and any(e.kind != "message" for e in self._items.values()):
            removed = True
        dropped = _orphans(marked)
        for position, item in enumerate(marked):
            if position in dropped or item is None or item is _STREAMED:
                continue
            for out in self._built(item):
                yield out
        if removed and not any(i.get("type") in ("message", "function_call") for i in self._emitted if i):
            for out in self._built(neutral_message()):
                yield out
        yield self._emit({"type": data["type"], "response": self._response(data, terminal=True)})

    def _built(self, item: dict[str, Any]) -> Iterator[bytes]:
        """An item's full event set, built from the item alone, so an accumulating client always has it whole."""
        index = len(self._emitted)
        self._emitted.append(item)
        where = {"item_id": item["id"], "output_index": index}
        if item["type"] == "function_call":
            yield self._emit({"type": _ADDED, "output_index": index,
                              "item": {**item, "status": "in_progress", "arguments": ""}})
            yield self._emit({"type": "response.function_call_arguments.delta", **where, "delta": item["arguments"]})
            yield self._emit({"type": "response.function_call_arguments.done", **where, "name": item["name"],
                              "arguments": item["arguments"]})
        elif item["type"] == "message":
            yield self._emit({"type": _ADDED, "output_index": index,
                              "item": {**item, "status": "in_progress", "content": []}})
            for position, part in enumerate(item["content"]):
                at = {**where, "content_index": position}
                if part["type"] == "refusal":
                    yield self._emit({"type": "response.content_part.added", **at,
                                      "part": {"type": "refusal", "refusal": ""}})
                    yield self._emit({"type": "response.refusal.delta", **at, "delta": part["refusal"]})
                    yield self._emit({"type": "response.refusal.done", **at, "refusal": part["refusal"]})
                else:
                    yield self._emit({"type": "response.content_part.added", **at,
                                      "part": {"type": "output_text", "text": "", "annotations": []}})
                    yield self._emit({"type": "response.output_text.delta", **at, "delta": part["text"],
                                      "logprobs": []})
                    yield self._emit({"type": "response.output_text.done", **at, "text": part["text"],
                                      "logprobs": []})
                yield self._emit({"type": "response.content_part.done", **at, "part": part})
        else:
            yield self._emit({"type": _ADDED, "output_index": index, "item": {**item, "summary": []}})
        yield self._emit({"type": _DONE, "output_index": index, "item": item})


class GovernedStream(StreamingResponse):
    """A StreamingResponse whose cleanup always runs once the response is sent or abandoned, even if its body never
    starts, so a governed stream never keeps its session lock, its pins or its upstream connection."""

    def __init__(self, content: AsyncIterator[bytes], cleanup: Callable[[], Awaitable[None]], **kwargs: Any) -> None:
        super().__init__(content, **kwargs)
        self._cleanup = cleanup

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self._cleanup()
