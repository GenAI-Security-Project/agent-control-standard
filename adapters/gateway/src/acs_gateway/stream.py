"""Governed streaming: a Responses API event stream edited so a tool call reaches the client only once it is decided.

Issue #578, Appendix B WP2. Text streams as it arrives. A function_call reaches the client only as the item the gate
judged: its events are rebuilt from the decided item and the upstream's own events for it never go out. An item's
type is the type of its finished item, so an item announced as text that finishes as a call ends the stream. Events
keep their sequence_number, so a removed event leaves a gap the client accepts (PREMORTEM P21), and output_index
follows the edited output, so response.completed lists exactly what was streamed and an accumulating client (openai's
responses.stream()) never indexes past its snapshot.
"""
from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from starlette.responses import StreamingResponse

from acs_gateway.apply import NEUTRAL_LINE, item_type, neutral_message
from acs_gateway.strict import loads_recording

_LIFECYCLE = frozenset({"response.created", "response.in_progress", "response.queued"})
_TERMINAL = frozenset({"response.completed", "response.incomplete", "response.failed"})
# The upstream's own error event ends a stream just as a terminal event does.
_LAST = _TERMINAL | {"error"}
_DONE = "response.output_item.done"
# The events each streamed type may carry. An event of another type's family on an item is a type mismatch.
_FAMILIES = {
    "message": ("response.output_text.", "response.content_part.", "response.refusal."),
    "reasoning": ("response.reasoning_summary_part.", "response.reasoning_summary_text.", "response.reasoning_text."),
    "function_call": ("response.function_call_arguments.",),
}
_ALL_FAMILIES = tuple(prefix for prefixes in _FAMILIES.values() for prefix in prefixes)
_BOUNDARY = re.compile(rb"\r\n\r\n|\n\n|\r\r")
_LINES = re.compile(r"\r\n|\r|\n")
UNREADABLE = "The model service returned an unreadable response."


def error_event(sequence_number: int) -> bytes:
    """The Responses API's own stream error, so a client sees an ordinary model failure and nothing about ACS."""
    data = {"type": "error", "code": "upstream_unreadable", "message": UNREADABLE, "param": None,
            "sequence_number": sequence_number}
    return _frame("error", data)


def _frame(name: str, data: dict[str, Any]) -> bytes:
    # ASCII-escaped, so text holding a lone surrogate can't fail to encode, and a JSON reader gets it back unchanged.
    return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=True)}\n\n".encode("ascii")


def _fits(kind: str, event_type: str) -> bool:
    """Whether an event belongs to an item of this type. An item outside the allowlist may carry its own events but
    never another type's."""
    if event_type == _DONE:
        return True
    if kind in _FAMILIES:
        return event_type.startswith(_FAMILIES[kind])
    return not event_type.startswith(_ALL_FAMILIES)


class _Unreadable(Exception):
    def __init__(self, cause: str, detail: str) -> None:
        super().__init__(detail)
        self.cause, self.detail = cause, detail


class _UpstreamFailed(Exception):
    """Reading the upstream failed or stalled, as distinct from a fault in the editor itself."""

    def __init__(self, cause: str) -> None:
        super().__init__(cause)
        self.cause = cause


@dataclass
class _Event:
    raw: bytes
    data: dict[str, Any] | None

    @property
    def type(self) -> str:
        return self.data["type"] if self.data else ""

    @property
    def seq(self) -> int | None:
        value = self.data.get("sequence_number") if self.data else None
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    @property
    def index(self) -> int | None:
        value = self.data.get("output_index") if self.data else None
        return value if isinstance(value, int) and not isinstance(value, bool) else None


@dataclass
class _Item:
    index: int
    kind: str
    # Held events of a message or reasoning item, released as they came.
    events: list[_Event] = field(default_factory=list)
    # The sequence numbers of a call's own events, which its rebuilt events reuse in order.
    numbers: list[int] = field(default_factory=list)
    final: dict[str, Any] | None = None
    client: int | None = None
    # held, released or dropped
    state: str = "held"


def _parse(raw: bytes) -> _Event:
    """One SSE event. data is None for a comment-only block or the [DONE] sentinel."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _Unreadable("upstream_unparseable", "event_not_utf8") from e
    lines = [line[5:].removeprefix(" ") for line in _LINES.split(text) if line.startswith("data:")]
    if not lines or lines == ["[DONE]"]:
        return _Event(raw, None)
    try:
        data, repeated = loads_recording("\n".join(lines))
    except (ValueError, RecursionError) as e:
        raise _Unreadable("upstream_unparseable", "event_not_json") from e
    if repeated is not None:
        raise _Unreadable("upstream_unparseable", "duplicate_json_key")
    if not isinstance(data, dict) or not isinstance(data.get("type"), str):
        raise _Unreadable("upstream_unparseable", "event_without_type")
    return _Event(raw, data)


def _item_of(event: _Event) -> dict[str, Any]:
    item = event.data.get("item")
    if not isinstance(item, dict):
        raise _Unreadable("upstream_unparseable", "event_without_item")
    return item


class StreamEditor:
    """Edits one upstream event stream for the client.

    decide(item) gets each finished function_call, and each finished item outside the output allowlist, and returns
    the item to deliver or None to remove it. Enforce releases items in the model's order: a later item waits while a
    call before it waits for its decision. Shadow (enforce=False) relays every byte unchanged and records decisions on
    a task of its own, so the client never waits, and drain() waits for those decisions. limit bounds a partial event
    and every byte the editor keeps at once. idle_timeout bounds the wait for each upstream chunk.
    """

    def __init__(self, *, enforce: bool, limit: int,
                 decide: Callable[[dict[str, Any]], Awaitable[dict[str, Any] | None]] | None,
                 audit: Callable[..., None], audit_fields: dict[str, Any] | None = None,
                 idle_timeout: float | None = None) -> None:
        self.enforce, self.limit, self.decide, self._audit = enforce, limit, decide, audit
        self.idle_timeout = idle_timeout
        self._fields = audit_fields or {}
        self._items: dict[int, _Item] = {}
        self._run: list[_Item] = []
        self._turn_items, self._turn_kept = 0, False
        self._released: list[_Item] = []
        self._removed: list[dict[str, Any]] = []
        # The upstream's own copy of each call the gateway rewrote, which a terminal event may still list.
        self._replaced: list[dict[str, Any]] = []
        # A call or unsupported item waiting for its finished item, and the later events waiting behind it.
        self._pending: _Item | None = None
        self._backlog: list[_Event] = []
        self._kept_bytes = 0
        self._last_emitted = -1
        self._max_seq = -1
        # _finished: the client has had its last event.
        self._finished = False
        self._relay_raw = False
        self._queue: asyncio.Queue[dict[str, Any] | None] | None = None
        self._recorder: asyncio.Task[None] | None = None

    @property
    def _mode(self) -> str:
        return "enforce" if self.enforce else "shadow"

    async def edit(self, chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        buffer, scan = bytearray(), 0
        try:
            async for chunk in self._read(chunks):
                if self._relay_raw:
                    yield chunk
                    continue
                buffer += chunk
                while not self._relay_raw and not self._finished:
                    # Resume near where the last search stopped, so a long event isn't rescanned per chunk.
                    match = _BOUNDARY.search(buffer, max(0, scan - 3))
                    if match is None:
                        scan = len(buffer)
                        break
                    raw = bytes(buffer[:match.end()])
                    del buffer[:match.end()]
                    scan = 0
                    try:
                        async for out in self._event(raw):
                            yield out
                    except _Unreadable as e:
                        async for out in self._unreadable(e, raw + bytes(buffer)):
                            yield out
                        buffer.clear()
                if self._finished:
                    return
                if self._relay_raw:
                    if buffer:
                        yield bytes(buffer)
                        buffer.clear()
                elif len(buffer) > self.limit:
                    async for out in self._unreadable(_Unreadable("upstream_too_large", "event_too_large"),
                                                      bytes(buffer)):
                        yield out
                    buffer.clear()
                    if self._finished:
                        return
            if self._relay_raw:
                if buffer:
                    yield bytes(buffer)
                return
            # The upstream ended without a final event. Held items were never finished, so nothing of them goes out.
            async for out in self._unreadable(_Unreadable("upstream_unparseable", "stream_ended_early"),
                                              bytes(buffer)):
                yield out
        except _UpstreamFailed as e:
            self._audit("upstream_error", cause=e.cause, mode=self._mode, stream=True, **self._fields)
            if not self._finished:
                self._finished = True
                yield error_event(self._max_seq + 1)
        except Exception as e:  # noqa: BLE001
            # A fault in the editor itself. The stream ends cleanly rather than hanging or leaking a held call.
            self._audit("gateway_step_error", phase="stream", mode=self._mode, error=f"{type(e).__name__}: {e}",
                        **self._fields)
            if not self._finished:
                self._finished = True
                yield error_event(self._max_seq + 1)

    async def drain(self) -> None:
        """Wait for every decision shadow queued. The caller holds the session lock until this returns, so the
        session's steps stay in order."""
        if self._recorder is not None and self._queue is not None:
            self._queue.put_nowait(None)
            await self._recorder

    async def _read(self, chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        iterator = chunks.__aiter__()
        while True:
            try:
                if self.idle_timeout is None:
                    chunk = await iterator.__anext__()
                else:
                    chunk = await asyncio.wait_for(iterator.__anext__(), self.idle_timeout)
            except StopAsyncIteration:
                return
            except asyncio.TimeoutError as e:
                # A stalled upstream would hold the session lock for as long as it stalls.
                raise _UpstreamFailed("upstream_idle_timeout") from e
            except Exception as e:  # noqa: BLE001
                raise _UpstreamFailed("upstream_unreachable") from e
            yield chunk

    async def _unreadable(self, error: _Unreadable, rest: bytes) -> AsyncIterator[bytes]:
        """Enforce ends the stream with an error event. Shadow, which only observes, relays the rest as it comes."""
        self._audit("upstream_error", cause=error.cause, detail=error.detail, mode=self._mode, stream=True,
                    **self._fields)
        if self.enforce:
            self._finished = True
            yield error_event(self._max_seq + 1)
        else:
            self._relay_raw = True
            if rest:
                yield rest

    async def _event(self, raw: bytes) -> AsyncIterator[bytes]:
        event = _parse(raw)
        if event.data is None:
            # Comments carry nothing a client reads, so enforce drops them. [DONE] passes as an end marker.
            if not self.enforce or raw.strip().endswith(b"[DONE]"):
                yield raw
            return
        if event.seq is not None:
            self._max_seq = max(self._max_seq, event.seq)
        if not self.enforce:
            # Read before relaying, so a malformed item is relayed once, as part of the rest.
            item = _item_of(event) if event.type == _DONE else None
            yield raw
            if item is not None and item_type(item) not in ("message", "reasoning"):
                self._record(item)
            if event.type in _LAST:
                self._finished = True
            return
        if event.seq is None:
            # Rebuilt and inserted events take their numbers from the upstream's, so every event needs one.
            raise _Unreadable("upstream_unparseable", "event_without_sequence_number")
        self._backlog.append(event)
        self._retain(len(event.raw))
        while not self._finished:
            event = self._next()
            if event is None:
                return
            self._retain(-len(event.raw))
            async for out in self._handle(event):
                yield out

    def _next(self) -> _Event | None:
        """The next event to handle: the oldest, or while a call waits, the oldest of that call's own events."""
        if self._pending is None:
            return self._backlog.pop(0) if self._backlog else None
        for position, event in enumerate(self._backlog):
            if event.index == self._pending.index and event.type != "response.output_item.added":
                return self._backlog.pop(position)
        return None

    def _retain(self, size: int) -> None:
        self._kept_bytes += size
        if self._kept_bytes > self.limit:
            raise _Unreadable("upstream_too_large", "kept_bytes_over_limit")

    def _record(self, item: dict[str, Any]) -> None:
        """Queue a shadow decision. One task takes them in order, so steps keep the session's order."""
        if self._queue is None:
            self._queue = asyncio.Queue()
            self._recorder = asyncio.get_running_loop().create_task(self._recording())
        self._queue.put_nowait(item)

    async def _recording(self) -> None:
        assert self._queue is not None
        while (item := await self._queue.get()) is not None:
            await self._decided(item)

    async def _handle(self, event: _Event) -> AsyncIterator[bytes]:
        kind = event.type
        if kind in _LIFECYCLE:
            yield self._with_output(event, terminal=False)
            return
        if kind == "error":
            self._finished = True
            yield self._emit_raw(event)
            return
        if kind in _TERMINAL:
            for out in self._close(event.seq):
                yield out
            yield self._with_output(event, terminal=True)
            self._finished = True
            return
        index = event.index
        if index is None:
            raise _Unreadable("upstream_unparseable", "event_without_output_index")
        if kind == "response.output_item.added":
            for out in self._added(event, index):
                yield out
            return
        entry = self._items.get(index)
        if entry is None:
            raise _Unreadable("upstream_unparseable", "output_index_unannounced")
        if not _fits(entry.kind, kind):
            raise self._mismatch()
        if kind == _DONE:
            final = _item_of(event)
            if item_type(final) != entry.kind:
                raise self._mismatch()
            entry.final = final
            self._retain(len(event.raw))
        if entry.state == "dropped":
            return
        if entry.state == "released":
            yield self._emit(event, entry)
            return
        if entry.kind == "reasoning":
            entry.events.append(event)
            self._retain(len(event.raw))
            return
        entry.numbers.append(event.seq)
        if kind != _DONE:
            return
        self._pending = None
        kept = await self._decided(entry.final)
        if entry.kind != "function_call" or kept is None:
            self._drop(entry)
        else:
            for out in self._keep(entry, kept):
                yield out

    def _mismatch(self) -> _Unreadable:
        # An item announced as one type and finished as another was never judged as what it became.
        return _Unreadable("upstream_unparseable", "item_type_mismatch")

    def _added(self, event: _Event, index: int) -> Iterator[bytes]:
        if index in self._items:
            raise _Unreadable("upstream_unparseable", "output_index_repeated")
        entry = _Item(index, item_type(_item_of(event)))
        self._items[index] = entry
        if entry.kind == "reasoning":
            if self._turn_items:
                self._close_turn()
            self._run.append(entry)
            entry.events.append(event)
            self._retain(len(event.raw))
            return
        self._turn_items += 1
        if entry.kind == "message":
            entry.events.append(event)
            self._retain(len(event.raw))
            yield from self._keep(entry, None)
            return
        entry.numbers.append(event.seq)
        self._pending = entry

    async def _decided(self, item: dict[str, Any]) -> dict[str, Any] | None:
        try:
            kept = await self.decide(item)
        except Exception as e:  # noqa: BLE001
            # Fail closed: a fault while gating removes the call in enforce, and shadow only records it.
            self._audit("gateway_step_error", phase="stream_output", mode=self._mode,
                        error=f"{type(e).__name__}: {e}", **self._fields)
            return None
        return kept

    def _drop(self, entry: _Item) -> None:
        """Remove an item: none of its events reach the client."""
        self._retain(-sum(len(e.raw) for e in entry.events))
        entry.state, entry.events, entry.numbers = "dropped", [], []
        if entry.kind != "reasoning":
            self._removed.append(entry.final or {})

    def _close_turn(self) -> None:
        """A reasoning run belongs to the items after it up to the next run. When every one of them was removed, the
        run goes too, since a reasoning model rejects resent reasoning whose turn is gone."""
        if not self._turn_kept:
            for entry in self._run:
                self._drop(entry)
        self._run, self._turn_items, self._turn_kept = [], 0, False

    def _keep(self, entry: _Item, kept: dict[str, Any] | None) -> Iterator[bytes]:
        self._turn_kept = True
        for reasoning in self._run:
            yield from self._release(reasoning)
        self._run = []
        if kept is not None:
            if kept != entry.final and entry.final is not None:
                self._replaced.append(entry.final)
            entry.final = kept
        yield from self._release(entry)

    def _release(self, entry: _Item) -> Iterator[bytes]:
        entry.state, entry.client = "released", len(self._released)
        self._released.append(entry)
        if entry.kind == "function_call":
            yield from self._rebuilt(entry)
            return
        self._retain(-sum(len(e.raw) for e in entry.events))
        events, entry.events = entry.events, []
        for event in events:
            yield self._emit(event, entry)

    def _rebuilt(self, entry: _Item) -> Iterator[bytes]:
        """A call's events, built from the decided item alone and numbered with the call's own sequence numbers in
        order. Numbers must keep rising past what was sent and stay below anything waiting behind the call, so a call
        with few usable numbers gets fewer events, and output_item.done always goes out."""
        item = entry.final
        arguments = item.get("arguments") if isinstance(item.get("arguments"), str) else ""
        waiting = [e.seq for e in self._backlog if e.seq is not None]
        ceiling = min(waiting) if waiting else None
        usable = [n for n in sorted(entry.numbers)
                  if n > self._last_emitted and (ceiling is None or n < ceiling)]
        where = {"item_id": item.get("id"), "output_index": entry.client}
        added = {"type": "response.output_item.added", "output_index": entry.client,
                 "item": {**item, "status": "in_progress", "arguments": arguments}}
        delta = {"type": "response.function_call_arguments.delta", **where, "delta": arguments}
        done_arguments = {"type": "response.function_call_arguments.done", **where, "name": item.get("name"),
                          "arguments": arguments}
        done = {"type": _DONE, "output_index": entry.client, "item": item}
        if len(usable) >= 4:
            added["item"]["arguments"] = ""
            plan = [added, delta, done_arguments, done]
        elif len(usable) == 3:
            plan = [added, done_arguments, done]
        elif len(usable) == 2:
            plan = [added, done]
        else:
            plan = [done]
        numbers = usable[:len(plan)] if usable else [self._last_emitted + 1]
        for data, number in zip(plan, numbers):
            self._last_emitted = max(self._last_emitted, number)
            yield _frame(data["type"], {**data, "sequence_number": number})

    def _emit(self, event: _Event, entry: _Item) -> bytes:
        self._last_emitted = max(self._last_emitted, event.seq)
        if event.index == entry.client:
            return event.raw
        return _frame(event.type, {**event.data, "output_index": entry.client})

    def _emit_raw(self, event: _Event) -> bytes:
        self._last_emitted = max(self._last_emitted, event.seq)
        return event.raw

    def _close(self, terminal_seq: int | None) -> Iterator[bytes]:
        """Before the terminal event: drop what never finished, settle the last reasoning run, and add the neutral line
        when removals left nothing else (A.4). The neutral line goes before a trailing reasoning run, so its numbers
        fit between the last event sent and that run."""
        for entry in self._items.values():
            if entry.state == "held" and entry.kind != "reasoning":
                self._drop(entry)
        if self._turn_items:
            self._close_turn()
        trailing, self._run = self._run, []
        if self._removed and not any(e.kind in ("message", "function_call") for e in self._released):
            bounds = [n for n in [terminal_seq, *(e.seq for r in trailing for e in r.events[:1])] if n is not None]
            yield from self._neutral(min(bounds) if bounds else self._last_emitted + 4)
        for reasoning in trailing:
            yield from self._release(reasoning)

    def _neutral(self, ceiling: int) -> Iterator[bytes]:
        """The neutral line as one assistant message, numbered strictly between the last event sent and ceiling. Its
        added item already holds an empty text part, so a delta can follow without a content_part event."""
        item = neutral_message()
        entry = _Item(-1, "message", final=item, state="released", client=len(self._released))
        self._released.append(entry)
        where = {"item_id": item["id"], "output_index": entry.client}
        added = {"type": "response.output_item.added", "output_index": entry.client,
                 "item": {**item, "status": "in_progress",
                          "content": [{"type": "output_text", "text": "", "annotations": []}]}}
        delta = {"type": "response.output_text.delta", **where, "content_index": 0, "delta": NEUTRAL_LINE,
                 "logprobs": []}
        done = {"type": _DONE, "output_index": entry.client, "item": item}
        free = list(range(self._last_emitted + 1, ceiling))
        plan = [added, delta, done] if len(free) >= 3 else [added, delta] if len(free) == 2 else [delta]
        for data, number in zip(plan, free or [self._last_emitted + 1]):
            self._last_emitted = number
            yield _frame(data["type"], {**data, "sequence_number": number})

    def _with_output(self, event: _Event, *, terminal: bool) -> bytes:
        """A lifecycle or terminal event whose response lists exactly the items streamed so far."""
        self._last_emitted = max(self._last_emitted, event.seq)
        response = event.data.get("response")
        if not isinstance(response, dict):
            if terminal:
                raise _Unreadable("upstream_unparseable", "terminal_without_response")
            return event.raw
        edited = [e.final for e in self._released if e.final is not None]
        upstream = response.get("output")
        if terminal and isinstance(upstream, list):
            extra = [i for i in upstream if i not in edited and i not in self._removed and i not in self._replaced]
            if extra:
                # The terminal event lists items the stream never carried. Only what was gated and streamed goes out.
                self._audit("upstream_error", cause="upstream_unparseable", detail="terminal_lists_unstreamed_items",
                            mode=self._mode, stream=True, **self._fields)
        if upstream == edited:
            return event.raw
        return _frame(event.type, {**event.data, "response": {**response, "output": edited}})


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
