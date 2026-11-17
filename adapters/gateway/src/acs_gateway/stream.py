"""Governed streaming: a Responses API event stream edited so a tool call reaches the client only once it is decided.

Issue #578, Appendix B WP2. Text streams as it arrives. Each function_call, and each output item outside the
allowlist, is held whole until decide() answers, then released as it came, rewritten, or removed. Events keep their
sequence_number, so a removed event leaves a gap the client accepts (PREMORTEM P21), and output_index follows the
edited output, so response.completed lists exactly what was streamed and an accumulating client (openai's
responses.stream()) never indexes past its snapshot.
"""
from __future__ import annotations

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
# Output items that stream as they arrive in enforce. Reasoning waits for its turn, and everything else is held.
_STREAMED = frozenset({"message", "reasoning"})
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


class _Unreadable(Exception):
    def __init__(self, cause: str, detail: str) -> None:
        super().__init__(detail)
        self.cause, self.detail = cause, detail


class _UpstreamFailed(Exception):
    """Reading the upstream failed, as distinct from a fault in the editor itself."""


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


@dataclass
class _Item:
    index: int
    kind: str
    events: list[_Event] = field(default_factory=list)
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
    the item to deliver or None to remove it. Shadow (enforce=False) relays every byte unchanged and calls decide only
    to record. limit bounds both a partial event and the bytes held back at once.
    """

    def __init__(self, *, enforce: bool, limit: int, decide: Callable[[dict[str, Any]], Awaitable[dict[str, Any] | None]],
                 audit: Callable[..., None], audit_fields: dict[str, Any] | None = None) -> None:
        self.enforce, self.limit, self.decide, self._audit = enforce, limit, decide, audit
        self._fields = audit_fields or {}
        self._items: dict[int, _Item] = {}
        self._run: list[_Item] = []
        self._turn_items, self._turn_kept = 0, False
        self._released: list[_Item] = []
        self._removed: list[dict[str, Any]] = []
        self._dropped: list[int] = []
        self._held_bytes = 0
        self._last_emitted = -1
        self._max_seq = -1
        # _finished: enforce has sent its last event. _terminal: the upstream sent its terminal event.
        self._finished = False
        self._terminal = False
        self._relay_raw = False

    async def edit(self, chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        buffer = b""
        try:
            async for chunk in _read(chunks):
                if self._relay_raw:
                    yield chunk
                    continue
                buffer += chunk
                while not self._relay_raw and not self._finished and (match := _BOUNDARY.search(buffer)):
                    raw, buffer = buffer[:match.end()], buffer[match.end():]
                    try:
                        async for out in self._event(raw):
                            yield out
                    except _Unreadable as e:
                        async for out in self._unreadable(e, raw + buffer):
                            yield out
                        buffer = b""
                if self._finished:
                    return
                if self._relay_raw:
                    if buffer:
                        yield buffer
                        buffer = b""
                elif len(buffer) > self.limit:
                    async for out in self._unreadable(_Unreadable("upstream_too_large", "event_too_large"), buffer):
                        yield out
                    buffer = b""
                    if self._finished:
                        return
            if self._relay_raw or self._terminal:
                if buffer and not self._finished:
                    yield buffer
                return
            # The upstream ended without a terminal event. Held items were never finished, so nothing of them goes out.
            async for out in self._unreadable(_Unreadable("upstream_unparseable", "stream_ended_early"), buffer):
                yield out
        except _UpstreamFailed as e:
            self._audit("upstream_error", cause="upstream_unreachable", error=type(e.__cause__).__name__,
                        **self._fields)
            if not self._finished:
                yield error_event(self._max_seq + 1)
        except Exception as e:  # noqa: BLE001
            # A fault in the editor itself. The stream ends cleanly rather than hanging or leaking a held call.
            self._audit("gateway_step_error", phase="stream", mode=self._mode, error=f"{type(e).__name__}: {e}",
                        **self._fields)
            if not self._finished:
                yield error_event(self._max_seq + 1)

    @property
    def _mode(self) -> str:
        return "enforce" if self.enforce else "shadow"

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
        if event.type in _TERMINAL:
            self._terminal = True
        if not self.enforce:
            # Read before relaying, so a malformed item is relayed once, as part of the rest.
            item = _item_of(event) if event.type == "response.output_item.done" else None
            yield raw
            if item is not None and item_type(item) not in _STREAMED:
                await self._decided(item)
            return
        kind = event.type
        if kind in _LIFECYCLE:
            yield self._with_output(event, terminal=False)
            return
        if kind in _TERMINAL:
            for out in self._close():
                yield out
            yield self._with_output(event, terminal=True)
            self._finished = True
            return
        if kind == "error":
            yield raw
            return
        index = event.data.get("output_index")
        if not isinstance(index, int) or isinstance(index, bool):
            raise _Unreadable("upstream_unparseable", "event_without_output_index")
        if kind == "response.output_item.added":
            for out in self._added(event, index):
                yield out
            return
        entry = self._items.get(index)
        if entry is None:
            raise _Unreadable("upstream_unparseable", "output_index_unannounced")
        if kind == "response.output_item.done":
            entry.final = _item_of(event)
        if entry.state == "dropped":
            self._drop_event(event)
            return
        if entry.state == "released":
            yield self._emit(event, entry)
            return
        self._hold(entry, event)
        if kind == "response.output_item.done" and entry.kind != "reasoning":
            kept = await self._decided(entry.final)
            if kept is None:
                self._drop(entry)
            else:
                for out in self._keep(entry, kept):
                    yield out

    def _added(self, event: _Event, index: int) -> Iterator[bytes]:
        if index in self._items:
            raise _Unreadable("upstream_unparseable", "output_index_repeated")
        entry = _Item(index, item_type(_item_of(event)))
        self._items[index] = entry
        if entry.kind == "reasoning":
            if self._turn_items:
                self._close_turn()
            self._run.append(entry)
            self._hold(entry, event)
            return
        self._turn_items += 1
        self._hold(entry, event)
        if entry.kind == "message":
            yield from self._keep(entry, None)

    async def _decided(self, item: dict[str, Any]) -> dict[str, Any] | None:
        try:
            kept = await self.decide(item)
        except Exception as e:  # noqa: BLE001
            # Fail closed: a fault while gating removes the call in enforce, and shadow only records it.
            self._audit("gateway_step_error", phase="stream_output", mode=self._mode,
                        error=f"{type(e).__name__}: {e}", **self._fields)
            return None if self.enforce else item
        return kept if self.enforce else item

    def _hold(self, entry: _Item, event: _Event) -> None:
        entry.events.append(event)
        self._held_bytes += len(event.raw)
        if self._held_bytes > self.limit:
            raise _Unreadable("upstream_too_large", "held_item_too_large")

    def _unhold(self, entry: _Item) -> None:
        self._held_bytes -= sum(len(e.raw) for e in entry.events)

    def _drop_event(self, event: _Event) -> None:
        if event.seq is not None:
            self._dropped.append(event.seq)

    def _drop(self, entry: _Item) -> None:
        """Remove an item: none of its events reach the client, and their numbers are free for the neutral line."""
        if entry.state == "held":
            self._unhold(entry)
        entry.state = "dropped"
        for event in entry.events:
            self._drop_event(event)
        entry.events = []
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
            yield from self._release(reasoning, None)
        self._run = []
        yield from self._release(entry, kept)

    def _release(self, entry: _Item, kept: dict[str, Any] | None) -> Iterator[bytes]:
        self._unhold(entry)
        entry.state, entry.client = "released", len(self._released)
        self._released.append(entry)
        events, entry.events = entry.events, []
        if kept is None or kept == entry.final:
            for event in events:
                yield self._emit(event, entry)
            return
        entry.final = kept
        yield from self._rewritten(entry, events, kept)

    def _rewritten(self, entry: _Item, events: list[_Event], kept: dict[str, Any]) -> Iterator[bytes]:
        """A modified call: its argument deltas collapse into one delta carrying the new arguments, numbered as the
        first delta was, and every event that named the old arguments names the new ones."""
        arguments = kept.get("arguments", "")
        deltas = [e for e in events if e.type == "response.function_call_arguments.delta"]
        for event in events:
            if event.type == "response.output_item.added":
                yield self._emit(event, entry, item={**_item_of(event), "arguments": "" if deltas else arguments})
            elif deltas and event is deltas[0]:
                yield self._emit(event, entry, delta=arguments)
            elif event.type == "response.function_call_arguments.done":
                yield self._emit(event, entry, arguments=arguments)
            elif event.type == "response.output_item.done":
                yield self._emit(event, entry, item=kept)
            else:
                self._drop_event(event)

    def _emit(self, event: _Event, entry: _Item, **changes: Any) -> bytes:
        if event.seq is not None:
            self._last_emitted = max(self._last_emitted, event.seq)
        if not changes and event.data.get("output_index") == entry.client:
            return event.raw
        return _frame(event.type, {**event.data, "output_index": entry.client, **changes})

    def _close(self) -> Iterator[bytes]:
        """Before the terminal event: drop what never finished, settle the last reasoning run, and add the neutral line
        when removals left nothing else (A.4)."""
        for entry in self._items.values():
            if entry.state == "held" and entry.kind != "reasoning":
                self._drop(entry)
        if self._turn_items:
            self._close_turn()
        for reasoning in self._run:
            # A run with nothing after it stays.
            yield from self._release(reasoning, None)
        self._run = []
        if self._removed and not any(e.kind in ("message", "function_call") for e in self._released):
            yield from self._neutral()

    def _neutral(self) -> Iterator[bytes]:
        item = neutral_message()
        entry = _Item(-1, "message", final=item, state="released", client=len(self._released))
        self._released.append(entry)
        where = {"item_id": item["id"], "output_index": entry.client}
        part = {"type": "output_text", "text": "", "annotations": []}
        events = [{"type": "response.output_item.added", "output_index": entry.client,
                   "item": {**item, "status": "in_progress", "content": []}},
                  {"type": "response.content_part.added", **where, "content_index": 0, "part": part},
                  {"type": "response.output_text.delta", **where, "content_index": 0, "delta": NEUTRAL_LINE,
                   "logprobs": []},
                  {"type": "response.output_item.done", "output_index": entry.client, "item": item}]
        for data, number in zip(events, self._numbers(len(events))):
            self._last_emitted = max(self._last_emitted, number)
            yield _frame(data["type"], {**data, "sequence_number": number})

    def _numbers(self, count: int) -> list[int]:
        """Numbers of dropped events for inserted ones, the ones after the last event sent first, so the client still
        sees sequence_number rise. A stream that dropped too few repeats its last number."""
        later = sorted(n for n in set(self._dropped) if n > self._last_emitted)
        earlier = sorted(n for n in set(self._dropped) if n <= self._last_emitted)
        numbers = (later + earlier)[:count]
        while len(numbers) < count:
            numbers.append(numbers[-1] if numbers else self._last_emitted)
        return numbers

    def _with_output(self, event: _Event, *, terminal: bool) -> bytes:
        """A lifecycle or terminal event whose response lists exactly the items streamed so far."""
        response = event.data.get("response")
        if not isinstance(response, dict):
            if terminal:
                raise _Unreadable("upstream_unparseable", "terminal_without_response")
            return event.raw
        edited = [e.final for e in self._released if e.final is not None]
        upstream = response.get("output")
        if terminal and isinstance(upstream, list):
            extra = [i for i in upstream if i not in edited and i not in self._removed]
            if extra:
                # The terminal event lists items the stream never carried. Only what was gated and streamed goes out.
                self._audit("upstream_error", cause="upstream_unparseable", detail="terminal_lists_unstreamed_items",
                            mode=self._mode, stream=True, **self._fields)
        if upstream == edited:
            return event.raw
        return _frame(event.type, {**event.data, "response": {**response, "output": edited}})


async def _read(chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    try:
        async for chunk in chunks:
            yield chunk
    except Exception as e:  # noqa: BLE001
        raise _UpstreamFailed(str(e)) from e


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
