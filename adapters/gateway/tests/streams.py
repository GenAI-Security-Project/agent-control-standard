"""Builders for Responses API event streams, with the full event set a model emits for each kind of output item."""
from __future__ import annotations

import json
from typing import Any

from conftest import call_item, message_item, response_body


def reasoning_item(summary: str, item_id: str = "rs_1") -> dict[str, Any]:
    return {"type": "reasoning", "id": item_id, "summary": [{"type": "summary_text", "text": summary}]}


def hosted_item(item_id: str = "ws_1") -> dict[str, Any]:
    return {"type": "web_search_call", "id": item_id, "status": "completed",
            "action": {"type": "search", "query": "vendor bank"}}


def _halves(text: str) -> list[str]:
    middle = max(1, len(text) // 2)
    return [part for part in (text[:middle], text[middle:]) if part]


def item_events(item: dict[str, Any], index: int) -> list[dict[str, Any]]:
    """The events a model streams for one finished output item, without sequence numbers."""
    kind, item_id = item["type"], item["id"]
    where = {"item_id": item_id, "output_index": index}
    if kind == "message":
        text = item["content"][0]["text"]
        part = {"type": "output_text", "text": "", "annotations": []}
        middle = [{"type": "response.output_text.delta", **where, "content_index": 0, "delta": d, "logprobs": []}
                  for d in _halves(text)]
        return [{"type": "response.output_item.added", "output_index": index,
                 "item": {**item, "status": "in_progress", "content": []}},
                {"type": "response.content_part.added", **where, "content_index": 0, "part": part},
                *middle,
                {"type": "response.output_text.done", **where, "content_index": 0, "text": text, "logprobs": []},
                {"type": "response.content_part.done", **where, "content_index": 0, "part": {**part, "text": text}},
                {"type": "response.output_item.done", "output_index": index, "item": item}]
    if kind == "function_call":
        deltas = [{"type": "response.function_call_arguments.delta", **where, "delta": d}
                  for d in _halves(item["arguments"])]
        return [{"type": "response.output_item.added", "output_index": index,
                 "item": {**item, "status": "in_progress", "arguments": ""}},
                *deltas,
                {"type": "response.function_call_arguments.done", **where, "name": item["name"],
                 "arguments": item["arguments"]},
                {"type": "response.output_item.done", "output_index": index, "item": item}]
    if kind == "reasoning":
        text = item["summary"][0]["text"]
        part = {"type": "summary_text", "text": ""}
        return [{"type": "response.output_item.added", "output_index": index, "item": {**item, "summary": []}},
                {"type": "response.content_part.added", **where, "content_index": 0,
                 "part": {"type": "reasoning_text", "text": ""}},
                {"type": "response.reasoning_text.delta", **where, "content_index": 0, "delta": "private"},
                {"type": "response.content_part.done", **where, "content_index": 0,
                 "part": {"type": "reasoning_text", "text": "private"}},
                {"type": "response.reasoning_summary_part.added", **where, "summary_index": 0, "part": part},
                {"type": "response.reasoning_summary_text.delta", **where, "summary_index": 0, "delta": text},
                {"type": "response.reasoning_summary_text.done", **where, "summary_index": 0, "text": text},
                {"type": "response.reasoning_summary_part.done", **where, "summary_index": 0,
                 "part": {**part, "text": text}},
                {"type": "response.output_item.done", "output_index": index, "item": item}]
    return [{"type": "response.output_item.added", "output_index": index, "item": {**item, "status": "in_progress"}},
            {"type": f"response.{kind}.in_progress", **where},
            {"type": f"response.{kind}.searching", **where},
            {"type": f"response.{kind}.completed", **where},
            {"type": "response.output_item.done", "output_index": index, "item": item}]


def stream_events(*items: dict[str, Any], terminal: str = "response.completed",
                  completed_output: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """A whole stream: created, in_progress, each item's events, then the terminal event, numbered from 0."""
    output = list(items) if completed_output is None else completed_output
    status = {"response.completed": "completed", "response.incomplete": "incomplete",
              "response.failed": "failed"}[terminal]
    events = [{"type": "response.created", "response": {**response_body(), "status": "in_progress"}},
              {"type": "response.in_progress", "response": {**response_body(), "status": "in_progress"}}]
    for index, item in enumerate(items):
        events += item_events(item, index)
    events.append({"type": terminal, "response": {**response_body(*output), "status": status}})
    return [{**event, "sequence_number": n} for n, event in enumerate(events)]


def encode(events: list[dict[str, Any]]) -> list[bytes]:
    return [f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events]


def decode(raw: bytes) -> list[dict[str, Any]]:
    """Every data payload in an SSE byte stream, in order."""
    events = []
    for block in raw.replace(b"\r\n", b"\n").split(b"\n\n"):
        data = [line[5:].strip() for line in block.split(b"\n") if line.startswith(b"data:")]
        if data:
            events.append(json.loads(b"\n".join(data)))
    return events


def rebuilt_output(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The output a client builds from output_item.done events, placed by output_index."""
    done = {e["output_index"]: e["item"] for e in events if e["type"] == "response.output_item.done"}
    return [done[i] for i in sorted(done)]


__all__ = ["call_item", "decode", "encode", "hosted_item", "item_events", "message_item", "reasoning_item",
           "rebuilt_output", "stream_events"]
