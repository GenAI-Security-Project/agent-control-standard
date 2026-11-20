"""Fake Anthropic Messages (/v1/messages) server that truncates a tool call.

The sibling of `server.py`, for clients that speak the Anthropic wire format
instead of Chat Completions. Same scenario, same mode vocabulary, same idea:
the "model" asks for one file write with 40 lines of content, and the call
arrives cut in the middle of line 17.

  complete  full arguments, the stream ends with stop_reason=end_turn
            (control: proves execution can be observed at all)
  length    arguments cut mid-line, stream ends with stop_reason=max_tokens
  drop      arguments cut mid-line, then the HTTP body ends cleanly: no
            message_delta, no message_stop
  reset     arguments cut mid-line, then the TCP connection is closed without
            finishing the chunked body (transport error)

Turn 2+ (the request carries a tool_result block) answers "Done." and stops.

URL layout:  http://127.0.0.1:PORT/<mode>/v1/messages
Every request is appended as one JSON line to the file named by $BENCH_LOG.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODES = ("complete", "length", "drop", "reset", "loop")
TARGET_NAME = "report.txt"
LINES = [f"line {i:02d}: the quick brown fox jumps over the lazy dog" for i in range(1, 41)]
CONTENT = "\n".join(LINES) + "\n"
CUT_LINE = 17  # truncation happens inside this line
CUT_MARKER = f"line {CUT_LINE:02d}: the quick"

# Claude Code's built-in tools; any other client offering none of these still gets
# the first name it sent, so a recording of what it did is never lost.
PREFERRED_TOOLS = ("Write", "Bash", "Edit")

# loop: how many times the same call is offered again before the stub gives up.
MAX_LOOP_TURNS = 4
_loop_turns = 0


def pick_tool(names: list[str]) -> str:
    for cand in PREFERRED_TOOLS:
        if cand in names:
            return cand
    return names[0] if names else "Write"


def args_for(tool: str) -> str:
    if tool == "Write":
        return json.dumps({"file_path": TARGET_NAME, "content": CONTENT})
    if tool == "Bash":
        return json.dumps({"command": f"cat > {TARGET_NAME} <<'EOF'\n{CONTENT}EOF",
                           "description": "write the report"})
    if tool == "Edit":
        return json.dumps({"file_path": TARGET_NAME, "old_string": "", "new_string": CONTENT})
    return json.dumps({"path": TARGET_NAME, "content": CONTENT})


def cut(args: str) -> str:
    """Cut the serialized arguments in the middle of line CUT_LINE."""
    return args[: args.index(CUT_MARKER) + len(CUT_MARKER)]


def sse(event: str, data: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def tool_names_of(body: dict) -> list[str]:
    return [t.get("name", "") for t in (body.get("tools") or []) if isinstance(t, dict)]


def tool_result_text(body: dict) -> str:
    """The client's own verdict on the call, as it echoed it back: the only record of a call
    that never reached the Guardian."""
    for m in body.get("messages") or []:
        c = m.get("content")
        if not isinstance(c, list):
            continue
        for b in c:
            if isinstance(b, dict) and b.get("type") == "tool_result":
                inner = b.get("content")
                if isinstance(inner, list):
                    parts = [x.get("text", "") for x in inner if isinstance(x, dict)]
                    return " ".join(parts)[:1200]
                return str(inner)[:1200]
    return ""


def has_tool_result(body: dict) -> bool:
    for m in body.get("messages") or []:
        c = m.get("content")
        if isinstance(c, list) and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c):
            return True
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # one line per request goes to $BENCH_LOG instead
        pass

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            body = json.dumps({"data": [{"id": "bench-model", "object": "model"}], "has_more": False}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        mode = parts[0] if parts and parts[0] in MODES else "complete"
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}
        names = tool_names_of(body)
        follow_up = has_tool_result(body)
        tool = pick_tool(names)
        self._log({"t": round(time.time(), 3), "mode": mode, "path": self.path, "bytes": len(raw),
                   "endpoint": "messages" if "/v1/messages" in self.path else "other",
                   "stream": bool(body.get("stream")), "turn": "after_tool_result" if follow_up else "first",
                   "tools_offered": names, "tool_called": None if follow_up else tool,
                   "model": body.get("model"), "tool_result": tool_result_text(body)})
        if "/v1/messages" not in self.path:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for chunk in self._events(mode, follow_up, tool):
                if chunk is None:  # reset: stop writing and drop the socket
                    self._hard_close()
                    return
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        self.close_connection = True

    def _hard_close(self) -> None:
        try:
            self.wfile.flush()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       socket.pack("ii", 1, 0))
            self.connection.close()
        except Exception:  # noqa: BLE001
            pass
        self.close_connection = True

    def _log(self, rec: dict) -> None:
        path = os.environ.get("BENCH_LOG")
        if not path:
            return
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _events(self, mode: str, follow_up: bool, tool: str):
        yield sse("message_start", {"type": "message_start", "message": {
            "id": "msg_bench", "type": "message", "role": "assistant", "model": "bench-model",
            "content": [], "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 12, "output_tokens": 1}}})
        global _loop_turns
        again = False
        if follow_up and mode == "loop":
            _loop_turns += 1
            again = _loop_turns <= MAX_LOOP_TURNS
        if follow_up and not again:
            yield sse("content_block_start", {"type": "content_block_start", "index": 0,
                                              "content_block": {"type": "text", "text": ""}})
            yield sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                              "delta": {"type": "text_delta", "text": "Done."}})
            yield sse("content_block_stop", {"type": "content_block_stop", "index": 0})
            yield sse("message_delta", {"type": "message_delta",
                                        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                        "usage": {"output_tokens": 3}})
            yield sse("message_stop", {"type": "message_stop"})
            if not again:
                return
        yield sse("content_block_start", {"type": "content_block_start", "index": 0,
                                          "content_block": {"type": "tool_use", "id": f"toolu_bench{_loop_turns}",
                                                            "name": tool, "input": {}}})
        args = args_for(tool)
        # loop repeats a *valid* call; only the truncating modes cut the arguments.
        payload = args if mode in ("complete", "loop") else cut(args)
        for i in range(0, len(payload), 24):
            yield sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                              "delta": {"type": "input_json_delta",
                                                        "partial_json": payload[i:i + 24]}})
        if mode == "reset":
            yield None
            return
        if mode == "drop":
            return  # body ends here: no content_block_stop, no message_delta, no message_stop
        yield sse("content_block_stop", {"type": "content_block_stop", "index": 0})
        stop = "end_turn" if mode == "complete" else "max_tokens"
        yield sse("message_delta", {"type": "message_delta",
                                    "delta": {"stop_reason": stop, "stop_sequence": None},
                                    "usage": {"output_tokens": 40}})
        yield sse("message_stop", {"type": "message_stop"})


def main(argv: list[str]) -> int:
    port = int(argv[1]) if len(argv) > 1 else 8766
    print(f"listening on 127.0.0.1:{port}  log={os.environ.get('BENCH_LOG', '(unset)')}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
