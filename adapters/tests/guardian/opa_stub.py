"""A stand-in OPA server for the Guardian's OPA backend tests, so no `opa` binary is needed.

It answers POST with a canned verdict, or with a chosen status, body, or delay, and records every
request body it receives. Each test starts its own, on a port the OS picks.
"""
from __future__ import annotations

import http.server
import json
import socket
import threading
import time
from typing import Any


class StubOpa:
    """Serve `{"result": verdict}`, or `body` verbatim when given, after `delay_s`, with `status`.

    With `dribble_s` the headers go out at once and the body follows one byte every `dribble_s` seconds.
    `client_closed` is set when a write fails because the client hung up.
    """

    def __init__(self, verdict: Any = None, *, status: int = 200, body: bytes | None = None,
                 delay_s: float = 0.0, dribble_s: float = 0.0) -> None:
        self.verdict = verdict
        self.status = status
        self.body = body
        self.delay_s = delay_s
        self.dribble_s = dribble_s
        self.client_closed = threading.Event()
        self.inputs: list[Any] = []
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                stub.inputs.append(json.loads(self.rfile.read(length) or b"null"))
                if stub.delay_s:
                    time.sleep(stub.delay_s)
                payload = stub.body if stub.body is not None else json.dumps({"result": stub.verdict}).encode()
                try:
                    self.send_response(stub.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    if not stub.dribble_s:
                        self.wfile.write(payload)
                        return
                    for i in range(len(payload)):
                        self.wfile.write(payload[i:i + 1])
                        self.wfile.flush()
                        time.sleep(stub.dribble_s)
                except OSError:
                    # The client gave up on a delayed or dribbled answer and closed the socket.
                    stub.client_closed.set()

            def log_message(self, *args: Any) -> None:
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}/v1/data/lab/verdict"

    def __enter__(self) -> "StubOpa":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()


def closed_port_url() -> str:
    """A URL on a port nothing listens on, for the OPA-down case."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}/v1/data/lab/verdict"
