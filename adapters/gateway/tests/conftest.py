"""Shared fixtures: a fake Responses API upstream, the example Guardian on a free port, and a gateway under test."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

# acs.client resolves its state directories on import, so the gateway's are set before anything imports it.
_BASE = Path(tempfile.mkdtemp(prefix="acs-gateway-tests-"))
os.environ["ACS_GATEWAY_STATE_DIR"] = str(_BASE / "state")
os.environ.pop("ACS_SESSION_STATE_DIR", None)
os.environ.pop("ACS_HANDSHAKE_CACHE", None)
from acs_gateway.config import prepare_state_dirs  # noqa: E402

prepare_state_dirs(os.environ)
os.environ["ACS_HMAC_SECRET"] = "lab-test-secret-" + "0123456789abcdef" * 2
os.environ["ACS_HMAC_KEY_ID"] = "lab"
for _name in ("ACS_LAB_MODE", "ACS_AUDIT_FILE", "ACS_DEFAULT_DENY", "ACS_STARTUP_POSTURE", "ACS_DISABLED"):
    os.environ.pop(_name, None)

HERE = Path(__file__).parent
NEUTRAL = "I couldn't complete that action."


def response_body(*items: dict[str, Any], response_id: str = "resp_test1") -> dict[str, Any]:
    """A non-streamed Responses API body shaped like the ones FinBot's SDK parses."""
    return {"id": response_id, "object": "response", "created_at": 1763300000, "status": "completed",
            "model": "gpt-5-nano", "output": list(items), "parallel_tool_calls": True, "tool_choice": "auto",
            "tools": [], "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}}


def message_item(text: str, item_id: str = "msg_1") -> dict[str, Any]:
    return {"type": "message", "id": item_id, "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []}]}


def call_item(name: str, arguments: dict[str, Any] | str, call_id: str, item_id: str | None = None) -> dict[str, Any]:
    args = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return {"type": "function_call", "id": item_id or f"fc_{call_id}", "call_id": call_id, "name": name,
            "arguments": args, "status": "completed"}


def finbot_request(*extra: dict[str, Any], system: str = "You are FinBot for ns1.", user: str = "Pay vendor 7") -> dict[str, Any]:
    """The body FinBot's OpenAIClient.chat sends: system and user messages, then resent history."""
    return {"model": "gpt-5-nano", "input": [{"role": "system", "content": system},
                                              {"role": "user", "content": user}, *extra],
            "max_output_tokens": 5000, "tools": [{"type": "function", "name": "get_vendor_details",
                                                   "description": "Look up a vendor", "parameters": {"type": "object"}}]}


@dataclass
class SSE:
    """A streamed reply: each entry is written and flushed on its own, like a model emitting events. hold_open keeps
    the connection open that many seconds after the last event, like an upstream that never closes."""
    events: list[bytes]
    hold_open: float = 0.0


def sse_events(text: str) -> list[bytes]:
    """The Responses API events FinBot's chat reads, for one assistant message carrying text."""
    item = message_item(text)
    events = [("response.created", {"type": "response.created", "sequence_number": 0,
                                    "response": {**response_body(), "status": "in_progress"}}),
              ("response.output_text.delta", {"type": "response.output_text.delta", "sequence_number": 1,
                                              "item_id": item["id"], "output_index": 0, "content_index": 0,
                                              "delta": text, "logprobs": []}),
              ("response.output_item.done", {"type": "response.output_item.done", "sequence_number": 2,
                                             "output_index": 0, "item": item}),
              ("response.completed", {"type": "response.completed", "sequence_number": 3,
                                      "response": response_body(item)})]
    return [f"event: {name}\ndata: {json.dumps(data)}\n\n".encode() for name, data in events]


@dataclass
class Received:
    path: str
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


@dataclass
class FakeUpstream:
    url: str
    received: list[Received] = field(default_factory=list)
    replies: list[tuple[int, Any, dict[str, str], float]] = field(default_factory=list)

    def reply(self, body: Any, status: int = 200, headers: dict[str, str] | None = None, delay: float = 0.0) -> None:
        """Queue the answer to the next request. delay holds it back, so a later request can finish first."""
        self.replies.append((status, body, headers or {}, delay))


@pytest.fixture
def upstream() -> Iterator[FakeUpstream]:
    state = FakeUpstream(url="")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            state.received.append(Received(self.path, {k.lower(): v for k, v in self.headers.items()}, body))
            status, reply, extra, delay = (state.replies.pop(0) if state.replies
                                           else (200, response_body(message_item("ok")), {}, 0.0))
            time.sleep(delay)
            if isinstance(reply, SSE):
                self.send_response(status)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("x-request-id", "req_upstream_1")
                self.end_headers()
                for event in reply.events:
                    self.wfile.write(event)
                    self.wfile.flush()
                time.sleep(reply.hold_open)
                self.close_connection = True
                return
            raw = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("x-request-id", "req_upstream_1")
            for name, value in extra.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.url = f"http://127.0.0.1:{server.server_address[1]}/v1"
    yield state
    server.shutdown()
    server.server_close()


def _start_guardian(argv: list[str], env: dict[str, str], state_dir: Path) -> tuple[subprocess.Popen, str]:
    proc_env = {**os.environ, "ACS_GUARDIAN_STATE_DIR": str(state_dir), **env}
    proc = subprocess.Popen([*argv, "--port", "0"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=proc_env, text=True)
    deadline = time.monotonic() + 20
    line = ""
    while time.monotonic() < deadline:
        line = proc.stdout.readline() if proc.stdout else ""
        if line.startswith("ACS_GUARDIAN_LISTENING"):
            port = line.strip().split("port=")[1]
            return proc, f"http://127.0.0.1:{port}/"
        if proc.poll() is not None:
            break
    proc.kill()
    raise RuntimeError(f"Guardian did not start: {line!r}")


@pytest.fixture
def guardian(tmp_path) -> Iterator[str]:
    """The unmodified example Guardian from acs-adapters, default backend."""
    proc, url = _start_guardian([sys.executable, "-m", "acs.guardian.example_guardian"], {}, tmp_path / "guardian")
    yield url
    proc.kill()
    proc.wait()


@pytest.fixture
def harness_guardian(tmp_path) -> Iterator[Callable[..., str]]:
    """The example Guardian with test-only policy hooks (tests/guardian_harness.py). Call it with env overrides."""
    procs: list[subprocess.Popen] = []

    def start(**env: str) -> str:
        proc, url = _start_guardian([sys.executable, str(HERE / "guardian_harness.py")], env,
                                    tmp_path / f"guardian{len(procs)}")
        procs.append(proc)
        return url

    yield start
    for proc in procs:
        proc.kill()
        proc.wait()


@pytest.fixture
def audit(tmp_path, monkeypatch) -> Callable[[], list[dict[str, Any]]]:
    path = tmp_path / "audit.log"
    monkeypatch.setenv("ACS_AUDIT_FILE", str(path))

    def lines() -> list[dict[str, Any]]:
        if not path.exists():
            return []
        return [json.loads(line.split(" ", 1)[1]) for line in path.read_text().splitlines()]

    return lines


@pytest.fixture
def gateway(tmp_path, upstream) -> Iterator[Callable[..., Any]]:
    """Build a gateway over the fake upstream and return a started Starlette TestClient."""
    from starlette.testclient import TestClient

    from acs_gateway.app import create_app
    from acs_gateway.config import GatewayConfig

    clients: list[Any] = []

    def make(**env: str) -> Any:
        base = {"ACS_UPSTREAM_URL": upstream.url, "ACS_GATEWAY_STATE_DIR": os.environ["ACS_GATEWAY_STATE_DIR"],
                "ACS_TRANSCRIPT_DIR": str(tmp_path / "transcripts"),
                "ACS_MODEL_INPUT_LOG": str(tmp_path / "model-inputs.jsonl"), "ACS_GUARDIAN_READY_TIMEOUT_S": "5"}
        client = TestClient(create_app(GatewayConfig.from_env({**base, **env})), raise_server_exceptions=True)
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.__exit__(None, None, None)


def transcript_lines(tmp_path: Path) -> list[dict[str, Any]]:
    lines: list[dict[str, Any]] = []
    directory = tmp_path / "transcripts"
    if directory.exists():
        for path in sorted(directory.glob("*.jsonl")):
            lines += [json.loads(line) for line in path.read_text().splitlines()]
    return lines
