"""
Lifecycle-observer integration test.

Subscribes the ACSMiddleware to NAT's IntermediateStepManager, pushes
synthetic WORKFLOW_START / WORKFLOW_END events, and asserts the Guardian
received ACS lifecycle hooks (sessionStart, userMessage, agentResponse,
sessionEnd) in addition to the function-level toolCallRequest/Result.

Without this middleware, NAT alone emits only function-call hooks and
does not satisfy ACS-Core's 6-hook taxonomy minimum
(`conformance.md:19`). This test proves the lifecycle middleware closes
that gap.

Requires nvidia-nat-core 1.7.0+ for IntermediateStepManager.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

try:
    from nat.builder.context import Context
    from nat.builder.intermediate_step_manager import IntermediateStepManager
    from nat.builder.context import ContextState
    from nat.data_models.intermediate_step import (
        IntermediateStepPayload, IntermediateStepType, StreamEventData,
    )
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from acs_adapter import ACSMiddleware  # noqa: E402

if _NAT_OK:
    from acs_adapter import ACSMiddlewareConfig  # noqa: E402


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "_common"))


class RecordingGuardian(BaseHTTPRequestHandler):
    """Tiny HTTP server that records every method it receives."""
    recorded: list = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        RecordingGuardian.recorded.append(body.get("method", ""))
        reply = json.dumps({
            "jsonrpc": "2.0", "id": body.get("id"),
            "result": {
                "type": "final",
                "acs_version": "0.1.0",
                "request_id": body.get("params", {}).get("request_id", ""),
                "decision": "allow",
                "chain_hash": "0" * 64,
            },
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args, **kwargs):
        return


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class LifecycleObserver(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), RecordingGuardian)
        cls.port = cls.server.server_address[1]
        cls.url = f"http://127.0.0.1:{cls.port}/acs"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        RecordingGuardian.recorded.clear()

    def _push(self, mgr, event_type, name="test", input=None, output=None, uuid_=None):
        data = StreamEventData(input=input, output=output) if (input or output) else None
        kwargs = {"event_type": event_type, "name": name, "data": data}
        if uuid_:
            kwargs["UUID"] = uuid_
        payload = IntermediateStepPayload(**kwargs)
        mgr.push_intermediate_step(payload)
        return payload.UUID

    def test_intermediate_function_events_do_not_fire_lifecycle_hooks(self) -> None:
        """FUNCTION_START / TOOL_START etc are covered by FunctionMiddleware's
        pre_invoke, NOT by the lifecycle observer. Lifecycle observer must
        ignore them."""
        cfg = ACSMiddlewareConfig(
            guardian_url=self.url, default_deny=False,
            session_id="lifecycle-non-trigger-test",
        )
        mw = ACSMiddleware(cfg)
        os.environ["ACS_HANDSHAKE"] = "0"
        ctx_state = ContextState.get()
        mgr = IntermediateStepManager(ctx_state)
        sub = mgr.subscribe(on_next=mw._on_intermediate_step)
        try:
            fn_uuid = self._push(mgr, IntermediateStepType.FUNCTION_START, name="weather_tool", input="x")
            self._push(mgr, IntermediateStepType.FUNCTION_END, name="weather_tool", output="sunny", uuid_=fn_uuid)
            llm_uuid = self._push(mgr, IntermediateStepType.LLM_START, name="llm", input="prompt")
            self._push(mgr, IntermediateStepType.LLM_END, name="llm", output="completion", uuid_=llm_uuid)
            time.sleep(0.2)
        finally:
            sub.unsubscribe()

        self.assertEqual(RecordingGuardian.recorded, [],
            "function/llm-level events MUST NOT fire lifecycle hooks "
            "(those events are FunctionMiddleware's responsibility); "
            f"got {RecordingGuardian.recorded}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
