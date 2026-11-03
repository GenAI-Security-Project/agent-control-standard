from __future__ import annotations

import asyncio
import contextvars
import json
import os
import socket
import subprocess
import sys
import threading
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

try:
    from nat.builder.context import Context, ContextState
    from nat.builder.intermediate_step_manager import IntermediateStepManager
    from nat.data_models.intermediate_step import (
        IntermediateStepPayload, IntermediateStepType, StreamEventData,
    )
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _handshake as client_handshake  # noqa: E402
from acs.integrations.nat.adapter import ACSMiddleware  # noqa: E402

if _NAT_OK:
    from acs.integrations.nat.adapter import ACSMiddlewareConfig  # noqa: E402

HERE = Path(__file__).resolve().parent
GUARDIAN_SCRIPT = HERE.parents[2] / "src" / "acs" / "guardian" / "example_guardian.py"


from acs.core import derive_session_key, sign_with_key  # noqa: E402
from acs.testing.harness import launch_guardian, seed_negotiated_session, sign_for_test, signing_env  # noqa: E402


class RecordingGuardian(BaseHTTPRequestHandler):
    """Records every method and answers a duplicate request_id per session with REPLAY_DETECTED."""
    recorded: list = []
    seen_per_session: dict = {}
    lock = threading.Lock()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        method = body.get("method", "")
        params = body.get("params") or {}
        meta = params.get("metadata") or {}
        sid = meta.get("session_id", "")
        rid = params.get("request_id", "")
        with RecordingGuardian.lock:
            RecordingGuardian.recorded.append({"method": method, "session_id": sid, "request_id": rid})
            seen = RecordingGuardian.seen_per_session.setdefault(sid, set())
            if rid in seen and rid:
                reply = {
                    "jsonrpc": "2.0", "id": body.get("id"),
                    "error": {"code": -32005, "message": f"REPLAY_DETECTED: {rid}"},
                }
            else:
                if rid:
                    seen.add(rid)
                reply = {
                    "jsonrpc": "2.0", "id": body.get("id"),
                    "result": {"type": "final", "acs_version": "0.1.0",
                               "request_id": rid, "decision": "allow",
                               "chain_hash": "0" * 64},
                }
        # Signed with the test secret under its label, as a Guardian signs every response (§10).
        key = derive_session_key(signing_env()["ACS_HMAC_SECRET"].encode(), sid)
        reply = json.dumps(sign_with_key(reply, key, key_id=signing_env()["ACS_HMAC_KEY_ID"])).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args, **kwargs):
        return


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class FailureMode1_DuplicateToolCallReplayDetected(unittest.TestCase):
    """Repeat calls to the same tool with the same args must carry
    distinct request_ids — the Guardian's per-session replay protection
    rejects duplicates with REPLAY_DETECTED (-32005).
    """

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
        RecordingGuardian.seen_per_session.clear()
        # Per-test handshake records, and environment changes undone after the test.
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        self.records = Path(records.name)
        for patcher in (mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", self.records),
                        mock.patch.dict(os.environ, signing_env())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _ctx(self, tool_name: str, kwargs: dict):
        from nat.middleware.middleware import (
            InvocationContext, FunctionMiddlewareContext)
        return InvocationContext(
            function_context=FunctionMiddlewareContext(
                name=tool_name, config=None, description=None,
                input_schema=None,
                single_output_schema=type(None),
                stream_output_schema=type(None),
            ),
            original_args=(), original_kwargs=kwargs,
            modified_args=(), modified_kwargs=dict(kwargs),
        )

    def test_repeat_tool_call_does_not_get_replay_detected(self) -> None:
        cfg = ACSMiddlewareConfig(
            guardian_url=self.url, default_deny=False,
        )
        mw = ACSMiddleware(cfg)
        seed_negotiated_session(self.records, session_id=mw._session_id, guardian_url=self.url,
                                hmac_secret=signing_env()["ACS_HMAC_SECRET"])

        ctx1 = self._ctx("list_files", {})
        r1 = asyncio.run(mw.pre_invoke(ctx1))
        ctx2 = self._ctx("list_files", {})
        r2 = asyncio.run(mw.pre_invoke(ctx2))

        tool_call_records = [r for r in RecordingGuardian.recorded
                             if r["method"] == "steps/toolCallRequest"]
        self.assertEqual(len(tool_call_records), 2,
            f"expected 2 toolCallRequest sends, got {tool_call_records}")

        rid1, rid2 = tool_call_records[0]["request_id"], tool_call_records[1]["request_id"]
        self.assertNotEqual(rid1, rid2,
            "BUG #1: NAT adapter sent the same request_id for two distinct "
            "calls to the same tool with the same args. Guardian replay "
            "protection rejects the second call with REPLAY_DETECTED. "
            "Repeat tool calls in real workflows (list_files, get_status, "
            "etc.) will break in production.")

@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class FailureMode2_GuardianRestartReplayWindow(unittest.TestCase):
    """Replay protection must survive a Guardian restart: §10.3 requires
    duplicate request_ids be rejected, so seen-request-id state must be
    durable rather than RAM-only.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmpdir = Path(__file__).resolve().parent / "_guardian_state_tmp"
        cls.tmpdir.mkdir(exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _start_guardian(self):
        # Replay durability lives in the shared state dir, not the port.
        env = os.environ.copy()
        env.update(signing_env())
        env.pop("ACS_HMAC_SECRET_FILE", None)
        env["ACS_GUARDIAN_STATE_DIR"] = str(self.tmpdir)
        proc, port = launch_guardian(env=env)
        self.url = f"http://127.0.0.1:{port}/acs"
        return proc

    def _send_envelope(self, sid: str, rid: str):
        import urllib.request
        import uuid as _uuid
        from datetime import datetime, timezone
        body = json.dumps(sign_for_test({
            "jsonrpc": "2.0", "id": str(_uuid.uuid4()),
            "method": "steps/sessionStart",
            "params": {
                "acs_version": "0.1.0", "request_id": rid,
                "timestamp": datetime.now(timezone.utc)
                    .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "metadata": {"agent_id": "test", "session_id": sid, "platform": "test"},
                "payload": {},
            },
        })).encode()
        req = urllib.request.Request(self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode())

    def test_replay_protection_survives_guardian_restart(self) -> None:
        import uuid as _uuid
        sid = str(_uuid.uuid4())
        rid = str(_uuid.uuid4())

        proc = self._start_guardian()
        try:
            r1 = self._send_envelope(sid, rid)
            self.assertIn("result", r1, "first send must succeed")
        finally:
            proc.terminate()
            try: proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired: proc.kill()

        proc = self._start_guardian()
        try:
            r2 = self._send_envelope(sid, rid)
            self.assertIn("error", r2,
                "BUG #2: replayed envelope was accepted after Guardian restart. "
                "§10.3 says Guardians MUST reject duplicate request_ids — but "
                "RAM-only state means every restart opens a replay window. "
                "Any deployment with autoscaling, deploys, or crash-restart "
                "loses replay protection on every restart.")
            self.assertEqual(r2["error"]["code"], -32005,
                f"expected REPLAY_DETECTED (-32005), got {r2['error']}")
        finally:
            proc.terminate()
            try: proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired: proc.kill()


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class FailureMode3_LifecycleSubscriptionRace(unittest.TestCase):
    """Two parallel pre_invoke calls must not double-subscribe the
    lifecycle observer, or every WORKFLOW event fires its ACS hooks twice.
    """

    def test_concurrent_subscribe_calls_subscribe_only_once(self) -> None:
        from acs.integrations.nat import adapter as adapter_mod

        subscribe_calls = [0]
        subscribe_lock = threading.Lock()

        class FakeSubscription:
            def unsubscribe(self): pass

        class FakeMgr:
            def subscribe(self, on_next, on_error=None, on_complete=None):
                # Sleep inside subscribe() to widen the race window.
                time.sleep(0.05)
                with subscribe_lock:
                    subscribe_calls[0] += 1
                return FakeSubscription()

        class FakeCtx:
            intermediate_step_manager = FakeMgr()

        cfg = ACSMiddlewareConfig(
            guardian_url="http://127.0.0.1:1/dead",
            default_deny=False,
        )
        mw = ACSMiddleware(cfg)

        # Patch Context.get() so both threads see our FakeCtx
        import unittest.mock as mock
        from nat.utils.reactive.subject import Subject
        with mock.patch.object(adapter_mod, "_NATContext") as patched_ctx:
            patched_ctx.get.return_value = FakeCtx()
            # Both calls belong to one run, so both see that run's step stream.
            token = ContextState.get().event_stream.set(Subject())
            self.addCleanup(ContextState.get().event_stream.reset, token)
            run_token = ContextState.get().workflow_run_id.set("race-run")
            self.addCleanup(ContextState.get().workflow_run_id.reset, run_token)
            runs = [contextvars.copy_context(), contextvars.copy_context()]
            sessions = []

            barrier = threading.Barrier(2)
            def runner(run):
                barrier.wait()  # release both threads simultaneously
                sessions.append(run.run(mw._session_of_call))

            t1 = threading.Thread(target=runner, args=(runs[0],))
            t2 = threading.Thread(target=runner, args=(runs[1],))
            t1.start(); t2.start()
            t1.join(); t2.join()

        self.assertEqual(subscribe_calls[0], 1,
            f"lifecycle subscribe() was called {subscribe_calls[0]} times instead of 1; "
            f"every later WORKFLOW event would report its hooks that many times.")
        self.assertEqual(len({id(session) for session in sessions}), 1, "both calls are in one session")
        mw.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
