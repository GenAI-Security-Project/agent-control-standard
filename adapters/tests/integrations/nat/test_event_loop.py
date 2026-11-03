"""NAT's Guardian calls run off the event loop: a session's calls share one handshake, and its lifecycle hooks go
out in event order without blocking NAT."""
from __future__ import annotations

import asyncio
import os
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

try:
    from nat.data_models.intermediate_step import (IntermediateStepPayload, IntermediateStepType,
                                                   StreamEventData)
    from nat.middleware.middleware import FunctionMiddlewareContext
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _handshake
from acs.integrations.nat import adapter as nat_adapter
from acs.integrations.nat.adapter import ACSGuardianDenied, ACSMiddleware
from acs.testing.harness import ProgrammableGuardian

if _NAT_OK:
    from acs.integrations.nat.adapter import ACSMiddlewareConfig, build_acs_middleware
    from tests.integrations.nat._nat_runs import with_middleware

SECRET = "nat-event-loop-secret-padded-to-32-bytes"
SLOW_S = 0.5


def _slow(handler):
    def slow(req: dict) -> dict:
        time.sleep(SLOW_S)
        return handler(req)
    return slow


async def _ticking(coro):
    """Run coro while counting event-loop turns of 10 ms; a blocked loop stops counting."""
    ticks = 0

    async def tick() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)
    task = asyncio.create_task(tick())
    try:
        return await coro, ticks
    finally:
        task.cancel()


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class GuardianCallsOffTheEventLoop(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(records.name)),
                        mock.patch.object(_handshake, "_HANDSHAKE_TIMEOUT_S", 5.0),
                        mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "test-key"}, clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.guardian = ProgrammableGuardian(hmac_secret=SECRET)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)
        self.executed = 0

    def _config(self, url: str | None = None) -> ACSMiddlewareConfig:
        return ACSMiddlewareConfig(guardian_url=url or self.guardian.url(), default_deny=False,
                                   session_id=str(uuid.uuid4()))

    async def _invoke(self, mw: ACSMiddleware) -> bool:
        """One protected call through the middleware; True when NAT blocked it."""
        async def target(command: str) -> str:
            self.executed += 1
            return f"ran: {command}"
        context = FunctionMiddlewareContext(name="Bash", config=None, description=None, input_schema=None,
                                            single_output_schema=type(None), stream_output_schema=type(None))
        try:
            await mw.function_middleware_invoke(command="echo hi", call_next=target, context=context)
        except ACSGuardianDenied:
            return True
        return False

    def test_building_the_middleware_sends_nothing(self) -> None:
        async def build() -> list[str]:
            async with build_acs_middleware(self._config(), None):
                return self.guardian.methods_seen()
        self.assertEqual(asyncio.run(build()), [])

    def test_concurrent_calls_share_one_handshake(self) -> None:
        self.guardian.handlers["handshake/hello"] = _slow(self.guardian._default_handshake)
        for name in ("builder", "constructed directly"):
            with self.subTest(name):
                self.guardian.reset()
                self.executed = 0

                async def run() -> list[bool]:
                    if name == "builder":
                        async with build_acs_middleware(self._config(), None) as mw:
                            return await asyncio.gather(*(self._invoke(mw) for _ in range(5)))
                    mw = ACSMiddleware(self._config())
                    try:
                        return await asyncio.gather(*(self._invoke(mw) for _ in range(5)))
                    finally:
                        mw.close()
                blocked, ticks = asyncio.run(_ticking(run()))
                self.assertEqual(blocked, [False] * 5)
                self.assertEqual(self.executed, 5)
                self.assertEqual(self.guardian.methods_seen().count("handshake/hello"), 1)
                self.assertGreater(ticks, 10, "the event loop kept running during the handshake")

    def test_a_slow_guardian_leaves_the_loop_running(self) -> None:
        for method in ("steps/toolCallRequest", "steps/toolCallResult"):
            with self.subTest(method):
                self.guardian.handlers = {"handshake/hello": self.guardian._default_handshake,
                                          "__default__": self.guardian._default_allow,
                                          method: _slow(self.guardian._default_allow)}
                self.executed = 0

                async def run() -> tuple[bool, int]:
                    async with build_acs_middleware(self._config(), None) as mw:
                        return await _ticking(self._invoke(mw))
                blocked, ticks = asyncio.run(run())
                self.assertFalse(blocked)
                self.assertEqual(self.executed, 1)
                self.assertGreater(ticks, 20, "the event loop kept running during the round trip")

    def test_a_refused_or_unanswered_session_never_runs_the_function(self) -> None:
        down = ProgrammableGuardian(hmac_secret=SECRET)
        down._server.server_close()
        self.guardian.handlers["handshake/hello"] = lambda req: {"code": -32000, "message": "agent not permitted"}
        for name, url, startup in (("refused", self.guardian.url(), ""),
                                   ("no answer, refuse", down.url(), "refuse")):
            with self.subTest(name):
                self.guardian.reset()
                os.environ["ACS_STARTUP_POSTURE"] = startup

                async def run() -> list[bool]:
                    async with build_acs_middleware(self._config(url), None) as mw:
                        return await asyncio.gather(*(self._invoke(mw) for _ in range(3)))
                self.assertEqual(asyncio.run(run()), [True] * 3)
                self.assertEqual(self.executed, 0)
                if name == "refused":
                    self.assertEqual(self.guardian.methods_seen(), ["handshake/hello"],
                                     "every call reuses the refusal and sends nothing")

    def test_a_disabled_middleware_skips_the_handshake(self) -> None:
        os.environ["ACS_DISABLED"] = "1"

        async def run() -> tuple[list[str], bool]:
            async with build_acs_middleware(self._config(), None) as mw:
                return self.guardian.methods_seen(), await self._invoke(mw)
        seen, blocked = asyncio.run(run())
        self.assertEqual((seen, blocked, self.executed), ([], False, 1))
        self.assertEqual(self.guardian.methods_seen(), [])

    def test_lifecycle_hooks_go_out_in_event_order_without_blocking_nat(self) -> None:
        self.guardian.handlers["steps/sessionStart"] = _slow(self.guardian._default_allow)
        reached: list[float] = []

        async def body(mw, run) -> None:
            async def entry(message: str) -> bool:
                reached.append(time.monotonic() - began)
                return await self._invoke(mw)
            began = time.monotonic()
            self.assertFalse(await run("wf", entry, "q"))
        asyncio.run(with_middleware(self._config(), body))
        self.assertLess(reached[0], SLOW_S / 2, "NAT's WORKFLOW_START returned without waiting on the Guardian")
        self.assertEqual(self.guardian.methods_seen(),
                         ["handshake/hello", "steps/sessionStart", "steps/userMessage", "steps/toolCallRequest",
                          "steps/toolCallResult", "steps/agentResponse", "steps/sessionEnd"],
                         "every hook reaches the Guardian in event order, sessionEnd included")

    def test_a_hook_that_arrives_while_closing_is_not_sent_after_the_sessions_end(self) -> None:
        """close() drains each session in order; a hook reported after its session ended is audited, not sent."""
        mw = ACSMiddleware(self._config())
        started, release = threading.Event(), threading.Event()
        sent: list[tuple[str, str]] = []

        def emit(method: str, payload: dict, session) -> None:
            if method == "steps/sessionStart":
                started.set()
                release.wait(5)
            sent.append((method, threading.current_thread().name))
        mw._emit_lifecycle_hook = emit
        session = mw._new_session()
        end = IntermediateStepPayload(event_type=IntermediateStepType.WORKFLOW_END, name="wf",
                                      data=StreamEventData(output="a"))

        async def run() -> float:
            mw._queue(session, "steps/sessionStart", {})
            self.assertTrue(await asyncio.to_thread(started.wait, 5))
            closing = asyncio.create_task(asyncio.to_thread(mw.close))
            await asyncio.sleep(0.05)
            began = time.monotonic()
            mw._workflow_ended(session, end)
            callback = time.monotonic() - began
            release.set()
            await closing
            return callback
        with mock.patch("acs.integrations.nat.adapter.audit_event") as audit:
            callback = asyncio.run(run())
        self.assertLess(callback, 0.05, "NAT's step callback returned without sending anything itself")
        self.assertEqual([method for method, _ in sent], ["steps/sessionStart", "steps/sessionEnd"])
        self.assertTrue(all(thread == "acs-lifecycle" for _, thread in sent), sent)
        self.assertEqual([c.args[0] for c in audit.call_args_list], ["lifecycle_hook_not_sent"],
                         "a hook after the session's end is audited, not sent")

    def test_a_cancelled_wait_does_not_stop_the_hooks_behind_it(self) -> None:
        mw = ACSMiddleware(self._config())
        session = mw._new_session()
        # A sender whose thread died would hold up interpreter exit; let this test fail instead.
        self.addCleanup(nat_adapter._OPEN_SENDERS.discard, session.lane)
        release, sent = threading.Event(), []

        def emit(method: str, payload: dict, session) -> None:
            if method == "first":
                release.wait(5)
            sent.append(method)
        mw._emit_lifecycle_hook = emit
        mw._queue(session, "first", {})
        session.lane.sent().cancel()
        mw._queue(session, "second", {})
        release.set()
        closer = threading.Thread(target=mw.close, daemon=True)
        closer.start()
        closer.join(5)
        self.assertFalse(closer.is_alive(), "close() returns once the queue drains")
        self.assertEqual(sent, ["first", "second", "steps/sessionEnd"])


if __name__ == "__main__":
    unittest.main()
