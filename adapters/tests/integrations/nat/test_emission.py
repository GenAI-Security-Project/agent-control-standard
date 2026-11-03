"""NAT emission: pre_invoke and post_invoke inside a real Runner, validated by CaptureGuardian against the canonical schemas."""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from nat.middleware.middleware import (  # type: ignore[import-not-found]
        InvocationContext, FunctionMiddlewareContext,
    )
    from pydantic import BaseModel
    _NAT_OK = True
except ImportError:
    _NAT_OK = False


from acs.client import _handshake as client_handshake  # noqa: E402
from acs.integrations.nat.adapter import ACSMiddleware  # noqa: E402
if _NAT_OK:
    from acs.integrations.nat.adapter import ACSMiddlewareConfig  # noqa: E402
    from tests.integrations.nat._nat_runs import with_middleware  # noqa: E402
from acs.testing.capture_guardian import CaptureGuardian  # noqa: E402

HMAC = "nat-emission-shared-secret-padded-to-32-bytes"


if _NAT_OK:
    class _ToolInput(BaseModel):
        command: str = "echo hi"

    def _ctx(tool_name: str) -> "InvocationContext":
        m = _ToolInput()
        return InvocationContext(
            function_context=FunctionMiddlewareContext(
                name=tool_name, config=None, description=None,
                input_schema=_ToolInput,
                single_output_schema=type(None),
                stream_output_schema=type(None)),
            original_args=(m,), original_kwargs={},
            modified_args=[m], modified_kwargs={})


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class NatEmission(unittest.TestCase):
    def setUp(self) -> None:
        self.guardian = CaptureGuardian(hmac_secret=HMAC)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)
        # Per-test handshake records, and environment changes undone after the test.
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        self.records = Path(records.name)
        for patcher in (mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", self.records),
                        mock.patch.dict(os.environ)):
            patcher.start()
            self.addCleanup(patcher.stop)
        os.environ["ACS_HMAC_SECRET"] = HMAC
        os.environ["ACS_HMAC_KEY_ID"] = "test-key"
        os.environ.pop("ACS_HANDSHAKE", None)

    def _mw(self) -> ACSMiddleware:
        return ACSMiddleware(ACSMiddlewareConfig(
            guardian_url=self.guardian.url(), default_deny=False,
            session_id="nat-emission"))

    def test_pre_invoke_emits_tool_call_request(self) -> None:
        mw = self._mw()
        asyncio.run(mw.pre_invoke(_ctx("weather_tool")))
        self.assertEqual(len(self.guardian.records_for("steps/toolCallRequest")), 1,
            f"captured {self.guardian.methods()}")
        self.assertIn("handshake/hello", self.guardian.methods())
        self.guardian.assert_all_valid(self)

    def test_post_invoke_emits_tool_call_result(self) -> None:
        mw = self._mw()
        ctx = _ctx("weather_tool")
        ctx.output = "sunny"
        asyncio.run(mw.post_invoke(ctx))
        self.assertEqual(len(self.guardian.records_for("steps/toolCallResult")), 1,
            f"captured {self.guardian.methods()}")
        self.guardian.assert_all_valid(self)

    def test_a_run_emits_each_session_hook_once(self) -> None:
        async def body(mw, run) -> None:
            await run("wf", lambda message: asyncio.sleep(0, "sunny"), "what is the weather?")
        asyncio.run(with_middleware(self._mw()._config, body))
        methods = self.guardian.methods()
        for expected in ("steps/sessionStart", "steps/userMessage",
                         "steps/agentResponse", "steps/sessionEnd"):
            # Exactly once — assertIn would let duplicate emissions pass.
            self.assertEqual(
                len(self.guardian.records_for(expected)), 1,
                f"lifecycle must emit {expected} exactly once; got {methods}")
        self.guardian.assert_all_valid(self)

    def test_sequential_session_invariants(self) -> None:
        """One run: one handshake, unique request_ids, request_id_ref links, advertised equals emitted."""
        async def body(mw, run) -> None:
            async def entry(message: str) -> str:
                # One context across pre_invoke + post_invoke: the stashed
                # correlation id makes request_id_ref equal the request's id.
                ctx = _ctx("weather_tool")
                await mw.pre_invoke(ctx)
                ctx.output = "sunny"
                await mw.post_invoke(ctx)
                return "a"
            await run("wf", entry, "q")
        asyncio.run(with_middleware(self._mw()._config, body))

        self.guardian.assert_all_valid(self)
        self.assertEqual(len(self.guardian.records_for("handshake/hello")), 1,
            f"handshake once per session: {self.guardian.methods()}")
        self.assertEqual(self.guardian.duplicate_request_ids(), [],
            "request_id MUST be unique per session")
        # Correlation: result references its request (same context).
        req_id = self.guardian.request_id_for("steps/toolCallRequest")
        ref = self.guardian.payload_of("steps/toolCallResult").get("request_id_ref")
        self.assertIsNotNone(req_id)
        self.assertEqual(ref, req_id,
            f"toolCallResult.request_id_ref must link to its request "
            f"({ref!r} != {req_id!r})")
        # advertised == emitted both directions; a subset check would
        # miss emitting an undeclared method.
        advertised = set(self.guardian.handshake_methods_implemented())
        emitted = {m for m in self.guardian.methods() if m != "handshake/hello"}
        self.assertEqual(advertised, emitted,
            f"advertised != emitted; over-advertised={sorted(advertised - emitted)}, "
            f"under-advertised (emitted but not declared)={sorted(emitted - advertised)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
