"""
Emission conformance — NAT (NVIDIA Agent Toolkit) middleware.

NAT is in-process, so "the production entry point" is the real
middleware lifecycle — pre_invoke / post_invoke and the
IntermediateStepManager observer — not a subprocess. This drives those
real paths against a validating CaptureGuardian whose oracle is the
canonical schemas. Requires nvidia-nat-core;
CI installs it and hard-fails on skips (see the authoritative runner),
so a skip here is a local-only condition, never a silent pass.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import unittest
from pathlib import Path

try:
    from nat.middleware.middleware import (  # type: ignore[import-not-found]
        InvocationContext, FunctionMiddlewareContext,
    )
    from nat.builder.context import ContextState  # type: ignore[import-not-found]
    from nat.builder.intermediate_step_manager import (  # type: ignore[import-not-found]
        IntermediateStepManager,
    )
    from nat.data_models.intermediate_step import (  # type: ignore[import-not-found]
        IntermediateStepPayload, IntermediateStepType, StreamEventData,
    )
    from pydantic import BaseModel
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "_common"))

from acs_adapter import ACSMiddleware  # noqa: E402
if _NAT_OK:
    from acs_adapter import ACSMiddlewareConfig  # noqa: E402
from capture_guardian import CaptureGuardian  # noqa: E402

HMAC = "nat-emission-shared-secret"


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
        self._cache = Path(
            __import__("tempfile").mkdtemp())
        prior = os.environ.get("ACS_HMAC_SECRET")
        os.environ["ACS_HMAC_SECRET"] = HMAC
        os.environ["ACS_HANDSHAKE"] = "1"
        os.environ["ACS_HANDSHAKE_CACHE"] = str(self._cache)

        def _restore():
            self.guardian.stop()
            if prior is None:
                os.environ.pop("ACS_HMAC_SECRET", None)
            else:
                os.environ["ACS_HMAC_SECRET"] = prior
        self.addCleanup(_restore)

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

    def test_lifecycle_observer_emits_session_hooks(self) -> None:
        os.environ["ACS_HANDSHAKE"] = "0"  # focus on lifecycle emissions
        mw = self._mw()
        mgr = IntermediateStepManager(ContextState.get())
        sub = mgr.subscribe(on_next=mw._on_intermediate_step)
        try:
            payload = IntermediateStepPayload(
                event_type=IntermediateStepType.WORKFLOW_START,
                name="wf", data=StreamEventData(input="what is the weather?"))
            wf_uuid = payload.UUID
            mgr.push_intermediate_step(payload)
            mgr.push_intermediate_step(IntermediateStepPayload(
                event_type=IntermediateStepType.WORKFLOW_END, name="wf",
                data=StreamEventData(output="sunny"), UUID=wf_uuid))
            time.sleep(0.3)
        finally:
            sub.unsubscribe()
        methods = self.guardian.methods()
        for expected in ("steps/sessionStart", "steps/userMessage",
                         "steps/agentResponse", "steps/sessionEnd"):
            # Exactly once — assertIn would let duplicate emissions pass.
            self.assertEqual(
                len(self.guardian.records_for(expected)), 1,
                f"lifecycle must emit {expected} exactly once; got {methods}")
        self.guardian.assert_all_valid(self)

    def test_sequential_session_invariants(self) -> None:
        """One middleware + one Guardian across a full sequence: handshake
        fires once, request_ids are unique, toolCallResult links to its
        request, and advertised == emitted in both directions. Covers the
        enforcement path + lifecycle observer."""
        mw = self._mw()
        # One context across pre_invoke + post_invoke: the stashed
        # correlation id makes request_id_ref equal the request's id.
        ctx = _ctx("weather_tool")
        asyncio.run(mw.pre_invoke(ctx))
        ctx.output = "sunny"
        asyncio.run(mw.post_invoke(ctx))
        # lifecycle observer
        mgr = IntermediateStepManager(ContextState.get())
        sub = mgr.subscribe(on_next=mw._on_intermediate_step)
        try:
            payload = IntermediateStepPayload(
                event_type=IntermediateStepType.WORKFLOW_START, name="wf",
                data=StreamEventData(input="q"))
            wf = payload.UUID
            mgr.push_intermediate_step(payload)
            mgr.push_intermediate_step(IntermediateStepPayload(
                event_type=IntermediateStepType.WORKFLOW_END, name="wf",
                data=StreamEventData(output="a"), UUID=wf))
            time.sleep(0.3)
        finally:
            sub.unsubscribe()

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
