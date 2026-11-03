"""A run's WORKFLOW_START and WORKFLOW_END become its four lifecycle hooks, which NAT's function calls alone do not cover (ACS-Core hook taxonomy)."""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from nat.builder.context import Context
    from nat.data_models.intermediate_step import IntermediateStepPayload, IntermediateStepType, StreamEventData
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _handshake as client_handshake  # noqa: E402
from acs.testing.harness import ProgrammableGuardian  # noqa: E402

if _NAT_OK:
    from acs.integrations.nat.adapter import ACSMiddlewareConfig  # noqa: E402
    from tests.integrations.nat._nat_runs import with_middleware  # noqa: E402

SECRET = "nat-lifecycle-test-secret-padded-to-32-bytes"


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class LifecycleObserver(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", Path(records.name)),
                        mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "test-key"},
                                        clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.guardian = ProgrammableGuardian(hmac_secret=SECRET)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)

    def test_function_and_llm_steps_inside_a_run_fire_no_lifecycle_hooks(self) -> None:
        async def entry(message: str) -> str:
            manager = Context.get().intermediate_step_manager
            for start, end, name in ((IntermediateStepType.FUNCTION_START, IntermediateStepType.FUNCTION_END, "tool"),
                                     (IntermediateStepType.LLM_START, IntermediateStepType.LLM_END, "llm")):
                step = IntermediateStepPayload(event_type=start, name=name, data=StreamEventData(input="x"))
                manager.push_intermediate_step(step)
                manager.push_intermediate_step(IntermediateStepPayload(
                    event_type=end, name=name, data=StreamEventData(output="y"), UUID=step.UUID))
            return "done"

        async def body(middleware, run) -> None:
            await run("wf", entry, "what is the weather?")
        asyncio.run(with_middleware(ACSMiddlewareConfig(guardian_url=self.guardian.url()), body))
        self.assertEqual(self.guardian.methods_seen(),
                         ["handshake/hello", "steps/sessionStart", "steps/userMessage", "steps/agentResponse",
                          "steps/sessionEnd"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
