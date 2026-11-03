"""A NAT input whose keys collide once normalized for signing never runs the function, under either posture."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from nat.middleware.middleware import FunctionMiddlewareContext
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _handshake
from acs.testing.harness import ProgrammableGuardian

SECRET = "nat-key-collision-secret-padded-to-32-bytes"


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
@mock.patch.dict(os.environ, {"ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "test-key", "ACS_HMAC_SECRET_FILE": "",
                              "ACS_DISABLED": "", "ACS_STARTUP_POSTURE": ""})
class CollidingKeysNeverRunTheFunction(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        patcher = mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(records.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.guardian = ProgrammableGuardian(hmac_secret=SECRET)

        def policy(req):
            dangerous = "danger" in json.dumps(req["params"]["payload"])
            return {"decision": "deny" if dangerous else "allow", "reasoning": "deny danger"}
        self.guardian.handlers["steps/toolCallRequest"] = policy
        self.guardian.start()
        self.addCleanup(self.guardian.stop)

    def _invoke(self, payload: dict, *, default_deny: bool) -> list[dict]:
        from acs.integrations.nat.adapter import ACSGuardianDenied, ACSMiddleware, ACSMiddlewareConfig
        ran: list[dict] = []

        async def target(value):
            ran.append(value)
            return "ran"

        async def call() -> None:
            mw = ACSMiddleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(), default_deny=default_deny))
            context = FunctionMiddlewareContext(name="Read", config=None, description=None, input_schema=None,
                                                single_output_schema=str, stream_output_schema=str)
            try:
                await mw.function_middleware_invoke(payload, call_next=target, context=context)
            except ACSGuardianDenied:
                pass
            finally:
                await asyncio.to_thread(mw.close)
        asyncio.run(call())
        return ran

    def test_a_safe_key_that_collides_with_a_dangerous_one_does_not_release_it(self) -> None:
        for default_deny in (True, False):
            with self.subTest(default_deny=default_deny):
                self.guardian.reset()
                self.assertEqual(self._invoke({"\ud800": "danger"}, default_deny=default_deny), [],
                                 "control: the Guardian denies the dangerous value")
                self.guardian.reset()
                self.assertEqual(self._invoke({"\ud800": "danger", "�": "safe"}, default_deny=default_deny), [])
                self.assertNotIn("steps/toolCallRequest", self.guardian.methods_seen())


if __name__ == "__main__":
    unittest.main()
