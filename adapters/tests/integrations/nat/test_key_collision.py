"""A NAT input whose keys collide once normalized for signing never runs the function, under either posture."""
from __future__ import annotations

import asyncio
import enum
import json
import os
import tempfile
import unittest
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

try:
    from nat.middleware.middleware import FunctionMiddlewareContext
    from pydantic import BaseModel
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _handshake
from acs.testing.harness import ProgrammableGuardian

SECRET = "nat-key-collision-secret-padded-to-32-bytes"


class Kind(enum.Enum):
    COLLIDING = {b"x": "danger", "x": "safe"}
    DANGER = {"x": "danger"}


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
        self.guardian.handlers["steps/toolCallResult"] = policy
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


    def test_keys_that_become_one_json_key_never_run_the_function(self) -> None:
        class Input(BaseModel):
            data: dict[Any, str]

        class Queue(BaseModel):
            data: deque[dict[Any, str]]

        class Kinds(BaseModel):
            data: set[Kind]
        cases = {"flat": {1: "danger", "1": "safe"}, "nested": {"outer": {True: "danger", "true": "safe"}},
                 "model": Input(data={1: "danger", "1": "safe"}), "model None": Input(data={None: "danger", "None": "safe"}),
                 "model bytes": Input(data={b"x": "danger", "x": "safe"}),
                 "model deque": Queue(data=deque([{b"x": "danger", "x": "safe"}])),
                 "model list": Queue(data=[{b"x": "danger", "x": "safe"}]),
                 "model enum set": Kinds(data={Kind.COLLIDING})}
        for name, payload in cases.items():
            for default_deny in (True, False):
                with self.subTest(name, default_deny=default_deny):
                    self.guardian.reset()
                    self.assertEqual(self._invoke(payload, default_deny=default_deny), [])
                    self.assertNotIn("steps/toolCallRequest", self.guardian.methods_seen())
        self.guardian.reset()
        self.assertEqual(len(self._invoke({1: "safe", "2": "safe"}, default_deny=False)), 1, "distinct keys run")
        self.guardian.reset()
        self.assertEqual(len(self._invoke(Queue(data=deque([{b"x": "safe", "y": "safe"}])), default_deny=False)), 1,
                         "a deque with distinct keys runs")
        self.guardian.reset()
        self.assertEqual(self._invoke(Queue(data=deque([{"x": "danger"}])), default_deny=False), [],
                         "a dangerous value in a deque reaches the Guardian, which denies it")
        self.guardian.reset()
        self.assertEqual(self._invoke({"kind": Kind.DANGER}, default_deny=False), [],
                         "a plain enum member reaches the Guardian as its value, which it denies")
        self.assertIn("steps/toolCallRequest", self.guardian.methods_seen())
        self.guardian.reset()
        self.assertEqual(self._invoke({None: "danger", "None": "safe"}, default_deny=False), [],
                         "a plain dict keeps both keys, so the Guardian sees the dangerous value and denies it")
        self.assertIn("steps/toolCallRequest", self.guardian.methods_seen())

    def _result(self, output: Any, *, default_deny: bool) -> Any:
        from acs.integrations.nat.adapter import ACSMiddleware, ACSMiddlewareConfig
        context = SimpleNamespace(function_context=SimpleNamespace(name="Read"), output=output,
                                  modified_args=("x",), modified_kwargs={})

        async def report() -> None:
            mw = ACSMiddleware(ACSMiddlewareConfig(guardian_url=self.guardian.url(), default_deny=default_deny))
            try:
                await mw.post_invoke(context)
            finally:
                await asyncio.to_thread(mw.close)
        asyncio.run(report())
        return context.output

    def test_an_output_whose_keys_become_one_json_key_is_withheld(self) -> None:
        class Output(BaseModel):
            data: dict[Any, str]

        class Queue(BaseModel):
            data: deque[dict[Any, str]]

        class Kinds(BaseModel):
            data: set[Kind]
        outputs = {"flat": {1: "danger", "1": "safe"}, "model None": Output(data={None: "danger", "None": "safe"}),
                   "model bytes": Output(data={b"x": "danger", "x": "safe"}),
                   "model deque": Queue(data=deque([{b"x": "danger", "x": "safe"}])),
                   "plain deque": deque([{1: "danger", "1": "safe"}]), "model enum set": Kinds(data={Kind.COLLIDING})}
        for name, output in outputs.items():
            for default_deny in (True, False):
                with self.subTest(name, default_deny=default_deny):
                    self.guardian.reset()
                    self.assertIsNone(self._result(output, default_deny=default_deny))
                    self.assertNotIn("steps/toolCallResult", self.guardian.methods_seen())
        self.guardian.reset()
        self.assertEqual(self._result({1: "safe", "2": "safe"}, default_deny=False), {1: "safe", "2": "safe"})


if __name__ == "__main__":
    unittest.main()
