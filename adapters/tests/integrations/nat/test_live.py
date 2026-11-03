"""The middleware through function_middleware_invoke, the method NAT's runtime calls for a wrapped function."""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from nat.middleware.middleware import FunctionMiddlewareContext
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _handshake as client_handshake  # noqa: E402
from acs.integrations.nat.adapter import ACSMiddleware, ACSGuardianDenied  # noqa: E402

if _NAT_OK:
    from acs.integrations.nat.adapter import ACSMiddlewareConfig  # noqa: E402

HERE = Path(__file__).resolve().parent


from acs.testing.harness import launch_guardian, signing_env  # noqa: E402


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class LiveNATWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        env = {k: v for k, v in os.environ.items() if k != "ACS_HMAC_SECRET_FILE"}
        env.update(signing_env())
        cls.guardian_proc, cls.port = launch_guardian(env=env)
        cls.guardian_url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()

    def setUp(self) -> None:
        # Per-test handshake records, and environment changes undone after the test.
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        self.records = Path(records.name)
        for patcher in (mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", self.records),
                        mock.patch.dict(os.environ, signing_env())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _make_middleware(self, default_deny: bool = True) -> ACSMiddleware:
        return ACSMiddleware(ACSMiddlewareConfig(
            guardian_url=self.guardian_url, default_deny=default_deny,
            session_id="nat-live",
        ))

    def _ctx(self, tool_name: str) -> "FunctionMiddlewareContext":
        return FunctionMiddlewareContext(
            name=tool_name, config=None, description=None,
            input_schema=None,
            single_output_schema=type(None),
            stream_output_schema=type(None),
        )

    def test_allow_function_executes(self) -> None:
        executed = {"count": 0, "args": None}

        async def target(command: str) -> str:
            executed["count"] += 1
            executed["args"] = command
            return f"ran: {command}"

        mw = self._make_middleware()
        result = asyncio.run(
            mw.function_middleware_invoke(
                command="ls -la",
                call_next=target,
                context=self._ctx("Bash"),
            )
        )
        self.assertEqual(executed["count"], 1, "allowed function should have run exactly once")
        self.assertEqual(executed["args"], "ls -la")
        self.assertEqual(result, "ran: ls -la")

    def test_deny_function_does_not_execute(self) -> None:
        executed = {"count": 0}

        async def target(command: str) -> str:
            executed["count"] += 1
            return "should not see this"

        mw = self._make_middleware()
        with self.assertRaises(ACSGuardianDenied) as cm:
            asyncio.run(
                mw.function_middleware_invoke(
                    command="rm -rf /home/u",
                    call_next=target,
                    context=self._ctx("Bash"),
                )
            )
        self.assertEqual(
            executed["count"], 0,
            "denied function MUST NOT execute; side-effect counter would expose the bug",
        )
        self.assertIn("destructive", str(cm.exception).lower())

    def test_deny_write_to_protected_path(self) -> None:
        executed = {"count": 0}

        async def target(file_path: str, content: str) -> str:
            executed["count"] += 1
            return "wrote"

        mw = self._make_middleware()
        with self.assertRaises(ACSGuardianDenied):
            asyncio.run(
                mw.function_middleware_invoke(
                    file_path="/etc/passwd", content="x",
                    call_next=target,
                    context=self._ctx("Write"),
                )
            )
        self.assertEqual(executed["count"], 0)

    def test_guardian_unreachable_default_deny_blocks_function(self) -> None:
        executed = {"count": 0}

        async def target(command: str) -> str:
            executed["count"] += 1
            return "ran"

        mw = ACSMiddleware(ACSMiddlewareConfig(
            guardian_url="http://127.0.0.1:1/dead",
            default_deny=True, session_id="nat-live",
        ))
        with self.assertRaises(ACSGuardianDenied):
            asyncio.run(
                mw.function_middleware_invoke(
                    command="ls",
                    call_next=target,
                    context=self._ctx("Bash"),
                )
            )
        self.assertEqual(executed["count"], 0,
                         "fail-closed: function must not execute when Guardian unreachable")

    def test_guardian_unreachable_fail_open_runs_function(self) -> None:
        executed = {"count": 0}

        async def target(command: str) -> str:
            executed["count"] += 1
            return "ran"

        mw = ACSMiddleware(ACSMiddlewareConfig(
            guardian_url="http://127.0.0.1:1/dead",
            default_deny=False, session_id="nat-live",
        ))
        result = asyncio.run(
            mw.function_middleware_invoke(
                command="ls",
                call_next=target,
                context=self._ctx("Bash"),
            )
        )
        self.assertEqual(executed["count"], 1)
        self.assertEqual(result, "ran")


if __name__ == "__main__":
    unittest.main(verbosity=2)
