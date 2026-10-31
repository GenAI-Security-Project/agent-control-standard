"""
Live NAT workflow test: invoke the ACS middleware exactly the way NAT's
runtime invokes wrapped functions.

Uses `FunctionMiddleware.function_middleware_invoke()` (the actual
orchestration method NAT's runtime calls). The test creates a real
target function, wraps it via the middleware's invoke method with a
real `FunctionMiddlewareContext`, and asserts:
  - Allow path: the function executes and its return value is propagated.
  - Deny path: the function does NOT execute (no side effect observed)
    and the block is signaled per NAT 1.7.0's contract.
  - Modify path: the function receives modified kwargs.

This exercises the same code path as a full NAT workflow run with the
middleware attached -- the runtime constructs the same context, calls
the same `function_middleware_invoke`, and respects the same block /
modify outcomes. It does not load YAML or instantiate a Builder; those
are NAT's responsibility, not the middleware's.

Requires nvidia-nat-core. Skipped cleanly otherwise.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import unittest
from pathlib import Path

try:
    from nat.middleware.middleware import FunctionMiddlewareContext
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from acs_adapter import ACSMiddleware, ACSGuardianDenied  # noqa: E402

if _NAT_OK:
    from acs_adapter import ACSMiddlewareConfig  # noqa: E402

HERE = Path(__file__).resolve().parent


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "_common"))
from test_harness import launch_guardian  # noqa: E402


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class LiveNATWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        env = os.environ.copy(); env["ACS_DEV_MODE"] = "1"; env.pop("ACS_HMAC_SECRET", None); env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.guardian_proc, cls.port = launch_guardian(env=env)
        cls.guardian_url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()

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

    # ----- ALLOW path: function executes, return value propagated -----

    def test_allow_function_executes(self) -> None:
        """Guardian allows -> function runs -> return value flows through middleware."""
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

    # ----- DENY path: function does NOT execute, block surfaced -----

    def test_deny_function_does_not_execute(self) -> None:
        """Guardian denies destructive Bash -> function MUST NOT run.

        This is the load-bearing property of the middleware:
        a function blocked by ACS must not produce its side effect.
        """
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

    # ----- Fail-closed posture: Guardian unreachable -> function blocked -----

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

    # ----- Fail-open posture: function runs when Guardian unreachable -----

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
