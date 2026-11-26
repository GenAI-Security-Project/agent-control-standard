# SPDX-License-Identifier: Apache-2.0
"""Security, failure-mode, disposition, and event-loop invariants for the FastMCP adapter."""
from __future__ import annotations

import asyncio
import os
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

from acs.client import _handshake as client_handshake
from acs.core import GUARDIAN_REFUSAL_CODES
from acs.integrations.fastmcp.adapter import (
    ACSFastMCPMiddleware,
    ACSGuardianDenied,
    GovernedFastMCPClient,
)
from acs.testing.harness import ProgrammableGuardian

SECRET = "fastmcp-adapter-test-secret-padded-to-32-bytes"
SLOW_S = 0.4


@dataclass
class _FakeCallParams:
    name: str
    arguments: dict[str, Any] | None = None


@dataclass
class _FakeContext:
    message: _FakeCallParams


async def _ticking(coro: Any) -> tuple[Any, int]:
    """Run coro while counting 10 ms event-loop turns; a blocked loop stops ticking."""
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


class FastMCPAdapterInvariants(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-fastmcp-hs-")
        self.addCleanup(records.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        env.update(
            {
                "ACS_HMAC_SECRET": SECRET,
                "ACS_HMAC_KEY_ID": "test-key",
                "ACS_HANDSHAKE_TIMEOUT_SECONDS": "5",
            }
        )
        for patcher in (
            mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", Path(records.name)),
            mock.patch.dict(os.environ, env, clear=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        self.guardian = ProgrammableGuardian(hmac_secret=SECRET)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)

    def test_acs_disabled_env_bypasses_guardian_completely(self) -> None:
        """ACS_DISABLED=1 must be respected even when guardian_url/default_deny kwargs are passed."""
        os.environ["ACS_DISABLED"] = "1"
        executed = 0

        async def call_next(ctx: _FakeContext) -> str:
            nonlocal executed
            executed += 1
            return "ran"

        async def run() -> str:
            async with ACSFastMCPMiddleware(guardian_url=self.guardian.url(), default_deny=True) as mw:
                return await mw.on_call_tool(_FakeContext(_FakeCallParams("echo", {"x": 1})), call_next)

        self.assertEqual(asyncio.run(run()), "ran")
        self.assertEqual(executed, 1)
        self.assertEqual(self.guardian.methods_seen(), [])

    def test_three_calls_in_one_scope_perform_one_handshake(self) -> None:
        async def call_next(ctx: _FakeContext) -> str:
            return f"ok:{ctx.message.name}"

        async def run() -> list[str]:
            async with ACSFastMCPMiddleware(guardian_url=self.guardian.url()) as mw:
                out = []
                for idx in range(3):
                    out.append(await mw.on_call_tool(_FakeContext(_FakeCallParams(f"tool_{idx}", {})), call_next))
                return out

        self.assertEqual(asyncio.run(run()), ["ok:tool_0", "ok:tool_1", "ok:tool_2"])
        self.assertEqual(self.guardian.methods_seen().count("handshake/hello"), 1)
        self.assertEqual(self.guardian.methods_seen().count("steps/sessionStart"), 1)
        self.assertEqual(self.guardian.methods_seen().count("steps/toolCallRequest"), 3)
        self.assertEqual(self.guardian.methods_seen().count("steps/toolCallResult"), 3)
        self.assertEqual(self.guardian.methods_seen().count("steps/sessionEnd"), 1)

    def test_concurrent_calls_share_one_handshake_without_blocking_event_loop(self) -> None:
        def slow_handshake(req: dict) -> dict:
            time.sleep(SLOW_S)
            return self.guardian._default_handshake(req)

        self.guardian.handlers["handshake/hello"] = slow_handshake
        executed = 0

        async def call_next(ctx: _FakeContext) -> str:
            nonlocal executed
            executed += 1
            return ctx.message.name

        async def run() -> list[str]:
            mw = ACSFastMCPMiddleware(guardian_url=self.guardian.url())
            try:
                return await asyncio.gather(
                    *(mw.on_call_tool(_FakeContext(_FakeCallParams(f"t{i}", {})), call_next) for i in range(5))
                )
            finally:
                await mw.aclose()

        results, ticks = asyncio.run(_ticking(run()))
        self.assertEqual(results, ["t0", "t1", "t2", "t3", "t4"])
        self.assertEqual(executed, 5)
        self.assertEqual(self.guardian.methods_seen().count("handshake/hello"), 1)
        self.assertGreater(ticks, 8, "event loop stalled during handshake")

    def test_tool_exception_propagates_unchanged_not_as_guardian_deny(self) -> None:
        """An allowed tool raising ValueError must propagate as ValueError, never ACSGuardianDenied."""
        async def exploding(ctx: _FakeContext) -> str:
            raise ValueError("database offline")

        async def run() -> None:
            async with ACSFastMCPMiddleware(guardian_url=self.guardian.url()) as mw:
                await mw.on_call_tool(_FakeContext(_FakeCallParams("query_db", {"sql": "SELECT 1"})), exploding)

        with self.assertRaises(ValueError) as cm:
            asyncio.run(run())
        self.assertEqual(str(cm.exception), "database offline")
        self.assertNotIsInstance(cm.exception, ACSGuardianDenied)

        # Tool failure still emitted steps/toolCallResult with exit_status="failure".
        result_reqs = [r for r in self.guardian.received if r.get("method") == "steps/toolCallResult"]
        self.assertEqual(len(result_reqs), 1)
        self.assertEqual(result_reqs[0]["params"]["payload"]["exit_status"], "failure")

    def test_guardian_refusal_codes_always_fail_closed_even_when_default_deny_is_false(self) -> None:
        """Every §17.1 GUARDIAN_REFUSAL_CODES error blocks even under ACS_DEFAULT_DENY=0."""
        os.environ["ACS_DEFAULT_DENY"] = "0"
        for code in sorted(GUARDIAN_REFUSAL_CODES):
            with self.subTest(code=code):
                self.guardian.reset()
                self.guardian.handlers["steps/toolCallRequest"] = lambda req, c=code: {
                    "code": c,
                    "message": f"refusal {c}",
                }
                executed = 0

                async def call_next(ctx: _FakeContext) -> str:
                    nonlocal executed
                    executed += 1
                    return "must-not-run"

                async def run() -> None:
                    async with ACSFastMCPMiddleware(guardian_url=self.guardian.url(), default_deny=False) as mw:
                        await mw.on_call_tool(_FakeContext(_FakeCallParams("danger", {})), call_next)

                with self.assertRaises(ACSGuardianDenied):
                    asyncio.run(run())
                self.assertEqual(executed, 0)

    def test_unsigned_response_fails_closed(self) -> None:
        unsigned = ProgrammableGuardian(hmac_secret=SECRET, sign_responses=False)
        unsigned.start()
        self.addCleanup(unsigned.stop)
        executed = 0

        async def call_next(ctx: _FakeContext) -> str:
            nonlocal executed
            executed += 1
            return "must-not-run"

        async def run() -> None:
            async with ACSFastMCPMiddleware(guardian_url=unsigned.url(), default_deny=False) as mw:
                await mw.on_call_tool(_FakeContext(_FakeCallParams("echo", {})), call_next)

        with self.assertRaises(ACSGuardianDenied):
            asyncio.run(run())
        self.assertEqual(executed, 0)

    def test_unreachable_guardian_respects_startup_posture(self) -> None:
        down = ProgrammableGuardian(hmac_secret=SECRET)
        down._server.server_close()

        # Default startup posture refuses.
        executed = 0

        async def call_next(ctx: _FakeContext) -> str:
            nonlocal executed
            executed += 1
            return "ran"

        async def run_default() -> str:
            async with ACSFastMCPMiddleware(guardian_url=down.url()) as mw:
                return await mw.on_call_tool(_FakeContext(_FakeCallParams("echo", {})), call_next)

        with self.assertRaises(ACSGuardianDenied):
            asyncio.run(run_default())
        self.assertEqual(executed, 0)

        # Explicit ACS_STARTUP_POSTURE=proceed honors env switch via Config.from_env.
        os.environ["ACS_STARTUP_POSTURE"] = "proceed"

        async def run_proceed() -> str:
            async with ACSFastMCPMiddleware(guardian_url=down.url()) as mw:
                return await mw.on_call_tool(_FakeContext(_FakeCallParams("echo", {})), call_next)

        self.assertEqual(asyncio.run(run_proceed()), "ran")
        self.assertEqual(executed, 1)

    def test_dispositions_deny_ask_defer_and_modify(self) -> None:
        for disp in ("deny", "ask", "defer"):
            with self.subTest(disposition=disp):
                self.guardian.reset()
                self.guardian.handlers["steps/toolCallRequest"] = lambda req, d=disp: {
                    "request_id": req["params"]["request_id"],
                    "decision": d,
                    "reasoning": f"policy {d}",
                }
                executed = 0

                async def call_next(ctx: _FakeContext) -> str:
                    nonlocal executed
                    executed += 1
                    return "must-not-run"

                async def run() -> None:
                    async with ACSFastMCPMiddleware(guardian_url=self.guardian.url()) as mw:
                        await mw.on_call_tool(_FakeContext(_FakeCallParams("shell", {"cmd": "rm -rf /"})), call_next)

                with self.assertRaises(ACSGuardianDenied):
                    asyncio.run(run())
                self.assertEqual(executed, 0)

    def test_modify_parameter_overrides_and_output_rewrite(self) -> None:
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: {
            "request_id": req["params"]["request_id"],
            "decision": "modify",
            "reasoning": "clamp limit",
            "modifications": {"parameter_overrides": {"limit": 10}},
        }
        self.guardian.handlers["steps/toolCallResult"] = lambda req: {
            "request_id": req["params"]["request_id"],
            "decision": "modify",
            "reasoning": "redact secret",
            "modifications": {"modified_content": "[redacted]"},
        }
        seen_args: list[dict[str, Any]] = []

        async def call_next(ctx: _FakeContext) -> str:
            seen_args.append(dict(ctx.message.arguments or {}))
            return "SECRET_TOKEN=12345"

        async def run() -> Any:
            async with ACSFastMCPMiddleware(guardian_url=self.guardian.url()) as mw:
                return await mw.on_call_tool(
                    _FakeContext(_FakeCallParams("query", {"q": "users", "limit": 9999})),
                    call_next,
                )

        out = asyncio.run(run())
        self.assertEqual(seen_args, [{"q": "users", "limit": 10}])
        self.assertEqual(out, "[redacted]")

    def test_modify_composition_violation_fails_closed(self) -> None:
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: {
            "request_id": req["params"]["request_id"],
            "decision": "modify",
            "reasoning": "invalid mixed modify",
            "modifications": {
                "modified_content": "wholesale",
                "parameter_overrides": {"x": 1},
            },
        }
        executed = 0

        async def call_next(ctx: _FakeContext) -> str:
            nonlocal executed
            executed += 1
            return "must-not-run"

        async def run() -> None:
            async with ACSFastMCPMiddleware(guardian_url=self.guardian.url()) as mw:
                await mw.on_call_tool(_FakeContext(_FakeCallParams("query", {"x": 0})), call_next)

        with self.assertRaises(ACSGuardianDenied) as cm:
            asyncio.run(run())
        self.assertEqual(cm.exception.cause, "modify_unsupported")
        self.assertEqual(executed, 0)

    def test_key_collision_fails_closed_before_sending(self) -> None:
        """Dict with keys {1: 'a', '1': 'b'} collides in JSON and must fail closed without sending."""
        executed = 0

        async def call_next(ctx: _FakeContext) -> str:
            nonlocal executed
            executed += 1
            return "must-not-run"

        async def run() -> None:
            async with ACSFastMCPMiddleware(guardian_url=self.guardian.url(), default_deny=False) as mw:
                await mw.on_call_tool(
                    _FakeContext(_FakeCallParams("parse", {1: "a", "1": "b"})),  # type: ignore[dict-item]
                    call_next,
                )

        with self.assertRaises(ACSGuardianDenied) as cm:
            asyncio.run(run())
        self.assertEqual(cm.exception.cause, "envelope_not_signable")
        self.assertEqual(executed, 0)
        self.assertNotIn("steps/toolCallRequest", self.guardian.methods_seen())

    def test_call_after_close_is_refused(self) -> None:
        class _Dummy:
            async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
                return "ran"

        async def run() -> None:
            client = GovernedFastMCPClient(_Dummy(), guardian_url=self.guardian.url())
            await client.aclose()
            await client.call_tool("echo", {"x": 1})

        with self.assertRaises(ACSGuardianDenied) as cm:
            asyncio.run(run())
        self.assertEqual(cm.exception.cause, "session_closed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
