# SPDX-License-Identifier: Apache-2.0
"""Live in-memory FastMCP server + Client tests against acs-example-guardian and ProgrammableGuardian."""
from __future__ import annotations

import asyncio
import http.server
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastmcp import Client, FastMCP
    from fastmcp.exceptions import ToolError

    _FASTMCP_OK = True
except ImportError:
    _FASTMCP_OK = False

from acs.client import _handshake as client_handshake
from acs.guardian import example_guardian
from acs.integrations.fastmcp.adapter import (
    ACSFastMCPMiddleware,
    ACSGuardianDenied,
    GovernedFastMCPClient,
)
from acs.testing.capture_guardian import CaptureGuardian
from acs.testing.harness import signing_env

SECRET = "fastmcp-live-secret-padded-to-32-bytes"


@unittest.skipUnless(_FASTMCP_OK, "fastmcp not installed (install with: uv sync --extra fastmcp)")
class LiveFastMCPIntegration(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-fastmcp-live-")
        self.addCleanup(records.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        env.update(signing_env())
        for patcher in (
            mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", Path(records.name)),
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(example_guardian, "OPA_CONFIG", None),
            mock.patch.object(example_guardian, "POLICY_BACKEND_NAME", ""),
            mock.patch.object(example_guardian, "PERSIST_ENABLED", False),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        self._server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), example_guardian.GuardianHandler
        )
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.addCleanup(self._stop_server)
        host, port = self._server.server_address
        self.guardian_url = f"http://{host}:{port}/acs"

    def _stop_server(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def test_server_middleware_with_real_fastmcp_and_example_guardian(self) -> None:
        """Real FastMCP server + Client(mcp) + real acs-example-guardian (signed HMAC-SHA256)."""
        executed: list[str] = []
        mcp = FastMCP("acs-live-server")
        mw = ACSFastMCPMiddleware(guardian_url=self.guardian_url)
        mcp.add_middleware(mw)

        @mcp.tool
        def Bash(command: str) -> str:
            executed.append(command)
            return f"ran: {command}"

        @mcp.tool
        def exploding(x: str) -> str:
            raise ValueError(f"boom:{x}")

        async def run() -> None:
            async with mw, Client(mcp) as client:
                # Benign call -> allowed by acs-example-guardian.
                res = await client.call_tool("Bash", {"command": "echo hello"})
                self.assertEqual(res.data, "ran: echo hello")

                # Destructive command -> denied pre-execution by acs-example-guardian.
                with self.assertRaises(ToolError) as denied:
                    await client.call_tool("Bash", {"command": "rm -rf /"})
                self.assertIn("ACS Guardian blocked", str(denied.exception))

                # Allowed tool raising ValueError -> propagates tool error, not ACS Guardian blocked.
                with self.assertRaises(ToolError) as err:
                    await client.call_tool("exploding", {"x": "db"})
                self.assertIn("boom:db", str(err.exception))
                self.assertNotIn("ACS Guardian blocked", str(err.exception))

        asyncio.run(run())
        self.assertEqual(executed, ["echo hello"], "denied destructive command must never execute")

    def test_client_wrapper_with_real_fastmcp_and_example_guardian(self) -> None:
        """Real GovernedFastMCPClient wrapping fastmcp.Client(mcp) against acs-example-guardian."""
        executed: list[str] = []
        mcp = FastMCP("acs-live-client-target")

        @mcp.tool
        def Bash(command: str) -> str:
            executed.append(command)
            return f"ok:{command}"

        async def run() -> None:
            async with GovernedFastMCPClient(Client(mcp), guardian_url=self.guardian_url) as client:
                r1 = await client.call_tool("Bash", {"command": "ls -la"})
                self.assertEqual(r1.data, "ok:ls -la")

                with self.assertRaises(ACSGuardianDenied):
                    await client.call_tool("Bash", {"command": "rm -rf /"})

        asyncio.run(run())
        self.assertEqual(executed, ["ls -la"])

    def test_real_fastmcp_modify_args_modify_output_and_withhold_with_capture_guardian(self) -> None:
        """Verify live FastMCP ToolResult rewriting, argument overrides, and schema-valid emission."""
        os.environ["ACS_HMAC_SECRET"] = SECRET
        os.environ["ACS_HMAC_KEY_ID"] = "test-key"
        guardian = CaptureGuardian(hmac_secret=SECRET)
        guardian.start()
        self.addCleanup(guardian.stop)

        def on_req(req: dict) -> dict:
            tool = req["params"]["payload"]["tool"]["name"]
            if tool == "search":
                return {
                    "request_id": req["params"]["request_id"],
                    "decision": "modify",
                    "reasoning": "cap page size",
                    "modifications": {"parameter_overrides": {"limit": 5}},
                }
            return guardian._default_allow(req)

        def on_res(req: dict) -> dict:
            tool = req["params"]["payload"]["tool"]["name"]
            if tool == "read_secret":
                return {
                    "request_id": req["params"]["request_id"],
                    "decision": "modify",
                    "reasoning": "redact token",
                    "modifications": {"modified_content": "[REDACTED]"},
                }
            if tool == "forbidden_output":
                return {
                    "request_id": req["params"]["request_id"],
                    "decision": "deny",
                    "reasoning": "sensitive output",
                }
            return guardian._default_allow(req)

        guardian.handlers["steps/toolCallRequest"] = on_req
        guardian.handlers["steps/toolCallResult"] = on_res

        mcp = FastMCP("acs-live-modify")
        mw = ACSFastMCPMiddleware(guardian_url=guardian.url())
        mcp.add_middleware(mw)

        @mcp.tool
        def search(query: str, limit: int = 100) -> str:
            return f"{query}:{limit}"

        @mcp.tool
        def read_secret() -> str:
            return "sk-live-secret-999"

        @mcp.tool
        def forbidden_output() -> str:
            return "confidential-payload"

        async def run() -> None:
            async with mw, Client(mcp) as client:
                r1 = await client.call_tool("search", {"query": "acs", "limit": 500})
                self.assertEqual(r1.data, "acs:5")

                r2 = await client.call_tool("read_secret", {})
                self.assertEqual(r2.data, "[REDACTED]")

                with self.assertRaises(ToolError) as withheld:
                    await client.call_tool("forbidden_output", {})
                self.assertIn("withheld by ACS Guardian", str(withheld.exception))

        asyncio.run(run())
        guardian.assert_all_valid(self)
        self.assertEqual(len(guardian.records_for("handshake/hello")), 1)
        self.assertEqual(len(guardian.records_for("steps/toolCallRequest")), 3)
        self.assertEqual(len(guardian.records_for("steps/toolCallResult")), 3)
        self.assertEqual(len(guardian.records_for("steps/sessionEnd")), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
