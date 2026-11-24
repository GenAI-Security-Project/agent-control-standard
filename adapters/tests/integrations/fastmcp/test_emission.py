# SPDX-License-Identifier: Apache-2.0
"""FastMCP emission conformance: validates every wire byte via CaptureGuardian against canonical schemas."""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

from acs.client import _handshake as client_handshake
from acs.integrations.fastmcp.adapter import (
    ACSFastMCPMiddleware,
    GovernedFastMCPClient,
)
from acs.testing.capture_guardian import CaptureGuardian

HMAC = "fastmcp-emission-shared-secret-padded-to-32-bytes"


@dataclass
class _FakeCallParams:
    name: str
    arguments: dict[str, Any] | None = None


@dataclass
class _FakeContext:
    message: _FakeCallParams


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        args = dict(arguments or {})
        self.calls.append((name, args))
        return {"ok": True, "tool": name, "args": args}


class FastMCPEmission(unittest.TestCase):
    def setUp(self) -> None:
        self.guardian = CaptureGuardian(hmac_secret=HMAC)
        self.guardian.start()
        self.addCleanup(self.guardian.stop)

        records = tempfile.TemporaryDirectory(prefix="acs-fastmcp-handshake-")
        self.addCleanup(records.cleanup)
        self.records = Path(records.name)

        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        env["ACS_HMAC_SECRET"] = HMAC
        env["ACS_HMAC_KEY_ID"] = "test-key"
        for patcher in (
            mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", self.records),
            mock.patch.dict(os.environ, env, clear=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_middleware_full_session_emission_and_invariants(self) -> None:
        """One middleware session: one handshake, unique request_ids, request_id_ref link, advertised == emitted."""
        async def run() -> Any:
            async with ACSFastMCPMiddleware(guardian_url=self.guardian.url()) as mw:
                ctx = _FakeContext(message=_FakeCallParams(name="weather_lookup", arguments={"city": "Buenos Aires"}))

                async def call_next(c: _FakeContext) -> dict[str, str]:
                    return {"forecast": f"sunny in {c.message.arguments['city']}"}

                return await mw.on_call_tool(ctx, call_next)

        out = asyncio.run(run())
        self.assertEqual(out, {"forecast": "sunny in Buenos Aires"})
        self.guardian.assert_all_valid(self)
        self.assertEqual(
            self.guardian.methods(),
            [
                "handshake/hello",
                "steps/sessionStart",
                "steps/toolCallRequest",
                "steps/toolCallResult",
                "steps/sessionEnd",
            ],
        )
        self.assertEqual(self.guardian.duplicate_request_ids(), [])
        req_id = self.guardian.request_id_for("steps/toolCallRequest")
        ref = self.guardian.payload_of("steps/toolCallResult").get("request_id_ref")
        self.assertIsNotNone(req_id)
        self.assertEqual(ref, req_id)

        advertised = set(self.guardian.handshake_methods_implemented())
        emitted = {m for m in self.guardian.methods() if m != "handshake/hello"}
        self.assertEqual(advertised, emitted)

    def test_client_wrapper_full_session_emission_and_invariants(self) -> None:
        """GovernedFastMCPClient emits schema-valid envelopes with one handshake across multiple calls."""
        fake = _FakeClient()

        async def run() -> list[dict[str, Any]]:
            async with GovernedFastMCPClient(fake, guardian_url=self.guardian.url()) as client:
                r1 = await client.call_tool("search_docs", {"q": "acs"})
                r2 = await client.call_tool("read_doc", {"id": 42})
                r3 = await client.call_tool("list_tags", {})
                return [r1, r2, r3]

        results = asyncio.run(run())
        self.assertEqual(len(results), 3)
        self.assertEqual(len(fake.calls), 3)
        self.guardian.assert_all_valid(self)
        self.assertEqual(len(self.guardian.records_for("handshake/hello")), 1)
        self.assertEqual(len(self.guardian.records_for("steps/sessionStart")), 1)
        self.assertEqual(len(self.guardian.records_for("steps/toolCallRequest")), 3)
        self.assertEqual(len(self.guardian.records_for("steps/toolCallResult")), 3)
        self.assertEqual(len(self.guardian.records_for("steps/sessionEnd")), 1)
        self.assertEqual(self.guardian.duplicate_request_ids(), [])

        req_ids = [
            (r.parsed.get("params") or {}).get("request_id")
            for r in self.guardian.records_for("steps/toolCallRequest")
        ]
        refs = [
            ((r.parsed.get("params") or {}).get("payload") or {}).get("request_id_ref")
            for r in self.guardian.records_for("steps/toolCallResult")
        ]
        self.assertEqual(refs, req_ids)

        end_payload = self.guardian.payload_of("steps/sessionEnd")
        self.assertEqual(end_payload["reason"], "completed")
        self.assertEqual(end_payload["summary"]["step_count"], 6)
        self.assertEqual(end_payload["summary"]["decision_failures"], {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
