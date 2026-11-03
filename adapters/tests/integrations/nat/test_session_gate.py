"""§4.1 through the NAT middleware: the first handshake decides the session, and a later middleware that finds the session's stored decision follows it."""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

try:
    from nat.middleware.middleware import FunctionMiddlewareContext
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _handshake
from acs.integrations.nat.adapter import ACSGuardianDenied, ACSMiddleware
from acs.testing.harness import ProgrammableGuardian

if _NAT_OK:
    from acs.integrations.nat.adapter import ACSMiddlewareConfig

SECRET = "nat-session-gate-secret-padded-to-32-bytes"


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class SessionGateThroughNat(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        self.records = Path(records.name)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", self.records),
                        mock.patch.dict(os.environ, {**env, "ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "test-key",
                                                     "ACS_HANDSHAKE_TIMEOUT_SECONDS": "2"}, clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _run(self, url: str, session: str, *, default_deny: bool = False) -> tuple[int, bool]:
        """Invoke a protected function through a new middleware for the session; return how often it ran and whether NAT blocked it."""
        mw = ACSMiddleware(ACSMiddlewareConfig(guardian_url=url, default_deny=default_deny))
        # Each middleware's own session id is fresh; reusing one is how a stored decision would be found again.
        mw._session_id = session
        executed = {"count": 0}

        async def target(command: str) -> str:
            executed["count"] += 1
            return f"ran: {command}"

        context = FunctionMiddlewareContext(name="Bash", config=None, description=None, input_schema=None,
                                            single_output_schema=type(None), stream_output_schema=type(None))
        try:
            asyncio.run(mw.function_middleware_invoke(command="echo hi", call_next=target, context=context))
        except ACSGuardianDenied:
            return executed["count"], True
        # Ends the session on the wire and keeps its records, as another process sharing the session would find them.
        mw._emit_lifecycle_hook("steps/sessionEnd", {"reason": "completed"}, mw._own)
        return executed["count"], False

    def test_an_unguarded_session_never_contacts_a_restored_guardian(self) -> None:
        down = ProgrammableGuardian(hmac_secret=SECRET)
        down._server.server_close()
        session = str(uuid.uuid4())
        self.assertEqual(self._run(down.url(), session), (1, False),
                         "a session started unguarded under proceed runs its steps")

        guardian = ProgrammableGuardian(hmac_secret=SECRET, port=down.port)
        guardian.start()
        self.addCleanup(guardian.stop)
        for record in self.records.glob("*.json"):
            os.utime(record, (0, 0))
        self.assertEqual(self._run(guardian.url(), session), (1, False))
        self.assertEqual(guardian.methods_seen(), [],
            "no handshake, step or lifecycle request for a session that started unguarded")

        self.assertEqual(self._run(guardian.url(), str(uuid.uuid4())), (1, False))
        self.assertEqual(guardian.methods_seen(),
                         ["handshake/hello", "steps/sessionStart", "steps/toolCallRequest", "steps/toolCallResult",
                          "steps/sessionEnd"])

    def test_a_refused_session_never_runs_the_function(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.handlers["handshake/hello"] = lambda req: {"code": -32000, "message": "agent not permitted"}
        guardian.start()
        self.addCleanup(guardian.stop)
        session = str(uuid.uuid4())
        self.assertEqual(self._run(guardian.url(), session), (0, True))
        self.assertEqual(guardian.methods_seen(), ["handshake/hello"])
        guardian.reset()
        self.assertEqual(self._run(guardian.url(), session), (0, True))
        self.assertEqual(guardian.methods_seen(), [])

    def _refusing(self) -> ProgrammableGuardian:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.handlers["handshake/hello"] = lambda req: {"code": -32000, "message": "agent not permitted"}
        guardian.start()
        self.addCleanup(guardian.stop)
        return guardian

    def _record(self, session: str, url: str) -> Path:
        return _handshake._handshake_cache_path(session, url, self.records)

    def test_a_damaged_refusal_record_never_runs_the_function(self) -> None:
        guardian = self._refusing()
        session = str(uuid.uuid4())
        self.assertEqual(self._run(guardian.url(), session), (0, True))
        record = self._record(session, guardian.url())
        record.write_bytes(record.read_bytes()[:20])
        guardian.reset()
        self.assertEqual(self._run(guardian.url(), session), (0, True))
        self.assertEqual(guardian.methods_seen(), [], "a damaged record must not trigger another handshake")

    def test_a_record_copied_from_another_endpoint_never_runs_the_function(self) -> None:
        down = ProgrammableGuardian(hmac_secret=SECRET)
        down._server.server_close()
        guardian = self._refusing()
        session = str(uuid.uuid4())
        self.assertEqual(self._run(down.url(), session), (1, False))
        self.assertEqual(self._run(guardian.url(), session), (0, True))
        self._record(session, guardian.url()).write_bytes(self._record(session, down.url()).read_bytes())
        guardian.reset()
        self.assertEqual(self._run(guardian.url(), session), (0, True),
            "another endpoint's no-negotiated-Guardian record must not unblock this endpoint's refusal")
        self.assertEqual(guardian.methods_seen(), [])

    def test_a_decision_that_cannot_be_stored_never_runs_the_function(self) -> None:
        down = ProgrammableGuardian(hmac_secret=SECRET)
        down._server.server_close()
        with mock.patch.object(_handshake.tempfile, "mkstemp", side_effect=OSError(28, "No space left on device")):
            self.assertEqual(self._run(down.url(), str(uuid.uuid4())), (0, True),
                "an unrecorded no-answer decision must fail closed, even under fail-open")


if __name__ == "__main__":
    unittest.main()
