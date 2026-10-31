"""An answer that fails its checks never lets a protected NAT function run, whatever the HTTP status and even under fail-open."""
from __future__ import annotations

import asyncio
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from typing import Any, Callable
from unittest import mock

try:
    from nat.middleware.middleware import FunctionMiddlewareContext
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

from acs.client import _exchange
from acs.client import _handshake
from acs.core import derive_session_key, sign_with_key
from acs.integrations.nat.adapter import ACSGuardianDenied, ACSMiddleware
from acs.testing.harness import seed_negotiated_session

if _NAT_OK:
    from acs.integrations.nat.adapter import ACSMiddlewareConfig

SECRET = "nat-untrusted-answers"
FORGED = {"algorithm": "HMAC-SHA256", "value": "AAAA"}


class _Body:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self) -> bytes:
        return self.raw


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
@mock.patch.dict(os.environ, {"ACS_HMAC_SECRET": SECRET, "ACS_HMAC_SECRET_FILE": "",
                              "ACS_DISABLED": "", "ACS_STARTUP_POSTURE": ""})
class UntrustedAnswersNeverRunTheFunction(unittest.TestCase):
    def setUp(self) -> None:
        records = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(records.cleanup)
        self.records = Path(records.name)
        patcher = mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", self.records)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, answer: Callable[[dict], tuple[int, dict]], *, default_deny: bool = False) -> tuple[int, bool]:
        """Invoke a protected function through the middleware (fail-open unless default_deny); return how often it ran and whether NAT blocked it."""
        url = "http://127.0.0.1:9/acs"
        mw = ACSMiddleware(ACSMiddlewareConfig(guardian_url=url, default_deny=default_deny,
                                               session_id="nat-untrusted"))
        # The session already negotiated, so every request below is a step.
        seed_negotiated_session(self.records, session_id=mw._session_id, guardian_url=url,
                                hmac_secret=SECRET)
        key = derive_session_key(SECRET.encode(), mw._session_id)
        executed = {"count": 0}

        async def target(command: str) -> str:
            executed["count"] += 1
            return f"ran: {command}"

        def urlopen(req: Any, timeout: float) -> _Body:
            status, body = answer(json.loads(req.data))
            if body.get("sign"):
                body = sign_with_key(body["envelope"], key)
            raw = json.dumps(body).encode()
            if status == 200:
                return _Body(raw)
            raise urllib.error.HTTPError(req.full_url, status, "status", {}, io.BytesIO(raw))

        context = FunctionMiddlewareContext(name="Bash", config=None, description=None, input_schema=None,
                                            single_output_schema=type(None), stream_output_schema=type(None))
        with mock.patch.object(_exchange.urllib.request, "urlopen", side_effect=urlopen):
            try:
                asyncio.run(mw.function_middleware_invoke(command="rm -rf /srv/data",
                                                          call_next=target, context=context))
            except ACSGuardianDenied:
                return executed["count"], True
        return executed["count"], False

    @staticmethod
    def _bound_result(request: dict, **extra: Any) -> dict:
        return {"jsonrpc": "2.0", "id": request["id"],
                "result": {"request_id": request["params"]["request_id"], "decision": "allow", **extra}}

    @staticmethod
    def _bound_error(request: dict, code: int) -> dict:
        return {"jsonrpc": "2.0", "id": request["id"], "error": {"code": code, "message": "internal error"}}

    def test_a_signed_allow_runs_the_function(self) -> None:
        """Control: the harness can run the function, so a zero count below means a block."""
        count, blocked = self._run(lambda r: (200, {"sign": True, "envelope": self._bound_result(r)}))
        self.assertEqual((count, blocked), (1, False))

    def test_a_forged_signature_over_an_unencodable_integer_never_runs_it(self) -> None:
        def answer(request: dict) -> tuple[int, dict]:
            response = self._bound_result(request, n=2**53)
            response["result"]["signature"] = FORGED
            return 200, response
        self.assertEqual(self._run(answer), (0, True))

    def test_an_unsigned_error_never_runs_it_under_any_status(self) -> None:
        for status in (200, 400, 413, 500, 503):
            with self.subTest(status=status):
                count, blocked = self._run(lambda r: (status, self._bound_error(r, -32603)))
                self.assertEqual((count, blocked), (0, True))

    def test_a_non_jsonrpc_400_or_413_body_never_runs_it(self) -> None:
        for status in (400, 413):
            for body in ({"detail": "Bad Request"}, {"error": "Bad Request"}, {"error": None},
                         {"jsonrpc": "2.0", "error": "Bad Request"}):
                with self.subTest(status=status, body=body):
                    self.assertEqual(self._run(lambda r: (status, body)), (0, True))

    def test_a_non_jsonrpc_503_body_follows_the_posture(self) -> None:
        """A 503 without a JSON-RPC response is a decision failure: fail-open runs the function, fail-closed blocks it."""
        answer = lambda r: (503, {"error": "Service Unavailable"})  # noqa: E731
        self.assertEqual(self._run(answer), (1, False))
        self.assertEqual(self._run(answer, default_deny=True), (0, True))

    def test_a_verifier_that_raises_never_runs_it(self) -> None:
        with mock.patch.object(_exchange, "verify_signature", side_effect=RuntimeError("verifier bug")):
            count, blocked = self._run(lambda r: (200, {"sign": True, "envelope": self._bound_result(r)}))
        self.assertEqual((count, blocked), (0, True))


if __name__ == "__main__":
    unittest.main()
