"""With response signing off, acs.client sends and accepts exactly what it did before issue #576."""
from __future__ import annotations

import builtins
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from acs.client import Config, Decided, Negotiated, open_session, response_keys_from_env, round_trip
from acs.client import _exchange, _handshake
from acs.testing.harness import signing_env
from tests.client.test_on_wire import (
    PROCEED,
    SESSION,
    URL,
    Recorder,
    decision_for,
    decoded,
    server_hello_for,
    step_request,
)


class ResponseSigningOff(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="acs-signing-off-")
        self.addCleanup(temporary.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.dict(os.environ, {**env, **signing_env()}, clear=True),
                        mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(temporary.name))):
            patcher.start()
            self.addCleanup(patcher.stop)
        mock.patch.object(_handshake, "audit_event").start()
        self.addCleanup(mock.patch.stopall)

    def test_the_client_hello_carries_no_lab_field(self) -> None:
        recorder = Recorder()
        config = Config.from_env({"ACS_GUARDIAN_URL": URL})
        with mock.patch.object(_handshake, "post", side_effect=decoded(lambda h, **_: server_hello_for(h))):
            decision = open_session(config=config, session_id=SESSION, agent_id="test", platform="test",
                                    methods_implemented=["steps/toolCallRequest"], on_wire=recorder)
        self.assertIsInstance(decision, Negotiated)
        payload = recorder.calls[0][1]["params"]["payload"]
        self.assertNotIn("x_acs_lab_response_algorithms", payload)
        self.assertEqual(payload["signature_algorithms_supported"], ["HMAC-SHA256"])

    def test_default_arguments_change_nothing(self) -> None:
        outcomes = []
        for kwargs in ({}, {"on_wire": None, "response_keys": None}):
            request = step_request()
            with mock.patch.object(_exchange, "post", side_effect=decoded(lambda r, **_: decision_for(r))):
                outcome: Any = round_trip(request, guardian_url=URL, posture=PROCEED, session_id=SESSION, **kwargs)
            self.assertIsInstance(outcome, Decided)
            outcomes.append(outcome.response["result"]["decision"])
        self.assertEqual(outcomes, ["allow", "allow"])

    def test_env_off_needs_no_extra(self) -> None:
        real_import = builtins.__import__

        def no_cryptography(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError(f"blocked {name}")
            return real_import(name, *args, **kwargs)

        with mock.patch.object(builtins, "__import__", side_effect=no_cryptography):
            self.assertIsNone(response_keys_from_env({}))
            self.assertIsNone(response_keys_from_env({"ACS_RESPONSE_ALGORITHMS": "HMAC-SHA256"}))

    def test_importing_the_key_document_module_loads_no_cryptography(self) -> None:
        code = ("import sys, acs.client._key_document, acs.client._exchange, acs.client._handshake; "
                "print(any(m == 'cryptography' or m.startswith('cryptography.') for m in sys.modules))")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.strip(), "False")


if __name__ == "__main__":
    unittest.main()
