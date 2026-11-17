"""Go's crypto/mldsa, an implementation outside the library under test, accepts acs.core's ML-DSA-65 signatures.

Issue #574 done_when. This module sits outside every suite run_conformance.py runs, because CI
runners don't promise Go 1.26. Run it with `uv run --extra pqc python -m pytest tests/interop -v`
from adapters/. Without Go it skips and says why.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.pqc_extra import require_pqc

require_pqc()

from acs.core import MLDSA65SigningKey, sign_with_signing_key, signing_input  # noqa: E402

GO_SOURCE = Path(__file__).resolve().parent / "mldsa" / "main.go"
SEED = bytes(range(32))
KEY_ID = "lab-guardian-1"
# GOTOOLCHAIN=local stops go from downloading a toolchain the test didn't ask for.
GO_ENV = {**os.environ, "GOTOOLCHAIN": "local"}


def _go_problem() -> str | None:
    go = shutil.which("go")
    if go is None:
        return "go is not on PATH: the ML-DSA-65 interop check needs Go 1.26 or later (crypto/mldsa)"
    probe = subprocess.run([go, "list", "crypto/mldsa"], capture_output=True, text=True, env=GO_ENV, timeout=60)
    if probe.returncode != 0:
        return "this Go has no crypto/mldsa: the ML-DSA-65 interop check needs Go 1.26 or later"
    return None


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@unittest.skipIf(_go_problem() is not None, _go_problem() or "")
class GoCryptoMldsaAcceptsTheLibrary(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls._tmp.name) / "mldsa"
        subprocess.run(["go", "build", "-o", str(cls.binary), str(GO_SOURCE)],
                       check=True, capture_output=True, env=GO_ENV, timeout=300)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _go(self, request: dict) -> dict:
        proc = subprocess.run([str(self.binary)], input=json.dumps(request), capture_output=True,
                              text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def setUp(self) -> None:
        self.signer = MLDSA65SigningKey.from_seed(SEED, KEY_ID)
        self.public_key = self.signer.verification_key().public_key
        envelope = {"jsonrpc": "2.0", "id": "1",
                    "result": {"acs_version": "0.1.0", "request_id": "1", "decision": "deny"}}
        self.envelope = sign_with_signing_key(envelope, self.signer)
        self.message = signing_input(self.envelope)
        self.signature = base64.b64decode(self.envelope["result"]["signature"]["value"])

    def _verify(self, *, signature: bytes | None = None, context: str = "") -> bool:
        return self._go({"op": "verify", "public_key": _b64(self.public_key), "message": _b64(self.message),
                         "signature": _b64(self.signature if signature is None else signature),
                         "context": context})["valid"]

    def test_go_derives_the_same_public_key_from_the_seed(self) -> None:
        go_public = base64.b64decode(self._go({"op": "keygen", "seed": _b64(SEED)})["public_key"])
        self.assertEqual(go_public, self.public_key)

    def test_go_accepts_the_envelope_signature_in_pure_mode_with_an_empty_context(self) -> None:
        self.assertTrue(self._verify())

    def test_go_rejects_the_signature_under_another_context(self) -> None:
        # A context mismatch fails with no other sign, which is why the library states its context.
        self.assertFalse(self._verify(context="acs"))

    def test_go_rejects_a_flipped_signature_byte(self) -> None:
        flipped = bytearray(self.signature)
        flipped[100] ^= 0x01
        self.assertFalse(self._verify(signature=bytes(flipped)))


if __name__ == "__main__":
    unittest.main()
