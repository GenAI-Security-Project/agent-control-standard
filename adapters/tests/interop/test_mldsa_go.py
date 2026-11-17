"""Go's crypto/mldsa, an implementation outside the library under test, accepts acs.core's ML-DSA-65 signatures.

Issue #574 done_when. The tests-pqc CI job runs this module with ACS_REQUIRE_GO_INTEROP=1,
under which a missing Go or a missing pqc extra fails instead of skipping. Locally, from
adapters/: `ACS_REQUIRE_GO_INTEROP=1 uv run --extra pqc python -m pytest tests/interop -q`.
Without the variable it skips and says why. It sits outside every run_conformance.py suite.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.pqc_extra import PQC_SKIP_REASON, pqc_installed

REQUIRE = os.environ.get("ACS_REQUIRE_GO_INTEROP") == "1"
GO_SOURCE = Path(__file__).resolve().parent / "mldsa" / "main.go"
SEED = bytes(range(32))
KEY_ID = "lab-guardian-1"
# GOTOOLCHAIN=local stops go from downloading a toolchain the test didn't ask for.
GO_ENV = {**os.environ, "GOTOOLCHAIN": "local"}
PROBE_TIMEOUT_S = 60


def go_problem(go: str | None, *, timeout: float = PROBE_TIMEOUT_S) -> str | None:
    """Why this Go can't run the check, or None. Probes once, with a timeout."""
    if go is None:
        return "go is not on PATH: the ML-DSA-65 interop check needs Go 1.27 or later (crypto/mldsa)"
    try:
        probe = subprocess.run([go, "list", "crypto/mldsa"], capture_output=True, text=True,
                               env=GO_ENV, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"{go} list crypto/mldsa timed out after {timeout} s"
    except OSError as exc:
        return f"{go} could not run: {exc}"
    if probe.returncode != 0:
        return "this Go has no crypto/mldsa: the ML-DSA-65 interop check needs Go 1.27 or later"
    return None


def unavailable(problem: str, *, require: bool) -> Exception:
    """A skip normally. A failure under ACS_REQUIRE_GO_INTEROP=1, where CI promises Go and the extra."""
    if require:
        return AssertionError(f"ACS_REQUIRE_GO_INTEROP=1 but {problem}")
    return unittest.SkipTest(problem)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class GoProbe(unittest.TestCase):
    """The probe and the skip-or-fail choice, checked without needing Go."""

    def _script(self, body: str) -> str:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        path = Path(directory) / "go"
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)

    def test_no_go_on_path(self) -> None:
        self.assertIn("not on PATH", go_problem(None) or "")

    def test_a_go_that_hangs_times_out(self) -> None:
        self.assertIn("timed out", go_problem(self._script("sleep 5"), timeout=0.5) or "")

    def test_a_go_that_cannot_run(self) -> None:
        self.assertIn("could not run", go_problem("/nonexistent/acs-test/go") or "")

    def test_a_go_without_crypto_mldsa(self) -> None:
        self.assertIn("no crypto/mldsa", go_problem(self._script("exit 1")) or "")

    def test_a_go_with_crypto_mldsa(self) -> None:
        self.assertIsNone(go_problem(self._script("echo crypto/mldsa")))

    def test_skip_by_default_and_fail_when_required(self) -> None:
        self.assertIsInstance(unavailable("why", require=False), unittest.SkipTest)
        failure = unavailable("why", require=True)
        self.assertIsInstance(failure, AssertionError)
        self.assertIn("why", str(failure))


class GoCryptoMldsaAcceptsTheLibrary(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not pqc_installed():
            raise unavailable(PQC_SKIP_REASON, require=REQUIRE)
        go = shutil.which("go")
        problem = go_problem(go)
        if problem is not None:
            raise unavailable(problem, require=REQUIRE)
        cls._tmp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls._tmp.name) / "mldsa"
        subprocess.run([go, "build", "-o", str(cls.binary), str(GO_SOURCE)],
                       check=True, capture_output=True, env=GO_ENV, timeout=300)

    @classmethod
    def tearDownClass(cls) -> None:
        tmp = getattr(cls, "_tmp", None)
        if tmp is not None:
            tmp.cleanup()

    def _go(self, request: dict) -> dict:
        proc = subprocess.run([str(self.binary)], input=json.dumps(request), capture_output=True,
                              text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def setUp(self) -> None:
        from acs.core._mldsa import MLDSA65SigningKey, sign_with_signing_key
        from acs.core._signing import signing_input
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

    def _go_raw(self, request: dict) -> dict:
        """The Go tool's JSON output as written, so byte fields stay in Go's own base64 spelling."""
        proc = subprocess.run([str(self.binary)], input=json.dumps(request), capture_output=True,
                              text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_a_go_encoded_ml_dsa_value_verifies_as_written(self) -> None:
        # Review finding CR5-8: Go's standard encoder emits the canonical spelling the library requires.
        import acs.core
        from acs.core._signing import signing_input
        request = {"jsonrpc": "2.0", "id": "go-1", "method": "steps/toolCallRequest",
                   "params": {"acs_version": "0.1.0", "request_id": "go-1"}}
        response = {"jsonrpc": "2.0", "id": "go-1",
                    "result": {"acs_version": "0.1.0", "request_id": "go-1", "decision": "allow"}}
        go_value = self._go_raw({"op": "sign", "seed": _b64(SEED), "message": _b64(signing_input(response))})["signature"]
        response["result"]["signature"] = {"algorithm": "ML-DSA-65", "value": go_value, "key_id": KEY_ID}
        keyring = acs.core.Keyring([self.signer.verification_key()])
        self.assertTrue(acs.core.verify_with_keyring(response, keyring, expected_key_id=KEY_ID, request=request))

    def test_a_go_encoded_hmac_value_verifies_on_the_default_path(self) -> None:
        # CR5-8: the canonical-base64 rule on the HMAC default path accepts what Go emits.
        from acs.core import derive_session_key, verify_with_key
        from acs.core._signing import signing_input
        key = derive_session_key(bytes(range(32)), "0f8fad5b-d9cb-469f-a165-70867728950e")
        request = {"jsonrpc": "2.0", "id": "go-2", "method": "steps/toolCallRequest",
                   "params": {"acs_version": "0.1.0", "request_id": "go-2",
                              "metadata": {"session_id": "0f8fad5b-d9cb-469f-a165-70867728950e"}}}
        go_value = self._go_raw({"op": "hmac", "key": _b64(key), "message": _b64(signing_input(request))})["mac"]
        request["params"]["signature"] = {"algorithm": "HMAC-SHA256", "value": go_value, "key_id": "lab"}
        self.assertTrue(verify_with_key(request, key))

    def test_go_rejects_a_flipped_signature_byte(self) -> None:
        flipped = bytearray(self.signature)
        flipped[100] ^= 0x01
        self.assertFalse(self._verify(signature=bytes(flipped)))


if __name__ == "__main__":
    unittest.main()
