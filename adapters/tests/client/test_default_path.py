"""The default HMAC path never imports cryptography, so an install without the pqc extra behaves as before."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest

from tests.pqc_extra import pqc_installed

# Review finding CR3-6: the keyring names are useless without the extra, so they share the gate.
PQC_NAMES = ("ML_DSA_CONTEXT", "ML_DSA_MODE", "MLDSA65SigningKey", "sign_with_signing_key", "verify_with_keyring",
             "Keyring", "VerificationKey", "ML_DSA_65", "WIRE_ALGORITHMS", "ml_dsa_available",
             "MLDSAUnavailableError")

PROBE = """
import json, os, sys
os.environ.update({"ACS_HMAC_SECRET": "default-path-secret-0123456789abcdef", "ACS_HMAC_KEY_ID": "lab"})
import acs.core, acs.client
import acs.integrations.claude_code.hook, acs.integrations.cursor.hook
import acs.guardian.example_guardian
from acs.client import sign_envelope, verify_signature
from acs.core import *
namespace = dict(globals())
envelope = {"jsonrpc": "2.0", "id": "1", "method": "steps/sessionStart",
            "params": {"metadata": {"session_id": "0f8fad5b-d9cb-469f-a165-70867728950e"}}}
sign_envelope(envelope)
assert verify_signature(envelope)
signing_input(envelope)
loaded = sorted(m for m in sys.modules if m == "cryptography" or m.startswith(("cryptography.", "acs.core._mldsa", "acs.core._ecdsa")))
names = %r
print(json.dumps({
    "loaded": loaded,
    "in_all": sorted(n for n in names + ("ECDSA_P256",) if n in acs.core.__all__),
    "in_dir": sorted(n for n in names + ("ECDSA_P256",) if n in dir(acs.core)),
    "star": sorted(n for n in names + ("ECDSA_P256",) if n in namespace),
    "has_ecdsa_name": hasattr(acs.core, "ECDSA_P256"),
}))
# Last, since with the extra installed this loads cryptography.
print(json.dumps({"has_pqc": {n: hasattr(acs.core, n) for n in names}}))
""" % (PQC_NAMES,)


class DefaultPathImportsNoCryptography(unittest.TestCase):
    def setUp(self) -> None:
        proc = subprocess.run([sys.executable, "-c", PROBE], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        first, second = proc.stdout.strip().splitlines()
        self.result = {**json.loads(first), **json.loads(second)}

    def test_hmac_signing_hooks_the_guardian_and_a_star_import_load_no_cryptography(self) -> None:
        self.assertEqual(self.result["loaded"], [])

    def test_pqc_names_stay_out_of_all_dir_and_star_imports(self) -> None:
        self.assertEqual((self.result["in_all"], self.result["in_dir"], self.result["star"]), ([], [], []))

    def test_ecdsa_p256_is_not_exported(self) -> None:
        self.assertFalse(self.result["has_ecdsa_name"])

    def test_a_pqc_name_resolves_only_with_the_extra(self) -> None:
        # hasattr is False, not an ImportError, when the extra is missing.
        self.assertEqual(self.result["has_pqc"], {n: pqc_installed() for n in PQC_NAMES})


BLOCKED = """
import json, sys
sys.modules["cryptography"] = None
import acs.core
out = {"dir": [n for n in ("ml_dsa_available", "MLDSAUnavailableError") if n in dir(acs.core)]}
for name in ("ml_dsa_available", "MLDSAUnavailableError"):
    try:
        getattr(acs.core, name)
        out[name] = "resolved"
    except AttributeError as exc:
        out[name] = "AttributeError: " + str(exc)
print(json.dumps(out))
"""


class WithoutTheExtra(unittest.TestCase):
    """Review finding R6-M3: the gated names fail the same way in a base install, with cryptography blocked."""

    def test_ml_dsa_available_and_its_error_raise_attribute_error_naming_the_extra(self) -> None:
        proc = subprocess.run([sys.executable, "-c", BLOCKED], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["dir"], [])
        for name in ("ml_dsa_available", "MLDSAUnavailableError"):
            with self.subTest(name=name):
                self.assertTrue(out[name].startswith("AttributeError: "), out[name])
                self.assertIn("pqc", out[name])


if __name__ == "__main__":
    unittest.main()
