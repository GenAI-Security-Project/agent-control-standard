from __future__ import annotations

import re
import unittest
from pathlib import Path

from acs.core import GUARDIAN_ERROR_CAUSE, guardian_error_cause, is_guardian_refusal

SPEC = Path(__file__).resolve().parents[3] / "docs" / "spec" / "instrument" / "specification.md"


class ErrorCauses(unittest.TestCase):
    def test_every_spec_error_code_has_its_own_cause(self) -> None:
        codes = {int(c) for c in re.findall(r"^\| `(-3\d{4})` \|", SPEC.read_text(), re.MULTILINE)}
        self.assertGreaterEqual(len(codes), 13, f"§17 tables not found in {SPEC}")
        self.assertEqual(codes - GUARDIAN_ERROR_CAUSE.keys(), set(),
            "an audit record should name the §17 code, not the generic fallback")
        self.assertEqual(len(set(GUARDIAN_ERROR_CAUSE.values())), len(GUARDIAN_ERROR_CAUSE))

    def test_codes_classify_as_json_integers(self) -> None:
        for code in (None, "-32004", -32004.5, float("inf"), float("nan"), True, [-32004], {"code": -32004}):
            with self.subTest(code=code):
                self.assertEqual(guardian_error_cause(code), "guardian_error_response")
                self.assertFalse(is_guardian_refusal(code))
        for code in (-32004, -32004.0):
            with self.subTest(code=code):
                self.assertTrue(is_guardian_refusal(code))
                self.assertEqual(guardian_error_cause(code), "signature_invalid_response")


if __name__ == "__main__":
    unittest.main()
