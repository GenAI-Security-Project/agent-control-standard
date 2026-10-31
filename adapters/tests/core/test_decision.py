from __future__ import annotations

import dataclasses
import json
import unittest

from acs.core import Decision, normalize_decision, schemas_dir


class NormalizeDecision(unittest.TestCase):
    def test_the_known_dispositions_are_the_schema_enum(self) -> None:
        schema = json.loads((schemas_dir() / "response-envelope.json").read_text())
        enum = schema["$defs"]["AcsResult"]["properties"]["decision"]["enum"]
        for disposition in enum:
            with self.subTest(disposition):
                self.assertTrue(normalize_decision({"decision": disposition}).known)
        self.assertFalse(normalize_decision({"decision": "maybe"}).known)

    def test_a_disposition_is_stripped_and_lower_cased(self) -> None:
        decision = normalize_decision({"decision": " DENY ", "reasoning": "no"})
        self.assertEqual(decision, Decision("deny", "no", {}))
        self.assertTrue(decision.known)

    def test_an_unusable_disposition_is_empty_and_unknown(self) -> None:
        for raw in (None, 1, ["allow"], {"value": "allow"}):
            with self.subTest(raw=raw):
                decision = normalize_decision({"decision": raw})
                self.assertEqual(decision.disposition, "")
                self.assertFalse(decision.known)

    def test_a_result_that_is_not_an_object_is_an_empty_decision(self) -> None:
        for result in (None, "allow", ["allow"], 7):
            with self.subTest(result=result):
                self.assertEqual(normalize_decision(result), Decision("", "", {}))

    def test_reasoning_is_always_a_string(self) -> None:
        self.assertEqual(normalize_decision({"decision": "deny"}).reasoning, "")
        self.assertEqual(normalize_decision({"decision": "deny", "reasoning": {"rule": 4}}).reasoning,
                         '{"rule": 4}')

    def test_modifications_are_always_an_object(self) -> None:
        mods = {"parameter_overrides": {"path": "/tmp"}}
        self.assertEqual(normalize_decision({"decision": "modify", "modifications": mods}).modifications, mods)
        for raw in (None, [], "redact", 3):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_decision({"decision": "modify", "modifications": raw}).modifications, {})

    def test_a_decision_is_immutable_and_owns_its_default(self) -> None:
        decision = normalize_decision(None)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            decision.disposition = "allow"  # type: ignore[misc]
        self.assertIsNot(Decision().modifications, Decision().modifications)


if __name__ == "__main__":
    unittest.main()
