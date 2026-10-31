from __future__ import annotations

import unittest

from acs.core import request_envelope, turn_start_envelope
from acs.testing.harness import validate_hook_payload, validate_request_envelope

METADATA = {"agent_id": "agent", "session_id": "11111111-1111-4111-8111-111111111111", "platform": "test"}


class RequestEnvelopes(unittest.TestCase):
    def test_a_step_envelope_validates(self) -> None:
        envelope = request_envelope("steps/sessionStart", request_id="22222222-2222-4222-8222-222222222222",
                                    metadata=METADATA, payload={})
        self.assertEqual(validate_request_envelope(envelope), [])
        self.assertNotIn("signature", envelope["params"], "the client signs as the last step before sending")

    def test_turn_start_carries_its_turn_id_three_ways(self) -> None:
        turn_id = "33333333-3333-4333-8333-333333333333"
        envelope = turn_start_envelope(METADATA, turn_id)
        self.assertEqual(validate_request_envelope(envelope), [])
        self.assertEqual(validate_hook_payload(envelope["params"]["payload"], "turn-start.json"), [])
        self.assertEqual((envelope["params"]["request_id"], envelope["params"]["metadata"]["turn_id"],
                          envelope["params"]["payload"]["turn_id"]), (turn_id, turn_id, turn_id))

    def test_envelopes_copy_their_inputs(self) -> None:
        payload = {"k": "v"}
        envelope = request_envelope("steps/sessionStart", request_id="r", metadata=METADATA, payload=payload)
        envelope["params"]["payload"]["k"] = "changed"
        self.assertEqual(payload, {"k": "v"})


if __name__ == "__main__":
    unittest.main()
