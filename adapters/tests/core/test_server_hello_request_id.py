"""server_hello_problem ignores an extra request_id but still refuses a step answer (PR #600 review).

Specification section 4 says unknown fields MUST be ignored, and handshake.json doesn't forbid
request_id on a ServerHello, so a Guardian that echoes it must still negotiate. The required
ServerHello fields are what keep a step answer from passing as a ServerHello.
"""
from __future__ import annotations

import unittest

from acs.core import server_hello_problem

OFFERED = {"acs_versions_supported": ["0.1.0"], "transports_supported": ["http"],
           "profiles_supported": ["acs-core"], "methods_implemented": ["steps/toolCallRequest"]}
VALID = {"negotiated_version": "0.1.0", "methods_evaluated": ["steps/toolCallRequest"],
         "selected_transport": "http", "timeout_config": {"default_ms": 5000}}


class AnExtraRequestIdIsIgnored(unittest.TestCase):
    def test_a_valid_server_hello_has_no_problem(self) -> None:
        self.assertIsNone(server_hello_problem(VALID, OFFERED))

    def test_a_server_hello_carrying_request_id_has_no_problem(self) -> None:
        for request_id in ("hello-request-1", None, ""):
            with self.subTest(request_id=request_id):
                self.assertIsNone(server_hello_problem({**VALID, "request_id": request_id}, OFFERED))

    def test_a_step_answer_offered_as_a_server_hello_is_still_a_problem(self) -> None:
        step_answer = {"type": "final", "acs_version": "0.1.0", "request_id": "r-1", "decision": "allow"}
        self.assertIsNotNone(server_hello_problem(step_answer, OFFERED))


if __name__ == "__main__":
    unittest.main()
