"""server_hello_problem refuses a ServerHello carrying request_id, for every consumer (review finding CR8-2)."""
from __future__ import annotations

import unittest

from acs.core import server_hello_problem

OFFERED = {"acs_versions_supported": ["0.1.0"], "transports_supported": ["http"],
           "profiles_supported": ["acs-core"], "methods_implemented": ["steps/toolCallRequest"]}
VALID = {"negotiated_version": "0.1.0", "methods_evaluated": ["steps/toolCallRequest"],
         "selected_transport": "http", "timeout_config": {"default_ms": 5000}}


class ServerHelloCarriesNoRequestId(unittest.TestCase):
    def test_a_valid_server_hello_has_no_problem(self) -> None:
        self.assertIsNone(server_hello_problem(VALID, OFFERED))

    def test_a_server_hello_carrying_request_id_is_a_problem(self) -> None:
        # A ServerHello echoes nothing from the ClientHello. A result with request_id is a step answer.
        for request_id in ("hello-request-1", None, ""):
            with self.subTest(request_id=request_id):
                self.assertEqual(server_hello_problem({**VALID, "request_id": request_id}, OFFERED),
                                 "a ServerHello carries no request_id")


if __name__ == "__main__":
    unittest.main()
