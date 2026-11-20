"""server_hello_problem checks a ServerHello against the ClientHello it answers (§4, handshake.json)."""
from __future__ import annotations

import unittest

from acs.core import server_hello_problem

OFFERED = {"acs_versions_supported": ["0.1.0"], "transports_supported": ["http"],
           "profiles_supported": ["acs-core"], "methods_implemented": ["steps/toolCallRequest"]}
VALID = {"negotiated_version": "0.1.0", "methods_evaluated": ["steps/toolCallRequest"],
         "selected_transport": "http", "timeout_config": {"default_ms": 5000}}


class ServerHelloProblem(unittest.TestCase):
    def test_valid_answers(self) -> None:
        for name, change in (("minimal", {}), ("another minor version", {"negotiated_version": "0.2.0"}),
                             ("per-method timeouts", {"timeout_config": {"default_ms": 1, "per_method_ms": {"m": 9}}}),
                             ("integral numbers JSON Schema calls integers",
                              {"timeout_config": {"default_ms": 5000.0, "per_method_ms": {"m": 300.0}}}),
                             ("deny posture", {"on_decision_failure": "deny"}),
                             ("accepted claim", {"profiles_accepted": ["acs-core"]}),
                             ("nothing accepted", {"profiles_accepted": []}),
                             ("methods the client never sends", {"methods_evaluated": ["steps/other"]})):
            with self.subTest(name):
                self.assertIsNone(server_hello_problem({**VALID, **change}, OFFERED))

    def test_invalid_answers(self) -> None:
        cases = {
            "another major version": ({"negotiated_version": "1.0.0"}, "matches no offered major version"),
            "not a version": ({"negotiated_version": "v0.1"}, "is not a semantic version"),
            "no methods_evaluated": ({"methods_evaluated": None}, "methods_evaluated is not a list"),
            "methods_evaluated not names": ({"methods_evaluated": [1]}, "methods_evaluated is not a list"),
            "transport not offered": ({"selected_transport": "stdio"}, "'stdio' was not offered"),
            "https for an http client": ({"selected_transport": "https"}, "'https' was not offered"),
            "no default timeout": ({"timeout_config": {}}, "default_ms is not a positive integer"),
            "zero default timeout": ({"timeout_config": {"default_ms": 0}}, "default_ms is not a positive integer"),
            "boolean default timeout": ({"timeout_config": {"default_ms": True}}, "default_ms is not a positive integer"),
            "fractional default timeout": ({"timeout_config": {"default_ms": 5000.5}}, "default_ms is not a positive integer"),
            "infinite default timeout": ({"timeout_config": {"default_ms": float("inf")}},
                                         "default_ms is not a positive integer"),
            "boolean per-method timeout": ({"timeout_config": {"default_ms": 5, "per_method_ms": {"m": True}}},
                                           "per_method_ms is not a map"),
            "per-method timeout not a number": ({"timeout_config": {"default_ms": 5, "per_method_ms": {"m": "5"}}},
                                                "per_method_ms is not a map"),
            "posture in another case": ({"on_decision_failure": "DENY"}, "is neither proceed nor deny"),
            "profile the client did not claim": ({"profiles_accepted": ["acs-core", "acs-trace"]},
                                                 "['acs-trace'], which the client did not claim"),
        }
        for name, (change, problem) in cases.items():
            with self.subTest(name):
                hello = {**VALID, **change}
                hello = {k: v for k, v in hello.items() if v is not None}
                self.assertIn(problem, server_hello_problem(hello, OFFERED) or "")


if __name__ == "__main__":
    unittest.main()
