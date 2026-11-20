"""The example Guardian declares on_decision_failure: deny unless its deployment opts out."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest

from acs.guardian import example_guardian


def _declared(value: str | None) -> str:
    env = {k: v for k, v in os.environ.items() if k != "ACS_ON_DECISION_FAILURE"}
    if value is not None:
        env["ACS_ON_DECISION_FAILURE"] = value
    run = subprocess.run([sys.executable, "-c",
                          "from acs.guardian import example_guardian as g; print(g.ON_DECISION_FAILURE)"],
                         env=env, capture_output=True, text=True, check=True)
    return run.stdout.strip()


class DeclaredPosture(unittest.TestCase):
    def test_the_server_hello_declares_deny(self) -> None:
        hello = example_guardian.evaluate_handshake(
            {"payload": {"acs_versions_supported": ["0.1.0"], "methods_implemented": ["steps/toolCallRequest"],
                         "transports_supported": ["http"], "provenance_producer": "none"}}, "req-1")
        self.assertEqual(hello["on_decision_failure"], "deny")

    def test_only_proceed_opens_it(self) -> None:
        self.assertEqual(_declared(None), "deny")
        self.assertEqual(_declared("proceed"), "proceed")
        self.assertEqual(_declared(" Proceed "), "proceed")
        for value in ("", "deny", "open", "0"):
            with self.subTest(value=value):
                self.assertEqual(_declared(value), "deny")


if __name__ == "__main__":
    unittest.main()
