"""acs-nat-wire wires and checks every point NAT gates: the workflow, each function group and each function."""
from __future__ import annotations

import unittest

try:
    from acs.integrations.nat import wire
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

PLAIN = """\
general:
  use_uvloop: false

functions:
  protected_write:
    _type: acs_protected_write
  lookup:
    _type: current_datetime
    middleware:
      - content_filter

workflow:
  _type: acs_nested_outer
  inner: protected_write
"""


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core is not installed")
class WireCoversEveryFunction(unittest.TestCase):
    def test_check_reports_every_function_without_acs_guardian(self) -> None:
        gaps = wire.find_attachment_points(wire._yaml().load(PLAIN))
        self.assertEqual(sorted(g.path for g in gaps if g.kind == "function"),
                         ["functions.lookup", "functions.protected_write"],
                         "a function's middleware gates only the calls to that function, so each one needs acs_guardian")

    def test_write_wires_every_function_and_unwire_restores_the_file(self) -> None:
        doc = wire._yaml().load(PLAIN)
        wire.install(doc, guardian_url="http://127.0.0.1:8787/acs", default_deny=False, timeout_s=5.0)
        self.assertEqual(wire.find_attachment_points(doc), [])
        functions = doc["functions"]
        self.assertEqual([str(m) for m in functions["protected_write"]["middleware"]], ["acs_guardian"])
        self.assertEqual([str(m) for m in functions["lookup"]["middleware"]], ["acs_guardian", "content_filter"])
        restored, _ = wire.unwire(wire.render(doc))
        self.assertEqual(restored, PLAIN)


if __name__ == "__main__":
    unittest.main()
