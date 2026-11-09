"""acs-nat-wire wires and checks every point NAT gates: the workflow, each function group and each function."""
from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

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


NAMED = """\
middleware:
  acs:
    _type: acs_guardian
    guardian_url: http://127.0.0.1:8787/acs

functions:
  tool:
    _type: current_datetime
    middleware:
      - acs
  lookup:
    _type: current_datetime

workflow:
  _type: acs_nested_outer
  inner: tool
  middleware:
    - acs
"""


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core is not installed")
class WireFindsTheMiddlewareByType(unittest.TestCase):
    def test_check_accepts_the_guardian_middleware_under_any_name(self) -> None:
        gaps = wire.find_attachment_points(wire._yaml().load(NAMED))
        self.assertEqual([g.path for g in gaps], ["functions.lookup"])

    def test_write_lists_the_existing_middleware_and_adds_no_second_guard(self) -> None:
        doc = wire._yaml().load(NAMED)
        wire.install(doc, guardian_url="http://127.0.0.1:8787/acs", default_deny=True, timeout_s=5.0)
        self.assertEqual(list(doc["middleware"]), ["acs"])
        self.assertEqual([str(m) for m in doc["functions"]["tool"]["middleware"]], ["acs"])
        self.assertEqual([str(m) for m in doc["functions"]["lookup"]["middleware"]], ["acs"])
        self.assertEqual([str(m) for m in doc["workflow"]["middleware"]], ["acs"])
        self.assertEqual(wire.find_attachment_points(doc), [])
        restored, _ = wire.unwire(wire.render(doc))
        self.assertEqual(restored, NAMED)

    def test_write_refuses_when_acs_guardian_names_another_middleware(self) -> None:
        taken = NAMED.replace("  acs:\n    _type: acs_guardian", "  acs_guardian:\n    _type: content_filter")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workflow.yml"
            path.write_text(taken)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertNotEqual(wire.main(["--workflow", str(path), "--write"]), 0)
            self.assertEqual(path.read_text(), taken)


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core is not installed")
class WiredPosture(unittest.TestCase):
    def _wired(self, *flags: str) -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workflow.yml"
            path.write_text(PLAIN)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(wire.main(["--workflow", str(path), "--write", *flags]), 0)
            return wire._yaml().load(path.read_text())["middleware"]["acs_guardian"]["default_deny"]

    def test_the_middleware_is_wired_fail_closed(self) -> None:
        self.assertIs(self._wired(), True)
        self.assertIs(self._wired("--default-deny"), True)

    def test_all_fail_open_wires_it_open(self) -> None:
        self.assertIs(self._wired("--all-fail-open"), False)

    def test_an_unset_default_deny_denies(self) -> None:
        from acs.integrations.nat.adapter import ACSMiddlewareConfig
        self.assertIs(ACSMiddlewareConfig(guardian_url="http://127.0.0.1:8787/acs").default_deny, True)


if __name__ == "__main__":
    unittest.main()
