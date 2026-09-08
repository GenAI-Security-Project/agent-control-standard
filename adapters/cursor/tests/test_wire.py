"""
wire.py installer tests for the Cursor adapter.

Guards the DEFAULT install path against silently dropping a documented
gate: subagentStart is the confused-deputy spawn gate proposed by PR #21
(open; not in this branch). These tests run the real CLI and assert the
generated hooks.json.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
WIRE = HERE.parent / "wire.py"


def _run_default_wire() -> dict:
    """Run wire.py with the DEFAULT hook set (no --hooks) and --write to
    a temp hooks.json; return the parsed result."""
    with tempfile.TemporaryDirectory() as d:
        settings = Path(d) / "hooks.json"
        secret = Path(d) / "hmac.key"
        secret.write_text("0" * 64)
        proc = subprocess.run(
            [sys.executable, str(WIRE),
             "--guardian-url=http://127.0.0.1:8787/acs",
             f"--secret-file={secret}",
             f"--settings={settings}",
             "--write"],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"wire.py --write failed ({proc.returncode}):\n{proc.stderr}")
        return json.loads(settings.read_text())


class DefaultWiringMatchesDocumentedSet(unittest.TestCase):
    def setUp(self) -> None:
        self.hooks = _run_default_wire().get("hooks", {})

    def test_subagent_start_is_fail_closed_both_mechanisms(self) -> None:
        """subagentStart is a gate: it must carry BOTH Cursor's native
        failClosed:true AND our ACS_DEFAULT_DENY=1 (defense in depth)."""
        entries = self.hooks.get("subagentStart", [])
        self.assertTrue(entries, "subagentStart has no entries")
        entry = entries[0]
        self.assertTrue(entry.get("failClosed") is True,
            f"subagentStart must set failClosed:true; got {entry}")
        self.assertIn("ACS_DEFAULT_DENY=1", entry.get("command", ""),
            f"subagentStart command must set ACS_DEFAULT_DENY=1; got "
            f"{entry.get('command')!r}")

    def test_default_covers_current_core_and_proposed_gate(self) -> None:
        """The default covers current Core plus the proposed spawn gate."""
        sys.path.insert(0, str(WIRE.parent))
        import wire  # noqa: E402
        self.assertEqual(
            wire.DEFAULT_HOOKS,
            wire.CURRENT_CORE_HOOKS + wire.PR21_PROPOSED_HOOKS)
        for hook in wire.DEFAULT_HOOKS:
            self.assertIn(hook, self.hooks,
                f"default wiring missing documented hook {hook!r}; "
                f"wired: {sorted(self.hooks)}")


class ExampleConfigMatchesDefaultWiring(unittest.TestCase):
    """The drop-in `hooks.json.example` — the file people actually copy —
    must itself cover the documented default hook set; neither the
    emission suite nor test_wire reads the checked-in example."""

    def test_example_wires_documented_default(self) -> None:
        import json
        example = json.loads((HERE.parent / "hooks.json.example").read_text())
        wired = set(example.get("hooks", {}))
        sys.path.insert(0, str(WIRE.parent))
        import wire  # noqa: E402
        missing = set(wire.DEFAULT_HOOKS) - wired
        self.assertEqual(missing, set(),
            f"hooks.json.example (the copy-paste config) is missing "
            f"default hooks {sorted(missing)}; wired: {sorted(wired)}")

    def test_example_gate_hooks_fail_closed_on_BOTH_mechanisms(self) -> None:
        """A gate hook in the example must carry BOTH failClosed:true and
        ACS_DEFAULT_DENY=1: failClosed only catches a non-zero exit, and
        the adapter exits 0 on a build failure under the §6.4 fail-open
        default."""
        import json
        example = json.loads((HERE.parent / "hooks.json.example").read_text())
        sys.path.insert(0, str(WIRE.parent))
        import wire  # noqa: E402
        # Every hook the example marks failClosed is a gate; each MUST
        # also set ACS_DEFAULT_DENY=1. This covers default, shell, and MCP
        # gates without assigning a normative status to the default extras.
        checked = 0
        for hook, entries in example["hooks"].items():
            entry = entries[0]
            if entry.get("failClosed") is True:
                checked += 1
                self.assertIn("ACS_DEFAULT_DENY=1", entry.get("command", ""),
                    f"gate hook {hook} sets failClosed:true but NOT "
                    f"ACS_DEFAULT_DENY=1 — fail-open on adapter build failure")
        # Every default gate hook must actually be a fail-closed gate.
        for hook in wire.GATE_HOOKS & set(wire.DEFAULT_HOOKS):
            entry = example["hooks"].get(hook, [{}])[0]
            self.assertTrue(entry.get("failClosed") is True
                            and "ACS_DEFAULT_DENY=1" in entry.get("command", ""),
                f"default gate hook {hook} must set BOTH failClosed:true "
                f"and ACS_DEFAULT_DENY=1")
        self.assertGreater(checked, 0, "no failClosed gate hooks found?")

    def test_unsupported_hooks_cannot_drift_into_shipped_wiring(self) -> None:
        """Tie the adapter taxonomy to both installation surfaces.

        A hook documented as unsupported must not appear in the generated
        default set or the copy-paste example, and a hook cannot be both
        mapped and unsupported.  This catches silent wiring drift without
        pretending that an unsupported native event has an ACS mapping.
        """
        sys.path.insert(0, str(WIRE.parent))
        import wire
        import acs_adapter

        example = json.loads((HERE.parent / "hooks.json.example").read_text())
        example_hooks = set(example.get("hooks", {}))
        generated_defaults = set(wire.DEFAULT_HOOKS)
        mapped = set(acs_adapter.HOOK_MAP)
        unsupported = set(acs_adapter.KNOWN_UNMAPPED)

        self.assertEqual(mapped & unsupported, set(),
            "a Cursor hook cannot be both forwarded and documented unsupported")
        self.assertEqual(example_hooks & unsupported, set(),
            "hooks.json.example wires a hook the adapter cannot translate")
        self.assertEqual(generated_defaults & unsupported, set(),
            "wire.py defaults include an unsupported hook")
        self.assertLessEqual(generated_defaults, mapped,
            "wire.py defaults must all have a production HOOK_MAP entry")
        self.assertLessEqual(example_hooks, mapped,
            "the copy-paste example must not invoke an unmapped hook")


if __name__ == "__main__":
    unittest.main(verbosity=2)
