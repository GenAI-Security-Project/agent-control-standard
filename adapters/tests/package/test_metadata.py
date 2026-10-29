from __future__ import annotations

import subprocess
import sys
import unittest
from importlib import metadata
from importlib.metadata import entry_points
from pathlib import Path

import acs

SCRIPTS = {
    "acs-claude-code-hook": "acs.integrations.claude_code.adapter:main",
    "acs-claude-code-wire": "acs.integrations.claude_code.wire:main",
    "acs-cursor-hook": "acs.integrations.cursor.adapter:main",
    "acs-cursor-wire": "acs.integrations.cursor.wire:main",
    "acs-nat-wire": "acs.integrations.nat.wire:main",
    "acs-example-guardian": "acs.guardian.example_guardian:main",
}


class Metadata(unittest.TestCase):
    def test_one_version_from_package_metadata(self) -> None:
        from acs.integrations.claude_code import adapter as claude
        from acs.integrations.cursor import adapter as cursor
        from acs.integrations.nat import adapter as nat
        version = metadata.version("acs-adapters")
        self.assertEqual(acs.__version__, version)
        for module in (claude, cursor, nat):
            with self.subTest(module=module.__name__):
                self.assertEqual(module.ADAPTER_VERSION, version)

    def test_console_scripts_point_at_their_main_functions(self) -> None:
        declared = {e.name: e.value for e in entry_points(group="console_scripts")
                    if e.name in SCRIPTS}
        self.assertEqual(declared, SCRIPTS)

    def test_scripts_load_with_only_the_base_dependencies(self) -> None:
        # acs-nat-wire needs the nat extra; the NAT suite loads it.
        for name in SCRIPTS.keys() - {"acs-nat-wire"}:
            with self.subTest(script=name):
                self.assertTrue(callable(entry_points(group="console_scripts")[name].load()))

    def test_integrations_entry_point_group_lists_each_integration(self) -> None:
        group = {e.name: e for e in entry_points(group="acs.integrations")}
        self.assertEqual(set(group), {"claude_code", "cursor", "nat"})
        for name, entry in group.items():
            with self.subTest(integration=name):
                self.assertEqual(entry.load().__name__, f"acs.integrations.{name}")

    def test_nat_discovers_the_middleware_module(self) -> None:
        (entry,) = [e for e in entry_points(group="nat.components") if e.name == "acs_guardian"]
        self.assertEqual(entry.value, "acs.integrations.nat.adapter")

    def test_installed_hook_scripts_run(self) -> None:
        bindir = Path(sys.executable).parent
        for name, label in (("acs-claude-code-hook", "claude-code"), ("acs-cursor-hook", "cursor")):
            with self.subTest(script=name):
                p = subprocess.run([str(bindir / name), "--version"],
                                   capture_output=True, text=True, timeout=30)
                self.assertEqual(p.returncode, 0, p.stderr[-500:])
                self.assertIn(f"({label}) {acs.__version__}", p.stdout)


if __name__ == "__main__":
    unittest.main()
