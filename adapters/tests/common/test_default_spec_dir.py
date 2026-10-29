"""Every default schema lookup resolves to the repository's schemas when ACS_SPEC_DIR is unset."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_SPEC_DIR = Path(__file__).resolve().parents[3] / "specification" / "v0.1.0"

# (description, code printing the resolved directory)
LOOKUPS = (
    ("example Guardian", "import acs.guardian.example_guardian as m; print(m._spec_dir)"),
    ("test harness", "from acs.testing.harness import _default_spec_dir; print(_default_spec_dir())"),
    ("conformance suite", "import tests.conformance.test_acs_core_conformance as m; print(m.SPEC_DIR)"),
    ("NAT envelope test", "import tests.integrations.nat.test_envelope_schema as m; print(m.SPEC_DIR)"),
    ("Claude Code e2e check", "import tests.integrations.claude_code.e2e_check as m; print(m.SPEC_DIR_DEFAULT)"),
    ("Cursor e2e check", "import tests.integrations.cursor.e2e_check as m; print(m.SPEC_DIR_DEFAULT)"),
    ("NAT e2e check", "import tests.integrations.nat.e2e_check as m; print(m.SPEC_DIR_DEFAULT)"),
)


def _env_without_override() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "ACS_SPEC_DIR"}
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
    return env


class DefaultSpecDir(unittest.TestCase):
    def test_repository_schemas_exist(self) -> None:
        self.assertTrue((REPO_SPEC_DIR / "request-envelope.json").is_file(), REPO_SPEC_DIR)

    def test_every_default_lookup_finds_the_repository_schemas(self) -> None:
        for name, code in LOOKUPS:
            with self.subTest(lookup=name):
                p = subprocess.run([sys.executable, "-c", code], env=_env_without_override(),
                                   capture_output=True, text=True, timeout=60)
                self.assertEqual(p.returncode, 0, p.stderr[-800:])
                resolved = Path(p.stdout.strip().splitlines()[-1]).resolve()
                self.assertEqual(resolved, REPO_SPEC_DIR.resolve())

    def test_example_guardian_validates_envelopes_by_default(self) -> None:
        p = subprocess.run(
            [sys.executable, "-c",
             "import acs.guardian.example_guardian as m; print(m._SPEC_VALIDATION_AVAILABLE)"],
            env=_env_without_override(), capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        self.assertEqual(p.stdout.strip().splitlines()[-1], "True")
        self.assertNotIn("validation DISABLED", p.stderr)


if __name__ == "__main__":
    unittest.main()
