"""Without the pqc extra, each ML-DSA test module skips as one entry that run_conformance.py expects.

The nat environment can't hold the pqc extra (cryptography below 47), so these skips are
expected there. With the extra installed they don't skip, and a broken import fails instead.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ADAPTERS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ADAPTERS))

import run_conformance as rc  # noqa: E402
from tests import pqc_extra  # noqa: E402

PQC_MODULES = {"core": "tests.core.test_pqc_signing", "client": "tests.client.test_pqc_verification"}


class PqcSkipsAreAllowlisted(unittest.TestCase):
    def test_each_pqc_module_has_one_allowlisted_module_skip(self) -> None:
        for suite, module in PQC_MODULES.items():
            with self.subTest(module=module):
                self.assertTrue(rc._is_expected_skip(
                    suite, f"unittest.loader.ModuleSkipped.{module}", pqc_extra.PQC_SKIP_REASON))

    def test_the_allowlist_names_no_other_pqc_entry(self) -> None:
        pqc = {e for e in rc.EXPECTED_SKIPS if e[2] == pqc_extra.PQC_SKIP_REASON}
        self.assertEqual(pqc, {(s, f"unittest.loader.ModuleSkipped.{m}", pqc_extra.PQC_SKIP_REASON)
                               for s, m in PQC_MODULES.items()})

    def test_a_missing_extra_skips_the_module_under_the_allowlisted_id(self) -> None:
        # Discover a stand-in module the way run_conformance does, with ML-DSA reported absent.
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(pqc_extra, "pqc_installed", return_value=False):
            package = Path(root) / "probe"
            package.mkdir()
            (package / "__init__.py").write_text("")
            (package / "test_needs_pqc.py").write_text(
                "from tests.pqc_extra import require_pqc\nrequire_pqc()\n")
            suite = unittest.TestLoader().discover(str(package), top_level_dir=root)
            result = unittest.TestResult()
            suite.run(result)
            sys.modules.pop("probe", None)
            sys.modules.pop("probe.test_needs_pqc", None)
        self.assertEqual([(t.id(), why) for t, why in result.skipped],
                         [("unittest.loader.ModuleSkipped.probe.test_needs_pqc", pqc_extra.PQC_SKIP_REASON)])


if __name__ == "__main__":
    unittest.main()
