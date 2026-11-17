"""The signature benchmark keeps working (issue #583). Timings are never asserted."""
from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tests.pqc_extra import require_pqc

require_pqc()

from benchmarks.signatures import bench  # noqa: E402

ALGORITHMS = ["HMAC-SHA256", "ML-DSA-65", "ECDSA-P256"]
ROW_FIELDS = ["algorithm", "signature_bytes", "public_key_bytes", "envelope_bytes",
              "sign_median_us", "sign_p95_us", "verify_median_us", "verify_p95_us"]


class SignatureBenchmarkTest(unittest.TestCase):
    def test_run_reports_every_algorithm_and_the_environment(self) -> None:
        result = bench.run(iterations=3, warmup=1)
        self.assertEqual([r["algorithm"] for r in result["rows"]], ALGORITHMS)
        for row in result["rows"]:
            for field in ROW_FIELDS:
                self.assertIn(field, row)
        sizes = {r["algorithm"]: r["signature_bytes"] for r in result["rows"]}
        self.assertEqual(sizes, {"HMAC-SHA256": 32, "ML-DSA-65": 3309, "ECDSA-P256": 64})
        for key in ("machine", "os", "python", "cryptography", "openssl", "date",
                    "iterations", "warmup", "source_sha256", "acs_adapters"):
            self.assertIn(key, result["environment"])
        self.assertEqual(result["environment"]["iterations"], 3)
        self.assertIn("hybrid", result["not_measured"])
        self.assertNotIn("describe", result["environment"])
        self.assertNotIn("branch", result["not_measured"]["hybrid"])

    def test_main_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code = bench.main(["--iterations", "2", "--warmup", "1", "--out-dir", tmp])
            self.assertEqual(code, 0)
            data = json.loads((Path(tmp) / "results.json").read_text())
            table = (Path(tmp) / "results.md").read_text()
            env = (Path(tmp) / "environment.md").read_text()
        self.assertEqual(len(data["rows"]), 3)
        for name in ALGORITHMS:
            self.assertIn(name, table)
        self.assertIn(data["environment"]["source_sha256"], env)
        self.assertIn(data["environment"]["cryptography"], env)

    def test_ecdsa_envelope_helpers_round_trip_and_reject_tampering(self) -> None:
        from acs.core._ecdsa import ecdsa_p256_generate, ecdsa_p256_public_bytes
        _, response = bench._workload()
        key = ecdsa_p256_generate()
        public = ecdsa_p256_public_bytes(key)
        signed = bench.sign_ecdsa_envelope(response, key, key_id="k")
        self.assertEqual(signed["result"]["signature"]["algorithm"], "ECDSA-P256")
        self.assertTrue(bench.verify_ecdsa_envelope(signed, public))
        signed["result"]["decision"] = "deny"
        self.assertFalse(bench.verify_ecdsa_envelope(signed, public))

    def test_source_hash_is_a_sha256_of_the_core_files(self) -> None:
        digest = bench.core_source_sha256()
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(digest, bench.core_source_sha256())

    def test_source_hash_covers_nested_python_files(self) -> None:
        import acs.core
        nested = Path(acs.core.__file__).resolve().parent / "_bench_probe" / "nested.py"
        before = bench.core_source_sha256()
        nested.parent.mkdir()
        self.addCleanup(lambda: (nested.unlink(missing_ok=True), nested.parent.rmdir()))
        nested.write_text("x = 1\n")
        self.assertNotEqual(before, bench.core_source_sha256())

    def test_update_reference_and_out_dir_are_mutually_exclusive(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            bench.main(["--update-reference", "--out-dir", "somewhere"])
        self.assertEqual(raised.exception.code, 2)

    def test_default_output_is_not_the_committed_reference(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out), tempfile.TemporaryDirectory() as ref:
            with mock.patch.object(bench, "REFERENCE_DIR", Path(ref)):
                bench.main(["--iterations", "2", "--warmup", "1"])
                self.assertEqual(list(Path(ref).iterdir()), [])
        self.assertIn("Wrote", out.getvalue())

    def test_update_reference_writes_the_committed_directory(self) -> None:
        with tempfile.TemporaryDirectory() as ref, redirect_stdout(io.StringIO()):
            with mock.patch.object(bench, "REFERENCE_DIR", Path(ref)):
                bench.main(["--iterations", "2", "--warmup", "1", "--update-reference"])
            self.assertTrue((Path(ref) / "results.json").exists())
            self.assertTrue((Path(ref) / "results.md").exists())


if __name__ == "__main__":
    unittest.main()
