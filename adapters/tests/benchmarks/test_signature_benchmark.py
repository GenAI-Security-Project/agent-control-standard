"""The signature benchmark keeps working (issue #583). Timings are never asserted."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

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
        for key in ("machine", "os", "python", "cryptography", "openssl", "commit", "date",
                    "iterations", "warmup"):
            self.assertIn(key, result["environment"])
        self.assertEqual(result["environment"]["iterations"], 3)
        self.assertIn("hybrid", result["not_measured"])

    def test_main_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code = bench.main(["--iterations", "2", "--warmup", "1", "--out-dir", tmp])
            self.assertEqual(code, 0)
            data = json.loads((Path(tmp) / "results.json").read_text())
            table = (Path(tmp) / "results.md").read_text()
        self.assertEqual(len(data["rows"]), 3)
        for name in ALGORITHMS:
            self.assertIn(name, table)


if __name__ == "__main__":
    unittest.main()
