"""The settings decision_keys prints are the whole recipe: exporting them starts the example Guardian (rehearsal R10).

Lab convention until issue #460 settles key publication.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

from decision_signing_helpers import require_pqc, signing_env

require_pqc()

from acs.testing.harness import launch_guardian  # noqa: E402

PRINTED = re.compile(r"(ACS_[A-Z_0-9]+)=(.*)")


def _printed_settings(stdout: str) -> dict[str, str]:
    return dict(m.groups() for m in map(PRINTED.fullmatch, stdout.splitlines()) if m)


def test_the_printed_settings_start_a_guardian(tmp_path):
    out = subprocess.run([sys.executable, "-m", "acs.guardian.decision_keys", "--out-dir", str(tmp_path / "keys"),
                          "--key-id", "lab-guardian-1", "--guardian-id", "lab-guardian"],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    printed = _printed_settings(out.stdout)
    assert {"ACS_GUARDIAN_SIGNING_KEY_FILE", "ACS_GUARDIAN_KEYS", "ACS_GUARDIAN_KEY_ID"} <= set(printed)
    base = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
    # Only the printed settings plus the two the output can't know: the HMAC secret and the signing switch.
    env = {**base, **signing_env(), "ACS_RESPONSE_SIGNING": "ML-DSA-65", **printed,
           "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "state")}
    process, port = launch_guardian(env=env)
    try:
        assert port > 0
    finally:
        process.terminate()
        process.wait(timeout=5)
