"""smoke.sh's reachability record (issue #588, LAB-15), driven against a fake docker. No Docker needed.

The LAB-15 review accepted that finbot-net isn't internal, so FinBot can reach the gateway's approver port, the host's
published ports and the internet. smoke.sh records what FinBot reaches on every run, so a change in that residual
shows in the log. It records and never fails the run on it.

Run from the repository root: python3 -m pytest labs/finbot/images/tests/test_smoke.py -v
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SMOKE = Path(__file__).resolve().parents[1] / "smoke.sh"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="smoke.sh runs on macOS and Linux only (Rock, 2026-11-17)")

# Logs each call on one line, newlines in inline code included, and answers the reachability probe, and only it,
# with one line per host and port it was given.
FAKE_DOCKER = """#!/bin/sh
printf '%s' "$*" | tr '\\n' ' ' >> "$FAKE_DOCKER_LOG"
printf '\\n' >> "$FAKE_DOCKER_LOG"
case "$*" in
    *lab-reach-record*)
        while [ "$#" -gt 0 ] && [ "$1" != -c ]; do shift; done
        shift 2
        while [ "$#" -ge 2 ]; do
            if [ "$1" = "$FAKE_REACHABLE" ]; then printf 'reaches %s:%s\\n' "$1" "$2"
            else printf 'cannot reach %s:%s (TimeoutError)\\n' "$1" "$2"; fi
            shift 2
        done ;;
esac
exit 0
"""


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    root = tmp_path / "bundle"
    (root / "images").mkdir(parents=True)
    shutil.copy2(SMOKE, root / "images" / "smoke.sh")
    (root / "lab.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (root / "lab.sh").chmod(0o755)
    (root / ".env").write_text("LAB_PORT_FINBOT=18000\nLAB_PORT_JAEGER=26686\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, text in (("docker", FAKE_DOCKER), ("curl", "#!/bin/sh\nexit 7\n")):
        (bin_dir / name).write_text(text, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    return root


def run_smoke(bundle: Path, reachable: str = "acs-gateway") -> tuple[subprocess.CompletedProcess, list[str]]:
    log = bundle.parent / "docker.log"
    log.write_text("", encoding="utf-8")
    env = {**os.environ, "PATH": f"{bundle.parent / 'bin'}:{os.environ['PATH']}", "FAKE_DOCKER_LOG": str(log),
           "FAKE_REACHABLE": reachable}
    result = subprocess.run(["sh", str(bundle / "images" / "smoke.sh")], env=env, capture_output=True, text=True,
                            timeout=60)
    return result, log.read_text(encoding="utf-8").splitlines()


def _probe_targets(calls: list[str]) -> list[str]:
    probe = [c for c in calls if "lab-reach-record" in c]
    assert len(probe) == 1, calls
    assert probe[0].startswith("compose -f compose.yaml exec -T finbot python -c ")
    words = probe[0].split()
    # The fake logs argv joined by spaces, so the code runs into the first target. Pairs read from the end.
    pairs = []
    while len(words) >= 2 and words[-1].isdigit():
        pairs.insert(0, f"{words[-2]}:{words[-1]}")
        words = words[:-2]
    return pairs


def test_smoke_probes_the_approver_the_host_and_the_internet_from_finbot(bundle):
    _, calls = run_smoke(bundle)
    targets = _probe_targets(calls)
    assert "acs-gateway:8090" in targets
    # The host's published ports, overrides from .env included, by Docker Desktop's host name and by the default route.
    for port in ("18000", "8090", "8095", "26686"):
        assert f"host.docker.internal:{port}" in targets, port
        assert f"@gateway:{port}" in targets, port
    assert "example.com:443" in targets


def test_smoke_writes_the_record_and_never_fails_on_it(bundle):
    result, _ = run_smoke(bundle, reachable="acs-gateway")
    lines = result.stdout.splitlines()
    notes = [line for line in lines if line.startswith("NOTE:")]
    assert "NOTE: finbot reaches acs-gateway:8090" in notes
    assert "NOTE: finbot cannot reach example.com:443 (TimeoutError)" in notes
    assert not any("reach" in line and "example.com" in line for line in lines if line.startswith("NOT YET"))
    # The record changes no check: the same run with nothing reachable fails exactly the same checks.
    other, _ = run_smoke(bundle, reachable="nothing")
    assert [line for line in other.stdout.splitlines() if not line.startswith("NOTE:")] == \
        [line for line in lines if not line.startswith("NOTE:")]
    assert other.returncode == result.returncode
