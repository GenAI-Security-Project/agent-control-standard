"""smoke.sh's reachability checks (issue #588, LAB-15), driven against a fake docker. No Docker needed.

FinBot joins only internal networks (Rock, 2026-11-22, C-17), so smoke.sh fails the run when FinBot reaches anything
outside the compose networks: a public address, a public name, or the host's ports. It still records, without
checking, that FinBot reaches the gateway's approver port on finbot-net, where the approver token guards it.

Run from the repository root: python3 -m pytest labs/finbot/images/tests/test_smoke.py -v
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

SMOKE = Path(__file__).resolve().parents[1] / "smoke.sh"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="smoke.sh runs on macOS and Linux only (Rock, 2026-11-17)")

# Logs each call on one line, newlines in inline code included. It answers the reachability probe with one line per
# host and port it was given.
FAKE_DOCKER = """#!/bin/sh
printf '%s' "$*" | tr '\\n' ' ' >> "$FAKE_DOCKER_LOG"
printf '\\n' >> "$FAKE_DOCKER_LOG"
case "$*" in
    *"exec -T redis wget"*)
        printf '%s\n' "${FAKE_NO_TOKEN_REPLY:-}"
        exit 1 ;;
    *"exec -T acs-gateway python -c "*lab-reach-record*)
        while [ "$#" -gt 0 ] && [ "$1" != -c ]; do shift; done
        shift 2
        if [ "${FAKE_CONTROL:-reaches}" = reaches ]; then printf 'reaches %s:%s\\n' "$1" "$2"
        else printf 'cannot reach %s:%s (OSError)\\n' "$1" "$2"; fi ;;
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


# Logs each call, fails the one whose arguments equal FAKE_LAB_FAIL, and, once the lab is in enforce mode, leaves a
# transcript named FAKE_LAB_TRANSCRIPT for each run, the way the gateway does for a new session.
FAKE_LAB = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_LAB_LOG"
if [ "$*" = "run s1" ] && [ -n "${FAKE_LAB_TRANSCRIPT:-}" ] && grep -qx 'mode enforce' "$FAKE_LAB_LOG"; then
    mkdir -p state/transcripts
    : > "state/transcripts/$FAKE_LAB_TRANSCRIPT"
fi
if [ "$*" = "${FAKE_LAB_FAIL:-}" ]; then
    printf 'NOT YET: %s fell over\\n' "$*"
    exit 1
fi
printf 'DONE: %s\\n' "$*"
"""


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    root = tmp_path / "bundle"
    (root / "images").mkdir(parents=True)
    shutil.copy2(SMOKE, root / "images" / "smoke.sh")
    (root / "lab.sh").write_text(FAKE_LAB, encoding="utf-8")
    (root / "lab.sh").chmod(0o755)
    (root / ".env").write_text("LAB_PORT_APPROVER=18090\nLAB_PORT_JAEGER=26686\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, text in (("docker", FAKE_DOCKER), ("curl", "#!/bin/sh\nexit 7\n")):
        (bin_dir / name).write_text(text, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    return root


def run_smoke(bundle: Path, reachable: str = "acs-gateway", no_token_reply: str = "", lab_fail: str = "",
              transcript: str = "", control: str = "reaches") -> tuple[subprocess.CompletedProcess, list[str]]:
    log = bundle.parent / "docker.log"
    log.write_text("", encoding="utf-8")
    lab_log = bundle.parent / "lab.log"
    lab_log.write_text("", encoding="utf-8")
    env = {**os.environ, "PATH": f"{bundle.parent / 'bin'}:{os.environ['PATH']}", "FAKE_DOCKER_LOG": str(log),
           "FAKE_REACHABLE": reachable, "FAKE_NO_TOKEN_REPLY": no_token_reply, "FAKE_LAB_LOG": str(lab_log),
           "FAKE_LAB_FAIL": lab_fail, "FAKE_LAB_TRANSCRIPT": transcript, "FAKE_CONTROL": control}
    result = subprocess.run(["sh", str(bundle / "images" / "smoke.sh")], env=env, capture_output=True, text=True,
                            timeout=60)
    return result, log.read_text(encoding="utf-8").splitlines()


def _probe_targets(calls: list[str]) -> list[str]:
    probe = [c for c in calls if "lab-reach-record" in c and "exec -T finbot " in c]
    assert len(probe) == 1, calls
    assert probe[0].startswith("compose -f compose.yaml exec -T finbot python -c ")
    words = probe[0].split()
    # The fake logs argv joined by spaces, so the code runs into the first target. Pairs read from the end.
    pairs = []
    while len(words) >= 2 and words[-1].isdigit():
        pairs.insert(0, f"{words[-2]}:{words[-1]}")
        words = words[:-2]
    return pairs


OUTSIDE = ["1.1.1.1:443", "example.com:443", "host.docker.internal:11434", "@gateway:11434"]


def test_smoke_probes_the_approver_the_host_and_the_internet_from_finbot(bundle):
    _, calls = run_smoke(bundle)
    targets = _probe_targets(calls)
    assert "acs-gateway:8090" in targets
    # The host's published ports, overrides from .env included, by Docker Desktop's host name and by the default route.
    for port in ("18090", "8095", "26686"):
        assert f"host.docker.internal:{port}" in targets, port
        assert f"@gateway:{port}" in targets, port
    # A public address with no name lookup, a public name, and a model served on the host, such as Ollama.
    for target in OUTSIDE:
        assert target in targets, target
    assert not any(t.endswith(":8000") or t.endswith(":18000") for t in targets)


def test_smoke_passes_when_finbot_reaches_nothing_outside(bundle):
    result, _ = run_smoke(bundle, reachable="acs-gateway")
    lines = result.stdout.splitlines()
    assert "NOTE: finbot reaches acs-gateway:8090" in lines
    for target in OUTSIDE:
        assert f"DONE: finbot can't reach {target}, outside the compose networks" in lines, target
    assert not any("outside the compose networks" in line for line in lines if line.startswith("NOT YET"))


@pytest.mark.parametrize("host", ["1.1.1.1", "example.com", "host.docker.internal", "@gateway"])
def test_smoke_fails_when_finbot_reaches_outside(bundle, host):
    result, _ = run_smoke(bundle, reachable=host)
    failed = [line for line in result.stdout.splitlines()
              if line.startswith("NOT YET: finbot reached") and line.endswith("outside the compose networks")]
    assert failed and all(host in line for line in failed), result.stdout
    assert result.returncode == 1


def test_smoke_proves_the_runner_can_see_out(bundle):
    # Review round 4, M3: FinBot failing to reach 1.1.1.1 means isolation only when something on the same runner can.
    result, calls = run_smoke(bundle)
    control = [c for c in calls if "lab-reach-record" in c and "exec -T acs-gateway " in c]
    assert len(control) == 1 and control[0].split()[-2:] == ["1.1.1.1", "443"], calls
    assert "DONE: acs-gateway reaches 1.1.1.1:443, so the runner can see out" in result.stdout.splitlines()


def test_smoke_fails_when_the_runner_cannot_see_out(bundle):
    result, _ = run_smoke(bundle, control="cannot")
    lines = [line for line in result.stdout.splitlines() if "runner" in line]
    assert len(lines) == 1 and lines[0].startswith("NOT YET: acs-gateway can't reach 1.1.1.1:443"), result.stdout
    assert result.returncode == 1


def test_smoke_fails_when_the_probe_does_not_run(bundle):
    (bundle.parent / "bin" / "docker").write_text(FAKE_DOCKER.replace("*lab-reach-record*)", "*lab-reach-record*)\n"
                                                  "        echo 'exec failed' >&2; exit 1 ;;\n    *never-matches*)"),
                                                  encoding="utf-8")
    result, _ = run_smoke(bundle)
    assert "NOT YET: the reachability probe did not run: exec failed" in result.stdout.splitlines()
    assert result.returncode == 1


def test_a_kept_model_key_names_the_reset_flag(bundle):
    # lab reset keeps openai.key by default, so the run that trips on it names the one command that deletes it.
    (bundle / "state" / "secrets").mkdir(parents=True)
    (bundle / "state" / "secrets" / "openai.key").write_text("sk-dummy\n", encoding="utf-8")
    result, _ = run_smoke(bundle)
    key_lines = [line for line in result.stdout.splitlines() if "openai.key" in line]
    assert len(key_lines) == 1 and key_lines[0].startswith("NOT YET:"), result.stdout
    assert "./lab.sh reset --delete-model-key" in key_lines[0]
    assert result.returncode == 1


def _reach_probe() -> str:
    text = SMOKE.read_text(encoding="utf-8")
    match = re.search(r"^reach_probe='(.*?)'$", text, re.S | re.M)
    assert match, "no reach_probe in smoke.sh"
    return match.group(1)


def test_the_probe_bound_covers_the_name_lookup(tmp_path):
    # A slow resolver must not stretch the run: the 2-second bound covers the DNS lookup as well as the connect.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    # The probe reads its targets from sys.argv[1:], so the wrapper's own first argument, the probe path, is
    # dropped before it runs.
    probe = tmp_path / "probe.py"
    probe.write_text(_reach_probe(), encoding="utf-8")
    slow = ("import runpy, socket, sys, time\n"
            "real = socket.getaddrinfo\n"
            "def lookup(host, *args, **kwargs):\n"
            "    if host == 'slow.invalid':\n"
            "        time.sleep(30)\n"
            "    return real(host, *args, **kwargs)\n"
            "socket.getaddrinfo = lookup\n"
            "path = sys.argv.pop(1)\n"
            "runpy.run_path(path, run_name='__main__')\n")
    started = time.monotonic()
    try:
        done = subprocess.run([sys.executable, "-c", slow, str(probe), "slow.invalid", "443", "127.0.0.1",
                               str(port)], capture_output=True, text=True, timeout=20)
    finally:
        listener.close()
    elapsed = time.monotonic() - started
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines() == ["cannot reach slow.invalid:443 (TimeoutError)", f"reaches 127.0.0.1:{port}"]
    assert elapsed < 6, elapsed


# ---------------------------------------------------------------------------------------------------------------------
# LAB-16 Task 16: module 1 is the model path, and every check needs a positive result from this run (final review R1)
# ---------------------------------------------------------------------------------------------------------------------

MODULE_1 = ["mode off", "run s1", "mode enforce", "run s1", "check 1"]
SESSION = "11111111-1111-4111-8111-111111111111"


def _line(result: subprocess.CompletedProcess, words: str) -> str:
    found = [line for line in result.stdout.splitlines() if words in line]
    assert len(found) == 1, result.stdout
    return found[0]


def test_smoke_plays_module_1_in_order(bundle):
    result, _ = run_smoke(bundle)
    calls = (bundle.parent / "lab.log").read_text(encoding="utf-8").splitlines()
    assert calls == MODULE_1
    done = [line for line in result.stdout.splitlines() if line.startswith("DONE: ./lab.sh ")]
    assert done == [f"DONE: ./lab.sh {step}" for step in MODULE_1]


@pytest.mark.parametrize("step", MODULE_1)
def test_a_failing_module_1_step_fails_the_smoke(bundle, step):
    result, _ = run_smoke(bundle, lab_fail=step)
    line = [x for x in result.stdout.splitlines() if x.startswith(f"NOT YET: ./lab.sh {step} exited 1")]
    assert line, result.stdout
    # The NOT YET line names what the step itself said, and the step's own output reaches stderr, never stdout.
    assert line[0].endswith(f"NOT YET: {step} fell over")
    assert f"lab {step}: NOT YET: {step} fell over" in result.stderr
    assert result.returncode == 1


def test_the_enforce_runs_new_transcript_is_verified(bundle):
    result, calls = run_smoke(bundle, transcript=SESSION)
    assert _line(result, "left a new transcript").startswith("DONE:")
    verify = [c for c in calls if "acs.testing.verify" in c]
    assert len(verify) == 1 and f"/lab/state/transcripts/{SESSION} " in verify[0]


def test_a_stale_transcript_fails_the_smoke(bundle):
    # A transcript an earlier run left holds nothing this run created.
    (bundle / "state" / "transcripts").mkdir(parents=True)
    (bundle / "state" / "transcripts" / SESSION).write_text("{}\n", encoding="utf-8")
    result, calls = run_smoke(bundle)
    assert _line(result, "transcript").startswith("NOT YET:")
    assert not [c for c in calls if "acs.testing.verify" in c]


# ---------------------------------------------------------------------------------------------------------------------
# Final review R8: the model port refuses a caller without the per-lab client token
# ---------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("answer", "verdict"), [
    ("wget: server returned error: HTTP/1.1 401 Unauthorized", "DONE:"),
    ("wget: server returned error: HTTP/1.1 500 Internal Server Error", "NOT YET:"),
    ("wget: can't connect to remote host: Connection refused", "NOT YET:"),
    ("", "NOT YET:"),
])
def test_a_call_from_another_container_without_the_token_must_get_401(bundle, answer, verdict):
    result, calls = run_smoke(bundle, no_token_reply=answer)
    probe = [c for c in calls if "exec -T redis wget" in c]
    assert len(probe) == 1 and "http://acs-gateway:8080/v1/responses" in probe[0], calls
    assert "authorization" not in probe[0].lower()
    assert _line(result, "without the client token").startswith(verdict)
