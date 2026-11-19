"""smoke.sh's reachability record (issue #588, LAB-15), driven against a fake docker. No Docker needed.

The LAB-15 review accepted that finbot-net isn't internal, so FinBot can reach the gateway's approver port, the host's
published ports and the internet. smoke.sh records what FinBot reaches on every run, so a change in that residual
shows in the log. It records and never fails the run on it.

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
# host and port it was given, and the model call with FAKE_MODEL_REPLY and exit status FAKE_MODEL_RC.
FAKE_DOCKER = """#!/bin/sh
printf '%s' "$*" | tr '\\n' ' ' >> "$FAKE_DOCKER_LOG"
printf '\\n' >> "$FAKE_DOCKER_LOG"
case "$*" in
    *OPENAI_BASE_URL*)
        printf '%s' "${FAKE_MODEL_REPLY:-}"
        exit "${FAKE_MODEL_RC:-0}" ;;
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


def run_smoke(bundle: Path, reachable: str = "acs-gateway", reply: str = "",
              reply_rc: int = 0) -> tuple[subprocess.CompletedProcess, list[str]]:
    log = bundle.parent / "docker.log"
    log.write_text("", encoding="utf-8")
    env = {**os.environ, "PATH": f"{bundle.parent / 'bin'}:{os.environ['PATH']}", "FAKE_DOCKER_LOG": str(log),
           "FAKE_REACHABLE": reachable, "FAKE_MODEL_REPLY": reply, "FAKE_MODEL_RC": str(reply_rc)}
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
    # A model served on the host, such as Ollama, is model traffic that never passes the gateway (LAB-15 re-review).
    assert "host.docker.internal:11434" in targets
    assert "@gateway:11434" in targets


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
# Final review R1: every model-path check needs a positive result from this run
# ---------------------------------------------------------------------------------------------------------------------

MISS_ANSWER = "resp_replay_miss: I couldn't complete that action."
TRACEBACK = """Traceback (most recent call last):
  File "<string>", line 8, in <module>
urllib.error.URLError: <urlopen error [Errno 111] Connection refused>"""


def _line(result: subprocess.CompletedProcess, words: str) -> str:
    found = [line for line in result.stdout.splitlines() if words in line]
    assert len(found) == 1, result.stdout
    return found[0]


def test_a_traceback_from_the_model_call_fails_the_smoke(bundle):
    result, _ = run_smoke(bundle, reply=TRACEBACK, reply_rc=1)
    assert _line(result, "model call through FinBot").startswith("NOT YET:")
    assert result.returncode == 1


def test_a_traceback_fails_even_when_the_exec_exits_0(bundle):
    result, _ = run_smoke(bundle, reply=TRACEBACK, reply_rc=0)
    assert _line(result, "model call through FinBot").startswith("NOT YET:")


def test_an_empty_answer_fails_the_smoke(bundle):
    result, _ = run_smoke(bundle, reply="", reply_rc=0)
    assert _line(result, "model call through FinBot").startswith("NOT YET:")


def test_the_replay_answer_passes_the_model_call_check(bundle):
    # The positive control: the check isn't simply always red.
    result, _ = run_smoke(bundle, reply=MISS_ANSWER, reply_rc=0)
    assert _line(result, "model call through FinBot").startswith("DONE:")


def test_the_call_carries_a_fresh_nonce_each_run(bundle):
    _, first = run_smoke(bundle, reply=MISS_ANSWER)
    _, second = run_smoke(bundle, reply=MISS_ANSWER)
    calls = [c for c in first + second if "OPENAI_BASE_URL" in c]
    assert len(calls) == 2
    nonces = [re.search(r" ([0-9a-f]{16})$", c) for c in calls]
    assert all(nonces), calls
    assert nonces[0].group(1) != nonces[1].group(1)


def test_a_stale_replay_miss_line_from_an_earlier_run_fails_the_smoke(bundle):
    # A local rerun keeps state/audit.log, so a miss line from the last run must not satisfy this one.
    (bundle / "state").mkdir()
    (bundle / "state" / "audit.log").write_text(
        'ACS_AUDIT {"acs_audit_event": "replay_miss", "cause": "no_recording", "timestamp": "2026-11-17T10:00:00Z"}\n',
        encoding="utf-8")
    result, _ = run_smoke(bundle, reply=MISS_ANSWER)
    assert _line(result, "replay miss").startswith("NOT YET:")


def test_stale_model_input_and_transcript_fail_the_smoke(bundle):
    # The input log and the transcripts from an earlier run hold nothing this run created.
    state = bundle / "state"
    (state / "transcripts").mkdir(parents=True)
    (state / "transcripts" / "11111111-1111-4111-8111-111111111111.jsonl").write_text("{}\n", encoding="utf-8")
    (state / "model-inputs.jsonl").write_text('{"input": "lab smoke check 0123456789abcdef"}\n', encoding="utf-8")
    result, _ = run_smoke(bundle, reply=MISS_ANSWER)
    assert _line(result, "model input log").startswith("NOT YET:")
    assert _line(result, "transcript").startswith("NOT YET:")
