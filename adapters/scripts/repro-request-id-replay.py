"""Show what replay detection keys on: the envelope's `request_id`, not the action.

Usage: python scripts/repro-request-id-replay.py

Starts the shipped example Guardian on a port it picks, opens one session, then
sends two `steps/toolCallRequest` envelopes that carry the same tool name and
the same arguments under different `request_id`s, followed by a repeat of the
first one:

  1. two envelopes, same action, distinct request_ids   -> both allowed
  2. the same envelope again, same request_id           -> -32005 REPLAY_DETECTED

Exit code 0 when both hold, 1 otherwise. This isolates the mechanism described
in docs/claude_code/prehook-coverage-2026-11-09.md from any host: a conformant
Guardian rejects a repeated envelope and has nothing to reject when the action
repeats under fresh ids. It reads the policy the example Guardian ships with,
which allows a `Write`.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ADAPTERS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ADAPTERS / "src"))

from acs import core
from acs.testing.harness import sign_for_test, signing_env

GUARDIAN = ADAPTERS / "src" / "acs" / "guardian" / "example_guardian.py"

ARGUMENTS = {
    "file_path": {"value": "report.txt"},
    "content": {"value": "line 01: same bytes every time\n"},
}


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def start_guardian() -> tuple[subprocess.Popen, int]:
    """Pick a port, start the shipped Guardian on it, and wait until it answers."""
    port = free_port()
    env = {**os.environ, **signing_env()}
    env.pop("ACS_HMAC_SECRET_FILE", None)
    process = subprocess.Popen(
        [sys.executable, str(GUARDIAN), "--port", str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    deadline = time.time() + 20.0
    while time.time() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"guardian exited early: {(process.stderr.read() or '')[:600]}")
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/acs", data=b"{}", timeout=1.0)
            return process, port
        except urllib.error.HTTPError:
            return process, port
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.1)
    process.terminate()
    raise SystemExit("guardian did not answer within 20s")


def envelope(session_id: str, request_id: str, method: str, payload: dict) -> dict:
    return sign_for_test({
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": "0.1.0",
            "request_id": request_id,
            "timestamp": core.iso8601_now(),
            "metadata": {"agent_id": "repro", "session_id": session_id, "platform": "repro"},
            "payload": payload,
        },
    })


def post(port: int, body: dict) -> dict:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/acs",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10.0) as response:
        return json.loads(response.read().decode())


def outcome(response: dict) -> tuple[str, object]:
    if "error" in response:
        return "error", response["error"].get("code")
    return "result", (response.get("result") or {}).get("decision")


def main() -> int:
    steps = []
    first_id = str(uuid.uuid4())
    second_id = str(uuid.uuid4())

    process, port = start_guardian()
    try:
        session_id = str(uuid.uuid4())
        payload_free = {}
        started = post(port, envelope(session_id, str(uuid.uuid4()), "steps/sessionStart", payload_free))
        steps.append(("sessionStart", outcome(started)))

        tool_payload = {"tool": {"name": "Write"}, "arguments": ARGUMENTS}
        first = post(port, envelope(session_id, first_id, "steps/toolCallRequest", tool_payload))
        steps.append(("same action, request_id #1", outcome(first)))

        second = post(port, envelope(session_id, second_id, "steps/toolCallRequest", tool_payload))
        steps.append(("same action, request_id #2", outcome(second)))

        repeated = post(port, envelope(session_id, first_id, "steps/toolCallRequest", tool_payload))
        steps.append(("same action, request_id #1 again", outcome(repeated)))
    finally:
        process.terminate()

    for label, (kind, value) in steps:
        print(f"{label:38s} {kind}: {value}")

    fresh_ids_allowed = steps[1][1] == ("result", "allow") and steps[2][1] == ("result", "allow")
    replay_refused = steps[3][1] == ("error", -32005)
    print()
    print(f"distinct request_ids, same action, both allowed: {fresh_ids_allowed}")
    print(f"repeated request_id refused with -32005:         {replay_refused}")
    return 0 if (fresh_ids_allowed and replay_refused) else 1


if __name__ == "__main__":
    raise SystemExit(main())
