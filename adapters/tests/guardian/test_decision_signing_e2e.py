"""A signed session over real HTTP: every answer verifies with the key document alone (issue #576).

The example Guardian runs as its own process with ACS_RESPONSE_SIGNING=ML-DSA-65, and acs.client talks to it with
the key document it fetched from GET /keys. The key document, the handshake fields, and the request hash are lab
conventions (issues #460, #316, #13).
"""
from __future__ import annotations

import copy
import datetime
import http.server
import json
import os
import threading
import urllib.request
import uuid

import pytest

from decision_signing_helpers import METADATA, SESSION, mldsa_env, require_pqc

require_pqc()

from acs.client import (  # noqa: E402
    Config,
    Decided,
    FailPosture,
    Negotiated,
    Resolution,
    SessionRefused,
    open_session,
    parse_key_document,
    round_trip,
)
from acs.client import _handshake  # noqa: E402
from acs.core import request_envelope, verify_with_keyring  # noqa: E402
from acs.testing.harness import launch_guardian  # noqa: E402

PROCEED = FailPosture(deny_on_failure=False, timeout_s=5.0)
ALLOWED = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls -la"}}}
DENIED = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "rm -rf /"}}}
NO_PROXY = {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}


@pytest.fixture
def guardian(tmp_path, monkeypatch):
    """Start the Guardian with decision signing on. Yields (url, process). The client shares its HMAC settings."""
    env = {**mldsa_env(tmp_path), **NO_PROXY, "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "state")}
    base = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
    for name, value in {**env}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    monkeypatch.setattr(_handshake, "_HANDSHAKE_CACHE_DIR", tmp_path / "handshake")
    process, port = launch_guardian(env={**base, **env})
    yield f"http://127.0.0.1:{port}", process
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)


def fetch_keys(base_url: str):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(base_url + "/keys", timeout=5) as response:
        document = json.loads(response.read())
    return parse_key_document(document, key_id=None, now=datetime.datetime.now(datetime.timezone.utc))


def step(method: str, payload: dict, *, session_id: str = SESSION) -> dict:
    return request_envelope(method, request_id=str(uuid.uuid4()), metadata={**METADATA, "session_id": session_id},
                            payload=payload)


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, direction: str, envelope: dict) -> None:
        self.calls.append((direction, envelope))

    def pairs(self) -> list[tuple[dict, dict]]:
        """Each answer with the request sent just before it."""
        out, last = [], None
        for direction, envelope in self.calls:
            if direction == "req":
                last = envelope
            else:
                out.append((last, envelope))
        return out


def test_every_response_verifies_with_the_key_document_alone(guardian, monkeypatch):
    base_url, _ = guardian
    url = base_url + "/acs"
    keys = fetch_keys(base_url)
    recorder = Recorder()

    def start(negotiated: Negotiated):
        return round_trip(step("steps/sessionStart", {"source": "startup"}), guardian_url=url, posture=PROCEED,
                          session_id=SESSION, response_keys=keys, on_wire=recorder)

    session = open_session(config=Config.from_env({"ACS_GUARDIAN_URL": url}), session_id=SESSION, agent_id="finbot",
                           platform="lab", methods_implemented=["steps/sessionStart", "steps/toolCallRequest"],
                           start=start, response_keys=keys, on_wire=recorder)
    assert isinstance(session, Negotiated), session
    allowed = round_trip(step("steps/toolCallRequest", ALLOWED), guardian_url=url, posture=PROCEED,
                         session_id=SESSION, response_keys=keys, on_wire=recorder)
    assert isinstance(allowed, Decided) and allowed.response["result"]["decision"] == "allow"
    denied = round_trip(step("steps/toolCallRequest", DENIED), guardian_url=url, posture=PROCEED,
                        session_id=SESSION, response_keys=keys, on_wire=recorder)
    assert isinstance(denied, Decided) and denied.response["result"]["decision"] == "deny"
    original = step("steps/toolCallRequest", ALLOWED)
    round_trip(copy.deepcopy(original), guardian_url=url, posture=PROCEED, session_id=SESSION,
               response_keys=keys, on_wire=recorder)
    replayed = round_trip(copy.deepcopy(original), guardian_url=url, posture=PROCEED, session_id=SESSION,
                          response_keys=keys, on_wire=recorder)
    assert isinstance(replayed, Resolution) and replayed.cause == "replay_detected_response"

    # The key document alone: no HMAC material anywhere in this process.
    for name in ("ACS_HMAC_SECRET", "ACS_HMAC_SECRET_FILE", "ACS_HMAC_KEY_ID"):
        monkeypatch.delenv(name, raising=False)
    kinds = set()
    for request, response in recorder.pairs():
        assert verify_with_keyring(response, keys.keyring, expected_key_id=keys.key_id, request=request,
                                   require_request_digest=True), response
        if "error" in response:
            kinds.add("error")
        elif "negotiated_version" in response["result"]:
            kinds.add("server_hello")
        else:
            kinds.add(response["result"]["decision"])
    assert {"server_hello", "allow", "deny", "error"} <= kinds


class TamperingRelay:
    """A threaded relay in front of the Guardian that rewrites one character of result.reasoning on a deny."""

    def __init__(self, target: str) -> None:
        relay = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                request = urllib.request.Request(target, data=body, headers={"Content-Type": "application/json"})
                with opener.open(request, timeout=5) as upstream:
                    answer = json.loads(upstream.read())
                result = answer.get("result") or {}
                if result.get("decision") == "deny" and result.get("reasoning"):
                    reasoning = result["reasoning"]
                    result["reasoning"] = ("X" if reasoning[0] != "X" else "Y") + reasoning[1:]
                    relay.tampered.append(answer)
                payload = json.dumps(answer).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: object) -> None:
                return

        self.tampered: list[dict] = []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/acs"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def test_a_flipped_byte_on_the_wire_blocks_the_step(guardian):
    base_url, _ = guardian
    keys = fetch_keys(base_url)
    relay = TamperingRelay(base_url + "/acs")
    try:
        recorder = Recorder()
        outcome = round_trip(step("steps/toolCallRequest", DENIED), guardian_url=relay.url, posture=PROCEED,
                             session_id=SESSION, response_keys=keys, on_wire=recorder)
    finally:
        relay.close()
    assert isinstance(outcome, Resolution)
    assert outcome.proceed is False
    assert outcome.cause == "response_signature_invalid"
    assert outcome.fields["failure_class"] == "signature_invalid"
    assert len(relay.tampered) == 1
    assert recorder.calls[-1] == ("resp", relay.tampered[0])


def test_hmac_only_client_is_refused_on_the_wire(guardian):
    base_url, process = guardian
    recorder = Recorder()
    url = base_url + "/acs"
    session = open_session(config=Config.from_env({"ACS_GUARDIAN_URL": url}), session_id=str(uuid.uuid4()),
                           agent_id="finbot", platform="lab", methods_implemented=["steps/toolCallRequest"],
                           on_wire=recorder)
    # Today's client can't verify an ML-DSA signature, so the refusal reads as unverifiable and blocks every step
    # (PREMORTEM P28). The reason is in the raw answer and in the Guardian's log.
    assert isinstance(session, SessionRefused)
    assert session.cause == "error_signature_invalid"
    assert session.fields["claimed_error_code"] == -32000
    direction, raw = recorder.calls[-1]
    assert direction == "resp"
    assert raw["error"]["data"]["reason"] == "unsupported_signature_algorithm"
    process.terminate()
    _, stderr = process.communicate(timeout=5)
    assert "[guardian] handshake refused: unsupported_signature_algorithm offered=null" in stderr
