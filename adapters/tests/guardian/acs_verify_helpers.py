"""Signed sessions for the acs-verify tests, recorded from the real example Guardian as the lab gateway records them.

Each session runs the example Guardian as its own process, talks to it through acs.client, and keeps every envelope
acs.client hands to on_wire as one transcript line, {"dir", "envelope"}, written the way the gateway writes it
(A.7). Keys are generated under tmp_path for each test, so no private key is ever committed.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import select
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from acs.client import Config, Decided, FailPosture, Negotiated, open_session, round_trip
from acs.client import _handshake
from acs.core import request_envelope
from acs.testing.harness import launch_guardian, signing_env

PROCEED = FailPosture(deny_on_failure=False, timeout_s=5.0)
ALLOWED = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls -la"}}}
DENIED = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "rm -rf /"}}}
NO_PROXY = {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
FINGERPRINT_LINE = re.compile(r"\[guardian\] decision signing ML-DSA-65 key_id=(\S+) fingerprint=(sha256:[0-9a-f]{64})")


def transcript_line(direction: str, envelope: dict | None, cause: str | None = None) -> str:
    """One line as the gateway's Transcript writes it: compact JSON with every non-ASCII character escaped."""
    record: dict[str, Any] = {"dir": direction, "envelope": envelope}
    if envelope is None:
        record["cause"] = cause
    return json.dumps(record, separators=(",", ":"), ensure_ascii=True)


@dataclass
class GuardianRun:
    """A running example Guardian and what a verifier needs from it."""

    url: str
    process: subprocess.Popen
    mldsa: bool
    session_id: str
    key_document_path: Path | None = None
    stderr_lines: list[str] = field(default_factory=list)

    @property
    def hmac_secret(self) -> bytes:
        return signing_env()["ACS_HMAC_SECRET"].encode("utf-8")

    def key_document(self) -> dict:
        assert self.key_document_path is not None
        return json.loads(self.key_document_path.read_text(encoding="utf-8"))

    def response_keys(self):
        from acs.client import parse_key_document
        return parse_key_document(self.key_document(), key_id=None, now=datetime.datetime.now(datetime.timezone.utc))

    def startup_fingerprint(self, timeout: float = 5.0) -> str:
        """The fingerprint the Guardian printed on stderr at startup, read from the live process."""
        # Raw reads from the descriptor: a buffered readline can pull several lines into Python's buffer, and then
        # select reports nothing left to read while the fingerprint line sits unread in that buffer.
        fd = self.process.stderr.fileno()
        deadline = time.time() + timeout
        while time.time() < deadline:
            match = FINGERPRINT_LINE.search("".join(self.stderr_lines))
            if match:
                return match.group(2)
            readable, _, _ = select.select([fd], [], [], 0.2)
            if readable:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                self.stderr_lines.append(chunk.decode("utf-8", "replace"))
        raise AssertionError(f"the Guardian printed no fingerprint line: {self.stderr_lines!r}")


def start_guardian(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, mldsa: bool) -> GuardianRun:
    """Start the example Guardian, in ML-DSA-65 response mode or today's HMAC mode. The client shares its HMAC settings."""
    env = {**signing_env(), **NO_PROXY, "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "state")}
    doc_path = None
    if mldsa:
        from decision_signing_helpers import mldsa_env
        env = {**mldsa_env(tmp_path), **NO_PROXY, "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "state")}
        doc_path = Path(env["ACS_GUARDIAN_KEYS"])
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    monkeypatch.setattr(_handshake, "_HANDSHAKE_CACHE_DIR", tmp_path / "handshake")
    base = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
    process, port = launch_guardian(env={**base, **env})
    return GuardianRun(url=f"http://127.0.0.1:{port}/acs", process=process, mldsa=mldsa,
                       session_id=str(uuid.uuid4()), key_document_path=doc_path)


def stop_guardian(run: GuardianRun) -> None:
    if run.process.poll() is None:
        run.process.terminate()
        run.process.wait(timeout=5)


class Recorder:
    """The on_wire callback: every envelope acs.client sends or receives, as transcript lines, in order."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, direction: str, envelope: dict) -> None:
        self.lines.append(transcript_line(direction, envelope))


class Session:
    """One Guardian session recorded the way the gateway records it."""

    def __init__(self, run: GuardianRun) -> None:
        self.run = run
        self.keys = run.response_keys() if run.mldsa else None
        self.recorder = Recorder()

    @property
    def lines(self) -> list[str]:
        return self.recorder.lines

    def envelope(self, method: str, payload: dict) -> dict:
        return request_envelope(method, request_id=str(uuid.uuid4()),
                                metadata={"agent_id": "finbot", "session_id": self.run.session_id,
                                          "platform": "lab"},
                                payload=payload)

    def send(self, request: dict):
        return round_trip(request, guardian_url=self.run.url, posture=PROCEED, session_id=self.run.session_id,
                          response_keys=self.keys, on_wire=self.recorder)

    def step(self, method: str, payload: dict):
        return self.send(self.envelope(method, payload))

    def open(self) -> None:
        def start(negotiated: Negotiated):
            return self.step("steps/sessionStart", {"source": "startup"})

        handshake = open_session(config=Config.from_env({"ACS_GUARDIAN_URL": self.run.url}),
                                 session_id=self.run.session_id, agent_id="finbot", platform="lab",
                                 methods_implemented=["steps/sessionStart", "steps/toolCallRequest",
                                                      "steps/sessionEnd"],
                                 start=start, response_keys=self.keys, on_wire=self.recorder)
        assert isinstance(handshake, Negotiated), handshake


def record_session(run: GuardianRun, *, end: bool = True, replay: bool = False) -> list[str]:
    """Handshake, sessionStart, an allow, a deny, optionally a replayed request, and optionally sessionEnd."""
    session = Session(run)
    session.open()
    allowed = session.step("steps/toolCallRequest", ALLOWED)
    assert isinstance(allowed, Decided) and allowed.response["result"]["decision"] == "allow", allowed
    if replay:
        # The Guardian refuses the second copy with a signed -32005 and adds no chain entry for it.
        original = session.envelope("steps/toolCallRequest", ALLOWED)
        session.send(json.loads(json.dumps(original)))
        session.send(json.loads(json.dumps(original)))
    denied = session.step("steps/toolCallRequest", DENIED)
    assert isinstance(denied, Decided) and denied.response["result"]["decision"] == "deny", denied
    if end:
        ended = session.step("steps/sessionEnd", {"reason": "user_exit"})
        assert isinstance(ended, Decided), ended
    return list(session.lines)
