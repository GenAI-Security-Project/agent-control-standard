"""Lab evidence for the module check tests, written by the code that writes it in the lab (issue #589, LAB-16).

Version 1.0.0. Owner: Rock Lambros.

Audit lines go through acs.client's audit_event, transcript lines through the gateway's Transcript writer, and model
input lines through its ModelInputLog, so a change to any of those formats turns the check tests red. Requests and
answers are built and signed the way LAB-13's viewer/tests/lab_lines.py builds them: requests HMAC-signed as
acs.client signs them, answers either HMAC-signed or signed with an ML-DSA-65 decision key after the request hash goes
in. This module copies that approach rather than importing it, so the viewer's tests and these change on their own.
Lab conventions: the key document (issue #460), the request hash (issue #13), ML-DSA-65 response signing (issue #316).

Importing it puts the checks directory and the gateway's source tree on sys.path, so a test can import evidence and
each m<n>.py beside it.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CHECKS_DIR = Path(__file__).resolve().parents[1]
BUNDLE = CHECKS_DIR.parents[1]
REPO_ROOT = BUNDLE.parents[1]
GATEWAY_SRC = REPO_ROOT / "adapters" / "gateway" / "src"
CLI_DIR = BUNDLE / "cli"

for _path in (CHECKS_DIR, GATEWAY_SRC, CLI_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from acs.client import audit_event  # noqa: E402
from acs.core import derive_session_key, request_envelope, sign_with_key  # noqa: E402
from acs_gateway.transcript import ModelInputLog, Transcript  # noqa: E402

SESSION_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SESSION_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
HMAC_SECRET = b"lab-module-check-test-secret-of-32-bytes-or-more"
HMAC_KEY_ID = "lab-hmac"
KEY_ID = "lab-guardian-1"
GUARDIAN_ID = "lab-guardian"


# ---------------------------------------------------------------------------------------------------------------------
# envelopes
# ---------------------------------------------------------------------------------------------------------------------

def request(method: str, payload: dict[str, Any] | None = None, *, session_id: str = SESSION_A) -> dict[str, Any]:
    """A step request HMAC-signed as acs.client signs it. Requests stay on HMAC in every response mode."""
    envelope = request_envelope(method, request_id=str(uuid.uuid4()),
                                metadata={"agent_id": "finbot", "session_id": session_id, "platform": "lab"},
                                payload=payload or {})
    return sign_with_key(envelope, derive_session_key(HMAC_SECRET, session_id), key_id=HMAC_KEY_ID)


def tool_request(tool: str, arguments: dict[str, Any] | None = None, *,
                 session_id: str = SESSION_A) -> dict[str, Any]:
    return request("steps/toolCallRequest", {"tool": {"name": tool}, "arguments": arguments or {}},
                   session_id=session_id)


def answer(req: dict[str, Any], decision: str = "allow", **result: Any) -> dict[str, Any]:
    """An unsigned decision answer bound to req by id and request_id."""
    return {"jsonrpc": "2.0", "id": req["id"],
            "result": {"request_id": req["params"]["request_id"], "decision": decision, **result}}


def sign_hmac(response: dict[str, Any], session_id: str = SESSION_A) -> dict[str, Any]:
    return sign_with_key(response, derive_session_key(HMAC_SECRET, session_id), key_id=HMAC_KEY_ID)


@dataclass
class DecisionKey:
    """A fresh ML-DSA-65 decision key, written by the Guardian's own key tool, and its key document."""

    signing_key: Any
    document_path: Path

    @property
    def fingerprint(self) -> str:
        return json.loads(self.document_path.read_text(encoding="utf-8"))["keys"][0]["fingerprint"]

    def sign(self, response: dict[str, Any], req: dict[str, Any]) -> dict[str, Any]:
        """The Guardian's order: the request hash goes into the answer, then the decision key signs it."""
        from acs.core import REQUEST_DIGEST_FIELD, request_sha256, sign_with_signing_key
        response["result"] = {**response["result"], REQUEST_DIGEST_FIELD: request_sha256(req)}
        return sign_with_signing_key(response, self.signing_key)


def decision_key(directory: Path) -> DecisionKey:
    """Needs the pqc extra. The key document lands where lab init puts it when directory is state/keys."""
    from acs.guardian.decision_keys import load_signing_key, write_key_files
    key_path, doc_path = write_key_files(directory, key_id=KEY_ID, guardian_id=GUARDIAN_ID)
    return DecisionKey(load_signing_key(str(key_path), KEY_ID), doc_path)


# ---------------------------------------------------------------------------------------------------------------------
# a lab bundle with its state directory
# ---------------------------------------------------------------------------------------------------------------------

@dataclass
class LabState:
    """A bundle directory laid out as lab init leaves it: state/ with its logs and .env beside it."""

    root: Path

    def __post_init__(self) -> None:
        self.state = self.root / "state"
        for name in ("transcripts", "runs", "keys", "secrets", "verify"):
            (self.state / name).mkdir(parents=True, exist_ok=True)
        self.audit_file = self.state / "audit.log"
        self.model_input_file = self.state / "model-inputs.jsonl"
        self._transcript = Transcript(self.state / "transcripts")
        self._model_inputs = ModelInputLog(self.model_input_file)

    # .env and secrets -------------------------------------------------------------------------------------------

    def write_env(self, **values: str) -> None:
        (self.root / ".env").write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")

    def write_hmac_secret(self) -> Path:
        path = self.state / "secrets" / "hmac.key"
        path.write_bytes(HMAC_SECRET + b"\n")
        os.chmod(path, 0o600)
        return path

    # logs -------------------------------------------------------------------------------------------------------

    @staticmethod
    def size(path: Path) -> int:
        return path.stat().st_size if path.exists() else 0

    def audit(self, event: str, **fields: Any) -> None:
        with _env("ACS_AUDIT_FILE", str(self.audit_file)):
            audit_event(event, **fields)

    def model_input(self, body: Any) -> None:
        self._model_inputs.append(body)

    def pair(self, req: dict[str, Any], resp: dict[str, Any] | None, *, cause: str | None = None) -> None:
        session_id = req["params"]["metadata"]["session_id"]
        self._transcript.append(session_id, "req", req)
        self._transcript.append(session_id, "resp", resp, cause=cause)

    def transcript_path(self, session_id: str = SESSION_A) -> Path:
        return self.state / "transcripts" / f"{session_id}.jsonl"

    # run records ------------------------------------------------------------------------------------------------

    def run_record(self, run_id: str, *, scenario: str = "s1", mode: str = "enforce", started: str | None = None,
                   audit: tuple[int, int] = (0, 0), model_inputs: tuple[int, int] = (0, 0),
                   sessions: list[str] | None = None, **extra: Any) -> Path:
        """One state/runs/<run_id>.json in the plan's acs-lab-run/1 shape. extra replaces any top-level field."""
        stamp = started or "2026-11-25T10:15:00Z"
        record: dict[str, Any] = {
            "format": "acs-lab-run/1", "run_id": run_id, "scenario": scenario,
            "flags": {"answer": None, "clean": False}, "mode": mode, "signing": "ML-DSA-65",
            "upstream": "replay", "capture": None, "policy_sha256": "0" * 64,
            "started": stamp, "ended": stamp, "result": "completed",
            "audit": list(audit), "model_inputs": list(model_inputs),
            "sessions": sessions if sessions is not None else [SESSION_A], "epoch": [1, 2],
            "finbot": {"namespace": "ns_user_test", "vendor": {}, "evidence": {}},
        }
        record.update(extra)
        path = self.state / "runs" / f"{run_id}.json"
        path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return path


@contextlib.contextmanager
def _env(name: str, value: str):
    before = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if before is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = before
