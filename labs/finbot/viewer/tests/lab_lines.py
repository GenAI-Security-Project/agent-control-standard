"""Lab log lines for the viewer tests, written by the code that writes them in the lab.

Transcript lines go through the gateway's own Transcript writer and audit lines through acs.client's audit_event, so a
change to either format turns these tests red (interface pinning, WAVE4 brief). Requests and responses are built the
way acs.client and the example Guardian build them. ML-DSA-65 signing follows the Guardian's _sign_response: the
request hash goes into the answer, then the decision key signs it. The key document, the request hash, and ML-DSA-65
response signing are lab conventions (issues #460, #13, #316).
"""
from __future__ import annotations

import contextlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acs.client import audit_event
from acs.core import derive_session_key, request_envelope, sign_with_key
from acs_gateway.transcript import Transcript

SESSION_A = "11111111-1111-4111-8111-111111111111"
SESSION_B = "22222222-2222-4222-8222-222222222222"
HMAC_SECRET = b"lab-viewer-test-secret-of-at-least-32-bytes"
HMAC_KEY_ID = "lab-hmac"
KEY_ID = "lab-guardian-1"
GUARDIAN_ID = "lab-guardian"


def request(method: str, payload: dict[str, Any] | None = None, *, session_id: str = SESSION_A) -> dict[str, Any]:
    """A step request HMAC-signed as acs.client signs it. Requests stay on HMAC in every response mode."""
    envelope = request_envelope(method, request_id=str(uuid.uuid4()),
                                metadata={"agent_id": "finbot", "session_id": session_id, "platform": "lab"},
                                payload=payload or {})
    return sign_with_key(envelope, derive_session_key(HMAC_SECRET, session_id), key_id=HMAC_KEY_ID)


def tool_request(tool: str, *, session_id: str = SESSION_A) -> dict[str, Any]:
    return request("steps/toolCallRequest", {"tool": {"name": tool}, "arguments": {}}, session_id=session_id)


def answer(req: dict[str, Any], decision: str | None = "allow", **result: Any) -> dict[str, Any]:
    """An unsigned decision answer bound to req by id and request_id."""
    body: dict[str, Any] = {"request_id": req["params"]["request_id"], **result}
    if decision is not None:
        body["decision"] = decision
    return {"jsonrpc": "2.0", "id": req["id"], "result": body}


def error_answer(req: dict[str, Any], code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": req["id"], "error": error}


def sign_hmac(response: dict[str, Any], session_id: str = SESSION_A) -> dict[str, Any]:
    return sign_with_key(response, derive_session_key(HMAC_SECRET, session_id), key_id=HMAC_KEY_ID)


@dataclass
class DecisionKey:
    """A fresh ML-DSA-65 decision key, written by the Guardian's own key tool, and its key document."""

    signing_key: Any
    document_path: Path

    @property
    def document(self) -> dict[str, Any]:
        return json.loads(self.document_path.read_text(encoding="utf-8"))

    def sign(self, response: dict[str, Any], req: dict[str, Any]) -> dict[str, Any]:
        from acs.core import REQUEST_DIGEST_FIELD, request_sha256, sign_with_signing_key
        digest = request_sha256(req)
        if "result" in response:
            response["result"] = {**response["result"], REQUEST_DIGEST_FIELD: digest}
        else:
            response["error"]["data"] = {**(response["error"].get("data") or {}), REQUEST_DIGEST_FIELD: digest}
        return sign_with_signing_key(response, self.signing_key)


def decision_key(directory: Path) -> DecisionKey:
    from acs.guardian.decision_keys import load_signing_key, write_key_files
    key_path, doc_path = write_key_files(directory, key_id=KEY_ID, guardian_id=GUARDIAN_ID)
    return DecisionKey(load_signing_key(str(key_path), KEY_ID), doc_path)


class LabLogs:
    """A lab state directory: transcripts under transcripts/, the audit log, written as the gateway writes them."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.transcript_dir = root / "transcripts"
        self.audit_file = root / "audit.log"
        self.verify_dir = root / "verify"
        self._transcript = Transcript(self.transcript_dir)

    def req(self, envelope: dict[str, Any]) -> None:
        self._transcript.append(envelope["params"]["metadata"]["session_id"], "req", envelope)

    def resp(self, session_id: str, envelope: dict[str, Any] | None, *, cause: str | None = None,
             discards: str | None = None) -> None:
        self._transcript.append(session_id, "resp", envelope, cause=cause, discards=discards)

    def pair(self, req: dict[str, Any], resp: dict[str, Any] | None, **kwargs: Any) -> None:
        self.req(req)
        self.resp(req["params"]["metadata"]["session_id"], resp, **kwargs)

    def audit(self, event: str, **fields: Any) -> None:
        with _env("ACS_AUDIT_FILE", str(self.audit_file)):
            audit_event(event, **fields)

    def transcript(self, session_id: str = SESSION_A) -> Path:
        return self.transcript_dir / f"{session_id}.jsonl"


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
