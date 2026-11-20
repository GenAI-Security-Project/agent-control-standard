"""lab downgrade: ask the Guardian for an HMAC only session and expect a refusal (issue #589, LAB-16 Task 12).

Version 1.2.0. Owner: Rock Lambros. Runs in the lab container, on acs-net, with acs from the image.

A client that can verify only HMAC would accept an allow from anyone holding the shared secret, so a Guardian that
signs decisions with ML-DSA-65 refuses to open a session for it. lab downgrade builds a ClientHello the way
acs.client's _hello builds it with no response keys, so it offers no x_acs_lab_response_algorithms, signs it with the
lab's HMAC secret under a fresh session id, posts it to the Guardian, and expects -32000 with the reason
unsupported_signature_algorithm. A Guardian still on HMAC opens the session, and the attendee switches signing first.

A refusal counts only when the Guardian signed it, since this module's lesson is to trust no decision nobody can
attribute (review I2). DONE needs all of these: HTTP 200, a JSON-RPC 2.0 error and no result, the ClientHello's id,
-32000 with unsupported_signature_algorithm, and an ML-DSA-65 signature that verifies under the key document pinned to
LAB_GUARDIAN_FINGERPRINT from .env, over the ClientHello's request hash. Only then is the downgrade result written,
which the viewer paints as downgrade_refused. It records that pin, so check 7 counts the refusal only while the pin
is unchanged (Task 13 review C1). Without a pin nothing is sent and the command exits 2.

The refusal shows that this Guardian won't fall back. It doesn't prove a downgrade is impossible everywhere, which
needs the handshake bound to the traffic after it (issue #13). Lab conventions: the x_acs_lab_response_algorithms
field and the refusal reason (issue #316), the result file shape (plan LAB-13, open question 1).
"""
from __future__ import annotations

import datetime
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import results
import sessions
from sessions import MLDSA

from acs.client import KeyDocumentError, ResponseKeys, load_response_keys
from acs.core import (ACS_VERSION, MAX_REQUEST_BODY_BYTES, derive_session_key, iso8601_now, sign_with_key,
                      verify_with_keyring)

GUARDIAN_URL = "http://acs-guardian:8787/"
# compose.yaml gives the Guardian and the gateway this label for the lab's HMAC secret.
LAB_HMAC_KEY_ID = "lab"
RESPONSE_ALGORITHM_FIELD = "x_acs_lab_response_algorithm"
REFUSAL_CODE = -32000
REFUSAL_REASON = "unsupported_signature_algorithm"
TIMEOUT_S = 10.0
MAX_ANSWER_BYTES = 64 * 1024
SECRET_BYTES = 4096


def client_hello(session_id: str, transport: str) -> dict[str, Any]:
    """acs.client._handshake._hello's ClientHello for a client holding no response keys, unsigned."""
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "handshake/hello",
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": str(uuid.uuid4()),
            "timestamp": iso8601_now(),
            "metadata": {"agent_id": "finbot", "session_id": session_id, "platform": "lab"},
            "payload": {
                "acs_versions_supported": [ACS_VERSION],
                "methods_implemented": ["steps/toolCallRequest"],
                "transports_supported": [transport],
                "max_payload_size_bytes": MAX_REQUEST_BODY_BYTES,
                "provenance_producer": "none",
                "wrapped_protocols": [],
                "profiles_supported": ["acs-core"],
                "signature_algorithms_supported": ["HMAC-SHA256"],
            },
        },
    }


def _post(url: str, body: bytes, timeout: float) -> tuple[int, Any]:
    """The HTTP status and the Guardian's JSON answer. Proxies are skipped: the Guardian sits on acs-net."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            status, data = resp.status, resp.read(MAX_ANSWER_BYTES + 1)
    except urllib.error.HTTPError as e:
        status, data = e.code, e.read(MAX_ANSWER_BYTES + 1)
    if len(data) > MAX_ANSWER_BYTES:
        raise ValueError(f"the answer is larger than {MAX_ANSWER_BYTES} bytes")
    return status, json.loads(data)


def refusal_problem(status: int, answer: Any, hello: dict[str, Any], keys: ResponseKeys) -> str | None:
    """Why answer isn't the Guardian's signed refusal of hello, or None when it is."""
    if status != 200:
        return f"it came back with HTTP {status}, not 200"
    if not isinstance(answer, dict) or answer.get("jsonrpc") != "2.0":
        return "it isn't a JSON-RPC 2.0 answer"
    if "result" in answer:
        return "it carries a result beside the error"
    if answer.get("id") != hello["id"]:
        return "its id isn't the ClientHello's"
    error = answer.get("error")
    data = error.get("data") if isinstance(error, dict) else None
    if not isinstance(error, dict) or error.get("code") != REFUSAL_CODE or not isinstance(data, dict) \
            or data.get("reason") != REFUSAL_REASON:
        shown = json.dumps(error)[:300]
        return f"it isn't {REFUSAL_CODE} {REFUSAL_REASON}: {shown}"
    if not keys.is_live(datetime.datetime.now(datetime.timezone.utc)):
        return f"the pinned key {keys.key_id} isn't live now"
    try:
        signed = verify_with_keyring(answer, keys.keyring, expected_key_id=keys.key_id, request=hello,
                                     require_request_digest=True)
    except (ValueError, TypeError) as e:
        return f"its signature can't be checked ({e})"
    if not signed:
        return f"its signature doesn't verify under the pinned key {keys.key_id} as the answer to this ClientHello"
    return None


def main(argv: list[str], *, root: Path | str | None = None, guardian_url: str = GUARDIAN_URL,
         key_id: str = LAB_HMAC_KEY_ID, timeout: float = TIMEOUT_S) -> int:
    if argv:
        return sessions.broken("lab downgrade takes no arguments")
    ev = sessions.evidence.Evidence(sessions.bundle_root(root))
    state = ev.state
    pin = ev.fingerprint()
    if pin is None:
        return sessions.broken(f"{sessions.evidence.FINGERPRINT_KEY} isn't in .env, so no refusal can be checked. "
                               "Run ./lab.sh init, which writes the fingerprint it prints there")
    try:
        keys = load_response_keys(state / "keys" / "guardian-keys.json", fingerprint=pin)
    except (KeyDocumentError, OSError) as e:
        return sessions.broken(f"the Guardian's key document doesn't hold the key lab init pinned ({e})")
    try:
        with (state / "secrets" / "hmac.key").open("rb") as f:
            secret = f.read(SECRET_BYTES).rstrip(b"\r\n\t ")
        if not secret:
            raise ValueError("hmac.key is empty")
    except (OSError, ValueError) as e:
        return sessions.broken(f"the lab's HMAC secret can't be read ({e}). Run ./lab.sh init")

    session_id = str(uuid.uuid4())
    hello = client_hello(session_id, urllib.parse.urlsplit(guardian_url).scheme)
    sign_with_key(hello, derive_session_key(secret, session_id), key_id=key_id)
    try:
        status, answer = _post(guardian_url, json.dumps(hello).encode("utf-8"), timeout)
    except (OSError, ValueError) as e:
        return sessions.broken(f"the Guardian at {guardian_url} gave no answer ({e}). Run ./lab.sh up and try again")

    if isinstance(answer, dict) and isinstance(answer.get("result"), dict) and "error" not in answer:
        if answer["result"].get(RESPONSE_ALGORITHM_FIELD) == MLDSA:
            # It claims ML-DSA-65 yet opened a session for a client that can verify only HMAC (review M4).
            return sessions.not_yet("the Guardian claims ML-DSA-65 but opened a session for a client offering only "
                                    "HMAC, so it fell back. Check its startup line with ./lab.sh logs acs-guardian")
        return sessions.not_yet("run ./lab.sh sign mldsa first")
    problem = refusal_problem(status, answer, hello, keys)
    if problem is not None:
        return sessions.broken(f"the Guardian's answer to an HMAC only ClientHello isn't a refusal it signed: "
                               f"{problem}")
    results.write(state, kind="downgrade", algorithm=MLDSA, session_id=session_id, result="refused", entry=None,
                  detail=f"the Guardian refused a ClientHello offering only HMAC: {REFUSAL_CODE} {REFUSAL_REASON}, "
                         f"signed by key {keys.key_id}", fingerprint=pin)
    return sessions.done(f"the Guardian refused a ClientHello offering only HMAC with {REFUSAL_CODE} "
                         f"{REFUSAL_REASON}, signed with the key lab init pinned. It signs decisions with ML-DSA-65 "
                         "and won't fall back")
