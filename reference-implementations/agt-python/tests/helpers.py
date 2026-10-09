"""Shared test helpers: the envelope builder and the harness's signing contract.

These mirror the external conformance mode contributed in the open PR #169
(``packages/conformance/src/external-guardian.ts`` in that branch; not merged
at the time of writing), so the probe test and the official harness measure
the same wire contract with the same primitives.
"""

from __future__ import annotations

import json
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from acs_guardian.canonical import request_signing_input, response_signing_input
from acs_guardian.crypto import derive_session_key, sign, verify

SECRET = bytes(range(32))
KEY_ID = "conformance"
AGENT_ID = "conformance-observed-agent"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def envelope(
    method: str,
    session_id: str,
    payload: dict[str, Any],
    *,
    request_id: str | None = None,
    agent_id: str = AGENT_ID,
    timestamp: str | None = None,
) -> dict[str, Any]:
    request_id = request_id or str(uuid.uuid4())
    return {
        "jsonrpc": "2.0",
        "method": method,
        "id": request_id,
        "params": {
            "acs_version": "0.1.0",
            "request_id": request_id,
            "timestamp": timestamp or now_iso(),
            "metadata": {"agent_id": agent_id, "session_id": session_id},
            "payload": payload,
        },
    }


def sign_request(request: dict[str, Any], session_id: str, secret: bytes = SECRET, key_id: str = KEY_ID) -> dict[str, Any]:
    key = derive_session_key(secret, session_id)
    request["params"]["signature"] = {
        "algorithm": "HMAC-SHA256",
        "value": sign(key, request_signing_input(request)),
        "key_id": key_id,
    }
    return request


def verify_response(
    response: dict[str, Any],
    session_id: str,
    expected_id: Any,
    secret: bytes = SECRET,
    key_id: str = KEY_ID,
) -> None:
    assert response.get("jsonrpc") == "2.0", f"uncorrelated response: {response}"
    assert response.get("id") == expected_id, f"uncorrelated response: {response}"
    holder_name = "result" if "error" not in response else "error"
    holder = response.get(holder_name) or {}
    signature = holder.get("signature")
    assert isinstance(signature, dict), f"no signature on {holder_name}: {response}"
    assert signature.get("algorithm") == "HMAC-SHA256", f"wrong algorithm: {signature}"
    assert signature.get("key_id") == key_id, f"wrong key_id: {signature}"
    key = derive_session_key(secret, session_id)
    assert verify(key, response_signing_input(response), signature.get("value")), (
        f"response signature does not verify: {response}"
    )


def http_post(url: str, body: Any) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def expect_error(response: dict[str, Any], code: int) -> None:
    assert response.get("error", {}).get("code") == code and "result" not in response, (
        f"expected error {code}, got {response}"
    )


def expect_decision(response: dict[str, Any], disposition: str, request_id: Any) -> None:
    result = response.get("result") or {}
    assert "error" not in response, f"expected a decision, got {response}"
    assert result.get("decision") == disposition, f"expected {disposition}, got {response}"
    assert result.get("request_id") == request_id, f"decision not correlated: {response}"


def signed_post(url: str, request: dict[str, Any], session_id: str) -> dict[str, Any]:
    signed = sign_request(request, session_id)
    response = http_post(url, signed)
    verify_response(response, session_id, request["id"])
    return response


def handshake(
    url: str,
    session_id: str,
    methods: list[str],
    *,
    transports: list[str] | None = None,
    versions: list[str] | None = None,
) -> dict[str, Any]:
    hello = envelope(
        "handshake/hello",
        session_id,
        {
            "acs_versions_supported": versions or ["0.1.0"],
            "methods_implemented": methods,
            "transports_supported": transports or ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
        },
    )
    return signed_post(url, hello, session_id)
