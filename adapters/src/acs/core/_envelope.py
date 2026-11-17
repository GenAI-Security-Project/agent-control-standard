from __future__ import annotations

import datetime
import uuid
from collections.abc import Mapping
from typing import Any


ACS_VERSION = "0.1.0"
DEFAULT_SKEW_WINDOW_MS = 300_000

MAX_REQUEST_BODY_BYTES = 1_048_576


def request_envelope(method: str, *, request_id: str, metadata: Mapping[str, Any],
                     payload: Mapping[str, Any]) -> dict[str, Any]:
    """An unsigned step request; round_trip signs it just before sending."""
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": request_id,
            "timestamp": iso8601_now(),
            "metadata": dict(metadata),
            "payload": dict(payload),
        },
    }


def turn_start_envelope(metadata: Mapping[str, Any], turn_id: str) -> dict[str, Any]:
    """turn_id doubles as request_id, as turn-start.json recommends."""
    return request_envelope("steps/turnStart", request_id=turn_id, metadata={**metadata, "turn_id": turn_id},
                            payload={"turn_id": turn_id, "triggered_by": "user_message"})


def same_json_rpc_id(a: object, b: object) -> bool:
    """Whether two ids are the same JSON value: strings, numbers, booleans or null, compared as JSON does.

    Python's == treats True as 1, and JSON doesn't, so a bool never equals a number. JSON and
    JCS treat 1 and 1.0 as one number, so a re-serialized numeric id still matches.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is None and b is None


# The ClientHello's method, as handshake.json and request-envelope.json name it.
HANDSHAKE_METHOD = "handshake/hello"


def response_matches_request(request: dict, response: dict) -> bool:
    """Whether the response answers this request, so a signed response can't be replayed onto another call (D-029).

    The rule follows the request, never the response's shape. Every response needs the
    request's JSON-RPC id. An error is bound by the id alone. For the handshake, a ServerHello
    echoes nothing else from the ClientHello, so its result must carry no request_id, which
    keeps a step decision from answering a ClientHello. Issue #13 tracks binding the
    handshake to the traffic after it. For every other request, a result must carry the
    request's request_id. A result that isn't an object answers nothing.
    """
    if not same_json_rpc_id(response.get("id"), request.get("id")):
        return False
    result = response.get("result")
    if result is None:
        return True
    if not isinstance(result, dict):
        return False
    if request.get("method") == HANDSHAKE_METHOD:
        return "request_id" not in result
    params = request.get("params")
    want = params.get("request_id") if isinstance(params, dict) else None
    return same_json_rpc_id(result.get("request_id"), want)


def iso8601_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def coerce_uuid(raw: str | None, *, namespace_prefix: str = "acs") -> str:
    if not raw:
        return str(uuid.uuid4())
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{namespace_prefix}:{raw}"))


def parse_iso8601(ts: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
