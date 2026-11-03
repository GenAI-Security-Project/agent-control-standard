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


def response_matches_request(request: dict, response: dict) -> bool:
    """Same JSON-RPC id and, for a result, the same request_id, so a signed response cannot be replayed onto another call."""
    if response.get("id") != request.get("id"):
        return False
    result = response.get("result")
    if result is not None:
        want = (request.get("params") or {}).get("request_id")
        if result.get("request_id") != want:
            return False
    return True


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
