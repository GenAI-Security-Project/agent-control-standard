"""Envelope constants, response binding, timestamps and IDs."""
from __future__ import annotations

import datetime
import uuid


ACS_VERSION = "0.1.0"
DEFAULT_SKEW_WINDOW_MS = 300_000

# Maximum bytes the Guardian will read from a single HTTP POST body.
# Matches the handshake's max_payload_size_bytes default. Defends against
# memory exhaustion via a huge Content-Length.
MAX_REQUEST_BODY_BYTES = 1_048_576  # 1 MiB


# ----- Response↔request binding -----

def response_matches_request(request: dict, response: dict) -> bool:
    """Bind a Guardian response to the request that elicited it.

    The per-session HMAC proves a response came from the Guardian, not
    that it answers *this* request — a captured signed ALLOW replays
    fine against a different call. Binding is two spec-carried checks:

      1. JSON-RPC `id` on the response equals the request's `id`.
      2. `result.request_id` equals the request's `params.request_id`
         (required on every result per response-envelope.json).

    Error responses carry no result; for those only check 1 applies.
    Adapters MUST fail closed when this returns False."""
    if response.get("id") != request.get("id"):
        return False
    result = response.get("result")
    if result is not None:
        want = (request.get("params") or {}).get("request_id")
        if result.get("request_id") != want:
            return False
    return True


# ----- Time + IDs -----

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
