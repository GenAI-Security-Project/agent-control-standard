from __future__ import annotations

import datetime
import math
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
    """Whether two ids name the same request: strings compare exactly, numbers as Python values.

    A bool never equals a number, although Python's == treats True as 1. Numbers compare as
    Python values, so 1 equals 1.0, but integers past 2**53 compare exactly where JSON parsers
    that use doubles would not. A missing or null id never matches, so a request without an id
    binds nothing. Ids should be strings, as acs.core.request_envelope makes them.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


# The ClientHello's method, as handshake.json and request-envelope.json name it.
HANDSHAKE_METHOD = "handshake/hello"


def request_envelope_problem(request: object) -> str | None:
    """Why this is no request envelope a response could answer, or None.

    The request must be a Mapping with a JSON-RPC id that is a string or a finite number. A
    missing or null id matches nothing, a bool would otherwise pass as a number, and NaN or an
    infinity can never bind a response. verify_with_keyring treats this as a caller error and
    raises ValueError with this text.
    """
    # Any Mapping is accepted, not only dict: _classify_hello types the ClientHello as a
    # Mapping, and a caller may hold its request read-only.
    if not isinstance(request, Mapping):
        return "request must be the request envelope this response answers"
    json_rpc_id = request.get("id")
    if isinstance(json_rpc_id, bool) or not isinstance(json_rpc_id, (str, int, float)):
        return "request must carry a string or numeric JSON-RPC id"
    if isinstance(json_rpc_id, float) and not math.isfinite(json_rpc_id):
        return "request must carry a string or numeric JSON-RPC id"
    return None


def request_binding_problem(request: object) -> str | None:
    """Why this request can bind no result, or None.

    It adds to request_envelope_problem. A handshake/hello request must carry object params with
    an object payload, the only ClientHello a ServerHello answers, and it binds on the id alone.
    For any other request, params, when present, must be a Mapping, and it must carry a
    non-empty string params.request_id. response_matches_request answers False for a result
    when this reports a problem. An error still binds by id alone.
    """
    problem = request_envelope_problem(request)
    if problem is not None:
        return problem
    params = request.get("params")
    if request.get("method") == HANDSHAKE_METHOD:
        if not isinstance(params, Mapping) or not isinstance(params.get("payload"), Mapping):
            return "a handshake/hello request must carry object params with an object payload"
        return None
    if params is not None and not isinstance(params, Mapping):
        return "request params must be an object when present"
    request_id = (params or {}).get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return "a request other than the handshake must carry a string params.request_id"
    return None


# Why response_binding_problem says a response doesn't answer a request. Callers map each reason
# to their own outcome, and none of them re-checks any part of the rule.
BINDING_SHAPE = "shape"
BINDING_REQUEST = "request"
BINDING_ID = "id"
BINDING_RESULT = "result"


def response_shape_problem(response: object) -> str | None:
    """BINDING_SHAPE unless the response is a JSON-RPC 2.0 object with exactly one object result or error and no method.

    The shape part of the one binding rule, on its own, so the client judges an HTTP error body
    by the same check as any other response.
    """
    if (not isinstance(response, Mapping) or response.get("jsonrpc") != "2.0"
            or "method" in response or ("result" in response) == ("error" in response)):
        return BINDING_SHAPE
    answer = response["result"] if "result" in response else response["error"]
    return None if isinstance(answer, Mapping) else BINDING_SHAPE


def response_binding_problem(request: object, response: object) -> str | None:
    """Why the response doesn't answer this request (D-029), as one BINDING_* reason, or None.

    This is the one binding rule. response_matches_request, verify_with_keyring, the client's
    step exchange and its handshake all decide through it. It checks the request first, then the
    response, in this order, so a caller error is reported as one whatever the response is:

    BINDING_REQUEST: the request passes request_envelope_problem. BINDING_SHAPE: the response is
    a JSON-RPC 2.0 object, carries no "method", and carries exactly one of result or error,
    which is an object. BINDING_ID: the response carries the request's JSON-RPC id. An error
    then binds by that id alone, whatever the request's request_id. BINDING_RESULT: a
    result binds only a request that passes request_binding_problem. For the handshake, a
    ServerHello echoes nothing else from the ClientHello, so its result binds by the id alone.
    An extra field such as request_id is ignored (spec section 4), and server_hello_problem's
    required fields decide whether the result is a ServerHello. Issue #13 tracks binding the
    handshake to the traffic after it. For any other request, the result must carry the
    request's request_id.
    """
    if request_envelope_problem(request) is not None:
        return BINDING_REQUEST
    if response_shape_problem(response) is not None:
        return BINDING_SHAPE
    answer = response["result"] if "result" in response else response["error"]
    if not same_json_rpc_id(response.get("id"), request.get("id")):
        return BINDING_ID
    if "error" in response:
        return None
    if request_binding_problem(request) is not None:
        return BINDING_RESULT
    if request.get("method") == HANDSHAKE_METHOD:
        return None
    # request_binding_problem already required a non-empty string request_id here.
    if not same_json_rpc_id(answer.get("request_id"), request["params"]["request_id"]):
        return BINDING_RESULT
    return None


def response_matches_request(request: object, response: object) -> bool:
    """Whether the response answers this request: response_binding_problem finds no reason."""
    return response_binding_problem(request, response) is None


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
