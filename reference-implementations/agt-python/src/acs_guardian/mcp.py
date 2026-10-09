"""The wrapped MCP handler: ``protocols/MCP/*`` (extend_mcp.md).

A wrapped call carries one MCP JSON-RPC 2.0 message intact in
``params.payload``: a request or notification the Observed Agent is about to
send, or the response it received, which it wraps under the method the
response answers. The message reaches the policy engine intact; this module
is the only protocol-specific part of a wrapped call — the envelope, the
session, the chain, the decision and the signature are the Guardian's,
shared with the native hooks.

``read`` implements the JSON-RPC 2.0 shape checks every MCP message shares;
the same checks the Go port contributed in the open PR #169
(``reference-implementations/agt-go/internal/mcp/mcp.go``) makes, so the two
refuse the same messages. The method name is not compared for a response: a
response carries no ``method``, and it is wrapped under the method of the
request it answers.
"""

from __future__ import annotations

import re
from typing import Any

from .errors import INVALID_PARAMS, AcsError

PROTOCOL = "MCP"

# Every MCP method name: slash-separated segments of letters, digits and
# underscores (initialize, tools/call, notifications/resources/list_changed).
_METHOD_NAME = re.compile(r"^[A-Za-z0-9_]+(/[A-Za-z0-9_]+)*$")


def supports(method: str) -> bool:
    """Whether the handler reads this MCP method (any well-formed name)."""
    return bool(_METHOD_NAME.match(method))


def read(method: str, payload: Any) -> dict[str, Any]:
    """Decode and check a wrapped MCP message, or raise INVALID_PARAMS (-32602).

    ``method`` is the part after ``protocols/MCP/``. A request's own method
    must equal it; a response must carry an id and exactly one of ``result``
    (an object) and ``error`` (an object with an integer code and a string
    message).
    """
    if not isinstance(payload, dict):
        raise AcsError(INVALID_PARAMS, "the wrapped MCP message must be an object", data={"method": method})
    if payload.get("jsonrpc") != "2.0":
        raise AcsError(
            INVALID_PARAMS, 'the wrapped MCP message must have jsonrpc "2.0"', data={"method": method}
        )
    has_id = "id" in payload
    if has_id:
        message_id = payload["id"]
        # A JSON null id is not a string or a number, and is reserved for
        # responses to unparseable requests, so it is refused here too.
        if isinstance(message_id, bool) or not isinstance(message_id, (str, int)):
            raise AcsError(
                INVALID_PARAMS, "the wrapped MCP message's id must be a string or a number", data={"method": method}
            )

    is_response = "method" not in payload
    if not is_response:
        if payload.get("method") != method:
            raise AcsError(
                INVALID_PARAMS,
                f"the wrapped MCP message is {payload.get('method')}, and the envelope wraps {method}",
                data={"method": method},
            )
        if "result" in payload or "error" in payload:
            raise AcsError(
                INVALID_PARAMS, "a wrapped MCP request carries neither result nor error", data={"method": method}
            )
        if "params" in payload and not isinstance(payload["params"], dict):
            raise AcsError(
                INVALID_PARAMS, "the wrapped MCP message's params must be an object", data={"method": method}
            )
        return payload

    if not has_id:
        raise AcsError(
            INVALID_PARAMS,
            "a wrapped MCP response must carry the id of the request it answers",
            data={"method": method},
        )
    has_result = "result" in payload
    has_error = "error" in payload
    if has_result == has_error:
        raise AcsError(
            INVALID_PARAMS,
            "a wrapped MCP response carries exactly one of result and error",
            data={"method": method},
        )
    if has_result and not isinstance(payload["result"], dict):
        raise AcsError(
            INVALID_PARAMS, "a wrapped MCP response's result must be an object", data={"method": method}
        )
    if has_error:
        error = payload["error"]
        if (
            not isinstance(error, dict)
            or not isinstance(error.get("code"), int)
            or isinstance(error.get("code"), bool)
            or not isinstance(error.get("message"), str)
        ):
            raise AcsError(
                INVALID_PARAMS,
                "a wrapped MCP response's error must be an object with an integer code and a string message",
                data={"method": method},
            )
    return payload
