"""The JSON-RPC and ACS error registry (Specification §17, §17.1).

Every mandated refusal maps to a fixed code so an SDK can branch on the code
without parsing prose. The constants below are the full registry — a reference
implementation is the natural place for it — and the Guardian raises a subset
today: ``PARSE_ERROR``, ``INVALID_REQUEST``, ``INVALID_PARAMS``,
``INTERNAL_ERROR``, ``SESSION_REFUSED``, ``UNSUPPORTED_VERSION``,
``PROVENANCE_REQUIRED``, ``CAPABILITY_NOT_NEGOTIATED``, ``SIGNATURE_INVALID``,
``REPLAY_DETECTED`` and ``TIMESTAMP_OUT_OF_WINDOW``. ``METHOD_NOT_FOUND`` and
``CHAIN_MISMATCH`` are defined but not yet raised (an unnegotiated method is
``CAPABILITY_NOT_NEGOTIATED``, and no cross-check path submits a chain head
yet).

The Guardian mints no codes of its own: the TypeScript reference implementation
uses three private codes from the reserved band (-32010, -32011, -32020) for
"envelope invalid", "method not dispatched", and "evaluation failed"; this
implementation answers those cases with the registry's own codes (-32600,
-32601/-32003, -32603) instead, because the §17 table already names them and a
port that invents codes is a port other implementations cannot branch on.
"""

from __future__ import annotations

from typing import Any

# JSON-RPC 2.0 (Specification §17).
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# ACS registry (Specification §17.1).
SESSION_REFUSED = -32000
UNSUPPORTED_VERSION = -32001
PROVENANCE_REQUIRED = -32002
CAPABILITY_NOT_NEGOTIATED = -32003
SIGNATURE_INVALID = -32004
REPLAY_DETECTED = -32005
TIMESTAMP_OUT_OF_WINDOW = -32006
CHAIN_MISMATCH = -32007


class AcsError(Exception):
    """A refusal that maps to a JSON-RPC error response.

    ``signable`` records whether the request authenticated: a request that did
    not establish a key (no session_id, or a failed signature) gets an
    unsigned answer, because signing it would claim a key relationship that
    does not exist (the Go reference implementation's rule).
    """

    def __init__(
        self,
        code: int,
        message: str,
        *,
        data: dict[str, Any] | None = None,
        signable: bool = True,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
        self.signable = signable
