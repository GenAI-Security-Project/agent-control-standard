"""JSON-RPC error codes: audit cause labels, and the refusals that fail closed."""
from __future__ import annotations




# ----- JSON-RPC error code → audit cause label -----
#
# Adapters use this when the Guardian returns a JSON-RPC `error` response
# (as opposed to a transport failure). Separating "Guardian rejected this
# envelope" from "I couldn't reach the Guardian" is load-bearing for
# operator triage — same fail-posture under §6.4, completely different
# remediation. Codes are the §17.1 / JSON-RPC reserved set.
GUARDIAN_ERROR_CAUSE: dict[int, str] = {
    -32001: "unsupported_version_response",
    -32002: "provenance_required_response",
    -32004: "signature_invalid_response",         # adapter or operator bug
    -32005: "replay_detected_response",            # duplicate request_id
    -32006: "timestamp_out_of_window_response",    # clock skew
    -32600: "malformed_envelope_response",         # non-conformant envelope
    -32700: "parse_error_response",
}


def guardian_error_cause(code: int | None) -> str:
    """Resolve a JSON-RPC error code to a stable audit cause label.

    Returns the generic 'guardian_error_response' for unrecognized codes
    so audit consumers always have a non-empty cause string."""
    if code is None:
        return "guardian_error_response"
    return GUARDIAN_ERROR_CAUSE.get(code, "guardian_error_response")


# ----- Guardian refusals fail closed -----
#
# DELIBERATELY STRICTER THAN v0.1 SPEC TEXT (tracked as spec issue #32).
# §6.4:156 as written routes ANY "error response instead of a decision"
# to the fail posture (default proceed). We do NOT do that for the codes
# below: the Guardian is ALIVE and REFUSED the envelope, and every one of
# them is attacker-reachable — oversize the body past the Guardian's cap
# (-32600 before policy runs), replay a request_id the adapter derives
# deterministically (-32005), strip or corrupt the signature (-32004),
# present a stale captured envelope (-32006). Routing those through a
# fail-OPEN posture turns each into a policy-bypass primitive. So we fail
# CLOSED on them regardless of ACS_DEFAULT_DENY / on_decision_failure.
# This is deliberate hardening ahead of the spec, NOT a claim that v0.1
# mandates it — #32 proposes the normative text; until it lands, treat
# this as adapter behavior, not a conformance requirement.
GUARDIAN_REFUSAL_CODES = frozenset({
    -32000,  # SESSION_REFUSED — policy refuses this session
    -32004,  # SIGNATURE_INVALID
    -32005,  # REPLAY_DETECTED
    -32006,  # TIMESTAMP_OUT_OF_WINDOW
    -32600,  # Invalid Request (malformed / oversized envelope)
    -32700,  # Parse error
})


def is_guardian_refusal(code: int | None) -> bool:
    """True when the error code means 'Guardian alive and refused this
    envelope' — the adapter must fail closed, not apply the §6.4 posture."""
    return code in GUARDIAN_REFUSAL_CODES
