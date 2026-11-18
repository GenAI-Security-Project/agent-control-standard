from __future__ import annotations


GUARDIAN_ERROR_CAUSE: dict[int, str] = {
    -32000: "session_refused_response",
    -32001: "unsupported_version_response",
    -32002: "provenance_required_response",
    -32003: "capability_not_negotiated_response",
    -32004: "signature_invalid_response",
    -32005: "replay_detected_response",
    -32006: "timestamp_out_of_window_response",
    -32007: "chain_mismatch_response",
    -32600: "malformed_envelope_response",
    -32601: "method_not_found_response",
    -32602: "invalid_params_response",
    -32603: "internal_error_response",
    -32700: "parse_error_response",
}


def _code(code: object) -> int | None:
    """code as a JSON integer, which -32000.0 also is (RFC 8785 writes both as -32000); never a bool."""
    if isinstance(code, bool):
        return None
    if isinstance(code, int):
        return code
    if isinstance(code, float) and code.is_integer():
        return int(code)
    return None


def guardian_error_cause(code: object) -> str:
    value = _code(code)
    return "guardian_error_response" if value is None else GUARDIAN_ERROR_CAUSE.get(value, "guardian_error_response")


def is_guardian_refusal(code: object) -> bool:
    """Every signed error but -32603 refuses the step (§6.4), a code added later or one that is not an integer included."""
    return _code(code) != -32603
