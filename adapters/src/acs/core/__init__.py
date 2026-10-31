"""Protocol logic with no I/O: envelopes, signing, decisions, error codes and the ACS schemas."""
from importlib import import_module
from typing import Any

# Exports load on first use, so stdlib-only modules import without rfc8785.
_EXPORTS = {
    "ACS_VERSION": "_envelope",
    "DEFAULT_SKEW_WINDOW_MS": "_envelope",
    "GUARDIAN_ERROR_CAUSE": "_errors",
    "GUARDIAN_REFUSAL_CODES": "_errors",
    "KNOWN_DECISIONS": "_decision",
    "MAX_REQUEST_BODY_BYTES": "_envelope",
    "SESSION_REFUSAL_CODES": "_errors",
    "coerce_uuid": "_envelope",
    "container_key": "_signing",
    "derive_session_key": "_signing",
    "guardian_error_cause": "_errors",
    "is_guardian_refusal": "_errors",
    "is_session_refusal": "_errors",
    "iso8601_now": "_envelope",
    "jcs_canonicalize": "_canonical",
    "method_evaluated": "_handshake",
    "modify_composition_violation": "_decision",
    "normalize_decision": "_decision",
    "parse_iso8601": "_envelope",
    "response_matches_request": "_envelope",
    "schemas_dir": "_schemas",
    "server_hello_problem": "_handshake",
    "sign_with_key": "_signing",
    "verify_with_key": "_signing",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module 'acs.core' has no attribute {name!r}")
    value = getattr(import_module(f"acs.core.{module}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return __all__
