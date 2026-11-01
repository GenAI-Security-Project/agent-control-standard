"""The adapter side's I/O: configuration, secrets, the handshake, the round trip, session state and audit."""
from importlib import import_module
from typing import Any

# Exports load on first use, so _config, _outcome and _audit import without the signing dependency.
_EXPORTS = {
    "Config": "_config",
    "Decided": "_outcome",
    "FailPosture": "_config",
    "GuardianHTTPError": "_exchange",
    "Handshake": "_outcome",
    "Negotiated": "_outcome",
    "NoAnswer": "_outcome",
    "Refused": "_outcome",
    "RequestTooLargeError": "_exchange",
    "Resolution": "_config",
    "SecretFilePermissionsError": "_secrets",
    "SecretFileUnreadableError": "_secrets",
    "SessionRefused": "_outcome",
    "Undecided": "_outcome",
    "audit_event": "_audit",
    "classify_response": "_exchange",
    "close_turn": "_store",
    "current_turn": "_store",
    "exchange": "_exchange",
    "load_hmac_secret": "_secrets",
    "load_key_id": "_secrets",
    "load_session_state": "_store",
    "mark_once": "_store",
    "open_session": "_handshake",
    "open_turn": "_store",
    "ping": "_transport",
    "post": "_exchange",
    "record_mcp_use": "_profiles",
    "record_step": "_store",
    "round_trip": "_exchange",
    "save_session_state": "_store",
    "sign_envelope": "_signing",
    "update_session_state": "_store",
    "validate_guardian_url": "_urls",
    "verify_signature": "_signing",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module 'acs.client' has no attribute {name!r}")
    value = getattr(import_module(f"acs.client.{module}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return __all__
