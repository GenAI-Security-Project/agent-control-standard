"""The adapter side's I/O: configuration, secrets, the handshake, the round trip, session state and audit."""
from importlib import import_module
from typing import Any

# Exports load on first use, so _config, _outcome and _audit import without the signing dependency.
_EXPORTS = {
    "Config": "_config",
    "Decided": "_outcome",
    "FailPosture": "_config",
    "GuardianHTTPError": "_exchange",
    "Refused": "_outcome",
    "RequestTooLargeError": "_exchange",
    "Resolution": "_config",
    "SecretFilePermissionsError": "_secrets",
    "SecretFileUnreadableError": "_secrets",
    "Undecided": "_outcome",
    "audit_event": "_audit",
    "classify_response": "_exchange",
    "ensure_session_handshake": "_handshake",
    "exchange": "_exchange",
    "load_hmac_secret": "_secrets",
    "load_session_state": "_store",
    "ping": "_transport",
    "post": "_exchange",
    "record_step": "_store",
    "save_session_state": "_store",
    "sign_envelope": "_signing",
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
