"""Protocol logic with no I/O: envelopes, signing, decisions, error codes and the ACS schemas."""
from importlib import import_module
from typing import Any

# Exports load on first use, so stdlib-only modules import without rfc8785.
_EXPORTS = {
    "ACS_VERSION": "_envelope",
    "DEFAULT_SKEW_WINDOW_MS": "_envelope",
    "Decision": "_decision",
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
    "request_envelope": "_envelope",
    "response_matches_request": "_envelope",
    "schemas_dir": "_schemas",
    "server_hello_problem": "_handshake",
    "sign_with_key": "_signing",
    "signing_input": "_signing",
    "turn_start_envelope": "_envelope",
    "verify_with_key": "_signing",
}

# ML-DSA-65 needs the pqc extra (issue #574). These names resolve on access but stay out of
# __all__ and __dir__, so `from acs.core import *` and tab completion never load cryptography.
# Without the extra, access raises AttributeError, so hasattr() answers False instead of raising.
# hasattr() says only that the extra is installed. On an OpenSSL without ML-DSA every name still
# resolves and the first key raises MLDSAUnavailableError, so ml_dsa_available() is the check
# that the backend works. The keyring names live in a standard-library module but share the
# gate, since no key can be built without the extra.
_PQC_EXPORTS = {
    "Keyring": "_keyring",
    "ML_DSA_65": "_keyring",
    "VerificationKey": "_keyring",
    "WIRE_ALGORITHMS": "_keyring",
    "ML_DSA_CONTEXT": "_mldsa",
    "ML_DSA_MODE": "_mldsa",
    "MLDSA65SigningKey": "_mldsa",
    "sign_with_signing_key": "_mldsa",
    "verify_with_keyring": "_mldsa",
    "ml_dsa_available": "_mldsa",
    "MLDSAUnavailableError": "_mldsa",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        module = _PQC_EXPORTS.get(name)
        if module is None:
            raise AttributeError(f"module 'acs.core' has no attribute {name!r}")
        try:
            # acs.core._mldsa is the gate: it fails to import without the extra or its backend.
            import_module("acs.core._mldsa")
        except ImportError as exc:
            raise AttributeError(f"acs.core.{name} needs the pqc extra: {exc}") from exc
    value = getattr(import_module(f"acs.core.{module}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return __all__
