"""Helpers the decision signing tests share: ML-DSA-65 key material, Guardian settings, and signed requests.

Decision signing is a lab convention until issue #460 settles key publication (issue #576).
"""
from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path
from typing import Any

import pytest

from acs.client import sign_envelope
from acs.core import request_envelope
from acs.testing.harness import signing_env

KEY_ID = "lab-guardian-1"
GUARDIAN_ID = "lab-guardian"
SESSION = "66666666-6666-4666-8666-666666666666"
METADATA = {"agent_id": "finbot", "session_id": SESSION, "platform": "lab"}


def require_pqc() -> None:
    """Skip the calling module without the pqc extra. Call at module import, before any gated name."""
    try:
        found = importlib.util.find_spec("cryptography.hazmat.primitives.asymmetric.mldsa") is not None
    except ModuleNotFoundError:
        found = False
    if not found:
        pytest.skip("the pqc extra is not installed: ML-DSA-65 needs cryptography 50 (uv sync --extra pqc)",
                    allow_module_level=True)


def mldsa_env(tmp_path: Path) -> dict[str, str]:
    """signing_env() plus a fresh decision key, its key document, and ACS_RESPONSE_SIGNING=ML-DSA-65."""
    from acs.guardian.decision_keys import write_key_files
    directory = tmp_path / "decision-keys"
    directory.mkdir(exist_ok=True)
    key_path, doc_path = write_key_files(directory, key_id=KEY_ID, guardian_id=GUARDIAN_ID)
    return {**signing_env(), "ACS_RESPONSE_SIGNING": "ML-DSA-65", "ACS_GUARDIAN_SIGNING_KEY_FILE": str(key_path),
            "ACS_GUARDIAN_KEY_ID": KEY_ID, "ACS_GUARDIAN_KEYS": str(doc_path)}


def configure_in_process(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Turn the mode on in this process as main() would, and return the DecisionSigner it loaded."""
    from acs.guardian import example_guardian
    from acs.guardian.decision_keys import load_decision_signer
    env = mldsa_env(tmp_path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    signer = load_decision_signer(env)
    monkeypatch.setattr(example_guardian, "RESPONSE_SIGNING_NAME", "ML-DSA-65")
    monkeypatch.setattr(example_guardian, "DECISION_SIGNER", signer)
    monkeypatch.setattr(example_guardian, "OPA_CONFIG", None)
    monkeypatch.setattr(example_guardian, "POLICY_BACKEND_NAME", "")
    monkeypatch.setattr(example_guardian, "PERSIST_ENABLED", False)
    return signer


def signed_step(method: str, payload: dict, *, session_id: str = SESSION) -> dict:
    """A step request HMAC-signed as acs.client signs it. Requests stay on HMAC in every mode."""
    request = request_envelope(method, request_id=str(uuid.uuid4()),
                               metadata={**METADATA, "session_id": session_id}, payload=payload)
    return sign_envelope(request, session_id=session_id)


def signed_hello(*, offered: Any = ("ML-DSA-65",), session_id: str = SESSION) -> dict:
    """A ClientHello HMAC-signed as acs.client signs it. offered=None leaves the lab field out."""
    payload: dict[str, Any] = {"acs_versions_supported": ["0.1.0"], "methods_implemented": ["steps/toolCallRequest"],
                               "transports_supported": ["http"], "provenance_producer": "none",
                               "profiles_supported": ["acs-core"], "signature_algorithms_supported": ["HMAC-SHA256"]}
    if offered is not None:
        payload["x_acs_lab_response_algorithms"] = list(offered) if isinstance(offered, tuple) else offered
    request = request_envelope("handshake/hello", request_id=str(uuid.uuid4()),
                               metadata={**METADATA, "session_id": session_id}, payload=payload)
    return sign_envelope(request, session_id=session_id)
