"""Verifier rules from Specification section 10.

Tests for the normative verifier requirements: missing signature rejection,
non-negotiated algorithm rejection, and state isolation for failed verification.
These are schema-level and behavioral tests, not reference-implementation tests;
the repository has no runnable verifier yet that enforces all of these rules.
"""

import json
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parent.parent / "specification" / "v0.1.0"
REQUEST_ENVELOPE = SPEC_DIR / "request-envelope.json"
HANDSHAKE = SPEC_DIR / "handshake.json"


def test_request_envelope_signature_is_optional_in_schema():
    """The signature field is optional in the JSON Schema to accommodate system/ping
    and key-resolution errors, but ACS-Core conformance requires it elsewhere.
    """
    schema = json.loads(REQUEST_ENVELOPE.read_text(encoding="utf-8"))
    params_schema = schema["$defs"]["AcsParams"]
    assert "signature" in params_schema["properties"]
    assert "signature" not in params_schema.get("required", [])


def test_handshake_clienthello_has_signature_algorithms_supported():
    """ClientHello declares which algorithms the client can sign and verify."""
    schema = json.loads(HANDSHAKE.read_text(encoding="utf-8"))
    client_hello = schema["$defs"]["ClientHello"]
    assert "signature_algorithms_supported" in client_hello["properties"]
    assert "signature_algorithms_supported" not in client_hello.get("required", [])


def test_handshake_serverhello_signature_algorithms_supported_has_no_empty_array_exemption():
    """The ServerHello.signature_algorithms_supported description no longer says
    'empty array = signatures not required'.
    """
    schema = json.loads(HANDSHAKE.read_text(encoding="utf-8"))
    server_hello = schema["$defs"]["ServerHello"]
    desc = server_hello["properties"]["signature_algorithms_supported"]["description"]
    assert "Empty array = signatures not supported" not in desc
    assert "Empty array = signatures not required" not in desc


def test_signature_algorithm_enums_match_across_handshake():
    """The algorithm enums in ClientHello and ServerHello match the request envelope."""
    handshake_schema = json.loads(HANDSHAKE.read_text(encoding="utf-8"))
    request_schema = json.loads(REQUEST_ENVELOPE.read_text(encoding="utf-8"))

    client_supported = set(
        handshake_schema["$defs"]["ClientHello"]["properties"]["signature_algorithms_supported"]["items"]["enum"]
    )
    server_supported = set(
        handshake_schema["$defs"]["ServerHello"]["properties"]["signature_algorithms_supported"]["items"]["enum"]
    )
    request_enum = set(
        request_schema["$defs"]["Signature"]["properties"]["algorithm"]["enum"]
    )

    assert client_supported == request_enum
    assert server_supported == request_enum


def test_specification_text_includes_verifier_rules():
    """Section 10 includes the normative verifier rules block."""
    spec = (Path(__file__).resolve().parent.parent / "docs" / "spec" / "instrument" / "specification.md").read_text(
        encoding="utf-8"
    )
    assert "Verifier rules (normative)" in spec
    assert "Verification order and state isolation" in spec
    assert "Constant-time comparison" in spec
    assert "Missing signature" in spec
    assert "Non-negotiated algorithm" in spec


def test_specification_mentions_atomic_request_id_check():
    """The spec requires that checking request_id for replay and reserving it is atomic."""
    spec = (Path(__file__).resolve().parent.parent / "docs" / "spec" / "instrument" / "specification.md").read_text(
        encoding="utf-8"
    )
    assert "atomic" in spec.lower()
    assert "request_id" in spec
    assert "replay" in spec.lower()


def test_specification_forbids_fallback_to_another_algorithm():
    """A non-negotiated algorithm is rejected with no fallback."""
    spec = (Path(__file__).resolve().parent.parent / "docs" / "spec" / "instrument" / "specification.md").read_text(
        encoding="utf-8"
    )
    assert "no fallback" in spec.lower() or "MUST NOT fall back" in spec


def test_specification_requires_constant_time_comparison():
    """Verifiers must compare signatures in constant time."""
    spec = (Path(__file__).resolve().parent.parent / "docs" / "spec" / "instrument" / "specification.md").read_text(
        encoding="utf-8"
    )
    assert "constant time" in spec.lower() or "constant-time" in spec.lower()


def test_specification_isolates_failed_verification_from_state():
    """A request that fails verification must not alter the four state kinds."""
    spec = (Path(__file__).resolve().parent.parent / "docs" / "spec" / "instrument" / "specification.md").read_text(
        encoding="utf-8"
    )
    assert "session state" in spec
    assert "replay state" in spec
    assert "audit-chain state" in spec
    assert "authorization state" in spec


def test_specification_defines_negotiated_set_as_intersection():
    """The negotiated set for both directions is the intersection of the two lists."""
    spec = (Path(__file__).resolve().parent.parent / "docs" / "spec" / "instrument" / "specification.md").read_text(
        encoding="utf-8"
    )
    assert "intersection" in spec.lower()
    assert "ClientHello.signature_algorithms_supported" in spec
    assert "ServerHello.signature_algorithms_supported" in spec


def test_specification_defines_baseline_when_field_omitted():
    """If ClientHello omits signature_algorithms_supported, only HMAC-SHA256 is negotiated."""
    spec = (Path(__file__).resolve().parent.parent / "docs" / "spec" / "instrument" / "specification.md").read_text(
        encoding="utf-8"
    )
    assert "omits" in spec.lower() or "omitted" in spec.lower()
    assert "HMAC-SHA256" in spec
    assert "baseline" in spec.lower()


def test_handshake_clienthello_signature_algorithms_supported_mentions_baseline():
    """The ClientHello description mentions the baseline when the field is omitted."""
    schema = json.loads(HANDSHAKE.read_text(encoding="utf-8"))
    client_hello = schema["$defs"]["ClientHello"]
    desc = client_hello["properties"]["signature_algorithms_supported"]["description"]
    assert "omitted" in desc.lower()
    assert "HMAC-SHA256" in desc


def test_handshake_descriptions_mention_intersection():
    """Both algorithm field descriptions mention the intersection."""
    schema = json.loads(HANDSHAKE.read_text(encoding="utf-8"))
    client_desc = schema["$defs"]["ClientHello"]["properties"]["signature_algorithms_supported"]["description"]
    server_desc = schema["$defs"]["ServerHello"]["properties"]["signature_algorithms_supported"]["description"]
    assert "intersection" in client_desc.lower()
    assert "intersection" in server_desc.lower()
