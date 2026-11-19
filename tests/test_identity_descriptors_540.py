"""Regression guards for Issue #540: identity descriptors, RFC 9493, SPIFFE, verification, and Guardian identity."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IDENTITY_DOC = ROOT / "docs" / "concepts" / "identity.md"
CORE_CONCEPTS_DOC = ROOT / "docs" / "topics" / "core_concepts.md"
AGENTS_DOC = ROOT / "docs" / "concepts" / "agents.md"
SPEC_DOC = ROOT / "docs" / "spec" / "instrument" / "specification.md"

SESSION_START_SCHEMA = ROOT / "specification" / "v0.1.0" / "hooks" / "session-start.json"
REQUEST_ENVELOPE_SCHEMA = ROOT / "specification" / "v0.1.0" / "request-envelope.json"
RESPONSE_ENVELOPE_SCHEMA = ROOT / "specification" / "v0.1.0" / "response-envelope.json"
HANDSHAKE_SCHEMA = ROOT / "specification" / "v0.1.0" / "handshake.json"


def _section(text: str, heading: str) -> str:
    return re.split(r"\n## ", text.split(heading + "\n", 1)[1], maxsplit=1)[0]


def test_item1_spiffe_and_wimse_forward_pointer_in_identity_examples():
    identity_text = IDENTITY_DOC.read_text(encoding="utf-8")
    core_concepts_text = CORE_CONCEPTS_DOC.read_text(encoding="utf-8")
    spec_section_11 = _section(SPEC_DOC.read_text(encoding="utf-8"), "## 11. Platform / OS Independence")

    for doc_text in (identity_text, core_concepts_text, spec_section_11):
        assert "spiffe" in doc_text
        assert "spiffe://example.com/agent/finbot" in doc_text
        assert "WIMSE" in doc_text

    assert "[Standards](../identity/standards.md)" in identity_text
    assert "[Standards](../identity/standards.md)" in core_concepts_text
    assert "[Standards](../../identity/standards.md)" in spec_section_11


def test_item2_rfc9493_subject_identifiers_and_v01_wire_shape():
    identity_text = IDENTITY_DOC.read_text(encoding="utf-8")
    spec_section_11 = _section(SPEC_DOC.read_text(encoding="utf-8"), "## 11. Platform / OS Independence")

    for doc_text in (identity_text, spec_section_11):
        assert "RFC 9493" in doc_text
        assert "https://www.rfc-editor.org/rfc/rfc9493" in doc_text
        for fmt in ("`iss_sub`", "`uri`", "`did`", "`email`", "`opaque`"):
            assert fmt in doc_text
        assert "oauth_subject" not in doc_text
        assert "session-start.json" in doc_text
        assert "request-envelope.json" in doc_text
        assert "{id, role, attributes}" in doc_text
        assert "{user_id, tenant_id, roles, session_attributes}" in doc_text
        assert "without a separate `type` or `format` discriminator field on the wire" in doc_text

    assert '"format": "iss_sub"' in identity_text
    assert '"iss": "https://idp.example.com"' in identity_text
    assert '"sub": "user-123"' in identity_text

    session_start = json.loads(SESSION_START_SCHEMA.read_text(encoding="utf-8"))
    user_identity_props = session_start["properties"]["user_identity"]["properties"]
    assert "type" not in user_identity_props
    assert "format" not in user_identity_props

    request_envelope = json.loads(REQUEST_ENVELOPE_SCHEMA.read_text(encoding="utf-8"))
    user_context_props = request_envelope["$defs"]["Metadata"]["properties"]["user_context"]["properties"]
    assert "type" not in user_context_props
    assert "format" not in user_context_props


def test_item3_verified_vs_asserted_identity_out_of_band_in_v01():
    identity_text = IDENTITY_DOC.read_text(encoding="utf-8")
    core_concepts_text = CORE_CONCEPTS_DOC.read_text(encoding="utf-8")

    for doc_text in (identity_text, core_concepts_text):
        assert "no on-wire field in the JSON-RPC envelope" in doc_text
        for token in ("proof of possession", "DPoP", "mTLS", "SVID presentation"):
            assert token in doc_text
        assert "whether an identity descriptor was verified by the transport/host or merely asserted by the caller" in doc_text
        assert "established out of band by the deployment's transport and authentication boundary" in doc_text


def test_item4_guardian_identity_distinct_from_policy_authority_and_wire_representation():
    identity_text = IDENTITY_DOC.read_text(encoding="utf-8")
    agents_text = AGENTS_DOC.read_text(encoding="utf-8")

    for doc_text in (identity_text, agents_text):
        assert "policy authority" not in doc_text.lower()
        assert "as its own principal" in doc_text
        assert "distinct from the policy document" in doc_text
        assert "[Conformance](../spec/conformance.md)" in doc_text
        assert "ServerHello" in doc_text
        assert "response-envelope.json" in doc_text
        assert "signature.key_id" in doc_text

    handshake = json.loads(HANDSHAKE_SCHEMA.read_text(encoding="utf-8"))
    server_hello_props = handshake["$defs"]["ServerHello"]["properties"]
    assert "guardian_id" not in server_hello_props

    response_envelope = json.loads(RESPONSE_ENVELOPE_SCHEMA.read_text(encoding="utf-8"))
    acs_result_props = response_envelope["$defs"]["AcsResult"]["properties"]
    assert "guardian_id" not in acs_result_props
    assert "signature" in acs_result_props
