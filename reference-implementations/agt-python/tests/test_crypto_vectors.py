"""The Go implementation's vectors, pinned byte for byte.

``tests/testdata/envelope-vectors.json`` is the vector file the Go reference
implementation contributes in the open PR #169
(``internal/envelope/testdata/vectors.json``). #169 is not merged at the time
of writing, so the file is vendored here with attribution: these are that
author's vectors, and this test asserts this implementation agrees with them
on HKDF inputs, JCS form, and the HMAC signature. That is the interoperability
claim expressed as bytes — a divergence fails here rather than at the
conformance run. When #169 merges, this test should load the file from the Go
tree instead of the copy.
"""

from __future__ import annotations

import json
from pathlib import Path

from acs_guardian.canonical import request_signing_input, response_signing_input
from acs_guardian.crypto import derive_session_key, sign, verify

VECTORS = json.loads((Path(__file__).parent / "testdata" / "envelope-vectors.json").read_text(encoding="utf-8"))


def test_hkdf_session_key_matches_the_vectors() -> None:
    key = derive_session_key(bytes.fromhex(VECTORS["ikm_hex"]), VECTORS["session_id"])
    assert key.hex() == VECTORS["session_key_hex"]


def test_request_canonical_form_and_signature_match_the_vectors() -> None:
    signed = VECTORS["request"]["signed"]
    assert request_signing_input(signed).decode("utf-8") == VECTORS["request"]["signing_input"]
    key = derive_session_key(bytes.fromhex(VECTORS["ikm_hex"]), VECTORS["session_id"])
    signature = signed["params"]["signature"]
    assert sign(key, request_signing_input(signed)) == signature["value"]
    assert verify(key, request_signing_input(signed), signature["value"])


def test_response_canonical_form_and_signature_match_the_vectors() -> None:
    signed = VECTORS["response"]["signed"]
    assert response_signing_input(signed).decode("utf-8") == VECTORS["response"]["signing_input"]
    key = derive_session_key(bytes.fromhex(VECTORS["ikm_hex"]), VECTORS["session_id"])
    holder = signed["result"] if "result" in signed else signed["error"]
    assert sign(key, response_signing_input(signed)) == holder["signature"]["value"]


def test_a_tampered_envelope_fails_verification() -> None:
    signed = json.loads(json.dumps(VECTORS["request"]["signed"]))
    signed["method"] = "steps/sessionStart"
    key = derive_session_key(bytes.fromhex(VECTORS["ikm_hex"]), VECTORS["session_id"])
    assert not verify(key, request_signing_input(signed), signed["params"]["signature"]["value"])


def test_jcs_number_formatting_follows_ecmascript() -> None:
    """The JCS rule an implementation is most likely to get wrong (§10 pins RFC 8785)."""
    from acs_guardian.canonical import canonical_bytes

    assert canonical_bytes({"n": 1.0}) == b'{"n":1}'
    assert canonical_bytes({"n": 1e21}) == b'{"n":1e+21}'
    assert canonical_bytes({"b": True, "a": "x"}) == b'{"a":"x","b":true}'
