"""The HMAC key-derivation example in Specification section 10 matches its parameters.

The example is the one known-answer value a second implementer checks against, so
a typo in it, or a parameter change that forgets to update it, would send every
new implementation chasing a key no correct HKDF produces. This recomputes it from
the stated parameters with the standard library alone.
"""

import hashlib
import hmac
import re
from pathlib import Path

SPEC = Path(__file__).resolve().parent.parent / "docs" / "spec" / "instrument" / "specification.md"


def _hkdf_sha256(ikm: bytes, info: bytes, length: int) -> bytes:
    # RFC 5869 with no salt: extract uses HashLen zero bytes as the HMAC key.
    prk = hmac.new(b"\x00" * hashlib.sha256().digest_size, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def test_section_10_hkdf_example_matches_its_parameters():
    text = SPEC.read_text(encoding="utf-8")
    example = re.search(
        r"the `session_id` `(?P<sid>[0-9a-f-]{36})` give the key `(?P<key>[0-9a-f]{64})`", text
    )
    assert example, "Specification section 10 no longer carries the HKDF example in the expected form"
    derived = _hkdf_sha256(bytes(range(32)), example["sid"].encode("utf-8"), 32)
    assert derived.hex() == example["key"]


def test_hkdf_helper_matches_rfc_5869_test_case_3():
    # RFC 5869 Appendix A.3, the SHA-256 case with no salt and empty info, so
    # the helper above is anchored to the RFC and not only to the spec's own example.
    okm = _hkdf_sha256(b"\x0b" * 22, b"", 42)
    assert okm.hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    )


def test_session_id_is_used_as_sent_not_normalized():
    # Section 10 says info is the session_id string exactly as the request carries
    # it. The schema's uuid format accepts other spellings of the same UUID, and
    # each one derives a different key, which is why normalizing breaks interop.
    sid = "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"
    as_sent = _hkdf_sha256(bytes(range(32)), sid.encode("utf-8"), 32)
    for spelling in (sid.upper(), f"urn:uuid:{sid}"):
        assert _hkdf_sha256(bytes(range(32)), spelling.encode("utf-8"), 32) != as_sent
