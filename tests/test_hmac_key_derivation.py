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
