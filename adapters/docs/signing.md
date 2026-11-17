# Signing With ML-DSA-65

The reference library signs and verifies HMAC-SHA256 by default. It can also sign envelopes with ML-DSA-65 (FIPS 204) and verify them through a keyring, which issue #574 adds for traffic that crosses a trust domain ([D-047](../../docs/decisions/index.md#d-047-use-symmetric-keys-inside-a-trust-domain-and-asymmetric-keys-across-trust-domains)). Nothing changes unless you install the `pqc` extra and call the API below.

## The variant and the context

The signature registry fixes neither the ML-DSA variant nor the context string (issue #566), so the library states both:

- **Variant:** pure ML-DSA-65 (FIPS 204 Algorithm 7, ML-DSA.Sign), not HashML-DSA.
- **Context string:** empty (`b""`, zero bytes).

A verifier on another stack has to use the same pair. A different context fails verification and gives no other sign of the cause. Go's standard library `crypto/mldsa` verifies these signatures with `mldsa.Verify(pk, msg, sig, nil)`, and `adapters/tests/interop/` checks that on every run where Go 1.26 or later is installed.

Signing is randomized, as FIPS 204 recommends, so two signatures of the same envelope differ and both verify.

## What gets signed

ML-DSA-65 signs the same bytes HMAC-SHA256 signs: the RFC 8785 (JCS) form of the envelope without its `signature` member. `acs.core.signing_input(envelope)` returns them. The signature object keeps its shape:

```json
{"algorithm": "ML-DSA-65", "value": "<standard base64 of the 3,309 byte signature>", "key_id": "lab-guardian-1"}
```

Only the canonical base64 spelling verifies, so one signature has one encoding.

## Keys and the keyring

A verifier never trusts the envelope's `signature.algorithm`. It looks up `key_id` in a keyring, and the key it finds carries the algorithm (RFC 8725 section 3.1, issue #308). Verification fails when:

- the keyring has no key under that exact `key_id`. The keyring never folds case, trims, or falls back to another key ([D-026](../../docs/decisions/index.md#d-026-treat-key_id-as-an-opaque-label)).
- the envelope's `algorithm` differs from the key's.
- the envelope is unsigned, the value isn't canonical base64, or the signature doesn't verify.

```python
from acs.core import Keyring, MLDSA65SigningKey, sign_with_signing_key, verify_with_keyring

signer = MLDSA65SigningKey.from_seed(seed, "lab-guardian-1")   # seed: the 32 byte FIPS 204 seed
keyring = Keyring([signer.verification_key()])

sign_with_signing_key(envelope, signer)
assert verify_with_keyring(envelope, keyring)
```

On the adapter side, `acs.client.verify_signature(envelope, keyring=keyring)` verifies a response by keyring. Without `keyring` it applies the HMAC rules exactly as before.

A keyring admits ML-DSA-65 keys only. `VerificationKey.fingerprint` gives `sha256:` and the hex SHA-256 of the raw 1,952 byte public key.

## Lab conventions

Each of these is a lab convention. It stays off by default and changes nothing for the Claude Code, Cursor, and NAT adapters.

- **No hybrid on the wire.** Pull request #564 (spec(crypto): call HMAC a MAC, take the algorithm from the key, and adopt composite ML-DSA) proposes a composite construction that differs from the length-prefixed one the lab plan first used. The library ships no hybrid until #564 merges and issue #532 closes.
- **ECDSA-P256 is a benchmark primitive.** `acs.core._ecdsa` signs and verifies ECDSA-P256 with SHA-256 so the signature benchmark can measure it. No keyring accepts an ECDSA-P256 key. #564 and #532 would settle whether it goes on the wire.
- **The `pqc` and `nat` extras can't be installed together.** `nvidia-nat-core` pins `cryptography` below 47. Issue #543 (NeMo Relay migration) would remove the conflict.

## Install

```bash
cd adapters
uv sync --locked --extra pqc --group test
```

`acs.core._mldsa` fails at import with a message naming the `pqc` extra when `cryptography` is missing, and names the OpenSSL version when the backend lacks ML-DSA.
