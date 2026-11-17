# Signing With ML-DSA-65

The reference library signs and verifies HMAC-SHA256 by default. It can also sign envelopes with ML-DSA-65 (FIPS 204) and verify them through a keyring, which issue #574 adds for traffic that crosses a trust domain ([D-047](../../docs/decisions/index.md#d-047-use-symmetric-keys-inside-a-trust-domain-and-asymmetric-keys-across-trust-domains)). Nothing changes unless you install the `pqc` extra and call the API below.

## The variant and the context

The signature registry fixes neither the ML-DSA variant nor the context string (issue #566), so the library states both.

The library signs with pure ML-DSA-65, FIPS 204 Algorithm 7 (ML-DSA.Sign). It does not use the pre-hash HashML-DSA.

The context string is empty (`b""`, zero bytes).

A verifier on another stack has to use the same pair. A different context fails verification and gives no other sign of the cause.

Signing is randomized, as FIPS 204 recommends. Two signatures of the same envelope differ, and both verify.

## Independent checks

Go's standard library package `crypto/mldsa` shares no code with the library. It verifies these signatures with `mldsa.Verify(pk, msg, sig, nil)`, derives the same public key from the same seed, and rejects a signature checked under another context. `adapters/tests/interop/` holds that check.

It runs in the `tests-pqc` job of `.github/workflows/adapter_tests.yml` on every adapter change, with `ACS_REQUIRE_GO_INTEROP=1` so a missing Go fails the job. To run it locally, install Go 1.26 or later and run this from `adapters/`:

```bash
ACS_REQUIRE_GO_INTEROP=1 uv run --extra pqc python -m pytest tests/interop -q
```

Without the variable, the check skips and says why when Go is missing.

NIST's ACVP vectors also pin key generation and verification. `adapters/tests/core/vectors/acvp_ml_dsa_65.json` names the source file, its commit, and each test case.

## What gets signed

ML-DSA-65 signs the same bytes HMAC-SHA256 signs: the RFC 8785 (JCS) form of the envelope without its `signature` member. `acs.core.signing_input(envelope)` returns them. The signature object keeps its shape:

```json
{"algorithm": "ML-DSA-65", "value": "<standard base64 of the 3,309 byte signature>", "key_id": "lab-guardian-1"}
```

Only the canonical base64 spelling of a 3,309 byte signature verifies, so one signature has one encoding. HMAC-SHA256 verification follows the same rule. A spelling with surplus padding or set unused trailing bits fails, which no compliant signer produces.

## Keys and the keyring

A verifier never trusts the envelope's `signature.algorithm`. It looks up `key_id` in a keyring, and the key it finds carries the algorithm (RFC 8725 section 3.1, issue #308).

The keyring matches `key_id` exactly. It never folds case, trims, or falls back to another key ([D-026](../../docs/decisions/index.md#d-026-treat-key_id-as-an-opaque-label)). An unknown `key_id` fails. So does an envelope whose `algorithm` differs from the key's, an unsigned envelope, a value that isn't canonical base64, and a signature that doesn't verify.

A keyring admits ML-DSA-65 keys only. Each key is parsed once, when it is built, so a malformed key fails at load. `VerificationKey.fingerprint` gives `sha256:` and the hex SHA-256 of the raw 1,952 byte public key.

```python
from acs.core import Keyring, MLDSA65SigningKey, sign_with_signing_key, verify_with_keyring

signer = MLDSA65SigningKey.from_seed(seed, "lab-guardian-1")   # seed: the 32 byte FIPS 204 seed
keyring = Keyring([signer.verification_key()])

sign_with_signing_key(envelope, signer)
assert verify_with_keyring(envelope, keyring, expected_key_id="lab-guardian-1", expected_session_id=session_id)
```

Verification takes two required pins. `expected_key_id` names the key that must answer. A keyring can hold several keys, so a response signed by any other key fails before any crypto runs. `expected_session_id` names the session the response must belong to. HMAC binds a response to its session through the per-session key, but one ML-DSA key signs every session, so the signed envelope has to name its session. A response that names another session, or none, fails before any crypto runs. A session rewritten after signing fails the signature.

The envelope names its session in `params.metadata.session_id` for a request, `result.metadata.session_id` for a response, and `error.data.session_id` for an error. A signer puts it there before signing.

On the adapter side, `acs.client.verify_signature(envelope, keyring=keyring, expected_key_id="lab-guardian-1", expected_session_id=session_id)` verifies a response by keyring, and core enforces both pins. Without `keyring`, `verify_signature` applies the HMAC rules exactly as before.

The ML-DSA and keyring names (`Keyring`, `VerificationKey`, `ML_DSA_65`, `WIRE_ALGORITHMS`, and the signing names) stay out of `acs.core.__all__`, so `from acs.core import *` never loads `cryptography`. They resolve on access when the extra is installed. Without it, access raises AttributeError naming the `pqc` extra, so `hasattr(acs.core, "Keyring")` is False.

## Lab conventions

Each item below is a lab convention. Each stays off by default and changes nothing for the Claude Code, Cursor, and NAT adapters.

The library puts no hybrid on the wire. Pull request #564 (spec(crypto): call HMAC a MAC, take the algorithm from the key, and adopt composite ML-DSA) proposes a composite construction that differs from the length-prefixed one the lab plan first used. No hybrid ships until #564 merges and issue #532 closes.

ECDSA-P256 is a benchmark primitive only. `acs.core._ecdsa` signs and verifies it with SHA-256, low-s only, so the signature benchmark can measure it. No keyring accepts an ECDSA-P256 key, and `acs.core` doesn't export it. #564 and #532 would settle whether it goes on the wire.

A signed response names its session in `result.metadata.session_id`, or in `error.data.session_id` for an error. The specification gives a response no `session_id` (§10), since the per-session HMAC key already binds it. Issue #532 (Signatures) would settle where an asymmetrically signed response names its session.

The `pqc` and `nat` extras can't be installed together. `nvidia-nat-core` pins `cryptography` below 47, and ML-DSA-65 needs a newer release. Issue #543 (NeMo Relay migration) would remove the conflict.

## Install

```bash
cd adapters
uv sync --locked --extra pqc --group test
```

`acs.core._mldsa` fails at import with a message that names the `pqc` extra when `cryptography` is missing. When the OpenSSL backend lacks ML-DSA, the first key generated, loaded, or parsed raises `MLDSAUnavailableError`, and the message names the OpenSSL version. The library checks the backend once per process and keeps the answer.
