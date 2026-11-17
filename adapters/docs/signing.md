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

It runs in the `tests-pqc` job of `.github/workflows/adapter_tests.yml` on every adapter change, with `ACS_REQUIRE_GO_INTEROP=1` so a missing Go fails the job. To run it locally, install Go 1.27 or later and run this from `adapters/`:

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

<!-- runnable -->
```python
import uuid

from acs.core import Keyring, MLDSA65SigningKey, sign_with_signing_key, verify_with_keyring

# The Guardian generates its key once. signer.seed() returns the 32 byte FIPS 204 seed, which is
# what it writes to its key file, and MLDSA65SigningKey.from_seed(seed, key_id) reloads it later.
signer = MLDSA65SigningKey.generate("lab-guardian-1")
seed = signer.seed()

# A verifier needs only the public key, under the same key_id.
keyring = Keyring([signer.verification_key()])

# The request the Observed Agent sent. Its ids must not repeat, since the binding relies on that.
request_id = str(uuid.uuid4())
request = {"jsonrpc": "2.0", "id": request_id, "method": "steps/toolCallRequest",
           "params": {"acs_version": "0.1.0", "request_id": request_id}}

# The Guardian signs its decision, which echoes both ids.
response = {"jsonrpc": "2.0", "id": request_id,
            "result": {"acs_version": "0.1.0", "request_id": request_id, "decision": "deny"}}
sign_with_signing_key(response, signer)

verified = verify_with_keyring(response, keyring, expected_key_id="lab-guardian-1", request=request)

# The same decision offered as the answer to another request fails before any crypto.
other_id = str(uuid.uuid4())
other_request = {**request, "id": other_id, "params": {"acs_version": "0.1.0", "request_id": other_id}}
replayed = verify_with_keyring(response, keyring, expected_key_id="lab-guardian-1", request=other_request)

assert verified and not replayed
```

### Pinning the key

Verification takes two required arguments besides the keyring. `expected_key_id` names the key that must answer. A keyring can hold several keys, so a response signed by any other key fails before any crypto runs.

### Binding the response to its request

`request` is the request envelope the response answers ([D-029](../../docs/decisions/index.md#d-029-verify-a-response-against-the-request-it-answers)). HMAC binds a response to its session through the per-session key. One ML-DSA key signs every session, so the key alone can't stop a response from one exchange being replayed onto another.

The response must carry the request's JSON-RPC `id`. An error is bound by the id alone, and an id with neither a result nor an error answers nothing. For any request but the handshake, the request must carry a string `params.request_id`, and the result must carry the same `request_id`. A request envelope answers nothing.

`acs.core.response_matches_request` holds this rule, and the keyring path and the client's step exchange both call it. A mismatch fails before any crypto runs, and a binding rewritten after signing fails the signature. On the keyring path, a request that can't bind anything, with no id or no `request_id`, is a caller error and raises ValueError.

### Comparing ids

Ids compare as values. A boolean never equals a number, so `true` and `1` are different ids. Numbers compare as Python values, so `1` and `1.0` match, and integers past 2**53 compare exactly. A missing or null id matches nothing. Ids should be strings.

### Replay depends on unique ids

The binding protects against replay only as far as the ids are unique, and core doesn't check that. `acs.core.request_envelope`, which `acs.client` and the adapters use, gives every request a fresh UUID4 as its JSON-RPC `id`. `params.request_id` is only as fresh as its source. An adapter may derive it from the host's event id, as the Cursor adapter does. A caller that reuses ids weakens replay protection.

### The handshake

A ServerHello carries no `request_id` under the current schema, and nothing else in it echoes the ClientHello. So when the request is the handshake (`acs.core.HANDSHAKE_METHOD`, `handshake/hello`), the JSON-RPC `id` binds the response, and its result must carry no `request_id`. A step decision therefore never answers a ClientHello, and a ServerHello never answers a step request.

The client's HMAC handshake compares the id with the same `acs.core.same_json_rpc_id`. It treats a signed ServerHello that carries `request_id` as no answer, so the fail posture applies and it never negotiates.

The id is a known limit. It ties a ServerHello to one ClientHello, not to the traffic that follows it. Issue #13 (Handshake downgrade is undetectable without transcript binding to subsequent traffic) tracks closing it.

### On the adapter side

On the adapter side, `acs.client.verify_signature(response, keyring=keyring, expected_key_id="lab-guardian-1", request=request)` verifies a response by keyring, and core enforces the key pin and the request binding. Without `keyring`, `verify_signature` applies the HMAC rules exactly as before.

The ML-DSA and keyring names (`Keyring`, `VerificationKey`, `ML_DSA_65`, `WIRE_ALGORITHMS`, and the signing names) stay out of `acs.core.__all__`, so `from acs.core import *` never loads `cryptography`. They resolve on access when the extra is installed. Without it, access raises AttributeError naming the `pqc` extra, so `hasattr(acs.core, "Keyring")` is False.

## Lab conventions

Each item below is a lab convention. Each stays off by default and changes nothing for the Claude Code, Cursor, and NAT adapters.

The library puts no hybrid on the wire. Pull request #564 (spec(crypto): call HMAC a MAC, take the algorithm from the key, and adopt composite ML-DSA) proposes a composite construction that differs from the length-prefixed one the lab plan first used. No hybrid ships until #564 merges and issue #532 closes.

ECDSA-P256 is a benchmark primitive only. `acs.core._ecdsa` signs and verifies it with SHA-256, low-s only, so the signature benchmark can measure it. No keyring accepts an ECDSA-P256 key, and `acs.core` doesn't export it. #564 and #532 would settle whether it goes on the wire.

The `pqc` and `nat` extras can't be installed together. `nvidia-nat-core` pins `cryptography` below 47, and ML-DSA-65 needs a newer release. Issue #543 (NeMo Relay migration) would remove the conflict.

## Install

```bash
cd adapters
uv sync --locked --extra pqc --group test
```

`acs.core._mldsa` fails at import with a message that names the `pqc` extra when `cryptography` is missing. When the OpenSSL backend lacks ML-DSA, the first key generated, loaded, or parsed raises `MLDSAUnavailableError`, and the message names the OpenSSL version. The library checks the backend once per process and keeps the answer.
