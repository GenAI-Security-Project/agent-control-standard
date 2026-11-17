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

The keyring matches `key_id` exactly. It never folds case, trims, or falls back to another key ([D-026](../../docs/decisions/index.md#d-026-treat-key_id-as-an-opaque-label)). Verification fails for an unknown `key_id`, an envelope whose `algorithm` differs from the key's, an unsigned envelope, a value that isn't canonical base64, and a signature that doesn't verify.

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

`acs.core.response_binding_problem` holds the one rule, and `acs.core.response_matches_request` is that check finding no reason. The keyring path, the client's step exchange, and the client's handshake all decide through it. It checks the request first, then the response, and names the first reason it finds.

`BINDING_REQUEST` means the request fails `acs.core.request_envelope_problem`. `BINDING_SHAPE` means the response isn't a JSON-RPC 2.0 object with exactly one object result or error, or it carries a `method`, so a request envelope never counts as an answer. `acs.core.response_shape_problem` is that shape check on its own, and the client judges an HTTP error body by it too. `BINDING_ID` means the response doesn't carry the request's JSON-RPC `id`, and `BINDING_RESULT` means a result doesn't bind, as below.

An error object binds by the id alone, whatever the request's `request_id`. A result binds when the request is a real ClientHello, by the id alone, or when the request carries a string `params.request_id` that the result repeats. `acs.core.request_binding_problem` is the exported check for whether a request can bind a result at all.

A mismatch fails before any crypto runs, and a binding rewritten after signing fails the signature. A request with no usable `request_id` binds no result, the same answer on both paths.

On the HMAC path, a body under HTTP 200 that isn't a JSON-RPC 2.0 answer is no decision, so the fail posture applies, as for a transport failure. A JSON-RPC 2.0 answer that carries a `method`, or both a result and an error, is refused as `response_shape_invalid`. The refusal holds under either posture. Its signature is never checked, so altering a signed deny this way can't select the fail posture. Under HTTP 400 or 413 the HTTP refusal wins and the call is denied, and under any other non-2xx status the call is an HTTP error, which gets the fail posture. Anyone who can tamper with a response in transit can also drop the connection, so transport integrity is TLS's job, and the default posture denies (D-036).

A caller error is the caller's on every path. On the HMAC path a request that can't bind any answer is refused as `request_envelope_invalid`, an observed-agent error. `exchange()` checks it with `acs.core.request_binding_problem` before any I/O, so a request with params that aren't an object, or a step request without a usable `request_id`, never reaches the network. The step exchange and the handshake give the same cause when the rule reports `BINDING_REQUEST`.

On the keyring path, only a request that is no envelope at all is a caller error. It raises ValueError with the text `acs.core.request_envelope_problem` gives. That covers a request that isn't a mapping and an id that isn't a string or a finite number: a missing or null id, a boolean, an object, an array, NaN, or an infinity.

### Comparing ids

Ids compare as values, and a boolean never equals a number, so `true` and `1` are different ids. Numbers compare as Python values, so `1` and `1.0` match and integers past 2**53 compare exactly. A missing or null id matches nothing. Ids should be strings.

### Replay depends on unique ids

The binding protects against replay only as far as the ids are unique, and core doesn't check that. `acs.core.request_envelope`, which `acs.client` and the adapters use, gives every request a fresh UUID4 as its JSON-RPC `id`. `params.request_id` is only as fresh as its source, and an adapter may derive it from the host's event id, as the Cursor adapter does. A caller that reuses ids weakens replay protection.

Error binding rests on the JSON-RPC `id` alone, on both paths, as D-029 sets. A caller that picks predictable ids could accept a signed error captured from another session. A caller must use the UUIDs `acs.client` generates, or ids just as unique.

### Known limit: relaying a Guardian's answer between sessions

One ML-DSA key signs every session, and a response names no session, so keyring verification binds a response only by its JSON-RPC `id` and `result.request_id`. An attacker who sits on the path to the Guardian and is also an authenticated client of the same Guardian can copy a victim's ids into its own request. It can then relay the Guardian's signed answer to the victim, and that answer verifies.

HMAC prevents this, because each session's key is derived from its `session_id`, so an answer signed for one session fails in another. A single ML-DSA key gives no such separation. Closing the gap needs the signed response to carry the session, or a hash of the request it answers. Specification section 10 says a response carries no `session_id`, so that is a wire change for the specification, not a library fix. Issue #13 (Handshake downgrade is undetectable without transcript binding to subsequent traffic) is the closest tracking issue.

The limit holds without the lab convention below and is closed with it. Without the convention, the connection to the Guardian must use TLS, which keeps an attacker off the path.

#### Lab convention: the request hash

In ML-DSA response mode (issue #576), every response the example Guardian signs carries `x_acs_lab_request_sha256`: the lowercase hex SHA-256 of the request's section 10 signed input, the JCS bytes of the request envelope without its `signature`. A result carries it in `result`, and an error carries it in `error.data`, the ServerHello and the session refusal included. It sits inside the signed bytes, so it can't be changed without breaking the signature.

That one value binds the response to the request's session, `request_id`, timestamp and content. A relayed answer names the attacker's request, not the victim's, so it fails.

`acs.core.verify_with_keyring(..., require_request_digest=True)` requires the field and compares it with `acs.core.request_sha256(request)`. `acs.client` always passes it when `response_keys` is set, on the step exchange and the handshake. A missing or different hash leaves the response unverified, so the step blocks as `signature_invalid`. The default is False, so a caller of `verify_with_keyring` that doesn't ask still has the limit above. The HMAC path never reads the field.

The field is a lab convention, not part of the specification.

### The handshake

A ServerHello carries no `request_id` under the current schema, and nothing else in it echoes the ClientHello. When the request is the handshake (`acs.core.HANDSHAKE_METHOD`, `handshake/hello`), the JSON-RPC `id` alone binds the response. An extra field such as an echoed `request_id` is ignored, as specification section 4 requires, and a ServerHello never answers a step request, since that needs the request's `request_id`.

The client's HMAC handshake decides through `response_binding_problem` as well. A reply that isn't a JSON-RPC 2.0 answer is no answer, a JSON-RPC 2.0 answer with a `method` or both members refuses the session as `response_shape_invalid`, an id problem refuses the session, and a request problem refuses it as `request_envelope_invalid`. `request_binding_problem` requires a `handshake/hello` request to carry object params with an object payload, so a ServerHello binds only a real ClientHello on every path. `acs.core.server_hello_problem` then checks the required ServerHello fields, which keep a step answer from passing as a ServerHello, so on the HMAC handshake such a result is no answer and never negotiates.

Binding by id is a known limit. It ties a ServerHello to one ClientHello, not to the traffic that follows it. Issue #13 (Handshake downgrade is undetectable without transcript binding to subsequent traffic) tracks closing it.

### On the adapter side

`acs.client.verify_signature(response, keyring=keyring, expected_key_id="lab-guardian-1", request=request)` verifies a response by keyring, and core enforces the key pin and the request binding. Without `keyring`, `verify_signature` applies the HMAC rules exactly as before.

The ML-DSA and keyring names (`Keyring`, `VerificationKey`, `ML_DSA_65`, `WIRE_ALGORITHMS`, and the signing names) stay out of `acs.core.__all__`, so `from acs.core import *` never loads `cryptography`. They resolve on access when the extra is installed. Without it, access raises AttributeError naming the `pqc` extra, so `hasattr(acs.core, "Keyring")` is False.

## Verifying a Guardian's decisions

The example Guardian can sign every response with its own ML-DSA-65 key (issue #576), as `docs/guardian/README.md` describes under "Decision signing". `acs.client` verifies those responses with the Guardian's key document alone. The response key comes from the key document by key_id (issue #308, RFC 8725 section 3.1). The envelope's algorithm never selects it, and D-026 applies per key_id: an exact match, no fallback.

`acs.client.response_keys_from_env(os.environ)` reads `ACS_RESPONSE_ALGORITHMS`, `ACS_GUARDIAN_KEYS`, and the optional pin `ACS_GUARDIAN_KEY_ID`. Unset, blank, or `HMAC-SHA256` returns None, which is today's HMAC path, and needs no extra. `ML-DSA-65` loads the key document. Any other value is a ValueError, a list of two included, because accepting HMAC beside ML-DSA-65 would let anyone holding the shared secret forge a decision. It takes exactly one value until issue #316 settles verifier rules. `Config.from_env` never reads these settings, so the Claude Code, Cursor, and NAT adapters are unchanged.

`acs.client.load_response_keys(path, key_id=None)` and `acs.client.parse_key_document(document, key_id=..., now=...)` return a `ResponseKeys` that holds a keyring with exactly one key. Every entry in the document is checked: the format `acs-lab-keys/1`, the algorithm `ML-DSA-65`, canonical base64 of a 1,952 byte public key, a `fingerprint` that matches that key, and RFC 3339 UTC times. A key is live when `not_before <= now < not_after` and no entry in `revoked` names it at or before now. With a pin, the pinned key must be live. Without one, the document must hold exactly one live key, so two live keys are refused, never resolved by order. Any problem raises `KeyDocumentError`. The format is a lab convention until issue #460 settles key publication.

`round_trip`, `exchange`, and `open_session` take two optional arguments. `response_keys` verifies every answer under the pinned key, as the answer to the request it answers (D-029), with the request hash above. A failure keeps its existing cause, `response_signature_invalid`, `error_signature_invalid`, or `server_hello_signature_invalid`, so it blocks the step as `signature_invalid` whatever the posture (D-025, D-040). An unsigned -32004 still reads as `key_id_rejected`. With keys, the ClientHello offers `x_acs_lab_response_algorithms`, and a verified ServerHello that doesn't select the same algorithm refuses the session as `response_algorithm_not_negotiated`. A verified handshake refusal keeps its `error.data.reason`. A stored session decision is reused under either mode, and its first step then fails closed if the Guardian signs in the other mode.

`on_wire(direction, envelope)` receives a copy of the signed request before it is sent ("req") and of every decoded answer before it is classified ("resp"), so a transcript holds refusals, errors, and tampered answers as they arrived. No "resp" call means no answer arrived, and the outcome's cause says why. A callback that raises refuses the step as `on_wire_failed`, an observed-agent error, and on "req" nothing is sent. A stored session decision is reused with no call, since nothing crosses the wire.

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
