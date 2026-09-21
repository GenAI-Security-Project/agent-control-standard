# Hash and sign the canonical form

Two Guardians compare chains and verify each other's signatures only if they hash and
sign the same bytes. ACS fixes those bytes as the RFC 8785 JSON Canonicalization Scheme
(JCS) form, and permits no other (§8.2, §10). This page says where the Go implementation produces
that form and how each use is proved.

## Canonicalize once, the same way everywhere

`internal/jcs` produces the JCS form with `jsontext.Value.Canonicalize` from
`github.com/go-json-experiment/json`, the upstream of Go's `encoding/json/v2`, which
implements RFC 8785 directly. Go's `encoding/json` v1 never produces canonical bytes: it
escapes `<`, `>`, `&`, U+2028 and U+2029, and formats numbers its own way.

The same package decodes every request. It refuses a duplicate member name, invalid UTF-8
and an unpaired surrogate, and it matches member names case-sensitively. A request two
parsers could read two ways never reaches a signature check, so a signature always covers
exactly one meaning.

## Where the form is used

| Use | Bytes | Specification |
| --- | --- | --- |
| Signed input | The request or response envelope with its `signature` member removed: `params.signature` in a request, `result.signature` in a result, `error.signature` in an error. | §10 |
| `request_hash` | Lowercase-hex SHA-256 of the request's `params`, signature included. | §8.1 |
| `entry_hash` | Lowercase-hex SHA-256 of the entry without `entry_hash` and `previous_hash`, then the raw 32 bytes of `previous_hash`, or nothing for a session's first entry. | §8.2 |

The HMAC-SHA256 signer derives a separate key for each session with HKDF (RFC
5869). It uses SHA-256, supplies no salt, uses the UTF-8 bytes of `session_id` as
the HKDF `info` input, and asks HKDF for 32 bytes. `salt` and `info` are inputs to
HKDF; they are not fields in an ACS message. Section 10 requires HKDF but does
not define those inputs. Two implementations must use the same values to verify
each other's signatures. The signature value is standard base64 with padding.

## Tests

The JCS tests protect the bytes used by this module; they do not test the
external library's internal design. An update that changes one number or
Unicode encoding must fail locally before it changes ACS signatures or chain
hashes. The 5,000 compressed number cases occupy 75 KiB.

| Property | Test | Vectors |
| --- | --- | --- |
| RFC 8785 conformance | `internal/jcs.TestReferenceVectors`, `internal/jcs.TestES6Numbers`, `internal/jcs.TestRFC8785Example` | The RFC author's reference vectors and the first 5,000 of its ES6 number vectors, in `internal/jcs/testdata/`. |
| Non-I-JSON refused | `internal/jcs.TestRefusesNonIJSON`, `internal/envelope.TestRefusesDuplicateMembers` | Written in the tests. |
| §8.1 and §8.2 digests | `internal/chain.TestVector`, `internal/chain.TestRequestHashVector` | `internal/chain/testdata/vectors.json`, computed with Python's `json` and `hashlib`. |
| §10 signed input and HMAC | `internal/envelope.TestSigningInputVectors`, `guardian.TestHMACSignerVectors` | `internal/envelope/testdata/vectors.json`, computed in Python; its HKDF matches RFC 5869 test case 3. |
| Live answers verify | `guardian.TestIndependentVerifier` and every `guardian` test that reads a decision | A verifier with its own canonicalizer and the standard library's HKDF and HMAC, sharing no code with the signer. |
