# Predicate: ACS conformance verdict evidence, version 1.0.1-draft

Predicate type URI (proposed, pending acceptance):
`https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/docs/predicates/acs-verdict-evidence-v1.md`

Status: proposed draft `v1.0.1-draft`. Modeled on the
[agent-change-admission-v1](https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md)
predicate: same DSSE v1 envelope, same field table, same verification-step
layout, same versioning rule. This draft records the field list after the
sharpening on issue #33 (2026-10-18). Breaking change versus `v1.0.0-draft`:
the runner no longer writes a lift state; `witness_scope` lift falls out of a
peer-authored artifact, and the quarantine record carries its own integrity
envelope. Not normative until accepted.

## Purpose

A conformance suite executes a named vector against a deployment and records
one verdict about one ACS-Core requirement: did the observed behavior match
the expected disposition for that requirement, and how independently was that
claim witnessed. This predicate packages that verdict so that a consumer of
the requirement ledger can tell, from bytes alone, (a) which vector and which
clause the verdict is about, (b) what was expected and observed, (c) whether
the witness is the deployment itself or someone who can check the requirement
without the enforcement point's own account, and (d) how much of the record
integrity covers versus what the runner's own signature covers.

A rejection is recorded with the same weight as a pass. A vector that cannot
yet be scored is quarantined, not silently defaulted.

## Envelope

The verdict is signed as a DSSE v1 envelope. The signature covers the DSSE
pre-authentication encoding of the payload type and the payload bytes, never
the raw payload:

```text
"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

The carriage is in-toto Statement v1, `payloadType`
`application/vnd.in-toto+json`: the statement's `_type` is
`https://in-toto.io/Statement/v1`, its `subject` is the digest-named vector,
`predicateType` is the URI above, and the verdict object is the statement's
`predicate`.

A signature's `keyid` is the lowercase hex SHA-256 of the raw public key. A
consumer pins its trusted keys out of band; a key carried inside the envelope
is never trusted. An envelope may carry an additional co-signature by a key the
consumer does not pin: that is the default honest state, non-repudiation only,
and it lifts nothing.

## Fields

Every field below is required in a verdict record. A verifier checks them in
this order and names the first one that is absent or malformed.

| Field | Type | Meaning |
| --- | --- | --- |
| `vector_id` | 16 lowercase hex | First 16 chars of the SHA-256 of the vector input's canonical form |
| `profile` | non-empty string | ACS profile the clause belongs to (e.g. `acs-core`) |
| `anchor` | non-empty string | Repo-relative, resolvable anchor to the normative clause (a heading anchor, not bold text) |
| `clause` | non-empty string | Human-readable clause name, matching the anchor |
| `verdict` | one of `pass`, `rejected`, `unmeasurable`, `quarantined` | The four-state verdict; `quarantined` uses the quarantine record below |
| `witness_derivation.runner.id` | non-empty string | Runner identifier |
| `witness_derivation.runner.hosting_operator_id` | non-empty string | Comparable identifier of the operator who runs the runner |
| `witness_derivation.deployment_operator_id` | non-empty string | Comparable identifier of the operator of the deployment under test |
| `witness_scope` | one of `SELF`, `PEER`, `EXTERNAL` | Derived per the table below; never asserted independently |
| `verification_basis` | non-empty array of strings | Values from the registry: `wire_transcript`, `signed_decision_record`, `policy_state`, `terminal_state_evidence`, `anchor_commitment` |
| `expected` | object | Expected disposition and reason codes |
| `observed` | object | Observed disposition and reason codes |
| `behavior_snapshot` | object or `null` | Runner-captured run data (rolling chain hashes, runner id); may be `null` in an offline deterministic sample |
| `integrity.payload_digest` | 64 lowercase hex | SHA-256 of the canonical bytes of exactly the fields named in `integrity.payload_digest_fields` |
| `integrity.payload_digest_fields` | non-empty array | The names of the fields the digest covers |
| `integrity.does_not_cover` | array | Lists `behavior_snapshot`, `integrity`, `provenance`, `subject` |
| `integrity.binding` | non-empty string | States the binding consequences: observed hashes are bound only by the runner's own envelope signature; the subject is bound by the envelope, not by `payload_digest` |
| `provenance.peer_artifact` | 64 lowercase hex or `null` | `null` when no peer artifact exists. Otherwise the SHA-256 of the canonical bytes of the peer-signed verification statement (see below) |
| `provenance.anchor` | object or `null` | Persistence only: `{kind: "rfc3161-timestamp" \| "transparency-log", reference}`; never lifts `witness_scope` |

A record may carry further fields (e.g. `observed_at` RFC 3339 timestamps); a
verifier ignores fields it does not check. A record must not carry any field
by which the runner asserts its own scope — there is no `lift_state`, no
`checked`, no `signer_relationship` written into the runner's envelope.

### The peer verification statement

A lift above `SELF` requires an artifact the runner did not author: an
in-toto Statement v1 signed by a peer key the consumer pins, whose predicate

- names **this vector** in its subject (digest equal to the verdict subject),
- names **the requirement** it checked (`anchor`/clause match), and
- names the **evidence artifact** it checked it with — either
  `{"kind": "client_run", "deployment": ...}` (the peer drove its own client
  against this deployment) or
  `{"kind": "wire_transcript", "transcript_digest": ..., "vector": ...}`.

`provenance.peer_artifact` is the SHA-256 of that statement's canonical bytes.
The runner can point at it; it cannot produce it.

## Deriving `witness_scope`

`witness_scope` is computed by the consumer, never asserted by the runner.
SELF falls out of identifier equality; a lift requires a verified
`peer_artifact`, and the signer's relationship comes from the pinned peer key's
out-of-band record, not from a field in the runner's envelope.

| `hosting_operator_id == deployment_operator_id` | `provenance.peer_artifact` | derived `witness_scope` |
| --- | --- | --- |
| equal | `null` | `SELF` |
| equal | present, verifies, pinned relationship = peer | `PEER` |
| equal | present, verifies, pinned relationship = external | `EXTERNAL` |
| unequal | `null` | not a valid `SELF` record: rejected at verification step 9 (`witness_scope_misderived`) |
| any | present but signature invalid, or requirement/artifact does not match this vector | `contradicted` (`peer_artifact_unverified`) |

A co-signature over the runner's envelope is not in this table: absent a peer
artifact, it is the default honest state — non-repudiation only — and the
record reads `SELF` however the runner might wish to relabel it. There is no
field in which it could do so.

`provenance.anchor` never appears in this table. A timestamp or a
transparency-log entry proves the digest existed at a time and was not
backdated; it is persistence, not verification. A `SELF` record carrying an
anchor remains `SELF`.

## `payload_digest` scope

`payload_digest` is SHA-256 of the canonical JSON (keys sorted, no whitespace,
UTF-8) of exactly the fields listed in `integrity.payload_digest_fields` — in
the reference sample: `anchor`, `clause`, `expected`, `observed`, `profile`,
`vector_id`, `verdict`, `verification_basis`, `witness_derivation`,
`witness_scope`. It proves those bytes are intact.

It deliberately does **not** cover:

- `behavior_snapshot` — observed run data is bound only by the runner's own
  DSSE envelope signature; a reader is told this by `integrity.binding` so
  the digest is not mistaken for a binding of the observed hashes.
- `integrity` and `provenance` themselves (self-reference).
- `subject` — the record is tied to the vector by the envelope's subject
  digest, not by `payload_digest`.

## Quarantine record

When `verdict` is `quarantined`, a second Statement carries:

| Field | Meaning |
| --- | --- |
| `quarantine_ref` | URL of the open spec issue whose closure resolves the vector's uncertainty, or `null` when no such issue exists yet |
| `quarantine_gap` | When `quarantine_ref` is `null`, the normative gap this vector's uncertainty is evidence of |
| `owner` | The accountable party (originator until the spec workstream takes the gap) |
| `review_by` | ISO date by which the gap must be resolved or the vector re-triaged; follows the `review_by` precedent on proposed terms |
| `excluded_from` | States the vector is excluded from formal results until the gap resolves |
| `expiry_disposition` | What happens when `review_by` passes with the gap open: the vector reverts to `unmeasurable` and stays excluded; the owner must re-quarantine with a new `review_by` or reference the gap issue's resolution; a quarantined vector never becomes a formal pass or reject while the gap is open |
| `integrity.payload_digest` | SHA-256 of the canonical bytes of the quarantine record's own declared fields (`vector_id`, `status`, `reason`, `quarantine_ref`, `quarantine_gap`, `owner`, `review_by`, `excluded_from`) — so a silent edit to any of them breaks the digest |

## Verification

A verifier takes the envelope, a policy (payload type, predicate type, trusted
keys, required verification bases) and any stored transcripts it holds. It
returns `supported`, `contradicted` or `not_established`, with the reason code
of the first check that fails.

| Step | Check | Decision and reason |
| --- | --- | --- |
| 1 | The bytes parse as a DSSE envelope with payload type, base64 payload and at least one signature | no verdict, `malformed_envelope` |
| 2 | Payload type is `application/vnd.in-toto+json` | `not_established`, `unsupported_payload_type` |
| 3 | A signature naming a pinned keyid verifies | `contradicted`, `untrusted_key` / `signature_invalid` |
| 4 | The payload is an in-toto Statement v1 | `not_established`, `payload_not_statement` |
| 5 | `predicateType` is this URI | `not_established`, `unsupported_predicate` |
| 6 | Every field in the table is well formed, in table order; no runner-written lift field is present | `not_established`, `field_invalid:<field>` |
| 7 | A subject carries `digest.sha256` equal to the canonical vector input | `contradicted`, `subject_digest_mismatch` |
| 8 | `payload_digest` recomputed over `payload_digest_fields` equals the claim | `contradicted`, `payload_digest_mismatch` |
| 9 | `witness_scope` equals the value derived from ID equality and `provenance.peer_artifact` (signature, requirement match, evidence artifact kind, pinned relationship) | `contradicted`, `witness_scope_misderived` / `peer_artifact_unverified` |
| 10 | A `quarantined` record carries `quarantine_ref` or `quarantine_gap`, `owner`, `review_by`, `expiry_disposition`, and its own `integrity.payload_digest` recomputes | `not_established`, `quarantine_field_missing:<field>` / `contradicted`, `quarantine_digest_mismatch` |

A record that passes every step is `supported`. A verifier that also holds the
vector input and the wire transcript may re-execute the vector and compare its
own outcome with the signed verdict; such a recomputation adds to these steps
and never replaces one.

## What a valid record does not establish

A supported verdict means the pinned key signed exactly these bytes and the
declared digest fields recompute. It does not establish that the evaluations
ran, that the observed hashes are true, that an unpeered co-signature holder is
an independent witness, or that a timestamp proves independence. A digest is
integrity; an anchor is persistence; neither is provenance. What the verifier
recomputed from bytes and what it accepted on a signer's signature are
separate statements, and a verifier reports them separately.

## Versioning

This document is `v1.0.1-draft`; on acceptance it becomes `v1.0.0` at the URI
above. A change that adds an optional field or a reason code that refuses
nothing previously supported edits this page. A change that adds a required
field, renames a field, changes a field's type, or supports a verdict version
1 refuses is breaking: it is published as `acs-verdict-evidence-v2.md` at a
new path, and this page stays.
