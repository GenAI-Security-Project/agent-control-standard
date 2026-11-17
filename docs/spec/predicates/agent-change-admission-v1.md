# Predicate family: Agent Change Admission (v1)

Type URIs:
- `urn:lgd:acs:predicate:agent-change-admission:v1` — the admission decision
- `urn:lgd:acs:predicate:agent-change-witness:v1` — a peer's statement over an admission
- `urn:lgd:acs:predicate:agent-change-anchor:v1` — an external anchor over an admission

Version: v1.1 (revised after external review; for discussion against GenAI-Security-Project/agent-control-standard#33)
Status: draft, not yet proposed upstream
Scope: predicate-only. No change to ACS normative text, no wire-format change.

### Why the type identifiers are URNs

These are `urn:` identifiers, deliberately not `https:`. An earlier draft used an `https:` host for
them and every one of those URIs returned HTTP 503 — a type URI that does not resolve is worse than
one that never pretended to: a verifier that dereferences it fails in a way that looks like our
fault, and a verifier that ignores it learns nothing. `docs/spec/conformance.md` records that
ACS v0.1.0 has no registry and no steward body, so there is no authority to resolve a type URI
against. A URN says exactly that: stable name, no resolver, resolution is the verifier's problem
via `pin.registry_revision`.

When a registry exists, `https:` URIs will be minted and these URNs kept as aliases, so no
statement signed today becomes unverifiable tomorrow. Until then, a verifier MUST NOT dereference
and MUST treat an unresolvable registry as `verifier_context_incomplete` (fail-closed), never as
a pass.

---

## 1. Purpose

ACS asks a Guardian to decide, at runtime, whether an agent may do a thing. It does not, by itself,
leave behind a portable record that a *third party* can check later: "this capability entered the
agent here, because this policy said so, and someone other than the agent can vouch that it did."

This family closes that gap with three attestations over the same object — the **change payload**:

| Predicate | Answers | `witness_scope` | Earns |
|---|---|---|---|
| `agent-change-admission` | Was this change admitted, by whom, under which policy? | `self` | authenticity only |
| `agent-change-witness` | Did a peer see the same payload and the same outcome? | `peer` | peer-binding |
| `agent-change-anchor` | Does a party the observed party cannot reach pin this record? | `external` | EXTERNAL lift |

The three share one identity model (`change`, `context`), one binding rule (AC-1/AC-2), and one
lift ladder (AC-4). A deployment may publish only the admission predicate; the other two are optional
and additive.

## 2. Why a family rather than one predicate

`witness_scope` is a **property of the evidence, not of the claim**. Collapsing SELF, PEER and
EXTERNAL into one boolean field would make the value unattributable: a consumer could not tell *which
key* earned the lift, and a deployment could silently upgrade itself by setting the field. Separate
predicate types force the lift to be carried by separate signatures over separate statements, which
is the only form a verifier can recompute.

Consequence, stated as a constraint rather than advice: **a single statement can never carry more
than one scope.** If a producer wants PEER, it publishes a witness statement signed by the peer key.
EXTERNAL requires an anchor statement signed by the anchored key.

## 3. Model

- `subject[]` — the digest of the canonical change payload. Consumers MUST match on `subject[].digest`.
- `predicate.change` — what kind of change, and how the payload was canonicalized.
- `predicate.context` — which ACS session/request/chain the change belongs to.
- `predicate.outcome` — the post-decision effect record; `outcome_digest` is recomputed from it.
- `predicate.<role>` — exactly one role block, named by the predicate type: `guardian` for admission,
  `witness` for witness, `anchor` for anchor. Its `key_id` is the only key allowed to have signed the
  statement.

**Statement digest (normative).** Wherever this document says "digest of the signed statement", it
means `sha256` over the JCS (RFC 8785) serialization of the Statement object with the detached
signature member `_sig` removed. The signature itself is computed over that same byte string, so the
digest a peer cites is the digest of exactly what was signed, and it is computable by any third party
without the signer's key.

## 4. Schema — admission

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "change-payload", "digest": { "sha256": "<64 hex>" } }],
  "predicateType": "urn:lgd:acs:predicate:agent-change-admission:v1",
  "predicate": {
    "change": {
      "kind": "tool_register|skill_load|skill_unload|memory_write|policy_update|capability_grant|config_mutation",
      "payload_digest": { "sha256": "<64 hex>" },
      "canonicalization": "jcs-rfc8785",
      "payload_media_type": "application/json"
    },
    "context": {
      "acs_version": "0.1.4",
      "session_id": "<uuid>",
      "request_id": "<uuid>",
      "chain_hash": "<hex>",
      "agent_id": "<string>"
    },
    "guardian": { "id": "<string>", "key_id": "<string>", "control_domain": "<string>" },
    "policy": { "digest": { "sha256": "<hex>" }, "version": "<string>" },
    "disposition": "ALLOW|DENY|ASK|DEFER|MODIFY",
    "reason_codes": ["<string>"],
    "decided_at": "<RFC3339>",
    "outcome": { "applied": <bool>, "effect": "<string>", "audit_id": "<string>" },
    "outcome_digest": { "sha256": "<digest of the outcome object above>" },
    "witness_scope": "self"
  },
  "_sig": "<base64 Ed25519 signature over the statement digest>"
}
```

**Disposition semantics (normative).** `ALLOW` and `MODIFY` are *admitted* — the change took effect,
and for `MODIFY` the effect is the modified one, which `outcome` MUST describe. `DENY`, `ASK` and
`DEFER` are *not admitted*: they record a decision, not an effect, and `outcome.applied` MUST be
`false`. A consumer asking "was this admitted?" reads `disposition` first and `outcome.applied`
second; they MUST agree. Reject: `outcome_mismatch`.

## 5. Schema — witness

```jsonc
"predicateType": "urn:lgd:acs:predicate:agent-change-witness:v1",
"predicate": {
  "change": { "...": "same as admission" },
  "context": { "...": "same session_id/request_id as the admission" },
  "witness": {
    "key_id": "<string>",
    "org": "<string>",
    "control_domain": "<string, required>",
    "role": "peer",
    "key_pin": {
      "registry_uri": "<https uri>",
      "key_fingerprint": "sha256:<hex>",
      "pinned_at": "<RFC3339>"
    }
  },
  "observed_admission": { "sha256": "<digest of the signed admission statement>" },
  "observed_agent": { "agent_id": "<string>", "key_id": "<string>", "control_domain": "<string>" },
  "outcome": { "...": "same effect record as the admission" },
  "outcome_digest": { "sha256": "<hex>" },
  "witnessed_at": "<RFC3339>",
  "witness_scope": "peer"
}
```

`witness.key_pin` is what stops a party from minting a fresh key and calling itself a peer: the
verifier resolves `key_id` in the registry named by `registry_uri` and requires the pinned fingerprint
to match, the pin to predate `witnessed_at`, and the registry entry to declare that the observed party
cannot write it. Without that entry a witness is an unauthenticated assertion, and the statement MUST
NOT earn `peer`.

## 6. Schema — anchor

```jsonc
"predicateType": "urn:lgd:acs:predicate:agent-change-anchor:v1",
"predicate": {
  "anchor": {
    "key_id": "<string>",
    "org": "<string>",
    "pin": {
      "registry_uri": "<https uri>",
      "registry_revision": "<string, the registry version the pin was read at>",
      "pinned_at": "<RFC3339>",
      "key_fingerprint": "sha256:<hex>"
    }
  },
  "independent_of": ["<agent_id or org>"],
  "binds": { "statement_digest": { "sha256": "<digest of the admission statement>" } },
  "anchored_at": "<RFC3339>",
  "witness_scope": "external"
}
```

`independent_of` MUST name the observed agent *and* its Guardian: the threat this layer answers is a
compromised Guardian (see §1 and §9), so independence measured only against the agent tests the wrong
party. `pin.registry_revision` exists so a verifier can distinguish "the key was pinned then" from
"the key is listed now": a registry lookup at verification time alone is a TOCTOU hole.

## 7. Conformance check conditions (normative)

These are the checks a verifier MUST run. Each has a reason code; the machine-readable vectors in
`examples/` plus `check_admission.py` exercise every one of them.

**AC-0 attribution.** Only the role block named by `predicateType` may be present; a statement that
carries a second role block is rejected (`foreign_role_block`). The statement MUST be signed, and the
signature MUST verify under the key named by that block's `key_id` (`unsigned`, `unknown_key`,
`bad_signature`). `predicate.witness_scope` MUST equal the scope implied by the predicate type
(`self`/`peer`/`external`), otherwise `scope_mismatch` — the field is a restatement, never a grant.

**AC-1 subject binding.** `subject[]` MUST contain at least one entry whose `digest` equals
`predicate.change.payload_digest`, and every digest MUST be a 64-hex `sha256` object; a missing or
empty digest object is rejected (`invalid_digest`, `subject_mismatch`). `change.canonicalization`
MUST be `jcs-rfc8785` (`non_canonical_payload`).

**AC-2 outcome binding.** `predicate.outcome` MUST be present as an object, and `outcome_digest`
MUST be recomputed from it by the verifier and MUST NOT equal `payload_digest`. A record that only
restates the proposal is not evidence that anything was admitted. Reject: `outcome_mismatch`.

**AC-3 witness binding and vector uniqueness.** A witness statement MUST carry
`observed_admission.sha256` — the digest defined in §3 — and it MUST equal the digest the verifier
computed over the admission statement it is resolving (`witness_not_bound`). Its
`context.session_id` and `context.request_id` MUST equal the admission's
(`witness_not_bound`). Consumers MUST resolve the association by that digest equality, never by
`subject[]` or `session_id` alone: two admissions in different sessions can share a payload digest,
and a subject-keyed lookup would attach one session's witness to the other.

**AC-4 lift ladder.**
  - `self`: the statement is signed by the admitting party. It earns authenticity and nothing more.
  - `peer`: the witness `key_id` MUST be distinct from the observed agent's key, `control_domain`
    MUST be present and different from the observed party's, and the witness key MUST be registry-
    pinned as in §5. A peer statement **alone** MUST NOT earn EXTERNAL. Reject:
    `witness_control_overlap`, `witness_key_unpinned`.
  - `external`: the anchor key MUST be pinned in a registry the observed party cannot write, MUST
    declare `independent_of` covering the observed agent and its Guardian, and the pin MUST carry a
    fingerprint and a `pinned_at` that precedes `anchored_at`. **A timestamp never confers lift**: a
    trusted timestamp proves *when*, not *who else could have written it*. Reject:
    `anchor_key_unpinned`, `anchor_not_independent`, `timestamp_not_lift`.
  - Lift is **monotone**: the scope reported for a record set is the minimum over its members, and
    dropping evidence can only lower it. This is a property of the computation, not a rejection
    condition — a deployment that publishes only an admission is conformant and simply reaches
    `self`. (Reason code `scope_mismatch` covers the only rejection case: a statement claiming a
    scope its own type does not confer.)

**AC-5 replay and freshness.** The ledger is a map `(session_id, request_id) -> statement digest`.
Both identifiers are mandatory (`invalid_context`). Any reuse of a pair already in the ledger is a
replay, whether the digest matches or not (`replay_detected`); two different statements for one pair
is a duplicate vector (`duplicate_vector`). The ledger's persistence and consensus are
**deployment-defined**: this predicate states the property a verifier needs, not a distributed
algorithm. A verifier with no ledger MUST report `replay_status: unknown` rather than assume
freshness.

**AC-6 policy binding.** `policy.digest` and `policy.version` MUST resolve in an immutable,
digest-addressed store. "Stale" means exactly one thing: the version is not in the verifier's active
set (`policy_stale`). An unresolvable digest is `policy_unresolvable`, a different finding — a
rotated policy does not retroactively invalidate a decision that resolved when it was made.

**AC-7 fail-closed absence.** Absence of a witness or anchor statement means the corresponding scope
is **not** claimed. Consumers MUST NOT synthesize a default scope from absence, MUST NOT infer
`external` from a signature alone, and MUST NOT treat missing verifier inputs (an absent
`admission_statement_digest`, `admission_context`, registry or ledger) as a pass
(`verifier_context_incomplete`). Every check is fail-closed on missing inputs.

## 8. Verification algorithm (informative)

```
verify(statement, ctx):
  ctx = {keys, registry, observed{key_id, control_domain, agent_id, org},
         active_policy_versions, ledger{(sid,rid): digest},
         admission_statement_digest, admission_context}
  parse per in-toto v1; require predicateType in the three family URIs, else unknown_predicate
  role = role implied by predicateType; reject any other role block   (AC-0)
  verify signature under keys[role.key_id]                            (AC-0)
  check AC-1 ... AC-6 in order; collect reason codes (fail-closed)
  scope = self
  if witness present and AC-3/AC-4(peer) pass:  scope = peer
  if anchor  present and AC-4(external) passes: scope = external
  return {admitted: disposition in {ALLOW, MODIFY} and outcome.applied,
          scope, reason_codes, replay_status}
```

## 9. Non-claims

This family does not establish that the policy itself was well designed, that the Guardian was
honest, or that the payload does what its name suggests. It does not make a peer's statement
truthful — it only makes it attributable and bound. It does not replace ACS's signature binding,
and it does not survive a compromised Guardian: a compromised Guardian can sign a false admission
and can also pin a key it controls in a registry it writes — which is why AC-4 requires the registry
entry to record that the observed party cannot write it, and why a verifier that cannot obtain that
record MUST NOT award `external`. Peer lift is as strong as the registry that pins the peer key;
absent a registry, a witness is an assertion by an unknown party and the ladder stops at `self`.
The ledger assumptions in AC-5 are not solved here: a single deployer's ledger detects replay inside
that deployment, not across deployments.

## 10. Examples

See `examples/` (regenerated by `python3 check_admission.py --emit-examples`):
- `admission-self.json` — ALLOW of a `tool_register`, with a recomputable outcome record
- `witness-peer.json` — peer statement with a registry-pinned key, binding the admission statement digest
- `anchor-external.json` — anchor pinned before it anchored, independent of both agent and Guardian
- `negative/*.json` — one file per rejection reason code (N1–N20)

## 11. Changelog

- v1.1 (this revision), after three external model reviews (DeepSeek-V3.2, GLM-5.3 via SiliconFlow):
  added AC-0 role binding (a witness statement could previously be verified with the Guardian's key
  by carrying a `guardian` block); made the statement digest normative; required registry pinning of
  witness keys (a peer could previously self-grant by minting a key and a domain string); required a
  recomputable outcome record; made every check fail-closed on missing verifier context; unified the
  ledger schema (the earlier draft's two shapes made `duplicate_vector` unreachable in one path and
  crash in the other); restated `scope_downgrade` as monotonicity; defined disposition semantics and
  `policy_unresolvable`; removed the reference to an internal `VERIFIABILITY-OVERVIEW.md` that no
  upstream repository contains.
- v1 (draft): initial family, split from a single predicate after the review objection that one
  boolean cannot attribute a lift to a key.
