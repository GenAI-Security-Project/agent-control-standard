# ACS conformance claim

One page. Copy it once per implementation, fill every cell, publish the filled copy where a
reader can fetch it unchanged.

## 1. Claim header

| Field | Value |
|---|---|
| Implementation under test | `<name and version>` |
| Specification version claimed against | `<tag>` at `<full commit SHA>` |
| Date of claim | `<date>` |
| Claimant | `<organisation or individual>` |
| Published at | `<URL that resolves to fixed bytes>` |
| SHA-256 of this filled copy | `<digest>` and `<filename it belongs to>` |

Pin the specification by tag and full commit SHA. A tag can move, and `version.txt` has
disagreed with the latest tag before (`Issue #143`). A full SHA is computed from the bytes and
cannot name anything else.

## 2. Trust topology

| Field | Value |
|---|---|
| Who operates the Observed Agent | `<party>` |
| Who operates the Guardian | `<party>` |
| Same party operates both | `<yes / no>` |
| If no, which profile carries integrity beyond the shared secret | `<acs-crypto / acs-audit / none, and why>` |

This block is not optional and it is not a formality. ACS-Core's baseline integrity is
HMAC-SHA256, which is symmetric, so the boundary it establishes holds only for agents the
deployment itself hosts. Two deployments can fill the rest of this page identically and
truthfully while one governs agents it hosts and the other governs a customer's agents behind an
independently operated Guardian. The second is making a much weaker claim. Without this block
the page does not show it.

## 3. Profile matrix

One row per profile, one column per role. The unit is the profile times the role, not the
deployment: `profiles_supported` is declared by the Observed Agent in ClientHello and
`profiles_accepted` by the Guardian in ServerHello, so a profile active at one end and not
claimed at the other is a normal outcome of per-session negotiation, not an inconsistency.

Every cell carries a state token and, where the state is not `EXERCISED`, a reason code from
section 4. **A blank cell is not a claim of any kind and voids the row.**

| Profile | Observed Agent (`profiles_supported`) | Guardian (`profiles_accepted`) |
|---|---|---|
| `acs-core` | | |
| `acs-trace` | | |
| `acs-inspect` | | |
| `acs-inspect-dynamic` | | |
| `acs-provenance` | | |
| `acs-crypto` | | |
| `acs-audit` | | |

**States.**

`EXERCISED` the profile is declared and something in the deployment demonstrates it.
`NOT CLAIMED` deliberately not declared. Carries a reason code.
`NOT ESTABLISHED` the claimant cannot say either way from what they have. Carries a reason code.

The third state is the one that disappears when a form offers a checkbox, because an unticked
box reads as the second. A reader who cannot separate a deliberate non-claim from an unmeasured
one sees a clean sheet in both cases.

## 4. Reason codes

Closed vocabulary. One code per non-exercised cell, no free text in the matrix. Free text turns
a one-pager into prose; no reason at all turns it back into a checkbox. A closed list is also
what lets two claims be compared later, which is the property a registry would need.

For `NOT CLAIMED`:

| Code | Meaning |
|---|---|
| `not-implemented` | The methods are not implemented. |
| `not-offered` | The product does not offer this profile. |
| `governed-elsewhere` | The control is provided outside this deployment. |
| `out-of-scope` | Deliberately outside the scope of this claim. |

For `NOT ESTABLISHED`:

| Code | Meaning |
|---|---|
| `no-test` | No test in this run covers it. |
| `no-sink` | The required sink or recorder is not installed. |
| `not-negotiated` | The peer never negotiated the profile in any observed session. |
| `not-observed` | The path exists but no traffic was seen traversing it. |

Anything that does not fit a code above is `NOT ESTABLISHED` plus a note in section 6, not a new
code invented on the page.

## 5. ACS-Core decision posture

Required whenever `acs-core` is `EXERCISED`. ACS-Core mandates decision honoring, and its
defaults are permissive, so a claim that omits this reports the default posture as evidence of
enforcement.

| Field | Value |
|---|---|
| `on_decision_failure` posture as configured (§6.4) | `<proceed / block>` |
| Startup posture on handshake failure (§4.1) | `<proceed / block>` |
| Sessions observed in this run | `<n>` |
| Steps that proceeded without a decision | `<n>` |
| Sessions started unguarded after handshake failure | `<n>` |
| Where the fail-open audit events were recorded | `<Guardian audit / deployment audit log / not recorded>` |

An action permitted by policy and an action permitted because no decision happened are
indistinguishable on the wire and both look like conformance. Section 6.4 requires every step
that proceeds without a decision to be recorded as an audit event. A session started unguarded
has no Guardian to receive that event and belongs in the deployment's own log. `Issue #37`
tracks the absence of a conformant shape for that MUST, so until it resolves, say here what was
recorded and where.

## 6. Limits of this claim

State what the claim does not cover, in the claimant's own words. At minimum, any cell marked
`NOT ESTABLISHED`, and whether the environment in which the run happened still exists.

`<free text>`

## 7. What this page is

Quoted from `docs/spec/conformance.md` so that it travels with the claim:

> What "ACS-Core conformant" guarantees: the channel is authenticated and the Observed Agent
> honors the Guardian's decisions. It does NOT assert that a deployment's policies are strict,
> nor that the audit chain is tamper-evident against a compromised Guardian (that is the
> ACS-Crypto and ACS-Audit profiles, since the HMAC baseline is symmetric). A permissive Guardian
> is a conformant but permissive deployment, not a violation.

> Who verifies a conformance claim: nobody, in v0.1.0. `profiles_supported` and
> `profiles_accepted` are self-declaration on the wire. This release ships no conformance test
> suite, no registry of conformant implementations, and no steward body to arbitrate a disputed
> claim.

This page records what an implementer asserts about itself. A claim form that does not repeat
that limit inside itself will be quoted without it.
