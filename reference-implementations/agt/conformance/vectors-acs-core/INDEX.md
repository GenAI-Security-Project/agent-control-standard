# Conformance vectors (ACS-Core negative suite)

Every member of this suite in one table, rejected and accepted alike.
Ground truth: the four normative files vendored in `spec-vendored/`, read at
`9d4a9da` of `GenAI-Security-Project/agent-control-standard`, each pinned by sha256 in
`MANIFEST.json`.

This corpus is 43 vectors, of which 15 a conformant verifier must
not fail closed on and 26 it must reject.

**No implementation has been run against this corpus.** There is no reference
adapter in the specification's repository at the pinned commit, and the two
pull requests that carried one are closed. So the suite ships with a self-check
and with no observed results, and the count above describes inputs with
declared expectations rather than anything measured. A table quoting it carries
that sentence.

**Identifiers are minted here and bound to a sentence, not to a section.** The
specification carries no requirement identifiers at the pinned commit, so a
vector citing a section number would survive a reword and silently mean
something else afterwards. Each row below quotes its normative sentence, the
generator locates that sentence in the vendored copy and hashes it, and a
reword stops the build rather than re-pointing every vector that cites it. The
line number is derived from the sentence and never typed.

**A verdict is asserted as a code, never as prose.** Two conformant
implementations word one refusal differently and a wrong one can word the right
cause while doing something else, so a member names a value from the fixed
error registry or names none at all.

**There are three verdicts.** A member whose property the specification cannot
express is `unmeasurable`, with the reason recorded. Folding those into
rejections would credit an implementation for behaviour nothing requires;
folding them into passes would hide the gap. 2 members carry that verdict
today.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-acs-core/` from the repository root.

## Requirements

| id | role | located at | sentence digest | normative sentence |
|---|---|---|---|---|
| `ACS-R-001` | verifier | `spec-vendored/specification-9d4a9da.md:295` | `ae415912eb16d0f9` | A verifier MUST recompute this canonical form and MUST reject a signature that does not cover it |
| `ACS-R-002` | guardian | `spec-vendored/specification-9d4a9da.md:322` | `15fcfd8b83334478` | MUST reject duplicate `request_id` values within the session with `REPLAY_DETECTED` |
| `ACS-R-003` | guardian | `spec-vendored/specification-9d4a9da.md:322` | `201aa2b8deec1b75` | Guardians MUST reject requests whose `timestamp` is more than the negotiated skew window |
| `ACS-R-004` | agent | `spec-vendored/specification-9d4a9da.md:157` | `18ef98e15043e772` | the Observed Agent MUST wait for the Guardian's decision, up to the negotiated timeout |
| `ACS-R-005` | agent | `spec-vendored/specification-9d4a9da.md:161` | `3a4c8fe649568d25` | Every step that proceeds without a decision MUST be recorded as an audit event |
| `ACS-R-006` | guardian | `spec-vendored/specification-9d4a9da.md:254` | `b1eca2d8a8ecba83` | the Guardian MUST include the resulting `chain_hash` in its response, and that `chain_hash` MUST be covered by the response signature |
| `ACS-R-007` | framework | `spec-vendored/specification-9d4a9da.md:244` | `7d06dbc863970fa7` | any attempt to modify `Intent.parsed` by the runtime LLM, by tool outputs, or by data crossing an `untrusted` channel MUST be ignored or rejected |
| `ACS-R-008` | framework | `spec-vendored/specification-9d4a9da.md:188` | `b5f8a7cb7475420a` | the framework MUST compute `trust` as the minimum trust of the entries in `derived_from` (monotonicity rule) |
| `ACS-R-009` | framework | `spec-vendored/specification-9d4a9da.md:189` | `08cd153f9816254e` | Receivers (especially across A2A or multi-Guardian boundaries) MUST treat the field as a hint and re-derive trust against local policy |
| `ACS-R-010` | framework | `spec-vendored/specification-9d4a9da.md:205` | `51168a2c9d2a6a83` | Provenance MUST be populated by deterministic code outside the LLM's output path. Implementations MUST NOT instruct the LLM to produce it. |
| `ACS-R-011` | guardian | `spec-vendored/specification-9d4a9da.md:262` | `2afe3fa652ea6bdd` | Approver authentication is REQUIRED. Guardian MUST verify approver identity against policy. |
| `ACS-R-012` | approver | `spec-vendored/specification-9d4a9da.md:264` | `b5136cfe508f1527` | Approvers MUST NOT return ASK. |
| `ACS-R-013` | guardian | `spec-vendored/specification-9d4a9da.md:276` | `c44bb0990be0c25e` | a Guardian operating under `scope_mode: strict` MUST NOT honor extensions that would add capabilities the deployment policy forbids in strict mode |
| `ACS-R-014` | framework | `spec-vendored/hooks-9d4a9da.md:172` | `8324ae363f284044` | Frameworks MUST fire `toolCallRequest` for every action that escapes the agent's reasoning context |
| `ACS-R-015` | deployment | `spec-vendored/trace-events-9d4a9da.md:72` | `fb05a87d8696121a` | Trace events MUST NOT block enforcement |
| `ACS-R-016` | deployment | `spec-vendored/conformance-9d4a9da.md:75` | `407ddbcabf898311` | A deployment claiming ACS-Audit MUST populate `request_hash` |
| `ACS-R-017` | guardian | `spec-vendored/specification-9d4a9da.md:71` | `802968dc8adb1d91` | Version mismatch terminates with `UNSUPPORTED_VERSION` |
| `ACS-R-018` | guardian | `spec-vendored/specification-9d4a9da.md:282` | `e141df498745672d` | When the Guardian determines that the client cannot resolve `ASK`, the Guardian MUST NOT return `ASK` |
| `ACS-R-019` | guardian | `spec-vendored/specification-9d4a9da.md:57` | `d045577eea0fab7a` | Accept `X.Y.Z` matching major version |
| `ACS-R-020` | guardian | `spec-vendored/specification-9d4a9da.md:293` | `4aba06b38783dc57` | canonical input is REQUIRED in ACS-Core |
| `ACS-R-021` | verifier | `spec-vendored/specification-9d4a9da.md:258` | `4c97a8c91e35a161` | Non-repudiation, proving to a third party that a specific Guardian issued a specific head, requires the asymmetric ACS-Crypto profile |
| `ACS-R-022` | verifier | `spec-vendored/specification-9d4a9da.md:428` | `2d0f1473abc9de5c` | A required signature is missing, malformed, or fails verification |

## Families

| id | what the family is |
|---|---|
| `acs-f-1` | correctly signed and outside the granted mandate |
| `acs-f-2` | a consumed authorization presented a second time |
| `acs-f-3` | valid at issuance and invalid at execution time |
| `acs-f-4` | an approval valid for one agent or tool presented for another |
| `acs-f-5` | structurally broken evidence with a consumer that proceeds |
| `acs-f-6` | an action whose observability references were removed |
| `acs-f-7` | steps in mandate individually and out of mandate in aggregate |
| `acs-f-8` | attributed content standing in for an authorization |
| `acs-f-9` | a handshake or a disposition answered outside the negotiated contract |
| `acs-f-10` | a Guardian response signed by a party other than the Guardian |

## Deliberately out of scope

An open pull request is moving these surfaces. A vector written against one
now is a vector rewritten when it lands.

| surface | why |
|---|---|
| the MODIFY disposition and its composition rules | an open pull request moves MODIFY support out of the mandatory profile and adds a new section for the declaration, and neither the new section nor the declaration field exists at the pinned commit |
| the liveness ping method | the same pull request moves it out of the mandatory profile |
| the second half of the subagent hook pair | split out of the mandatory set by a later push on the same pull request |
| the wrapped tool-protocol methods | the same pull request has moved these twice and they currently sit back at mandatory for sessions that use them, so their status is unsettled rather than relaxed |

## Waiting for a sentence

Cases raised on the specification's tracker that no sentence at the pinned
commit says. A member written now would cite a requirement that does not say
what it tests, so each waits for its sentence and is minted from it.

| case | why it waits |
|---|---|
| a session that began and was never sealed | the pinned text has no sentence requiring a party other than the Observed Agent to record that a session began, so a begun session with no seal leaves nothing a member could cite. Wording is proposed on GenAI-Security-Project/agent-control-standard#37. Once it lands, the member expects a counted decision failure, never unmeasurable, because a begun and unsealed session is countable |
| an argument textually inside a scoped mandate that resolves outside it | a dot-dot segment, a symlink, an encoded traversal or an unnormalised egress hostname passes a raw prefix check and resolves out of scope. The pinned text fixes the URI form of a resource identifier and says nothing about checking its resolved form against a mandate. Raised on GenAI-Security-Project/agent-control-standard#29, where a Guardian unable to resolve the argument is proposed as unmeasurable rather than allow |

## Vectors

| id | kind | family | requirements | verdict | code | basis | witness scope |
|---|---|---|---|---|---|---|---|
| `v0577dc8ccd4d7e47` | accept | acs-f-1 | ACS-R-020 | allow | none | substrate | PEER |
| `v07180a3ca8f10123` | accept | acs-f-8 | ACS-R-007 | allow | none | substrate | SELF |
| `v0c6dcb9ff13af3c9` | reject | acs-f-6 | ACS-R-014 | deny | none | substrate | SELF |
| `v100f74962fbb8b94` | reject | acs-f-4 | ACS-R-011 | deny | `CAPABILITY_NOT_NEGOTIATED` | substrate | PEER |
| `v10351021bf6e46b1` | reject | acs-f-7 | ACS-R-009 | deny | `CAPABILITY_NOT_NEGOTIATED` | substrate | SELF |
| `v221edeb22c4e8634` | reject | acs-f-6 | ACS-R-006, ACS-R-021 | deny | `CHAIN_MISMATCH` | artifact | EXTERNAL |
| `v25f01d8fe1e91bf5` | accept | acs-f-8 | ACS-R-006 | allow | none | artifact | PEER |
| `v3232493ab40ae031` | reject | acs-f-10 | ACS-R-021 | deny | none | artifact | EXTERNAL |
| `v3c03d4e4ce213e9c` | accept | acs-f-6 | ACS-R-016 | allow | none | artifact | PEER |
| `v3e946bcfde26bbe2` | accept | acs-f-2 | ACS-R-002 | allow | none | substrate | SELF |
| `v412653087b92cb07` | reject | acs-f-9 | ACS-R-017 | deny | `UNSUPPORTED_VERSION` | substrate | PEER |
| `v448a61c91554a125` | reject | acs-f-7 | ACS-R-013 | deny | `CAPABILITY_NOT_NEGOTIATED` | substrate | SELF |
| `v4f75a079844635af` | accept | acs-f-6 | ACS-R-006, ACS-R-021 | allow | none | artifact | EXTERNAL |
| `v53ef0aaa91303587` | accept | acs-f-10 | ACS-R-022, ACS-R-021 | allow | none | artifact | EXTERNAL |
| `v661266c5c87cb206` | reject | acs-f-1 | ACS-R-013 | deny | `CAPABILITY_NOT_NEGOTIATED` | substrate | SELF |
| `v699f3f41215849ca` | accept | acs-f-7 | ACS-R-013 | allow | none | substrate | SELF |
| `v6daaec0f6f0c8a14` | accept | acs-f-6 | ACS-R-006, ACS-R-021 | allow | none | artifact | PEER |
| `v78927805373a6c06` | accept | acs-f-9 | ACS-R-017 | allow | none | substrate | PEER |
| `v7b0b32fb369136c1` | reject | acs-f-8 | ACS-R-006 | deny | `CHAIN_MISMATCH` | artifact | PEER |
| `v82b6d110b4d68e7c` | indeterminate | acs-f-3 | ACS-R-003 | unmeasurable | none | artifact | EXTERNAL |
| `v8557c978bf12ca55` | reject | acs-f-6 | ACS-R-016 | deny | `CHAIN_MISMATCH` | artifact | PEER |
| `v855c3b68b325eec1` | accept | acs-f-10 | ACS-R-021 | allow | none | artifact | PEER |
| `v986429a577e03404` | reject | acs-f-6 | ACS-R-006, ACS-R-021 | deny | `CHAIN_MISMATCH` | artifact | PEER |
| `v9f011986566cb7bc` | indeterminate | acs-f-10 | ACS-R-022, ACS-R-021 | unmeasurable | none | artifact | SELF |
| `va00ef569d09bf7d5` | reject | acs-f-6 | ACS-R-015 | deny | none | substrate | SELF |
| `va0ee5d0830b0490b` | accept | acs-f-5 | ACS-R-005 | allow | none | substrate | SELF |
| `va200b64093301e14` | reject | acs-f-9 | ACS-R-018 | deny | none | substrate | SELF |
| `va2fea96983583972` | reject | acs-f-8 | ACS-R-010 | deny | `PROVENANCE_REQUIRED` | substrate | SELF |
| `va6d6e952d417c5a1` | accept | acs-f-3 | ACS-R-003 | allow | none | substrate | SELF |
| `va8eebd3334b97257` | reject | acs-f-5 | ACS-R-004 | deny | `SIGNATURE_INVALID` | substrate | SELF |
| `vae2037ee96435463` | reject | acs-f-9 | ACS-R-019 | deny | none | substrate | PEER |
| `vb10df32610db1173` | reject | acs-f-3 | ACS-R-003 | deny | `TIMESTAMP_OUT_OF_WINDOW` | substrate | SELF |
| `vb87b86b4930665ca` | reject | acs-f-1 | ACS-R-001 | deny | `SIGNATURE_INVALID` | substrate | PEER |
| `vc333473269d1b3a9` | reject | acs-f-8 | ACS-R-007 | deny | none | substrate | SELF |
| `vd57793caa251dec6` | reject | acs-f-8 | ACS-R-008 | deny | none | substrate | SELF |
| `vd67cd207a4eb6798` | reject | acs-f-1 | ACS-R-001 | deny | `SIGNATURE_INVALID` | substrate | PEER |
| `vd8ac84523a5a038c` | reject | acs-f-10 | ACS-R-022, ACS-R-021 | deny | `SIGNATURE_INVALID` | artifact | EXTERNAL |
| `vef655ce2a45f618b` | reject | acs-f-2 | ACS-R-002 | deny | `REPLAY_DETECTED` | substrate | SELF |
| `vf3679e6ac60fd250` | accept | acs-f-1 | ACS-R-013 | allow | none | substrate | SELF |
| `vf80a81054d3f0862` | reject | acs-f-1 | ACS-R-020 | deny | `SIGNATURE_INVALID` | substrate | PEER |
| `vfcab242ddb38d018` | reject | acs-f-4 | ACS-R-012 | deny | `CAPABILITY_NOT_NEGOTIATED` | substrate | PEER |
| `vfdd68340c2094962` | reject | acs-f-5 | ACS-R-005 | deny | none | substrate | SELF |
| `vff6b4d46f470f2ad` | accept | acs-f-4 | ACS-R-011 | allow | none | substrate | PEER |
