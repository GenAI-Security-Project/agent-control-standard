# Crosswalk: suite cases to the ACS requirement ledger

This maps every case in this suite to the draft normative-requirement ledger being built for ACS issue [#33](https://github.com/GenAI-Security-Project/agent-control-standard/issues/33). The ledger is the place where ACS gives each MUST a stable ID. This suite does not mint its own IDs; it cites the ledger's.

**Source of the IDs.** `conformance/ledger/requirement-ledger.csv` on `Johnbjoseph-cybersec/agent-control-standard`, branch `docs/requirement-ledger` at `ac9388ca0d24` (2026-11-03), built against ACS `integration` at `bba1b84`. The ledger is a draft and unmerged, and its README says IDs may move to section anchors. When it merges, this file is re-pinned to the merged IDs.

**How to read the Relation column.** *Tests* means the case falsifies that requirement directly: a Guardian that violates it fails the case. *Related* means the case exercises the requirement's behaviour under a stated configuration, and does not by itself prove conformance to it. *None* means the case tests a guarantee the v0.1.0 text does not state as a MUST.

## Layer A: protocol (`run_conformance.py`)

| Suite check | Ledger IDs | Relation | Note |
|---|---|---|---|
| handshake returns a schema-valid ServerHello | (schema) | Tests the schema | Validated against the v0.1.0 `$defs`; the ledger has no row for ServerHello required fields, because they are set by the schema, not a sentence |
| `system/ping` answers | ACS-SPECIFICATIO-060, -064 | Tests, if implemented | 060: Guardians MUST always return `allow` for ping. `conformance.md` makes implementing ping SHOULD, with a declared alternative. The suite reports a non-answer as an open observation until the project settles which governs |
| `toolCallRequest` returns a schema-valid AcsResult | ACS-CONFORMANCE-003 | Tests, for the dispositions returned | Required fields per §6 for each disposition the Guardian returns |
| undeclared method is refused | (JSON-RPC 2.0) | Tests JSON-RPC | No ACS ledger row; JSON-RPC requires an error for an unknown method |
| §10 valid HMAC-SHA256 signature accepted | ACS-SPECIFICATIO-045, -046 | Tests | Key derivation reproduces the specification's §10 test vector |
| §10 tampered request rejected | ACS-SPECIFICATIO-050 | Tests | `SIGNATURE_INVALID` (-32004) |
| §10.3 out-of-window timestamp rejected | ACS-SPECIFICATIO-052, -053 | Tests | `TIMESTAMP_OUT_OF_WINDOW` (-32006); the ledger notes 052 and 053 are one requirement split across a sentence |
| §10.3 replayed `request_id` rejected | ACS-CONFORMANCE-005, ACS-SPECIFICATIO-053 | Tests | `REPLAY_DETECTED` (-32005) |

Not yet covered here, and in the ledger: ACS-SPECIFICATIO-048 (unknown `key_id` rejected without fallback), -061 (ping not written into SessionContext), -062 (ping needs no signature), -002 (batch rejection), -003 (unknown fields ignored). Each is a candidate vector.

## Layer B and the T1 to T10 matrix (`run_conformance.py`, `matrix.py`)

| Suite cases | Ledger IDs | Relation | Note |
|---|---|---|---|
| Layer B race, lost-ack continue, lost-ack retry | none | None | Cumulative-grant enforcement across operations is not a v0.1.0 MUST. These cases come from the AIMM Pillar 2 §5.1 delegated-authority discussion |
| T1, T2, T6, T7 (limit cut, overrun flag, revocation) | none | None | Same: grant-level accounting the spec does not require |
| T3, T5, T8, T10 (lost ack, resend, partial fill, late commit) | ACS-HOOKS-002 | Related | HOOKS-002 asks a Guardian to record a result it cannot resolve to a request. These cases go further and reconcile the result against the resource's own record |
| T4a, T4b (definition digest drift) | none | None | v0.1.0 `toolCallRequest` carries no definition digest. The suite delivers it out of band |
| T9 (behaviour change, digest unchanged) | none | None | Expected miss by construction; records the ceiling of any digest check |

## Pre-forward mode (`preforward.py`, see PREFORWARD.md)

| Suite cases | Ledger IDs | Relation | Note |
|---|---|---|---|
| P2, P2r (held for reauthorization via `ask`) | ACS-CONFORMANCE-003 | Related | ASK must carry its required fields. The cases test that nothing is forwarded while held |
| P5, P6 (no basis presented, reused attempt) | none | None | Pilot-specific basis channel, not a v0.1.0 field |
| P7 to P10 (unreachable, slow, wrong `request_id`, malformed `allow`) | ACS-SPECIFICATIO-012, -013, -014 | Related, under `on_decision_failure: deny` | §6.4 makes the default posture `proceed` (fail-open). These cases test a gateway configured fail-closed; under the default posture the same events would proceed and only the audit-event requirement (013) would apply |
| P3, P3b (declaration-bound, resource readback) | none | None | The authorized-action versus observed-effect correspondence case proposed in #33 is the closest match |
| P11 (ACK while HELD, dispatch-report mode) | none | None | A finding about one R1 mapping, kept as a regression case |

## What the crosswalk shows

Of the eight Layer A checks, six test a ledger requirement directly, and two test the schema or JSON-RPC beneath it. None of the grant-accounting, reconciliation or pre-forward cases maps to a v0.1.0 MUST. Those cases measure guarantees a buyer may need and the current text does not require, so a Guardian can be ACS-Core conformant and still fail them. That reflects the scope of v0.1.0.
