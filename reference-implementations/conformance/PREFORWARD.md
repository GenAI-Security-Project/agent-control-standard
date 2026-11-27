# T4 pilot: pre-forward R1

The Guardian-side answer to the R1 transport blocker in the joint T4 pilot (ARC × Guardian × ERP), made executable. Contract: Test Contract V0.3, [boris-ai-sec/ai-security-lab @ 6154918](https://github.com/boris-ai-sec/ai-security-lab/blob/6154918bc62dd497263f619a8cb6496082ac83f3/labs/aimm-p2-executable-evidence/TEST_CONTRACT_V0.3.md). Discussion: [ARC #117](https://github.com/suirindo/agent-role-contracts/issues/117).

**Scope, first.** Everything here runs against models: the suite's `reconciling` mock Guardian (one executable reading of AIMM Pillar 2 §5.1, not a production Guardian and not the AGT reference implementation), a reference gateway written for this suite (not the lab's gateway), and an in-memory ledger (not PostgreSQL). It shows that the pre-forward mapping can be represented honestly and that it behaves as specified. It does not show that the lab's gateway or ERP behave this way. That is what the pilot itself measures.

## The problem it answers

In the T1–T10 matrix, R1 runs when the runner reports `dispatched` on a `steps/toolCallResult`. The reply to that report is `allow / result recorded` even when the reservation has just gone HELD. That reply is an acknowledgement, not a permit, and sending `dispatched` before anything is sent would be the fabricated event V0.3 §5 prohibits. t-iida found this by reading the source; case P11 below reproduces it by measurement.

## The mapping

R1 moves onto `steps/toolCallRequest`, the ACS hook a Guardian answers before a tool runs.

1. **A1.** The gateway sends a `steps/toolCallRequest` for `demo_erp_create_order` with `{quantity: 40, resource_id: COMP-17, supplier_id: SUP-A}`. Its orchestration identity rides in `params.metadata.x_pilot_orchestration` as `{grant_id, operation_id, attempt_id, stage: "admission"}`, outside the tool arguments, as V0.3 §3 asks. The Guardian reserves Q = 40 and records the A1 digest. An admission `allow` is not a forward permit.
2. **Mutation.** The fixture controller activates D1.
3. **R1.** Immediately before any send, the gateway measures the active definition object once, hashes it (RFC 8785 JCS, SHA-256, lower hex), presents the digest and the V0.3 §3 provenance record out of band (`control/presentBasis`, keyed by operation_id and attempt_id), then sends a fresh `steps/toolCallRequest` with a new attempt_id and `stage: "pre_forward"`.
4. **Decision.** The Guardian answers that request under one lock, in the same call that changes reservation state, so the gateway never has to poll state:

   | Situation | Reply |
   |---|---|
   | digest matches A1 | `allow`, `r1_permit` |
   | digest differs, enforced (C2) | `ask`, `basis_reauth_required`, with `ask_details` and `timeout_disposition: "deny"`. This is the documented mapping for HELD. `defer` does not fit, since its schema means the Guardian could not reach a verdict |
   | digest differs, recorded-only (T4b, extra) | `allow`, `basis_mismatch` flagged |
   | declaration-bound policy (C3) | `allow`, no digest comparison |
   | no basis presented for this attempt | `deny`, `basis_not_presented` |
   | attempt_id already used | `deny`, `attempt_replayed` |
   | operation unknown, or not in a forwardable state | `deny` |

5. **Gateway.** It forwards only on a schema-valid `allow` whose `request_id` matches the R1 request. `ask`, `deny`, `defer`, a transport error, a timeout, a schema-invalid reply or a mismatched request_id all mean no forward. The forwarded quantity is computed from the same measured object whose digest was presented, so a definition change after R1 cannot alter this forward.
6. **After execution only.** A schema-valid `steps/toolCallResult` with `request_id_ref` set to the R1 request. After a 409 or a lost response the gateway reports `unresolved`, reads the ledger back, and reconciles from the readback, never from the HTTP status.

The T1–T10 matrix is unchanged: `r1_mode` defaults to `dispatch_report`, and the pilot sets `pre_forward` per grant.

## Results (`python3 preforward.py`, re-derived by `python3 verify.py`)

| Case | V0.3 | Measures | Verdict |
|---|---|---|---|
| P0 | C0 | D0 at A1 and R1, enforced: allow, forward 40 | PASS |
| P2 | C2 | D1 at R1, enforced: `ask` (HELD) before any send, nothing forwarded, ledger 0 | PASS |
| P2r | C2 drill | after HELD, a fresh attempt_id for the same operation: deny `reservation_held`, still nothing forwarded | PASS |
| P3 | C3 | declaration-bound: allow, forward 120 while the Guardian books Q = 40 against L = 100 | EXPECTED-MISS |
| P3b | C3 drill | the ledger persists 120, then answers 409; readback shows the 120 the status hid | EXPECTED-MISS |
| P4 | T4b (extra) | recorded-only: allow, `basis_mismatch` flagged, forward 120 | PASS |
| P5 | fail-closed | no basis presented for the R1 attempt: deny | PASS |
| P6 | fail-closed | R1 reuses the A1 attempt_id: deny | PASS |
| P7 | fail-closed | Guardian unreachable: no forward | PASS |
| P8 | fail-closed | Guardian slower than the gateway timeout: no forward | PASS |
| P9 | fail-closed | `allow` for a different request_id: no forward | PASS |
| P10 | fail-closed | schema-invalid `allow`: no forward | PASS |
| P11 | finding | dispatch_report mode: the R1-triggering result report is ACKed `allow` while the reservation is HELD | FINDING-REPRODUCED |

Both V0.3 digests reproduce from the suite's own JCS: D0 `679a28ff…f52060`, D1 `25fa0f7b…87c0b6`, 446 canonical bytes each. `verify.py` re-derives them with an independent serializer.

**Verification.** `verify.py` re-derives every verdict above from `results/preforward_transcript.jsonl` with its own scorer, including a rule that any forward must follow an `allow` for the same attempt. Changing P2's reply to `allow`, injecting a forward into P5, or altering D1's canonical bytes each makes it report NOT VERIFIED. `tools/schema_check.py` validates every recorded request envelope, hook payload and Guardian reply against the official v0.1.0 schemas (agent-control-standard `integration` @ db457a8) with a JSON Schema validator: 70/70 valid. P9 and P10's replies are deliberately malformed and excluded. Planting a missing `exit_status` or a missing `ask_details` makes it fail.

## Limits, stated rather than solved

- **The digest channel is test instrumentation.** `control/presentBasis` is not ACS v0.1.0 wire authorization. Its correlation key is operation_id plus attempt_id, recorded in the evidence.
- **R1 source is `contract_fixture_current`.** The active fixture object is measured directly. No MCP `tools/list` fetch happens, so this says nothing about client freshness or caching (Paolo Costanzo's boundary). `fresh_tools_list` and `cached_approved_copy` stay out of scope, as V0.3 §4 states.
- **TOCTOU (time of check to time of use).** Inside the Guardian, the check and the state change are atomic. Between the Guardian's `allow` and the physical POST, the gateway binds the forward to the measured object, which closes the gap for the forwarded quantity. A change on a real server after R1 is not closed by this design.
- **No real network forward or ERP.** "No forward" here means the reference gateway made no ledger call. The pilot must show the same with the lab gateway's outbound records and an independent PostgreSQL read after K1.
- **No re-approval path.** A HELD operation stays HELD: a fresh attempt is refused (P2r). Re-approval after HELD, the `ask` being answered, is not modelled.

## Run

```
python3 preforward.py
python3 verify.py
uv run --no-project --with jsonschema --with referencing --with rfc3339-validator \
  python tools/schema_check.py <agent-control-standard>/specification/v0.1.0 results/preforward_transcript.jsonl
```
