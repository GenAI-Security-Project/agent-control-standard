# The T1–T10 reconciliation matrix, made executable

*The OWASP GenAI Security Project's delegated-authority discussion produced a set of reconciliation test cases: the 3×40 cumulative-grant race and its lost-ack, revocation, limit-change, basis-drift, partial-fulfilment, and behaviour-drift variants. They exist as prose. This runs them, and measures each from an independent ledger.*

**Suite:** `matrix.py` · **Guardian:** `mock_guardians/reconciling.py` · **Verifier:** `verify.py` · **Target contract:** ACS v0.1.0 Guardian wire (JSON-RPC 2.0 over HTTP).

**Status.** §5.1 (AIMM Pillar 2) was marked **Approved** in November 2026. The delegated-authority points this suite exercises are in the final L4 model: shared quantitative authority across concurrent operations and retries, the operation/attempt split, unresolved effects requiring authoritative reconciliation, and the commitment boundary. Per the workstream lead, this repository is the executable reference point for those cases. The suite now runs as executable tests against the stable model rather than as input to the normative text: a case that exposes a real contradiction or a missing invariant is something concrete to bring back, not a reason to reopen the section.

## The model, and whose it is

The reconciling Guardian encodes the design the thread converged on:

- the **operation / attempt split** and **holding the reservation on a lost acknowledgement** ([Boris Abuzov](https://github.com/boris-ai-sec)),
- the **lost-ack boundary** and **stop-or-reauthorize** on a changed basis (t-iida),
- **ordered admission** of concurrent requests (Sol_ni_shko),
- the **authority-basis drift** scenario: a tool redefined under an unchanged name, and content-addressed **digests** (Paolo Costanzo).

That model is theirs. The encoding here is Noctis's own, and it may differ from what any of them intended; the point of making it executable is that a difference now shows up as a failing assertion instead of a disagreement in prose. Corrections to the encoding are welcome.

## How it is measured

Ground truth is an independent **ERP ledger** the runner keeps, never the Guardian's own books. Two deliberate choices:

- The ERP is **idempotent on `operation_id`**: Paolo's setup passes `operation_id` as the ERP idempotency key. So a double dispatch commits once. The test of a Guardian is then whether its *authority accounting* stays consistent with that reconciled truth. (This differs from the base Layer B ledger, which has no idempotency backstop; there the Guardian must prevent the double-spend itself. The two ledgers model two different questions.)
- A **well-behaved agent** drives the wire: it honours each verdict, and after a policy change it consults the Guardian's reservation state before dispatching, dispatching only what the Guardian still holds.
- Limit changes, revocation, and basis drift are injected through out-of-band `control/*` methods rather than ACS wire hooks. They model the authorization-state changes a Guardian receives from policy, not from agent traffic; the admission and reconciliation decisions themselves run over the ACS wire (`steps/toolCallRequest`, `steps/toolCallResult`).
- v0.1.0 has no field for a reconciliation status (committed, non_effect, unresolved, partial, or a stage report). Each `steps/toolCallResult` carries the schema's required `tool`, `exit_status` and `outputs`, maps the status to the nearest `exit_status` (a stage report maps to `success`, meaning the stage was reached), and carries the status itself in `outputs[0].value` and as harness fields beside them. Up to and including commit 8ea942f, result payloads omitted the required fields; the AGT reference Guardian rejected them as `envelope_invalid`, which is how this was found. `verify.py` now re-checks every recorded result payload against the required fields.

Each case is scored on the **one property it isolates**, not a single notion of pass/fail, because the cases isolate different things.

## The eleven cases

Measured by `matrix.py`, re-derived from the transcript by `verify.py`. `reconciling` is the model above; `naive` is a foil that releases on a lost ack, does not re-admit on a limit cut, treats a resend as new work, frees a partial-fulfilment remainder, silently absorbs a commit that lands after a non-effect reconciliation, and does not flag.

| Case | What it isolates | reconciling | naive |
|---|---|---|---|
| T1 | undispatched reservation re-admitted on a limit cut (ledger stays ≤ the new limit) | PASS | FAIL (overshoots to 80) |
| T2 | a pre-cut in-flight commit over the new limit is **flagged** as an overrun, not silent | PASS | FAIL (silent) |
| T3 | lost ack, no committed effect: reservation released, fresh retry denied against the cut | PASS | PASS |
| T4a | definition digest drift, **enforced**: operation held for reauthorization, never commits | PASS | n/a |
| T4b | definition digest drift, **recorded-not-enforced**: commits, but the attempt is flagged | PASS | n/a |
| T5 | a transport resend of a known `operation_id` is idempotent (allowed once; books = ledger) | PASS | FAIL (rejects it as new work) |
| T6 | a limit cut below already-committed consumption flags an overrun on the grant | PASS | FAIL (silent) |
| T7 | revocation releases the not-yet-dispatched; nothing new commits; a prior commit isn't retro-flagged | PASS | FAIL (dispatches past revocation) |
| T8 | partial fulfilment (ERP confirms 20 of 40): consumption counts the confirmed effect, the remainder stays reserved until the key closes, then a fill after close is counted and the grant is flagged **reconciliation_required**; a competing op is denied while the remainder is held | PASS | FAIL (frees the remainder; a competing op is admitted and the late fill double-spends to 120, unflagged) |
| T9 | unchanged definition digest, changed server behaviour: a digest attests the declaration, not the behaviour: an **expected-miss** by construction | E-MISS | n/a |
| T10 | a commit that lands **after** a `non_effect` reconciliation (the ERP record shows up late): the effect is counted and the grant flagged `reconciliation_required`, even within the limit, rather than silently absorbed | PASS | FAIL (absorbs it, unflagged) |

T3 passing for both is the point of T3: a correct **release** on a confirmed non-effect is as required as holding on an unresolved one. T4 is an enforcement posture rather than a foil, so it runs against the reconciling Guardian under both settings. T9 is not scored pass/fail: it is an **expected-miss**, the executable statement that attestation-by-digest is necessary but not sufficient. The digest proves the declaration is stable and says nothing about the behaviour behind it, so no honest digest-based check could catch this, and the suite records the ceiling rather than pretending to cover it. Flagging it would be a false positive, which is the fail condition.

T10 is the case T3 stops short of. T3 reconciles a lost-ack operation as `non_effect` and ends there; T10 asks what happens when the ERP record then shows up late, after that verdict. The authority was accounted as having spent nothing, and now an effect has landed, so the correct handling counts it and raises `reconciliation_required` whether or not the total is within the limit. It is the general case of the late-fill-after-key-closed path in T8. This case exists because Paolo Costanzo read `reconciling.py` and noticed the suite's own claim, that a late fill is handled like a commit after a non-effect verdict, was not in fact run anywhere, and that a plain commit after a non-effect verdict was being absorbed silently. The fix made the code match the claim rather than softening the claim, and T10 now runs the path: the reconciling Guardian flags it, the naive foil absorbs it unflagged.

## Two further axes, now executable

**Commitment-boundary sweep.** The boundary is a declared per-grant parameter (`control/setBoundary`), not a fixed assumption. The sweep advances op-B to each pre-cut stage, cuts the limit 100 → 60, and runs that against each boundary. Running stage × boundary, rather than fixing op-B at dispatched, separates boundaries a dispatched-only setup conflates: a queued-but-not-dispatched op is immune at queue_admission yet re-admitted at dispatch. This refinement is due to Paolo Costanzo, who noted the original dispatched-only sweep could not tell the two apart. Committed total per cell; immune (80) when op-B's stage is at or beyond the boundary, else re-admitted (40):

| op-B stage \ boundary | queue_admission | dispatch | resource_acceptance | transaction_commit |
|---|---|---|---|---|
| queued | 80 | 40 | 40 | 40 |
| dispatched | 80 | 80 | 40 | 40 |
| resource_accepted | 80 | 80 | 80 | 40 |

The earlier the boundary relative to the operation's stage, the more of the operation sits past it, so the grant absorbs a larger overrun: Paolo's observation, measured. Which boundary §5.1 should mandate per action class is still an open normative question (below); the suite makes the consequence of each choice concrete.

**Non-idempotent ledger variant.** The matrix ledger is idempotent on `operation_id` by default, but that is a switch. Running a transport resend of op-B against both ledgers, with a `resource-reliant` Guardian alongside `reconciling`, separates a guarantee the Guardian provides from one the resource provides:

| Guardian | idempotent ledger | non-idempotent ledger |
|---|---|---|
| `reconciling` (stable operation_id) | HOLD (80) | HOLD (80) |
| `resource-reliant` (trusts the ERP key) | HOLD (80) | DOUBLE-SPEND (120) |

`reconciling` holds under both because it binds consumption to the operation itself. `resource-reliant` holds only while the resource dedupes; flip the resource and the guarantee is gone, and the Guardian's own books do not even register the second commit. That is the line between a Guardian-provided and a resource-provided guarantee, made testable.

## Boundary conformance: declaring a boundary versus honouring it

§5.1 (Approved) does not mandate a universal boundary. It allows an architecture- or action-class-specific one that is "explicitly defined, stable for that action class, and grounded in the actual cancellation or commitment semantics of the execution path," and then requires that "by that point, the maximum remaining consequential exposure must already be bounded and accounted against the applicable authority." The sweep above measures exposure at each boundary; this check enforces that last clause. It separates a Guardian that merely *declares* a boundary from one that *honours* it.

**The modelling assumption, stated plainly.** Once an operation is at or past its declared boundary it can no longer be cancelled, so the resource commits it regardless of what the Guardian's books later say. That is what "grounded in the actual cancellation semantics" means, and the check drives it on the wire: past the boundary, op-B lands whatever the Guardian decides.

**The case.** op-B is advanced to its declared boundary (immune, not yet committed). The limit is cut 100 → 60. A competing op-C for 20 then arrives, sized so it fits only if op-B's immune exposure has been freed. A conformant Guardian keeps that exposure accounted: op-B stays reserved across the cut and denies op-C. The unavoidable overrun from the cut is flagged when op-B commits (80, over the new 60). The `boundary-blind` foil declares the boundary but releases op-B on the cut, admits op-C into the freed headroom, and commits 100, with nothing at the boundary that would have prevented it.

| Guardian | queue_admission | dispatch | resource_acceptance |
|---|---|---|---|
| `reconciling` (honours it) | PASS (80) | PASS (80) | PASS (80) |
| `boundary-blind` (declares, does not honour) | FAIL (100) | FAIL (100) | FAIL (100) |

The foil is the point. A check only a correct Guardian could pass proves nothing until a plausible-but-wrong one visibly fails it; `boundary-blind` is `reconciling` in every respect except that it ignores its own declared boundary when a limit is cut. `transaction_commit` is omitted because the immune-but-uncommitted window is empty there: at commit the exposure *is* the commit, so the condition is trivially met and there is nothing to separate.

This turns "declares a boundary" into "declares a boundary it can be shown to honour." It maps to ASI03 (Identity and Privilege Abuse), like the rest of the matrix: exposure beyond the intended bound.

## What is open, and not silently chosen

The thread has not settled these, and neither does this suite. It encodes one reading and says so:

1. **Which boundary is normative: settled by §5.1, and now checked.** §5.1 (Approved) does not mandate a universal boundary such as dispatch; it requires a declared, action-class-specific one that is explicitly defined, stable for that class, grounded in the real cancellation or commitment semantics of the execution path, and that bounds the maximum remaining exposure by that point. That last condition is now enforced by the boundary-conformance invariant above, with `boundary-blind` as the foil. What remains genuinely open is upstream of the suite: which boundary §5.1 integration should mandate per action class. The suite measures the consequence of each and checks that whatever a Guardian declares is honoured; it does not pick one.
2. **Is a committed overrun (T2) a violation or valid-plus-reconcile?** Paolo's open question #1. This encodes reading **(a)**: valid at admission, the overrun flagged on the grant, not reading (b), where the effective limit simply cannot drop below consumed-plus-in-flight. The gap measured is identical (20 in T2); only its label differs.
3. **Partial fulfilment** (the ERP confirms 20 of 40), Paolo's open question #2, is **encoded as T8**, following the rule Paolo specified: consumption counts the confirmed effect (60), the remaining 20 stays reserved until the ERP confirms no more fills or the key's deadline passes, only then released; and a fill arriving after that is handled like a commit after a non_effect verdict, counted with the grant flagged `reconciliation_required`. The competing-op denial while the remainder is held shows the reservation is real, not cosmetic. What stays open is whether a late fill should be allowed to exceed the grant at all, or only logged for reconciliation as encoded here.
4. **Per-attempt records.** The operation/attempt split is encoded as a stable `operation_id` with idempotent resend, which covers the transport-resend case (T5). A distinct `attempt_id` carrying its own matched/mismatched authorization record, as in Paolo's scenario, is not yet modeled separately; a basis mismatch is flagged on the operation. Per-attempt records are the other extension worth adding.

## Reproduce

```
python3 matrix.py
python3 verify.py
```

`verify.py` re-derives every verdict above from `results/matrix_transcript.jsonl` and re-hashes the sources against `results/manifest.json`. If a verdict does not reproduce from the transcript, it does not count.

## Mapping

Delegated-authority / cumulative-limit, and the retry/revocation/basis-drift variants → OWASP Agentic **ASI03** (Identity & Privilege Abuse). The authority-basis-drift cases (T4) also touch **ASI02** (Tool Misuse) where a redefined tool changes behaviour under an unchanged name.
