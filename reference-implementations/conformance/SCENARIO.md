# Invariant conformance for ACS Guardians

*Protocol conformance asks whether a Guardian speaks ACS correctly. Invariant conformance asks whether speaking ACS correctly is enough to keep an agent inside its authority. It is not, and this measures the gap.*

**Suite:** `run_conformance.py` · **Verifier:** `verify.py` · **Target contract:** ACS v0.1.0 Guardian wire (JSON-RPC 2.0 over HTTP).

## Why a second layer

ACS defines a Guardian that returns `allow`, `deny`, `modify`, `ask`, or `defer` at each decision point, the control point between an agent's request and a tool's execution. The project's open conformance work (issue #311) tests the **wire**: handshake, decision shapes, signatures, replay. That is necessary and it is what Layer A does.

But ACS-Core itself says it "does not assert that policies are strict." A Guardian can return perfectly well-formed verdicts and still fail to hold a security property. Three well-formed `allow` verdicts against a shared 100-unit grant still land the execution layer at 120. That is the delegated-authority cumulative-limit case (OWASP Agentic ASI03), and no amount of protocol conformance catches it. Layer B does.

## The invariant and how it is measured

The property is `committed_total ≤ grant.limit`, where the committed total is the sum of effects a well-behaved agent actually executed after the Guardian allowed them. The suite plays that agent: it sends `steps/toolCallRequest` envelopes and honours each verdict literally. On `allow` it executes (appends to an independent world ledger), on `deny`/`ask`/`defer` it does not. Ground truth is the world ledger, not the Guardian's own books. The world ledger has no idempotency backstop, so preventing a double-spend falls to the Guardian. This isolates the control plane, the thing under test.

## The three scenarios (delegated-authority cumulative limit)

- **race**: three `budget.consume(40)` operations arrive concurrently against a limit of 100 (a barrier models concurrent arrival). Does the Guardian stop the third?
- **lost-ack continue**: one `consume(40)` is allowed and executed; its `toolCallResult` reports `unresolved` (the acknowledgement was lost); then a later, unrelated `consume(70)` arrives. Does a pending reservation get freed and let the later operation overshoot?
- **lost-ack retry**: one `consume(40)` is allowed and executed; its ack is lost; then the *same operation* is retried. Does the Guardian recognise the retry, or consume the grant twice?

## Result

Three bundled Guardians, all protocol-conformant, measured by `run_conformance.py --selftest` and reproduced from the transcript by `verify.py`:

| Guardian | race 3×40 | lost-ack continue | lost-ack retry | holds? |
|---|---|---|---|---|
| `stateless`: confirmed-consumption check only | OVERSHOOT (120) | LEAK (110) | DOUBLE-SPEND (80) | no |
| `reserve-only`: atomic reservation, auto-releases on lost ack | HOLD (80) | LEAK (110) | DOUBLE-SPEND (80) | no |
| `holding`: reservation + stable op-id + holds pending | HOLD (80) | HOLD (40) | HOLD (40) | **yes** |

What each column isolates:

- **race** separates a Guardian that reserves atomically from one that only checks a point-in-time total. The stateless Guardian sees three requests before any result confirms, reads a committed total of zero for all three, and allows them all.
- **lost-ack continue** separates a Guardian that *reconciles* from one that *auto-releases*. `reserve-only` frees the pending reservation when the ack is lost, so the grant believes nothing is spent while the world kept 40, and the next operation walks the total to 110. `holding` keeps the reservation pending and denies the 70.
- **lost-ack retry** separates a Guardian that *binds consumption to a stable operation identity* from one that does not. `holding` recognises the retried `operation_id` and refuses the duplicate; the others treat it as new work and commit a second effect for one logical operation.

Reservation alone (the `reserve-only` row) is the trap: it passes the concurrency test and fails both in-doubt tests. Only reservation **plus** stable-operation-id binding **plus** holding the reservation on a lost ack keeps the limit under all three. That matches the design the delegated-authority discussion converged on, now executable and measured over the ACS wire.

## Mapping

- Delegated-authority / cumulative-limit → ASI03 (Identity & Privilege Abuse).
- The sibling egress/relay coverage finding (a Guardian blind to a relay through an allowed intermediary) → ASI02 (Tool Misuse & Exploitation).

## Reproduce

```
python3 run_conformance.py --selftest
python3 verify.py
```
