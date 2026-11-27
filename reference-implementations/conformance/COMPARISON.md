# Three layers, one scenario

### A three-layer comparison, ARC declaration checks against Guardian commitment-boundary enforcement and an independent ledger, run over the delegated-authority cases from OWASP AIMM Pillar 2 §5.1

This suite tests OWASP Agent Control Standard (ACS) Guardians; the delegated-authority cases it drives against them come from OWASP AIMM Pillar 2 §5.1, a separate document. The two are kept distinct throughout.

A reproducible comparison between [ARC (Agent Role Contracts)](https://github.com/suirindo/agent-role-contracts) and this conformance suite, ARC is an independent open-source project, not an OWASP artifact. The §5.1 cases this comparison runs come from OWASP's AIMM Pillar 2 workstream. The point is to locate the seam between the layers, not to rank them. The three answer different questions about the same scenario, and none validates another.

## The three layers

- **ARC, at declaration time.** ARC is a preflight declaration-consistency checker. It validates that declared roles, task and action scope, review separation, and bindings are internally consistent before execution. Its G1 subject is `canonical({profile, bundle, task, action})`, and per ARC's ARCHITECTURE.md it "binds the reference declaration, not the retrieved artifact bytes." An ARC PASS "grants no permission to run an agent." ARC does not authorize execution, authenticate identities, verify artifacts, or reconcile external effects, and it says so plainly.
- **The Guardian, at the commitment boundary.** A protocol-perfect ACS Guardian returns allow, deny, modify, ask or defer over the wire. This layer measures whether it actually holds a cumulative authority at runtime under basis drift, partial fulfilment, and late-arriving effects.
- **The independent ledger.** The test harness's own append-only record of the effects that actually landed, never the Guardian's books. It confirms what happened.

## Method and honesty

The Guardian and ledger columns below are measured by this suite and re-derived from the recorded wire transcript by `verify.py`; each cell names the case it comes from (T4a, T4b, T8, and the `reconciling` versus `declaration-bound` comparison run for the underlying-change row). `comparison.py` only renders these verified results; it measures nothing of its own. The ARC column is taken from ARC's maintainer-run fixture, merged upstream at [873b410](https://github.com/suirindo/agent-role-contracts/blob/873b4104a95e443ba22367cf8378deb7dcbe6cfd/experiments/external-evaluation/acs-conformance/README.md). Its provenance is recorded as `MAINTAINER_RUN`: synthetic inputs, run against the published ARC 1.0.1 package. We have run that fixture ourselves against the published 1.0.1 tarball, and the integrity check passes. Its output matches the committed observations on every case. That run uses ARC's own runner unchanged, so it confirms the reproduction and does not audit the method. A reproduction by a party outside both projects is still outstanding. The fixture's observations confirm the G1 reading we drew from ARC's ARCHITECTURE.md: the underlying definition is not in the subject, so ARC does not see that change.

## T4: authority-basis drift

T4 splits on exactly what changes, and the split is entirely an ARC-side distinction. The Guardian records the underlying definition digest at admission and checks it when the operation is first reported dispatched, so it catches the drift in both sub-cases. The check is keyed to the dispatch report, not to the declared commitment boundary; the two coincide only at the default boundary (`dispatch`), which is the one these cases run under. That reply is an acknowledgement, not a pre-forward permit; the T4 pilot uses a separate pre-forward mode, described in [PREFORWARD.md](PREFORWARD.md). What differs is whether ARC's declaration-time subject moved.

| Sub-case | ARC (declaration time) | Guardian (commitment boundary) | Independent ledger |
|---|---|---|---|
| **Declared change**, in the bundle, task or action | REJECT, `G1_SUBJECT_MISMATCH` for all three declaration changes *(ARC fixture, maintainer-run)* | drift caught at dispatch: hold for reauthorization when enforced (T4a, held, never commits), commit and flag `basis_mismatch` when recorded (T4b) *(measured)* | effect bounded: 40 held, 80 committed-and-flagged *(measured)* |
| **Underlying change**, the tool or MCP definition changes while the declaration is unchanged | G1 PASS, `EXPECTED_MISS`, with `execution_authorized: false` *(ARC fixture, maintainer-run)* | a definition-binding Guardian catches it (reconciling flags `basis_mismatch`); a Guardian that binds only the declaration misses it, unflagged *(measured)* | 80 committed either way; the difference is whether the drift was noticed *(measured)* |

The underlying-change row is the one that draws the boundary, and the suite measures it on its own side rather than asserting it. By its documented G1 construction ARC does not see this change, because its subject does not include the underlying definition. That is the declaration-time analogue of this suite's own T9: a digest cannot detect a change in something it was never computed over. To make the point measured, the comparison runs the same scenario against two Guardians: `reconciling`, which binds the underlying definition and flags the drift, and `declaration-bound`, which binds only the declaration and lets the drift pass unflagged, exactly the blind spot ARC has, projected into the runtime layer. The ledger records the same effect (80) in both; the difference is whether the Guardian noticed. So for an underlying-definition change, ARC misses it by construction, a declaration-bound runtime check misses it too, and only a definition-binding Guardian catches it. In the declared-change row the ARC and Guardian layers overlap, each confirming the same change from a different vantage, and the ledger confirms the effect in both.

## T8: partial fulfilment with a late-arriving effect

| Scenario | ARC (declaration time) | Guardian (commitment boundary) | Independent ledger |
|---|---|---|---|
| Partial fulfilment (20 of 40 confirmed), then a fill after the key closes | G3 validates lifecycle declarations; reconciliation of actual partial fills and late-arriving effects is outside ARC's scope *(ARC fixture, maintainer-run)* | counts the confirmed 20, holds the remainder until the key closes, denies a competing op while it is held, flags `reconciliation_required` on the late fill *(measured, T8)* | 80, flagged, no double-spend; a naive Guardian double-spends to 120 *(measured)* |

Partial fulfilment and late-arriving effects are runtime and effect phenomena. ARC's G3 validates lifecycle declarations; reconciliation of actual partial fills and late-arriving effects is outside ARC's scope, which is why its runtime-reconciliation cell does not apply. The substantive work is the Guardian's and the ledger's.

## What the comparison shows

Three independent layers, each with a ceiling, each catching what the others cannot. ARC confirms declaration consistency and invalidates stale bindings before execution, and by its documented G1 construction it does not see an underlying-definition change. The Guardian holds the authority at the commitment boundary and catches that underlying change at dispatch, and it enforces nothing about declaration consistency. The independent ledger confirms the effect that actually landed, and decides nothing. An ARC PASS grants no execution authority, and a Guardian decision validates no declaration. The value is in the distance between the layers, not in one checking another.

## Reproduce

```
python3 comparison.py   # the three-layer table; Guardian and ledger columns from the live run
python3 matrix.py       # the full T1-T10 matrix the Guardian and ledger cells come from
python3 verify.py       # re-derive every Guardian and ledger verdict from the wire transcript
```

## Credits and cross-reference

The reconciliation model and these cases come from the OWASP GenAI Security Project's AIMM Pillar 2 §5.1 delegated-authority discussion (Boris Abuzov, t-iida, Sol_ni_shko, Paolo Costanzo). ARC is at [github.com/suirindo/agent-role-contracts](https://github.com/suirindo/agent-role-contracts). The ARC fixture and the declaration-check column are ARC's maintainer's, merged upstream; the Guardian and ledger columns are this suite's. The comparison is intended to live in both repositories, each linking the other.

**Status.** Guardian and ledger columns measured and verified in this suite. ARC column taken from ARC's merged, maintainer-run fixture (pinned above). Reproduced by Noctis against the published 1.0.1 tarball, with output identical to the committed observations. Not yet reproduced by a party outside both projects.
