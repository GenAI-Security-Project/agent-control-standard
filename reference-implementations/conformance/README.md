# acs-conformance

An independent, language-independent conformance suite for OWASP **Agent Control Standard (ACS)** v0.1.0 Guardians. It points at any Guardian over its HTTP endpoint and asks two questions:

1. **Protocol conformance (Layer A)**: does the Guardian speak ACS correctly? Handshake/ServerHello, schema-valid decision envelopes, refusal of undeclared methods, `system/ping`, and §10 message authentication (a valid HMAC-SHA256 signature accepted; tampered, stale-timestamp, and replayed requests rejected).
2. **Invariant conformance (Layer B)**: does a *protocol-perfect* Guardian actually preserve a security invariant? ACS-Core states it "does not assert that policies are strict." This layer drives the delegated-authority, cumulative-limit scenarios (OWASP Agentic ASI03); a shared grant consumed under concurrency, lost acknowledgements, and retries; and measures, from an independent world ledger, whether the committed total ever exceeds the grant.

Built in response to [issue #311](https://github.com/GenAI-Security-Project/agent-control-standard/issues/311) (a language-independent Guardian contract test suite) and issue #19 (no independent conformance steward in v0.1.0).

## Quickstart

```
python3 run_conformance.py --selftest          # Layer A + B against the three bundled mock Guardians
python3 matrix.py                              # the T1–T10 reconciliation matrix (OWASP AIMM Pillar 2 §5.1 cases)
python3 preforward.py                          # the T4 pilot's pre-forward R1 (Test Contract V0.3), P0–P11
python3 verify.py                              # re-derive every verdict from the wire transcripts
python3 run_conformance.py --guardian-url http://localhost:8787/acs   # point Layer A/B at a real Guardian
```

Standard library only. No dependencies.

## What it finds (bundled mock Guardians)

All three mocks are protocol-conformant. Only one holds the invariant.

| Guardian | race 3×40 | lost-ack continue | lost-ack retry |
|---|---|---|---|
| stateless | OVERSHOOT (120) | LEAK (110) | DOUBLE-SPEND (80) |
| reserve-only | HOLD (80) | LEAK (110) | DOUBLE-SPEND (80) |
| holding | HOLD (80) | HOLD (40) | HOLD (40) |

The point of Layer B in one line: a destination that passes the obvious concurrency test can still fail two less obvious ones, a reservation auto-released on a lost acknowledgement (leak) and a retry that is not bound to a stable operation identity (double-spend). Only `holding` (atomic reservation, stable-operation-id binding, and holding the pending reservation on a lost ack) keeps the limit under all three. Full write-up in [SCENARIO.md](SCENARIO.md).

## The T1–T10 reconciliation matrix

The OWASP delegated-authority discussion took the 3×40 case well past the race, into a full reconciliation model: an operation/attempt split, holding a reservation on a lost acknowledgement, ordered admission, limit changes mid-flight, revocation, authority-basis drift (a tool redefined under an unchanged name), partial fulfilment, and behaviour drift under an unchanged digest. Those cases (T1–T10) began as prose in that thread. `matrix.py` makes them executable and measures each one from an independent, `operation_id`-idempotent ERP ledger. §5.1 (AIMM Pillar 2) was marked **Approved** in November 2026; this suite is its executable reference point for these cases, run as tests against the stable model.

| | T1 | T2 | T3 | T4a | T4b | T5 | T6 | T7 | T8 | T9 | T10 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `reconciling` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | E-MISS | PASS |
| `naive` | FAIL | FAIL | PASS | n/a | n/a | FAIL | FAIL | FAIL | FAIL | n/a | FAIL |

T8 is partial fulfilment (the ERP confirms 20 of a 40-unit request; consumption counts the confirmed effect, the remainder stays reserved until the key closes, and a fill after close is counted and the grant flagged `reconciliation_required`). T9 is an **expected-miss**: a digest attests the declaration, not the behaviour behind it, so a changed-behaviour/unchanged-digest case is outside what any digest check can catch; the suite records the ceiling rather than pretending to cover it. T10 is the reconciliation discrepancy T3 stops short of: a commit that lands after the operation was reconciled as `non_effect` (the ERP record shows up late) must be counted and flagged `reconciliation_required`, even within the limit, rather than silently absorbed; `naive` absorbs it (the gap, caught by Paolo Costanzo reading the source). `matrix.py` also runs a commitment-boundary sweep (each pre-cut stage against each declared boundary, 12 cells), a **boundary-conformance invariant**, and a non-idempotent ledger variant (separating a guarantee the Guardian provides from one the resource provides). The model is credited to the thread's participants; the encoding, and the questions it does not pretend to settle (whether a committed overrun is a violation, how to model per-attempt records), are written up in [SCENARIO_T1_T10.md](SCENARIO_T1_T10.md).

The boundary-conformance invariant enforces the condition §5.1 settled: a Guardian may declare its own commitment boundary, but at that boundary the maximum remaining exposure must be bounded and accounted against the authority. Once an operation is past the declared boundary it can no longer be cancelled, so the suite cuts the limit, then offers a competing op sized to fit only if the immune operation's exposure were freed. A Guardian that honours its boundary keeps that exposure accounted and denies the competitor; the `boundary-blind` foil declares a boundary but frees the exposure on the cut and overruns. `reconciling` passes at every boundary (committed 80), `boundary-blind` fails at every boundary (committed 100); a check only a correct Guardian passes, with a plausible-but-wrong one made to fail it.

## Comparison with ARC (declaration-time)

[ARC (Agent Role Contracts)](https://github.com/suirindo/agent-role-contracts) checks declaration consistency before execution; this suite measures runtime enforcement and the actual effect. They are complementary layers, and [COMPARISON.md](COMPARISON.md) lays the two against each other over T4 (authority-basis drift) and T8 (partial fulfilment), with an independent ledger as the third column. The Guardian and ledger columns are measured by `comparison.py` from the verified matrix results; the ARC column is taken from ARC's merged, maintainer-run fixture (pinned in COMPARISON.md) and has been reproduced by Noctis against the published tarball, but not yet by a party outside both projects. The sharp case is an underlying tool-definition change under an unchanged declaration: ARC cannot see it by construction, a `declaration-bound` Guardian misses it too, and only a definition-binding Guardian catches it; the runtime analogue of the declaration-time blind spot, measured here.

## The T4 pilot: pre-forward R1

The joint T4 pilot (ARC × Guardian × ERP, Test Contract V0.3) needs the Guardian's decision before the gateway sends anything to the ERP. The matrix runs R1 on a `dispatched` result report, whose reply is an acknowledgement, so it cannot serve as a pre-forward permit. `preforward.py` measures the replacement: R1 on a pre-forward `steps/toolCallRequest`, a reference gateway that forwards only on a valid `allow` for the same attempt, and thirteen cases covering C0, C2 and C3, a retry after HELD, a post-persistence 409, the recorded-only extra case, six fail-closed drills, and a measured reproduction of the dispatch-report acknowledgement gap. Every message validates against the official v0.1.0 schemas (`tools/schema_check.py`, optional, needs `jsonschema`). Design, results and limits in [PREFORWARD.md](PREFORWARD.md).

## Requirement IDs

Every case is mapped to the draft ACS normative-requirement ledger from issue #33 in [CROSSWALK.md](CROSSWALK.md). The suite cites the ledger's IDs and mints none of its own. Six of the eight protocol checks test a ledger requirement directly; the grant, reconciliation and pre-forward cases test guarantees v0.1.0 does not yet state as a MUST.

## Running it against the real reference Guardian

The suite is the instrument; the AGT reference Guardian is a target. See [REFERENCE_GUARDIAN.md](REFERENCE_GUARDIAN.md) for standing the reference Guardian up in an isolated container and pointing the suite at it.

## Integrity

`verify.py` recomputes every invariant verdict from `results/transcript.jsonl`: the recorded wire effects, not the runner's own flags, summing the amounts the suite actually executed on each honoured `allow`, re-deriving HOLD / OVERSHOOT / LEAK / DOUBLE-SPEND, and flagging any operation that committed more than once. It re-hashes the sources against `results/manifest.json` and exits non-zero if anything fails to reproduce.

## Scope, stated plainly

The world ledger is modelled as a faithful append-only record with **no idempotency backstop**, so preventing a double-spend is forced onto the control plane; this isolates the Guardian, which is the point of a conformance test (a production ERP with an idempotency key would also stop a double-spend). Layer A's §10 message authentication is implemented in [acs_sig.py](acs_sig.py) and exercised against the mock: HMAC-SHA256 over the RFC 8785 (JCS) canonicalization of the envelope with the signature field removed, keyed by HKDF-SHA256(secret, info=session_id), whose derivation reproduces the ACS §10 published test vector (re-checked by `verify.py`). §10.3 replay is enforced via the timestamp skew window and duplicate request_id/nonce. Testing a real external Guardian's §10 needs that deployment's shared key material; without it the check reports so rather than failing. The suite measures the wire; it does not inspect a Guardian's internals.

## Credits

The reconciliation model (Layer B and the T1–T10 matrix) comes from the OWASP GenAI Security Project's delegated-authority discussion:

- [Boris Abuzov](https://github.com/boris-ai-sec) ([borisabuzov.com](https://borisabuzov.com)): the 3×40 cumulative-grant case, the operation/attempt split, and holding the reservation on a lost acknowledgement.
- t-iida: the lost-ack boundary and stop-or-reauthorize.
- Sol_ni_shko: ordered admission.
- Paolo Costanzo: authority-basis drift and the T1–T7 scenario.

The encoding is Noctis's own and may differ from their intent; corrections welcome.

## License

Apache-2.0 (see [LICENSE](LICENSE)), matching the upstream ACS project. Copyright © 2026 Malachi Zion Kopman.
