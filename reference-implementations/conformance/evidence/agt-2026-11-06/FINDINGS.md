# AGT reference Guardian run, 2026-11-06

Two measured runs (before and after the toolCallResult fix in 39606f1) plus source reading. Every section says which it is.

## Setup
- Target: AGT reference Guardian, `GenAI-Security-Project/agent-control-standard` branch `integration` at `db457a8` (`agt_source_commit.txt`). Wire spec v0.1.0, release 0.1.4.
- Container: `oven/bun` pinned by digest (`bun_image_digest.txt`), bun 1.4.4, source copied in, port bound to host loopback only. Container removed after the run.
- Suite: `acs-conformance` at `8ea942f`, run from a clean clone so the repo's frozen `results/` were untouched. `verify.py` on the clone: VERIFIED.
- Raw evidence: `suite-results/` (the suite's transcript, scorecard, manifest) and `agt_envelopes.jsonl` (AGT's own envelope log, every request and response). Checksums in `SHA256SUMS`.

## Measured
| Check | Result | Basis |
|---|---|---|
| Handshake, ServerHello required fields | PASS | suite transcript |
| system/ping | -32011 "method not dispatched", left as an open observation (unchanged from the 2026-11-02 #311 comment) | suite + AGT log |
| toolCallRequest returns schema-valid AcsResult | PASS | suite transcript |
| Undeclared method refused | PASS (-32011) | suite + AGT log |
| §10 signing, §10.3 replay | not exercised: ServerHello advertises `signature_algorithms_supported: []`, `skew_window_ms: 300000` | suite transcript |
| Layer B cumulative grant (race, lost-ack continue, lost-ack retry) | N/A: every `budget.consume` denied `evaluation_failed`, because AGT's `mapping.yaml` reads the policy target from an argument named `command` | AGT log |

Change since 2026-11-02: the ServerHello now advertises a 300000 ms skew window. It still advertises no signature algorithm, so §10 cannot be asserted against AGT.

## Defect in our suite (measured, confirmed against the schema)
AGT rejected every `steps/toolCallResult` the suite sent with `envelope_invalid`: "must have required property 'tool'". The v0.1.0 schema (`hooks/tool-call-result.json`) requires `tool` (with `name`), `exit_status` and `outputs` (items with `value`), and has required them since the canonical import on 2026-06-05. The suite sends only `{grant_id, operation_id, status}` (`run_conformance.py` `send_result`, `matrix.py` `Client.result`). Our mocks accept it, so it never surfaced.

Scope of the impact: the result envelopes are not schema-valid ACS. The mock-measured verdicts are still internally consistent results about the model, but the claim that the matrix runs "over the ACS wire" is overstated for `toolCallResult` until fixed. The schema sets no `additionalProperties: false`, so the fix is additive: send the required fields alongside the existing ones, regenerate the frozen evidence, re-pin.

## Fix confirmed (measured, second run, same AGT commit and image)
After the payload fix, AGT logged 2 `steps/toolCallResult` responses as `deny` with `runtime_error:tool_unknown`, a policy decision about the unknown `budget.consume` tool, and none as `envelope_invalid`. The result envelopes now pass AGT's schema validation. Layer A and Layer B results are otherwise identical to the first run. Raw log and suite output in `after-fix/`. On the mock suite, `verify.py` re-checks every recorded result payload (175/175 pass), every T1–T10 and Layer B verdict is unchanged, and a deliberately stripped `exit_status` makes `verify.py` report NOT VERIFIED.

## Read from source, not executed
- AGT's budget counters are session-level (`tool_call_count`, `token_count`, `elapsed_seconds`, `cost_usd`; `assemble-snapshot.ts`). There is no per-grant amount ledger keyed by operation_id.
- AGT has a drift gate (`policy/lib/drift.rego`, enabled only via `policy/manifest.drift.yaml`). It reads a host-supplied `drift_score` annotation and is observe-only (warn). AGT's own manifest comment states that the v0.1.0 `toolCallRequest` payload carries `tool, operation, capability, arguments, raw_command, intent` and "nothing a drift score could be derived from on this wire."
- Consequence for T4: no field in the v0.1.0 `toolCallRequest` carries a tool-definition digest. Our mock gets its digest through the harness's `control/setBasis`, not the ACS wire. In the pilot, the digest has to reach the Guardian out of band or through an argument convention agreed in the contract.
