# TypeScript test parity

This table accounts for the TypeScript reference's 69 test files. Where the
same behavior exists in the Go Guardian, it names the corresponding Go
tests. Otherwise it records why the test does not apply. The table does not
claim identical test structure or general behavioral equivalence.

Go tests are named `<package directory>.<test>`, run from this directory with
`go test ./<package directory> -run <test>`.

## Guardian and AGT bridge

| TypeScript test | Go counterpart |
| --- | --- |
| `packages/guardian/test/server.test.ts` | `guardian.TestCoreFloor`, `guardian.TestEnvelopeGate`, `guardian.TestTransportErrors`, `guardian.TestBodyCap`, `guardian.TestEngineFailuresAreDenials`, `guardian.TestMethodRouting`, `agtbridge.TestDecisions`, `agtbridge.TestResultRedaction`, `agtbridge.TestRecordedCases` |
| `packages/guardian/test/validate-envelope.test.ts` | `internal/schema.TestValidateRequest`, `internal/schema.TestValidatePayload`, `guardian.TestEnvelopeGate` |
| `packages/guardian/test/deny-on-invalid-envelope.test.ts` | `guardian.TestEnvelopeGate`; an unaddressable envelope gets -32600 (differences.md) |
| `packages/guardian/test/check-response.test.ts` | `guardian.TestHandshake` (the ServerHello against `response-envelope.json`), `guardian.TestEngineFailuresAreDenials` (an unfit decision is never sent) |
| `packages/guardian/test/handshake.test.ts` | `guardian.TestHandshake`, `guardian.TestHandshakeRefusals`, `guardian.TestNewRefusesIncompleteConfig` (an unknown posture stops the Guardian) |
| `packages/guardian/test/session-context.test.ts` | `internal/chain.TestVector`, `internal/chain.TestEntryHashCommitsToEveryMember`, `guardian.TestChainPublication`; the digest differs by design (differences.md) |
| `packages/guardian/test/ifc-labels.test.ts` | `agtbridge.TestLabelsRoundTrip`, `agtbridge.TestEmptyLabelsClearSessionState`, `agtbridge.TestNormalizeResultLabelsPresence`, `guardian.TestPolicyStateFollowsTheSession` |
| `packages/guardian/test/map-verdict.test.ts` | `agtbridge.TestDecisions` (reasoning, reason codes, references), `agtbridge.TestResultRedaction`, `agtbridge.TestEscalate`, `agtbridge.TestRecordedCases` |
| `packages/guardian/test/assemble-snapshot.test.ts` | `agtbridge.TestRecordedCases` (`policy_target_argument_missing`, `argument_named_like_the_leaf`, `raw_command_absent`, the result cases) |
| `packages/guardian/test/annotate-egress.test.ts` | `agtbridge.TestWhatwgOrigin`, `agtbridge.TestRecordedCases` (every `egress_*` and `fetch_*` case) |
| `packages/guardian/test/envelope-log-sink.test.ts` | `guardian.TestJSONLAuditLog`, `guardian.TestJSONLAuditLogRefusesAnUnwritablePath` |
| `packages/guardian/test/envelope-log-sink-wiring.test.ts` | `guardian.TestAuditLogReceivesEveryEnvelope` |
| `packages/agt-bridge/test/bridge.test.ts` | `agtbridge.TestDecisions`, `agtbridge.TestNewRefusesAnUnsupportedManifest` |
| `packages/agt-bridge/test/opa-path.test.ts` | Does not apply: OPA runs in process, with no binary to find. |

## Whole-tree tests

| TypeScript test | Go counterpart |
| --- | --- |
| `test/dispositions.test.ts` | `guardian.TestCoreFloor` (all five through the Guardian), `agtbridge.TestEscalate` (escalate), `agtbridge.TestLabelsRoundTrip` (warn), `agtbridge.TestResultRedaction` (transform) |
| `test/redaction.test.ts` | `agtbridge.TestResultRedaction`, `agtbridge.TestRecordedCases` (`result_*` cases) |
| `test/ifc-round-trip.test.ts` | `agtbridge.TestLabelsRoundTrip`, `agtbridge.TestRecordedCases` (`labels_across_steps`) |
| `test/handshake-declares-what-it-evaluates.test.ts` | `guardian.TestHandshake` (the declared hooks exactly), `guardian.TestCoreFloor` (every hook evaluated), `internal/handshake.TestEvaluatedMethods` |
| `test/invariants.test.ts` | `agtbridge.TestAGTConfinedToAgtbridge`; the host-side gates do not apply |
| `test/path-dialects.test.ts` | `agtbridge.TestPathDialectsAgree` |
| `test/session-context-roundtrip.test.ts` | `guardian.TestReserveAndAppendAtomicity`, `guardian.TestMemoryStoreRefusesWhenFull` |
| `test/envelope-log-sink-roundtrip.test.ts` | `guardian.TestJSONLAuditLog` (the Inspector's line shape) |
| `test/readme-captures.test.ts` | Does not apply. The Go command's runnable configuration and commands are documented directly in `README.md`. |
| `test/pin.test.ts` | Does not apply: the Go Guardian copies no policy files; it reads `../agt/policy/lib/`, whose version that test fixes. |
| `test/audit-sink-roundtrip.test.ts` | Does not apply: the host adapter's audit log. |

## Conformance harness

The existing TypeScript command still measures what ACS can express of AGT.
When `ACS_CONFORMANCE_GUARDIAN_URL` is set, the same command also sends fixed,
signed ACS requests to an external Guardian. `make conformance` starts the Go
Guardian on a free port and runs that external mode. `make docs-check` checks
the Go Guardian's ACS-Core table and its references to Go tests.

| TypeScript test | Go counterpart |
| --- | --- |
| `packages/conformance/test/external-guardian.test.ts` | `make conformance` verifies the independent JCS, HKDF and HMAC vectors, then runs the shared signed wire checks against a live Go Guardian. |
| `packages/conformance/test/failure-domains.test.ts` | `guardian.TestEngineFailuresAreDenials`, `guardian.TestShutdownAnswersInFlightSteps` |
| `packages/conformance/test/exit-code.test.ts` | `internal/docscheck.TestConformanceRequiresTestsForClaims` |
| `packages/conformance/test/policy-input-schema.test.ts` | Not ported: it fetches AGT's schema from GitHub. The recorded cases prove the policy input decides as AGT's does. |
| `packages/conformance/test/diff-surfaces.test.ts`, `fetch-upstream.test.ts`, `identity.test.ts`, `intervention-points.test.ts`, `main.test.ts`, `merge-cells.test.ts`, `render-coverage-matrix.test.ts`, `render-mapping-table.test.ts`, `render-upstream-diff.test.ts`, `surfaces.test.ts`, `tools-registry.test.ts`, `trace-pillar.test.ts`, `upstream-schema-check.test.ts`, `upstream-watch.test.ts`, `verdicts.test.ts` | Do not apply: the harness's coverage matrix, upstream watch and Trace rows. |

## Hosts, host adapter and Inspector

The Go Guardian ships Codex `PreToolUse` and OpenCode V2 `execute.before` and
`execute.after` examples. `internal/hostadapter` owns their shared signed session,
handshake, timeout, failure-posture and audit behavior; each example contains only the
host event conversion and decision application. `internal/observedagent` is the lower
level Observed Agent shared by those examples and the Guardian tests.

| TypeScript tests | Go counterpart |
| --- | --- |
| `hosts/claude-code/test/*.test.ts` (4 files) | Do not apply: no Claude Code example is shipped. |
| `hosts/opencode/test/*.test.ts` (6 files) | The TypeScript adapter targets OpenCode V1. The current V2 request and result gates are covered by `acs-opencode-hook.TestRunGovernsRequestAndResult`, `acs-opencode-hook.TestRunBlocksEveryNonProceedingDisposition`, `acs-opencode-hook.TestProjectPluginConfiguration` and the [plugin callback test](../examples/opencode/plugin.test.mjs). |
| Codex `PreToolUse` | `examples/codex/cmd/acs-codex-hook.TestRunSendsSignedDecisionAndReusesHandshake`, `examples/codex/cmd/acs-codex-hook.TestRunTranslatesDecisions`, `internal/hostadapter.TestSessionUUIDIsStableAndAgentScoped`, `examples/codex/cmd/acs-codex-hook.TestProjectHookConfiguration` |
| `packages/host-adapter/test/*.test.ts` (11 files) | The Go adapter is deliberately smaller. Its shared behavior is covered by `internal/hostadapter.TestDecisionTimeoutUsesMethodOverride`, `internal/hostadapter.TestLoadStateDefaultsAnOmittedFailurePosture`, `internal/hostadapter.TestSessionUUIDIsStableAndAgentScoped`, `internal/observedagent.TestHonour`, and the Codex and OpenCode adapter command tests. |
| `packages/inspector/test/*.test.ts` (4 files) | Do not apply. The envelope file keeps the line shape the Inspector reads (`guardian.TestJSONLAuditLog`). |
