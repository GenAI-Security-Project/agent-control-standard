/**
 * Public surface of the guardian package: the governance verbs, and nothing
 * else.
 *
 * The envelope log's writer (`./envelope-log-sink.ts`) is deliberately not
 * re-exported. Observability is an internal detail of running a Guardian,
 * not part of the vocabulary a consumer of this package speaks, and a
 * barrel that mixed `startGuardian` / `mapVerdict` with
 * `createEnvelopeLogSink` / `NULL_ENVELOPE_LOG_SINK` / `extractRpcId` / the
 * entry types would make the second look like the first. The one affordance
 * a consumer actually needs is `envelopeLogPath` on `StartGuardianOptions`,
 * which stays exactly where it was: you tell a Guardian where to write its
 * envelope log, you do not assemble the sink yourself.
 *
 * `./server.ts` imports the sink directly, and the two test files that
 * exercise it on its own
 * (`packages/guardian/test/envelope-log-sink*.test.ts`) import
 * `../src/envelope-log-sink.ts` directly too, so nothing outside this
 * package needs it re-exported here. If an external writer of the envelope
 * log ever becomes a real need, the answer is a narrow subpath export, not
 * putting it back in this barrel.
 *
 * The Inspector is unaffected either way: it imports nothing from this
 * package, reads the envelope log purely as a file, and re-declares
 * `EnvelopeLogEntry` on its own side. `test/invariants.test.ts` enforces
 * that boundary, and `test/envelope-log-sink-roundtrip.test.ts` keeps the
 * two declarations honest with each other.
 */
export {
  startGuardian,
  METHOD_NOT_DISPATCHED_CODE,
  type StartGuardianOptions,
  type StartedGuardian,
  type GuardianSnapshot,
} from "./server.ts";
export { buildServerHello, type ServerHello } from "./handshake.ts";
export {
  validateEnvelope,
  isToolCallRequest,
  isToolCallResult,
  EnvelopeValidationError,
  type AcsRequestEnvelope,
  type ToolCallRequestEnvelope,
  type ToolCallResultEnvelope,
} from "./validate-envelope.ts";
export { checkResponse, type ResponseCheck } from "./check-response.ts";
export {
  assemblePreToolCallSnapshot,
  assemblePostToolCallSnapshot,
  POLICY_TARGET_LEAF,
  type AgtPreToolCallSnapshot,
  type AgtPostToolCallSnapshot,
} from "./assemble-snapshot.ts";
export {
  loadMapping,
  mapVerdict,
  resolveInterventionPoint,
  resolvePolicyTargetArgument,
  type Mapping,
  type AcsDecision,
} from "./map-verdict.ts";
export {
  loadSessionContext,
  appendContextEntry,
  createMemorySessionContextStore,
  GENESIS_HASH,
  type SessionContext,
  type SessionContextEntry,
  type SessionContextStore,
  type SessionIntentStore,
  type SessionProvenanceReader,
  type IfcLabels,
  type Intent,
  type SessionProvenance,
} from "./session-context-store.ts";
export { persistIfcLabels, supplySourceLabels } from "./ifc-labels.ts";
