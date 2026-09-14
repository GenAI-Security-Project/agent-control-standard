/**
 * Public surface of the host-adapter package (packages/host-adapter).
 *
 * Every host shim imports from here rather than from individual src files,
 * so this list is the whole contract a shim relies on. The package boundary
 * still binds every file this barrel re-exports: no policy-runtime vocabulary
 * of any kind anywhere under packages/host-adapter/.
 */
export {
  buildEnvelope,
  loadHookmap,
  modificationDocumentOf,
  toSessionUuid,
  type Hookmap,
  type HookmapHookEntry,
  type HookmapOutputs,
  type AcsRequestEnvelope,
} from "./build-envelope.ts";
export {
  createGuardianClient,
  GuardianResponseMismatchError,
  GuardianResultCorrelationError,
  GuardianTimeoutError,
  type DecisionOrFailure,
  type GuardianClient,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type JsonRpcSuccessResponse,
  type JsonRpcErrorResponse,
  type PostOptions,
} from "./guardian-client.ts";
export { renderDecision, type HostOutput } from "./render-decision.ts";
// The ACS decision message every seam below speaks, and the one refinement of
// it a host reads directly. One stem, adjectives for stage: the third member,
// `FailureResolvedAcsDecision`, is exported with the posture that produces it.
export { type AcsDecision, type ValidatedAcsDecision } from "./decision-message.ts";
export {
  governStep,
  // The record a `tools` skip leaves, exported for the same reason
  // `governsTool` is: a shim that skips one call earlier skips this module's
  // own audit entry along with the work it was saving, and an optimisation
  // that quietly changes the durable record is a divergence between the two
  // hosts rather than a saving. A shim that asks `governsTool` must file this
  // when the answer is no.
  auditUngovernedStep,
  // The `tools` rule itself, exported because both sides of it are real: a
  // shim asks it before it validates a session id or negotiates a session
  // config, so an out-of-scope tool costs neither; `governStep` asks it again,
  // about the tool the shim tells it (`GovernStepInput.scopedTool`), so the
  // two are one question about one value. One implementation, two call sites
  // -- see governsTool's own doc comment for why that is not one call site
  // too many.
  //
  // A shim that never tells `governStep` which tool a step is does not skip
  // silently at a gate declaring `tools`: `governStep` refuses that call
  // outright, because it has no way to know which tool the step is. A
  // forgetful shim gets a loud stop rather than a skip filed against the
  // wrong tool.
  governsTool,
  type DecisionStage,
  type GovernStepInput,
  type GovernedStep,
} from "./govern-step.ts";
export {
  negotiateSessionConfig,
  resolveSessionConfig,
  ServerHelloInvalidError,
  SessionConfigNotStoredError,
  SessionConfigStoreFailedError,
  type HandshakeOptions,
  type ResolvedSessionConfig,
} from "./handshake.ts";
export {
  createMemorySessionConfigStore,
  createFileSessionConfigStore,
  isSessionConfig,
  InvalidSessionIdError,
  sessionConfigPath,
  type SessionConfig,
  type SessionConfigStore,
  type CreateFileSessionConfigStoreOptions,
} from "./session-config.ts";
export {
  createAuditSink,
  NULL_AUDIT_SINK,
  type AuditEntry,
  // `AuditSink.write()` takes one of these, so a caller that builds an event
  // to hand to a sink could not name its type through this barrel. Coherent
  // under structural typing, which is why it went unnoticed -- but the barrel
  // is documented as "the whole contract a shim relies on", and a parameter
  // type of an exported method belongs in it.
  type AuditEvent,
  type AuditSink,
  type CreateAuditSinkOptions,
} from "./audit-sink.ts";
export {
  applyFailurePosture,
  classifyDeliveryFailure,
  classifySessionFailure,
  DEFAULT_POSTURE,
  DEFAULT_TIMEOUT_MS,
  type ApplyFailurePostureInput,
  type DeliveryFailureKind,
  type FailureResolvedAcsDecision,
  type FailureStage,
  type HostFailureKind,
  type SessionFailureKind,
  type StepFailureKind,
} from "./failure-posture.ts";
export { applyModifications, ModificationsInvalidError } from "./modifications.ts";
// The result gate's replacing output, and the target a caller has to name for
// one. `HostOutputLocation` is a member type of the exported
// `ValidateDecisionContext`, so a caller that builds a context could not name it
// through this barrel otherwise -- the same reason `AuditEvent` is above.
//
// `withholdsAtResultGate` is here for a host shim rather than for the adapter:
// which dispositions withhold at a result gate is what a shim's own gate over
// its mapping table has to know to tell a mapping that withholds from one that
// only says it does, and a shim re-deriving that list would be a second copy of
// the rule, free to drift from the one that attaches the replacement.
export {
  projectAppliedOutput,
  replacingOutput,
  withholdsAtResultGate,
  withResultOutput,
  WITHHELD_OUTPUT,
  type HostOutputLocation,
} from "./result-output.ts";
export { validateDecision, type ValidateDecisionContext } from "./validate-decision.ts";
// The one shared surface for JavaScript's prototype-machinery names, and
// the value-tree walker that checks a rendered value against them at any
// depth -- exported so a host applier (hosts/opencode/apply-opencode-output.ts
// today; any later host tomorrow) imports these rather than keeping its own
// module-private copy. `isReservedSegment` is a predicate, not the
// underlying Set -- see reserved-segments.ts's own header for why the Set
// itself stays module-private.
export { isReservedSegment, findReservedKey } from "./reserved-segments.ts";
