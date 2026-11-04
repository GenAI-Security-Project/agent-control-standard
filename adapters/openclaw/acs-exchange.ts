/**
 * Each step uses host-adapter for signing, verification and decision validation.
 * This exchange adds the sender and turn. All steps from one hook share its deadline.
 * README.md#failure-posture defines refusal and failure handling.
 */
import {
  applyFailurePosture,
  classifyDeliveryFailure,
  classifySessionFailure,
  GuardianTimeoutError,
  isSessionConfig,
  ServerHelloInvalidError,
  signEnvelope,
  toSessionUuid,
  validateDecision,
  type AcsDecision,
  type FailureResolvedAcsDecision,
  type GuardianClient,
  type HmacKey,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type ResolvedSessionConfig,
  type SessionConfig,
  type ValidatedAcsDecision,
} from "./host-adapter.ts";
import { randomUUID } from "node:crypto";
import type { AdapterAuditSink } from "./audit.ts";
import { decisionSchemaFailure, responseEnvelopeFailure, serverHelloSchemaFailure } from "./response-schema.ts";
import { STATE_RESERVE_MS, type FailurePosture } from "./config.ts";

export const AGENT_ID = "openclaw";
const ACS_VERSION = "0.1.0";
/** §17.1 CAPABILITY_NOT_NEGOTIATED: the Guardian holds no session, or not this method in it. */
const CAPABILITY_NOT_NEGOTIATED = -32003;
/** §17.1 SESSION_REFUSED: Guardian policy refuses the session. */
const SESSION_REFUSED = -32000;
/** SESSION_REFUSED, UNSUPPORTED_VERSION, PROVENANCE_REQUIRED (§17.1): a handshake refused for good. */
const SESSION_REFUSALS: ReadonlySet<number> = new Set([SESSION_REFUSED, -32001, -32002]);
/** JSON-RPC -32603: the Guardian failed to decide, the one error that follows the posture (#308). */
const INTERNAL_ERROR = -32603;

export const METHODS = {
  sessionStart: "steps/sessionStart",
  agentTrigger: "steps/agentTrigger",
  turnStart: "steps/turnStart",
  userMessage: "steps/userMessage",
  toolCallRequest: "steps/toolCallRequest",
  toolCallResult: "steps/toolCallResult",
  agentResponse: "steps/agentResponse",
  turnEnd: "steps/turnEnd",
  sessionEnd: "steps/sessionEnd",
} as const;
export type StepMethod = (typeof METHODS)[keyof typeof METHODS];
/** §13: the liveness probe, signature-exempt and outside the audit chain. */
export const PING_METHOD = "system/ping";
/** The ACS session a probe, or a step OpenClaw names no session for, is recorded under: the envelope and the audit entry require one. */
const NO_SESSION_ID = "00000000-0000-4000-8000-000000000000";

/** `summary.decision_failures` (session-end.json): failures counted per `acs.failure.class`. */
export type DecisionFailures = Partial<Record<string, number>>;

/**
 * Registrations share failure counts through OpenClaw's plugin state, keyed by ACS session id.
 * The registration that sends sessionEnd reports the combined counts.
 */
export type FailureCountStore = {
  /** Starts the session's count at none; a session not started in this store has no count. */
  start(sessionUuid: string): Promise<void>;
  /** Adds one failure of `failureClass` to a started session's count. */
  add(sessionUuid: string, failureClass: string): Promise<void>;
  get(sessionUuid: string): Promise<DecisionFailures | undefined>;
  delete(sessionUuid: string): Promise<void>;
};

/**
 * These values follow acs.failure.class in trace/otel-mapping.json and include adapter failures.
 * Importing the Guardian's audit-to-otlp.ts would also import its OpenTelemetry dependencies.
 */
const FAILURE_CLASS_BY_KIND: Readonly<Record<string, string>> = {
  timeout: "timeout",
  transport: "unreachable",
  error_without_decision: "guardian_error",
  refused: "guardian_error",
  signature_invalid: "signature_invalid",
  host_configuration: "observed_agent_error",
  unsignable: "observed_agent_error",
  decision_invalid: "malformed_response",
  handshake_failure: "handshake_failure",
};

const GATES_BEFORE_ACTION: ReadonlySet<StepMethod> = new Set([METHODS.toolCallRequest, METHODS.userMessage, METHODS.agentResponse]);

/** `metadata.user_context`: who the step acts for, as the channel names them. */
export type UserContext = { user_id: string; authentication_method: string };

export type Step = {
  method: StepMethod;
  /**
   * OpenClaw assigns this id to each session, even when the session key is reused.
   * The ACS session id is its UUIDv5.
   */
  sessionId: string;
  /** Who the step acts for; absent for a run no person started (a heartbeat, a system event). */
  userContext?: UserContext;
  payload: Record<string, unknown>;
  /** The document a `modify` decision's pointers address (§6.3); the payload when absent. */
  modificationDocument?: Record<string, unknown>;
  /**
   * OpenClaw omitted a required fact. The exchange checks the session's refusal and ServerHello first.
   * The failure posture then applies instead of sending the step (§6.4).
   */
  cannotSend?: string;
  /** `metadata.turn_id`: the turn this step belongs to, absent outside one. */
  turnId?: string;
  /** `metadata.agent_name`: the host's agent that runs the session, when the host names one. */
  agentName?: string;
  /**
   * A tool result uses the ServerHello that governed its call, including calls from another registration.
   */
  serverHello?: SessionConfig;
};

/**
 * requestId identifies the sent step; null means no step was sent.
 * The exchange returns unevaluated when methods_evaluated omits the method.
 * The handshake schema allows such a step without sending it.
 */
export type StepOutcome = { requestId: string | null } & (
  | { stage: "honoured"; decision: ValidatedAcsDecision }
  | { stage: "delivery"; decision: FailureResolvedAcsDecision }
  | { stage: "unevaluated"; decision: AcsDecision }
);

export type AcsExchange = {
  /** `deadlineAt` (`performance.now()` time) bounds the step; one `deadlineMs` from now when absent. */
  decide(step: Step, deadlineAt?: number): Promise<StepOutcome>;
  /** The deadline of a hook that starts now. */
  deadlineFromNow(): number;
  /** Drops the stored ServerHello of a session OpenClaw ended. */
  forget(sessionId: string): void;
  /** The session's verified ServerHello, for another registration of this plugin. */
  serverHelloOf(sessionId: string): SessionConfig | undefined;
  /** The error with which the Guardian refused the session at a handshake (§4.1), or `undefined`. */
  refusalOf(sessionId: string): SessionRefusal | undefined;
  /** Takes on a refusal another registration of this plugin received, so every step of the session is blocked here too. */
  adoptRefusal(sessionId: string, refusal: SessionRefusal): void;
  /**
   * All registrations contribute to the session's counts by failure class (§6.4).
   * The result is undefined if counting never started or a write failed.
   */
  decisionFailures(sessionId: string): Promise<DecisionFailures | undefined>;
  /** Sends `system/ping` (§13); throws when no `status: "ok"` answer arrives within `deadlineMs`. */
  ping(): Promise<void>;
  /**
   * A missing required fact prevents sending the step; a gate blocks it, a tool result follows the posture.
   * A known session supplies its refusal and ServerHello through decide with cannotSend.
   * Without a session, the host's failure posture or the ACS default applies.
   */
  withoutDecision(method: StepMethod, sessionId: string | undefined, why: string, deadlineAt?: number): Promise<StepOutcome>;
};

export type CreateAcsExchangeOptions = {
  /** Created with the same `hmacKey`, so it verifies every reply (§10). */
  client: GuardianClient;
  hmacKey: HmacKey;
  audit: AdapterAuditSink;
  failurePosture: FailurePosture;
  deadlineMs: number;
  failureCounts: FailureCountStore;
};

type Answer =
  | { arrived: true; decision: ValidatedAcsDecision; rpcId: string; askedToModify: boolean }
  | { arrived: false; failure: unknown; rpcId: string | null; stage: "sign" | "delivery" };

type JsonRpcError = { code: number; message?: unknown };

/** A Guardian's refusal of a session (§17.1 `SESSION_REFUSALS`), as one registration of this plugin hands it to another. */
export type SessionRefusal = { code: number; message: string };

/** A JSON-RPC error object the Guardian answered with, as `client.post` let it through. */
function isJsonRpcError(failure: unknown): failure is JsonRpcError {
  return typeof failure === "object" && failure !== null && !(failure instanceof Error) && typeof (failure as { code?: unknown }).code === "number";
}

function isNotNegotiated(failure: unknown): boolean {
  return isJsonRpcError(failure) && failure.code === CAPABILITY_NOT_NEGOTIATED;
}

/**
 * The hook's deadline ended before the negotiated timeout.
 * The adapter blocks because §6.4 permits the failure posture only after the negotiated timeout (#269).
 */
class HostDeadlineError extends Error {
  constructor(method: string, waitedMs: number, negotiatedMs: number) {
    super(`the hook's deadline ended the wait for ${method} after ${waitedMs} ms, before the negotiated ${negotiatedMs} ms`);
    this.name = "HostDeadlineError";
  }
}

/** A signed decision that breaks the specification's response schema. */
class DecisionSchemaError extends Error {
  constructor(reason: string) {
    super(`the decision does not match response-envelope.json: ${reason}`);
    this.name = "DecisionSchemaError";
  }
}

export function createAcsExchange({ client, hmacKey, audit, failurePosture, deadlineMs, failureCounts }: CreateAcsExchangeOptions): AcsExchange {
  /** Negotiated ServerHellos and handshakes in flight, by ACS session id. */
  const sessions = new Map<string, Promise<ResolvedSessionConfig>>();
  /**
   * Each session's count writes run in order without delaying its steps.
   * A failed write prevents the session from reporting an incomplete count.
   */
  const countWrites = new Map<string, Promise<void>>();
  const uncounted = new Set<string>();

  function writeCount(sessionUuid: string, write: () => Promise<void>): void {
    const next = (countWrites.get(sessionUuid) ?? Promise.resolve()).then(write).catch(() => {
      uncounted.add(sessionUuid);
    });
    countWrites.set(sessionUuid, next);
  }

  /** Counts a failure of `kind` under its `acs.failure.class`. */
  function countFailure(sessionUuid: string, kind: string): void {
    const failureClass = FAILURE_CLASS_BY_KIND[kind] ?? "other";
    writeCount(sessionUuid, () => failureCounts.add(sessionUuid, failureClass));
  }

  function remainingMs(deadlineAt: number): number {
    const remaining = Math.floor(deadlineAt - performance.now());
    if (remaining <= 0) {
      throw new GuardianTimeoutError(deadlineMs);
    }
    return remaining;
  }

  /**
   * host-adapter's negotiateSessionConfig offers only the two tool steps.
   * This ClientHello offers all adapter steps because methods_evaluated must be a subset of methods_implemented.
   */
  async function handshake(sessionId: string, deadlineAt: number): Promise<SessionConfig> {
    const requestId = randomUUID();
    const hello = signEnvelope({
      jsonrpc: "2.0",
      method: "handshake/hello",
      id: requestId,
      params: {
        acs_version: ACS_VERSION,
        request_id: requestId,
        timestamp: new Date().toISOString(),
        metadata: { agent_id: AGENT_ID, session_id: sessionId },
        payload: {
          acs_versions_supported: [ACS_VERSION],
          methods_implemented: [...Object.values(METHODS), PING_METHOD],
          transports_supported: ["http"],
          provenance_producer: "none",
          profiles_supported: ["acs-core"],
        },
      },
    } satisfies JsonRpcRequest, hmacKey);
    const response = await client.post(hello, { timeoutMs: remainingMs(deadlineAt) });
    if (response.error !== undefined) {
      // The JSON-RPC error itself, so the posture reads its code: a refusal is
      // the Guardian's decision and blocks the step (§4.1).
      throw response.error;
    }
    const malformed = serverHelloSchemaFailure(response.result);
    if (malformed !== undefined) {
      throw new ServerHelloInvalidError(`the ServerHello does not match handshake.json: ${malformed}`);
    }
    const serverHello = response.result as Partial<SessionConfig> & { negotiated_version?: unknown; selected_transport?: unknown };
    if (serverHello.negotiated_version !== ACS_VERSION || serverHello.selected_transport !== "http") {
      throw new ServerHelloInvalidError(
        `the Guardian negotiated ${JSON.stringify(serverHello.negotiated_version)} over ${JSON.stringify(serverHello.selected_transport)}; this host offered ${ACS_VERSION} over http`,
      );
    }
    // handshake.json's default for a ServerHello that names no posture.
    const config: unknown = { ...serverHello, on_decision_failure: serverHello.on_decision_failure ?? "proceed" };
    if (!isSessionConfig(config)) {
      throw new ServerHelloInvalidError(`the ServerHello is not a usable session config: ${JSON.stringify(response.result)}`);
    }
    if (!Array.isArray(config.profiles_accepted) || !config.profiles_accepted.includes("acs-core")) {
      throw new ServerHelloInvalidError("the Guardian did not accept the acs-core profile this signed client requires", config);
    }
    if (!Array.isArray(config.signature_algorithms_supported) || !config.signature_algorithms_supported.includes("HMAC-SHA256")) {
      throw new ServerHelloInvalidError("the Guardian did not advertise HMAC-SHA256 for this acs-core session", config);
    }
    return config;
  }

  async function negotiate(sessionId: string, deadlineAt: number): Promise<ResolvedSessionConfig> {
    try {
      return { config: await handshake(sessionId, deadlineAt), failure: undefined };
    } catch (failure) {
      // A verified ServerHello that refuses acs-core or HMAC keeps its posture, as in `resolveSessionConfig`.
      return { config: failure instanceof ServerHelloInvalidError ? failure.config : undefined, failure };
    }
  }

  /**
   * Failed or late handshakes retain the session's last verified ServerHello.
   * A -32003 followed by a failed handshake must not replace the negotiated posture with the startup default.
   */
  const verified = new Map<string, SessionConfig>();
  /** Sessions the Guardian refused at a handshake, with the refusal, until OpenClaw ends them. */
  const refused = new Map<string, SessionRefusal>();

  /** Blocks every later step of the session with `refusal`, whatever ServerHello it had. */
  function holdRefusal(sessionId: string, refusal: SessionRefusal): void {
    verified.delete(sessionId);
    refused.set(sessionId, refusal);
    sessions.set(sessionId, Promise.resolve({ config: undefined, failure: refusal }));
  }

  /** Waits for `pending` no longer than `deadlineAt`; a late one leaves the session on its verified ServerHello, if any. */
  async function waitFor(sessionId: string, pending: Promise<ResolvedSessionConfig>, deadlineAt: number): Promise<ResolvedSessionConfig> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<ResolvedSessionConfig>((resolve) => {
      timer = setTimeout(
        () => resolve({ config: verified.get(sessionId), failure: new GuardianTimeoutError(deadlineMs) }),
        Math.max(0, deadlineAt - performance.now()),
      );
    });
    return await Promise.race([pending, late]).finally(() => clearTimeout(timer));
  }

  /**
   * Concurrent steps share the handshake. A failure preserves the last verified ServerHello.
   * A rejected ServerHello applies to waiting steps only; later steps negotiate again unless the session was refused.
   */
  function startHandshake(sessionId: string, deadlineAt: number): Promise<ResolvedSessionConfig> {
    const negotiation: Promise<ResolvedSessionConfig> = negotiate(sessionId, deadlineAt).then((resolved) => {
      if (resolved.failure === undefined) {
        verified.set(sessionId, resolved.config!);
        return resolved;
      }
      countFailure(sessionId, "handshake_failure");
      // A terminal refusal replaces the ServerHello until OpenClaw ends the session (§4.1, §17.1).
      if (isJsonRpcError(resolved.failure) && SESSION_REFUSALS.has(resolved.failure.code)) {
        holdRefusal(sessionId, { code: resolved.failure.code, message: String(resolved.failure.message) });
        return { config: undefined, failure: resolved.failure };
      }
      const kept = verified.get(sessionId);
      if (kept === undefined && sessions.get(sessionId) === negotiation) {
        sessions.delete(sessionId);
      }
      return { config: resolved.config ?? kept, failure: resolved.failure };
    });
    sessions.set(sessionId, negotiation);
    return negotiation;
  }

  /** The stored ServerHello, or one handshake shared by every step that needs it, waited for no longer than this step's own deadline. */
  async function resolveSession(sessionId: string, deadlineAt: number): Promise<ResolvedSessionConfig> {
    return waitFor(sessionId, sessions.get(sessionId) ?? startHandshake(sessionId, deadlineAt), deadlineAt);
  }

  async function send(step: Step, sessionId: string, config: SessionConfig, startedAt: number, deadlineAt: number): Promise<Answer> {
    const requestId = randomUUID();
    const unsigned = {
      jsonrpc: "2.0",
      method: step.method,
      id: requestId,
      params: {
        acs_version: ACS_VERSION,
        request_id: requestId,
        timestamp: new Date().toISOString(),
        metadata: {
          agent_id: AGENT_ID,
          session_id: sessionId,
          ...(step.userContext === undefined ? {} : { user_context: step.userContext }),
          ...(step.turnId === undefined ? {} : { turn_id: step.turnId }),
          ...(step.agentName === undefined ? {} : { agent_name: step.agentName }),
        },
        payload: step.payload,
      },
    } satisfies JsonRpcRequest;
    let envelope: JsonRpcRequest;
    try {
      envelope = signEnvelope(unsigned, hmacKey);
    } catch (failure) {
      return { arrived: false, failure, rpcId: requestId, stage: "sign" };
    }
    const negotiated = config.timeout_config.per_method_ms?.[step.method] ?? config.timeout_config.default_ms;
    const left = Math.floor(deadlineAt - STATE_RESERVE_MS - performance.now());
    if (left <= 0) {
      return { arrived: false, failure: new HostDeadlineError(step.method, 0, negotiated), rpcId: requestId, stage: "delivery" };
    }
    const timeoutMs = Math.min(negotiated, left);
    // `post`, not `requestDecision`: the host adapter's `requestDecision`
    // drops a result with no string `decision` before the schema could see it.
    // `post` still verifies the signature and the ids.
    let response: JsonRpcResponse;
    try {
      response = await client.post(envelope, { timeoutMs });
    } catch (failure) {
      const cutShort = failure instanceof GuardianTimeoutError && timeoutMs < negotiated;
      return { arrived: false, failure: cutShort ? new HostDeadlineError(step.method, timeoutMs, negotiated) : failure, rpcId: requestId, stage: "delivery" };
    }
    if (response.result === undefined) {
      return { arrived: false, failure: response.error ?? new Error("the Guardian's response carried neither a result nor an error"), rpcId: requestId, stage: "delivery" };
    }
    const malformed = responseEnvelopeFailure(response) ?? decisionSchemaFailure(response.result);
    if (malformed !== undefined) {
      return { arrived: false, failure: new DecisionSchemaError(malformed), rpcId: requestId, stage: "delivery" };
    }
    const sent = response.result as AcsDecision;
    const decision = validateDecision(sent, {
      elapsedMs: performance.now() - startedAt,
      modificationDocument: step.modificationDocument ?? { ...step.payload },
    });
    return { arrived: true, decision, rpcId: requestId, askedToModify: sent.decision === "modify" };
  }

  /**
   * The adapter records each refusal, invalid decision or deadline failure (§6.4).
   * README.md#failure-posture defines which failures block regardless of the negotiated posture.
   */
  function blockByHost(step: Step, session: ResolvedSessionConfig, failure: unknown, rpcId: string | null, why: "decision_invalid" | "refused" | "deadline" | "host" | "unsendable"): StepOutcome {
    const message = failure instanceof Error ? failure.message : String(failure);
    const classified = why === "host" ? classifyDeliveryFailure(failure)
      : why === "deadline" ? { kind: "timeout" as const, message }
      : why === "unsendable" ? { kind: "unsignable" as const, message }
      : why === "refused" ? { kind: why, message: `the Guardian answered error ${String((failure as JsonRpcError).code)}: ${String((failure as JsonRpcError).message)}` }
      : { kind: why, message };
    countFailure(toSessionUuid(step.sessionId), classified.kind);
    const byHost = why === "host" || why === "deadline" || why === "unsendable";
    audit.write({
      session_id: step.sessionId,
      method: step.method,
      rpc_id: rpcId,
      request_id: rpcId,
      outcome: "blocked",
      posture: byHost ? "deny" : (session.config?.on_decision_failure ?? "proceed"),
      posture_source: byHost ? "host" : session.config === undefined ? "default" : "negotiated",
      failure: classified,
      ...(session.failure === undefined || session.failure === failure ? {} : { session_failure: classifySessionFailure(session.failure) }),
    });
    const reasoning = {
      decision_invalid: `the Guardian's decision for ${step.method} is not a valid ACS decision (${message}), so this step was blocked whatever the posture says`,
      deadline: `${message}; the Guardian had not failed to decide, so this step was blocked whatever the posture says`,
      refused: `${classified.message} for ${step.method} instead of a decision; a verified error other than -32603 blocks the step whatever the posture says`,
      unsendable: `${message}, and a ${step.method} the Guardian never saw is blocked whatever the posture says`,
      host: `no usable decision arrived from the Guardian for ${step.method} (${classified.kind}: ${classified.message}), and this host never proceeds without one`,
    }[why];
    const decision: FailureResolvedAcsDecision = { decision: "deny", reasoning, reason_codes: [{ host: "decision_failure", deadline: "decision_failure", refused: "guardian_refused", decision_invalid: "decision_invalid", unsendable: "step_unsendable" }[why]] };
    return { stage: "delivery", decision, requestId: rpcId };
  }

  /** `stage: "sign"` blocks whatever the posture says: an unsigned request is one an ACS-Core Guardian refuses. */
  function resolveByPosture(
    step: Step,
    session: ResolvedSessionConfig,
    failure: unknown,
    rpcId: string | null,
    stage: "sign" | "delivery" = "delivery",
  ): StepOutcome {
    if (failure instanceof DecisionSchemaError) {
      return blockByHost(step, session, failure, rpcId, "decision_invalid");
    }
    if (failure instanceof HostDeadlineError) {
      return blockByHost(step, session, failure, rpcId, "deadline");
    }
    // #308: an error the client let through (verified, or an unsigned
    // refusal) blocks, except -32603, the Guardian's own failure to decide.
    if (isJsonRpcError(failure) && failure.code !== INTERNAL_ERROR) {
      return blockByHost(step, session, failure, rpcId, "refused");
    }
    if (failurePosture === "closed" && stage === "delivery") {
      return blockByHost(step, session, failure, rpcId, "host");
    }
    countFailure(toSessionUuid(step.sessionId), stage === "sign" ? "unsignable" : classifyDeliveryFailure(failure).kind);
    const decision = applyFailurePosture({
      failure,
      session,
      sessionId: step.sessionId,
      method: step.method,
      rpcId,
      requestId: rpcId,
      audit,
      stage,
    });
    return { stage: "delivery", decision, requestId: rpcId };
  }

  /**
   * A step OpenClaw gives too few facts to send. A gate before the action
   * blocks it, as for a step that cannot be signed; a tool result follows
   * the failure posture (README.md#failure-posture).
   */
  function unsendable(step: Step, session: ResolvedSessionConfig, why: string): StepOutcome {
    const failure = new Error(`the step cannot be sent: ${why}`);
    return GATES_BEFORE_ACTION.has(step.method) ? blockByHost(step, session, failure, null, "unsendable") : resolveByPosture(step, session, failure, null);
  }

  /** The ServerHello's `methods_evaluated`, or `undefined` when it carries no list to read. */
  function evaluatedMethods(config: SessionConfig): unknown[] | undefined {
    return Array.isArray(config.methods_evaluated) ? config.methods_evaluated : undefined;
  }

  return {
    deadlineFromNow(): number {
      return performance.now() + deadlineMs;
    },

    async decide(step: Step, deadlineAt: number = performance.now() + deadlineMs): Promise<StepOutcome> {
      const startedAt = performance.now();
      const sessionId = toSessionUuid(step.sessionId);
      if (step.method === METHODS.sessionStart) {
        writeCount(sessionId, () => failureCounts.start(sessionId));
      }

      /** What the ServerHello says of this method, or the posture's outcome when it cannot say. */
      const evaluation = (session: ResolvedSessionConfig): StepOutcome | "evaluated" => {
        if (session.config === undefined) {
          // A refused handshake is this step's failure, with its code; the
          // session-level record would only repeat it without one.
          const refused = typeof session.failure === "object" && session.failure !== null && !(session.failure instanceof Error);
          return resolveByPosture(step, refused ? { config: undefined, failure: undefined } : session, session.failure, null);
        }
        const evaluated = evaluatedMethods(session.config);
        if (evaluated === undefined) {
          return resolveByPosture(step, session, new Error("the ServerHello carries no methods_evaluated list"), null);
        }
        if (!evaluated.includes(step.method)) {
          return {
            stage: "unevaluated",
            decision: { decision: "allow", reasoning: `the Guardian does not evaluate ${step.method}` },
            requestId: null,
          };
        }
        return "evaluated";
      };

      // A ServerHello saved with a call does not outlive the session's refusal;
      // used here, it is the session's verified ServerHello for later steps too.
      const saved = step.serverHello !== undefined && isSessionConfig(step.serverHello) && !refused.has(sessionId) ? step.serverHello : undefined;
      if (saved !== undefined && !verified.has(sessionId)) {
        verified.set(sessionId, saved);
      }
      let session = saved !== undefined ? { config: saved, failure: undefined } : await resolveSession(sessionId, deadlineAt);
      const first = evaluation(session);
      if (first !== "evaluated") {
        return first;
      }
      if (step.cannotSend !== undefined) {
        return unsendable(step, session, step.cannotSend);
      }
      let answer = await send(step, sessionId, session.config!, startedAt, deadlineAt);

      // Retry negotiation once after -32003, then resend with a new request_id.
      // A failed handshake preserves the last verified ServerHello and the step's refusal.
      if (!answer.arrived && isNotNegotiated(answer.failure)) {
        session = await waitFor(sessionId, startHandshake(sessionId, deadlineAt), deadlineAt);
        if (session.failure !== undefined) {
          return resolveByPosture(step, session, answer.failure, answer.rpcId);
        }
        const again = evaluation(session);
        if (again !== "evaluated") {
          return again;
        }
        answer = await send(step, sessionId, session.config!, startedAt, deadlineAt);
      }

      if (!answer.arrived) {
        return resolveByPosture(step, session, answer.failure, answer.rpcId, answer.stage);
      }
      // §6.3: a MODIFY whose modifications cannot be applied fails closed, and
      // the substitution `validateDecision` made is recorded.
      const reasonCodes: unknown = answer.decision.reason_codes;
      if (answer.askedToModify && answer.decision.decision === "deny" && Array.isArray(reasonCodes) && reasonCodes.includes("modifications_invalid")) {
        audit.write({
          session_id: step.sessionId,
          method: step.method,
          rpc_id: answer.rpcId,
          outcome: "substituted",
          substituted: { decision: "modify", reason_code: "modifications_invalid" },
        });
      }
      // A sessionStart that is not allowed refuses the whole session, including its other registrations (§6.4).
      if (step.method === METHODS.sessionStart && answer.decision.decision !== "allow") {
        holdRefusal(sessionId, { code: SESSION_REFUSED, message: `the Guardian refused this session: ${String(answer.decision.reasoning ?? answer.decision.decision)}` });
      }
      return { stage: "honoured", decision: answer.decision, requestId: answer.rpcId };
    },

    forget(sessionId: string): void {
      sessions.delete(toSessionUuid(sessionId));
      verified.delete(toSessionUuid(sessionId));
      refused.delete(toSessionUuid(sessionId));
      const sessionUuid = toSessionUuid(sessionId);
      writeCount(sessionUuid, () => failureCounts.delete(sessionUuid));
      void countWrites.get(sessionUuid)!.then(() => {
        countWrites.delete(sessionUuid);
        uncounted.delete(sessionUuid);
      });
    },

    async decisionFailures(sessionId: string): Promise<DecisionFailures | undefined> {
      const sessionUuid = toSessionUuid(sessionId);
      await countWrites.get(sessionUuid);
      return uncounted.has(sessionUuid) ? undefined : await failureCounts.get(sessionUuid);
    },

    async ping(): Promise<void> {
      const requestId = randomUUID();
      const response = await client.post({
        jsonrpc: "2.0",
        method: PING_METHOD,
        id: requestId,
        params: {
          acs_version: ACS_VERSION,
          request_id: requestId,
          timestamp: new Date().toISOString(),
          metadata: { agent_id: AGENT_ID, session_id: NO_SESSION_ID },
          payload: {},
        },
      } satisfies JsonRpcRequest, { timeoutMs: deadlineMs });
      if (response.error !== undefined) {
        throw new Error(`the Guardian answered system/ping with error ${String(response.error.code)}: ${String(response.error.message)}`);
      }
      const status = (response.result as { payload?: { status?: unknown } } | null | undefined)?.payload?.status;
      if (status !== "ok") {
        throw new Error(`the Guardian answered system/ping without status "ok"`);
      }
    },

    serverHelloOf(sessionId: string): SessionConfig | undefined {
      return verified.get(toSessionUuid(sessionId));
    },

    async withoutDecision(method: StepMethod, sessionId: string | undefined, why: string, deadlineAt?: number): Promise<StepOutcome> {
      if (sessionId !== undefined) {
        return this.decide({ method, sessionId, payload: {}, cannotSend: why }, deadlineAt);
      }
      return unsendable({ method, sessionId: NO_SESSION_ID, payload: {} }, { config: undefined, failure: undefined }, why);
    },

    refusalOf(sessionId: string): SessionRefusal | undefined {
      return refused.get(toSessionUuid(sessionId));
    },

    adoptRefusal(sessionId: string, refusal: SessionRefusal): void {
      holdRefusal(toSessionUuid(sessionId), refusal);
    },
  };
}
