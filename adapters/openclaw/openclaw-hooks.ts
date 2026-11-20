/**
 * The hooks share run, tool-call and reply state.
 * mapping.md defines each hook's ACS steps and decision handling.
 */
import { METHODS, type AcsExchange, type Step, type StepOutcome } from "./acs-exchange.ts";
import type { AdapterAuditSink } from "./audit.ts";
import type { PluginConfig } from "./config.ts";
import { WITHHELD_RESULT, blockedRun, droppedMessage } from "./decisions.ts";
import { type AdmissionStore, type RefusalStore, type RunFactsStore, createHookState, memoryOnlyAdmissions } from "./hook-state.ts";
import type { AfterToolCallContext, AfterToolCallEvent, AgentContext, AgentEndEvent, BeforeAgentRunEvent, BeforeAgentRunResult, BeforeToolCallEvent, BeforeToolCallResult, MessageContext, MessageSendingEvent, MessageSendingResult, ReplyDispatchContext, ReplyDispatchEvent, ReplyDispatchResult, ReplyPayloadContext, ReplyPayloadSendingEvent, ReplyPayloadSendingResult, SessionContext, SessionEndEvent, ToolContext, ToolResultAnswer, ToolResultContext, ToolResultEvent } from "./openclaw-types.ts";
import { createReplyGate } from "./replies.ts";
import { createRunGate } from "./runs.ts";
import { createToolCallGate } from "./tool-calls.ts";

export type Hooks = {
  beforeAgentRun(event: BeforeAgentRunEvent, ctx: AgentContext): Promise<BeforeAgentRunResult>;
  replyDispatch(event: ReplyDispatchEvent, ctx: ReplyDispatchContext): Promise<ReplyDispatchResult>;
  beforeToolCall(event: BeforeToolCallEvent, ctx: ToolContext): Promise<BeforeToolCallResult>;
  afterToolCall(event: AfterToolCallEvent, ctx: AfterToolCallContext): Promise<void>;
  toolResult(event: ToolResultEvent, ctx: ToolResultContext): Promise<ToolResultAnswer>;
  replyPayloadSending(event: ReplyPayloadSendingEvent, ctx: ReplyPayloadContext): Promise<ReplyPayloadSendingResult>;
  messageSending(event: MessageSendingEvent, ctx: MessageContext): Promise<MessageSendingResult>;
  agentEnd(event: AgentEndEvent, ctx: AgentContext): Promise<void>;
  sessionEnd(event: SessionEndEvent, ctx: SessionContext): Promise<void>;
  /** OpenClaw's `gateway_start`: the active registration starts restoring admissions. */
  gatewayStart(): Promise<void>;
};

export type CreateHooksOptions = {
  config: Pick<PluginConfig, "maxUndecidedMessages" | "maxAttachmentBytes">;
  exchange: AcsExchange;
  audit: AdapterAuditSink;
  logger: { error(message: string): void };
  /** In-memory admission store for direct hook tests; production requires the OpenClaw store. */
  admissions?: AdmissionStore;
  /** OpenClaw's plugin-scoped state store is the only bridge between registrations. */
  runFacts: RunFactsStore;
  /** The sessions a Guardian refused, shared by the registrations the same way. */
  refusals: RefusalStore;
};

/** State operations can outlast a Guardian answer. Recheck refusals before releasing the action. */
export type ConfirmDecision = (step: Pick<Step, "sessionId" | "method">, outcome: StepOutcome, deadline: number) => Promise<StepOutcome>;

export function createHooks(options: CreateHooksOptions): Hooks {
  const state = createHookState({ ...options, store: options.admissions ?? memoryOnlyAdmissions });
  const { refusals } = options;
  // Refusals in OpenClaw's plugin state also cancel decisions pending in another registration.
  const shared = new Set<string>();
  async function readRefusal(sessionId: string, deadline: number): Promise<void> {
    if (options.exchange.refusalOf(sessionId) !== undefined) {
      return;
    }
    const recorded = await state.beforeDeadline(refusals.get(sessionId), deadline, "reading the session's refusal from OpenClaw's plugin state");
    if (recorded !== undefined) {
      shared.add(sessionId);
      options.exchange.adoptRefusal(sessionId, recorded);
    }
  }
  const confirmDecision: ConfirmDecision = async (step, outcome, deadline) => {
    await readRefusal(step.sessionId, deadline);
    const refusal = options.exchange.refusalOf(step.sessionId);
    if (refusal !== undefined) {
      if (!shared.has(step.sessionId)) {
        await state.beforeDeadline(refusals.put(step.sessionId, refusal), deadline, "storing the session's refusal in OpenClaw's plugin state");
        shared.add(step.sessionId);
      }
      const runIds = [...state.runs].filter(([, run]) => run.sessionId === step.sessionId).map(([runId]) => runId);
      await state.until(Promise.all(runIds.map((runId) => state.revokeRunFacts(runId))).then(() => {}), deadline);
      const refusesSession = step.method === METHODS.sessionStart && outcome.decision.decision !== "allow";
      if (!refusesSession && outcome.decision.decision !== "deny") {
        options.audit.write({
          session_id: step.sessionId,
          method: step.method,
          rpc_id: outcome.requestId,
          request_id: outcome.requestId,
          outcome: "substituted",
          substituted: { decision: outcome.decision.decision, reason_code: "guardian_refused" },
        });
        return {
          ...outcome,
          decision: { decision: "deny", reasoning: `The Guardian refused this session (${refusal.code}: ${refusal.message}).`, reason_codes: ["guardian_refused"] },
        };
      }
    }
    return outcome;
  };
  const exchange: AcsExchange = {
    ...options.exchange,
    async decide(step, deadlineAt) {
      const deadline = deadlineAt ?? options.exchange.deadlineFromNow();
      await readRefusal(step.sessionId, deadline);
      return confirmDecision(step, await options.exchange.decide(step, deadline), deadline);
    },
    forget(sessionId) {
      options.exchange.forget(sessionId);
      shared.delete(sessionId);
    },
    async withoutDecision(method, sessionId, why, deadlineAt) {
      return sessionId === undefined
        ? options.exchange.withoutDecision(method, undefined, why)
        : exchange.decide({ method, sessionId, payload: {}, cannotSend: why }, deadlineAt);
    },
  };
  const gated = { ...options, exchange };
  return {
    ...createRunGate(gated, state, confirmDecision),
    ...createToolCallGate(gated, state, confirmDecision),
    ...createReplyGate(gated, state),
  };
}


/**
 * OpenClaw unloads a plugin whose registration throws, leaving the agent ungoverned.
 * Invalid configuration or missing host capabilities therefore register blocking hooks.
 * Registration logs the reason once. Each blocked step carries the same reason.
 */
export function createBlockingHooks(reason: string): Hooks {
  return {
    async beforeAgentRun() {
      return blockedRun(reason);
    },
    async replyDispatch(_event, ctx) {
      return droppedMessage(ctx, reason);
    },
    async beforeToolCall() {
      return { block: true, blockReason: reason };
    },
    async afterToolCall() {},
    async gatewayStart() {},
    async toolResult() {
      return WITHHELD_RESULT;
    },
    async replyPayloadSending() {
      return { cancel: true };
    },
    async messageSending() {
      return { cancel: true };
    },
    async agentEnd() {},
    async sessionEnd() {},
  };
}

