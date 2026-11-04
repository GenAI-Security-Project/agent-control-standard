/**
 * Each tool call uses toolCallRequest before execution and toolCallResult before the model reads the result.
 * Human ASK decisions use OpenClaw's plugin approvals.
 */
import { createHash } from "node:crypto";
import { METHODS, type UserContext } from "./acs-exchange.ts";
import { WITHHELD_RESULT, reasoningOf } from "./decisions.ts";
import { callKey, type DecidedCall, type HookState, type RunFactsStore } from "./hook-state.ts";
import type { AcsDecision, SessionConfig } from "./host-adapter.ts";
import type { ConfirmDecision, CreateHooksOptions, Hooks } from "./openclaw-hooks.ts";
import type { ApprovalResolution, BeforeToolCallEvent, BeforeToolCallResult, ToolContext, ToolResultAnswer, ToolResultBlock, ToolResultContext, ToolResultEvent } from "./openclaw-types.ts";

/** OpenClaw's bounds on approval prompt text (docs/plugins/plugin-permission-requests.md). */
const APPROVAL_TITLE_MAX = 80;
const APPROVAL_DESCRIPTION_MAX = 512;

function callNamespace(toolCallId: string): string {
  return `tool-call-${createHash("sha256").update(toolCallId).digest("hex")}`;
}

function toolCallFact(params: {
  runId: string;
  sessionKey: string;
  sessionId: string;
  toolCallId: string;
  toolName: string;
  requestId: string | null;
  ran: boolean;
/** The approval is pending; OpenClaw may run the call before recording its resolution. */
  approvalPending?: boolean;
  serverHello: SessionConfig | null;
}): Record<string, unknown> {
  return { kind: "tool-call", ...params, approvalPending: params.approvalPending ?? false };
}

const APPROVAL_RECORD_POLL_MS = 10;

function isAdmittedRunContext(value: unknown, runId: string, ctx: ToolResultContext): value is Record<string, unknown> & {
  runId: string;
  sessionKey: string;
  sessionId: string;
  userContext?: UserContext;
} {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  // ACS makes `user_context` optional when no person started the run.
  const person = candidate.userContext;
  return candidate.runId === runId &&
    typeof candidate.sessionKey === "string" && candidate.sessionKey === ctx.sessionKey &&
    typeof candidate.sessionId === "string" && candidate.sessionId === ctx.sessionId &&
    candidate.terminal !== true &&
    (person === undefined || person === null ||
      (typeof person === "object" &&
        typeof (person as Record<string, unknown>).user_id === "string" &&
        typeof (person as Record<string, unknown>).authentication_method === "string"));
}

function isToolCallContext(value: unknown, event: ToolResultEvent, runId: string, ctx: ToolResultContext): value is Record<string, unknown> & {
  requestId: string | null;
  ran: boolean;
  approvalPending: boolean;
} {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return candidate.kind === "tool-call" && candidate.runId === runId &&
    candidate.sessionKey === ctx.sessionKey && candidate.sessionId === ctx.sessionId &&
    candidate.toolCallId === event.toolCallId && candidate.toolName === event.toolName &&
    (candidate.requestId === null || typeof candidate.requestId === "string") &&
    typeof candidate.ran === "boolean" && typeof candidate.approvalPending === "boolean";
}

/** Maps each result block to one `steps/toolCallResult` output. */
function outputsOf(content: readonly ToolResultBlock[]): Array<{ value: unknown }> {
  return content.map((block) => ({ value: block.type === "text" ? block.text : block }));
}

// OpenClaw 2026.10.9 truncates larger results (src/agents/harness/tool-result-middleware.ts).
// A rewrite must fit these host limits to reach the model unchanged.
const MAX_MIDDLEWARE_CONTENT_BLOCKS = 200;
const MAX_MIDDLEWARE_TEXT_CHARS = 100_000;
const MAX_MIDDLEWARE_IMAGE_DATA_CHARS = 5_000_000;

/** Converts Guardian outputs to tool-result blocks, or returns `undefined` for unsupported or oversized content. */
function contentOf(outputs: unknown): ToolResultBlock[] | undefined {
  if (!Array.isArray(outputs) || outputs.length > MAX_MIDDLEWARE_CONTENT_BLOCKS) {
    return undefined;
  }
  const content: ToolResultBlock[] = [];
  for (const output of outputs) {
    const value = (output as { value?: unknown } | null)?.value;
    if (typeof value === "string") {
      if (value.length > MAX_MIDDLEWARE_TEXT_CHARS) {
        return undefined;
      }
      content.push({ type: "text", text: value });
      continue;
    }
    const image = value as { type?: unknown; data?: unknown; mimeType?: unknown } | null;
    if (image?.type !== "image" || typeof image.data !== "string" || image.data.length > MAX_MIDDLEWARE_IMAGE_DATA_CHARS ||
      typeof image.mimeType !== "string" || image.mimeType.trim() === "") {
      return undefined;
    }
    content.push({ type: "image", data: image.data, mimeType: image.mimeType });
  }
  return content;
}

type AskDetails = {
  approver?: { type?: unknown; id?: unknown };
  question?: unknown;
  context?: unknown;
  timeout_seconds: number;
};

function wrapArguments(params: Record<string, unknown>): Record<string, { value: unknown }> {
  return Object.fromEntries(Object.entries(params).map(([name, value]) => [name, { value }]));
}

/**
 * Combines the Guardian's question and optional context for the OpenClaw prompt.
 */
function approvalDescription(details: AskDetails, decision: AcsDecision): string {
  const question = typeof details.question === "string" && details.question !== "" ? details.question : reasoningOf(decision);
  return typeof details.context === "string" && details.context !== "" ? `${question}\n${details.context}` : question;
}

export function createToolCallGate({ exchange, audit, logger, runFacts }: CreateHooksOptions, state: HookState, confirmDecision: ConfirmDecision) {
  const { runs, sessionIdOf, decidedCalls, refuse, auditSubstitution, isAllowed, runFactsUntil } = state;

  function approvalFor(
    toolName: string,
    params: Record<string, unknown>,
    decision: AcsDecision,
    sessionId: string,
    requestId: string | null,
    onResolved: (approved: boolean) => Promise<void> | void,
  ): BeforeToolCallResult {
    const details = decision.ask_details as AskDetails;
    const approverId = typeof details.approver?.id === "string" ? details.approver.id : "";
    const approverType = typeof details.approver?.type === "string" ? details.approver.type : "";
    // OpenClaw approvals go only to people; do not replace an agent or service approver.
    if (approverType !== "human") {
      auditSubstitution(sessionId, METHODS.toolCallRequest, requestId, "ask", "approver_unavailable");
      return {
        block: true,
        blockReason: `${reasoningOf(decision)} (an approver of type ${JSON.stringify(approverType)} cannot be reached from this host; it puts approvals to a person only)`,
      };
    }
    // Truncating an approval prompt would change the Guardian's question.
    const description = approvalDescription(details, decision);
    if (toolName.length > APPROVAL_TITLE_MAX || description.length > APPROVAL_DESCRIPTION_MAX) {
      auditSubstitution(sessionId, METHODS.toolCallRequest, requestId, "ask", "approval_text_too_long");
      return {
        block: true,
        blockReason: `${reasoningOf(decision)} (OpenClaw shows an approval's title in ${APPROVAL_TITLE_MAX} characters and its description in ${APPROVAL_DESCRIPTION_MAX}, and the tool's name or the Guardian's question is longer; nothing ran and no approval was created)`,
      };
    }
    return {
      params,
      requireApproval: {
        title: toolName,
        description,
        timeoutMs: details.timeout_seconds * 1000,
        allowedDecisions: ["allow-once", "deny"],
    // OpenClaw calls this before running an approved call.
        onResolution(resolution: ApprovalResolution): void {
          // OpenClaw does not await this and runs approved calls at once.
          // `governToolResult` waits for this record.
          const approved = resolution === "allow-once";
          void Promise.resolve(onResolved(approved)).catch((error: unknown) => {
            logger.error(`ACS plugin could not record the approval's resolution: ${(error as Error).message}`);
          });
          audit.write({
            session_id: sessionId,
            method: METHODS.toolCallRequest,
            rpc_id: requestId,
            outcome: "approval",
            approval: {
              requested_approver: { type: approverType, id: approverId },
              resolution,
              decision: approved ? "allow" : "deny",
            },
          });
        },
      },
    };
  }

  async function governToolCall(event: BeforeToolCallEvent, ctx: ToolContext): Promise<BeforeToolCallResult> {
    const deadlineAt = exchange.deadlineFromNow();
    const withoutDecision = async (why: string): Promise<BeforeToolCallResult> => {
      const { decision } = await exchange.withoutDecision(METHODS.toolCallRequest, ctx.sessionId ?? sessionIdOf(ctx.sessionKey), why, deadlineAt);
      return decision.decision === "allow" ? undefined : { block: true, blockReason: reasoningOf(decision) };
    };
    if (ctx.runId !== undefined && event.runId !== undefined && ctx.runId !== event.runId) {
      return withoutDecision("OpenClaw names two different runs for the call");
    }
    const runId = ctx.runId ?? event.runId;
    const run = runId === undefined ? undefined : runs.get(runId);
    if (runId === undefined || run === undefined) {
      return withoutDecision("the call's run did not pass before_agent_run in this process");
    }
    const { sessionKey, sessionId, userContext, agentName } = run;
    if ((ctx.sessionKey !== undefined && ctx.sessionKey !== sessionKey) || (ctx.sessionId !== undefined && ctx.sessionId !== sessionId)) {
      return withoutDecision("the call's session is not the session its run started in");
    }
    run.toolCallCount += 1;
    const outcome = await exchange.decide({
      method: METHODS.toolCallRequest,
      sessionId,
      userContext,
      agentName,
      turnId: runId,
      payload: {
        tool: { name: event.toolName },
        arguments: wrapArguments(event.params),
      },
      modificationDocument: { ...event.params },
    }, deadlineAt);
    // Reject the authorization if its run or session changed during the decision.
    if (runs.get(runId) !== run) {
      return { block: true, blockReason: "This call's run or session changed while the Guardian decided." };
    }
    const { decision } = outcome;
    const confirm = async (answer: BeforeToolCallResult): Promise<BeforeToolCallResult> => {
      const current = await confirmDecision({ sessionId, method: METHODS.toolCallRequest }, outcome, deadlineAt);
      return current.decision.decision === "deny" ? { block: true, blockReason: reasoningOf(current.decision) } : answer;
    };
    // OpenClaw links the result to this decision by tool call id.
    const callId = event.toolCallId ?? ctx.toolCallId;
    const decided: DecidedCall = { run, requestId: outcome.requestId, ran: false, serverHello: exchange.serverHelloOf(sessionId) ?? null };
    const facts = runFactsUntil(deadlineAt);
    if (callId !== undefined) {
      decidedCalls.set(callKey(runId, callId), decided);
      if (!(await facts.setIfAbsent(runId, callNamespace(callId), toolCallFact({
        runId,
        sessionKey,
        sessionId,
        toolCallId: callId,
        toolName: event.toolName,
        requestId: outcome.requestId,
        ran: false,
        serverHello: decided.serverHello,
      })))) {
        decidedCalls.delete(callKey(runId, callId));
        return { block: true, blockReason: "OpenClaw did not retain this call's authorization context." };
      }
    }
    /**
     * Approval resolution uses the unbounded store after the hook deadline ends.
     */
    const markRan = async (store: RunFactsStore = facts): Promise<void> => {
      if (callId === undefined || runs.get(runId) !== run) {
        return;
      }
      decided.ran = true;
      try {
        await store.set(runId, callNamespace(callId), toolCallFact({
          runId, sessionKey, sessionId, toolCallId: callId,
          toolName: event.toolName, requestId: outcome.requestId, ran: true, serverHello: decided.serverHello,
        }));
      } catch (error) {
        decided.ran = false;
        throw error;
      }
      if (runs.get(runId) !== run) {
        decided.ran = false;
        await store.clear(runId, callNamespace(callId));
      }
    };
    const applied = decision.decision === "modify" ? (decision.applied_input as Record<string, unknown> | undefined) : undefined;
    if (decision.decision === "modify" && applied === undefined) {
      return { block: true, blockReason: "The Guardian's modification could not be applied." };
    }
    switch (decision.decision) {
      case "allow":
        await markRan();
        // This handler runs last, so OpenClaw uses the parameters the Guardian saw.
        return confirm({ params: event.params });
      case "modify":
        await markRan();
        return confirm({ params: applied! });
      case "ask": {
        const approval = approvalFor(event.toolName, event.params, decision, sessionId, outcome.requestId, async (approved) => {
          if (approved) {
            await markRan(runFacts);
          } else if (callId !== undefined) {
            await runFacts.set(runId, callNamespace(callId), toolCallFact({
              runId, sessionKey, sessionId, toolCallId: callId, toolName: event.toolName, requestId: outcome.requestId, ran: false, serverHello: decided.serverHello,
            }));
          }
        });
        if (approval?.requireApproval !== undefined && callId !== undefined) {
          await facts.set(runId, callNamespace(callId), toolCallFact({
            runId, sessionKey, sessionId, toolCallId: callId, toolName: event.toolName, requestId: outcome.requestId, ran: false, approvalPending: true, serverHello: decided.serverHello,
          }));
        }
        return confirm(approval);
      }
      case "defer":
        auditSubstitution(sessionId, METHODS.toolCallRequest, outcome.requestId, "defer", "defer_unsupported");
        return { block: true, blockReason: `Pending: ${reasoningOf(decision)}` };
      default:
        return { block: true, blockReason: reasoningOf(decision) };
    }
  }

  /**
   * The model receives allowed or rewritten results. Other decisions withhold
   * the result. Missing admission context follows README.md#failure-posture.
   */
  async function governToolResult(event: ToolResultEvent, ctx: ToolResultContext): Promise<ToolResultAnswer> {
    const deadlineAt = exchange.deadlineFromNow();
    const facts = runFactsUntil(deadlineAt);
    const runId = ctx.runId;
    const withoutDecision = async (why: string): Promise<ToolResultAnswer> =>
      (await exchange.withoutDecision(METHODS.toolCallResult, ctx.sessionId ?? sessionIdOf(ctx.sessionKey), why, deadlineAt)).decision.decision === "allow" ? undefined : WITHHELD_RESULT;
    const admitted = runId === undefined ? undefined : await facts.get(runId, "admission");
    if (runId === undefined || ctx.runtime !== "openclaw" || ctx.sessionKey === undefined || ctx.sessionId === undefined ||
      !isAdmittedRunContext(admitted, runId, ctx)) {
      return withoutDecision("the result's run did not pass before_agent_run");
    }
    const namespace = callNamespace(event.toolCallId);
    let availableCall = await facts.get(runId, namespace);
    // OpenClaw may run an approved call before it writes the approval record.
    // Wait within the result deadline to learn whether the call ran.
    while (isToolCallContext(availableCall, event, runId, ctx) && availableCall.approvalPending && performance.now() < deadlineAt) {
      await new Promise((resolve) => setTimeout(resolve, APPROVAL_RECORD_POLL_MS));
      availableCall = await facts.get(runId, namespace);
    }
    if (isToolCallContext(availableCall, event, runId, ctx) && availableCall.approvalPending) {
      refuse(ctx.sessionId, METHODS.toolCallResult, "the result's call still awaits the record of its approval");
      return WITHHELD_RESULT;
    }
    if (!isToolCallContext(availableCall, event, runId, ctx)) {
      return withoutDecision("the result's call did not pass before_tool_call");
    }
    const call = await facts.consume(runId, namespace);
    if (!isToolCallContext(call, event, runId, ctx)) {
      return withoutDecision("the result's call was already read");
    }
    decidedCalls.delete(callKey(runId, event.toolCallId));
    const localRun = runs.get(runId);
    const sessionKey = ctx.sessionKey;
    const sessionId = ctx.sessionId;
    const userContext = admitted.userContext ?? undefined;
    const agentName = typeof admitted.agentName === "string" ? admitted.agentName : undefined;
    const payload: Record<string, unknown> = {
      tool: { name: event.toolName },
      exit_status: !call.ran ? "blocked" : event.isError === true ? "failure" : "success",
      outputs: outputsOf(event.result.content),
      ...(call.requestId == null ? {} : { request_id_ref: call.requestId }),
    };
    const outcome = await exchange.decide({
      method: METHODS.toolCallResult,
      sessionId,
      userContext,
      agentName,
      turnId: runId,
      payload,
      ...(call.serverHello !== null && typeof call.serverHello === "object" ? { serverHello: call.serverHello as SessionConfig } : {}),
    }, deadlineAt);
    const currentAdmission = await facts.get(runId, "admission");
    if (!isAdmittedRunContext(currentAdmission, runId, ctx) ||
      (localRun !== undefined && runs.get(runId) !== localRun)) {
      return WITHHELD_RESULT;
    }
    const current = await confirmDecision({ sessionId, method: METHODS.toolCallResult }, outcome, deadlineAt);
    const { decision } = current;
    if (decision.decision === "modify") {
      const content = contentOf((decision.applied_input as { outputs?: unknown } | undefined)?.outputs);
      if (content === undefined) {
        auditSubstitution(sessionId, METHODS.toolCallResult, outcome.requestId, "modify", "modify_unsupported");
        return WITHHELD_RESULT;
      }
      return { result: { content, details: undefined } };
    }
    return isAllowed(current, sessionId, METHODS.toolCallResult) ? undefined : WITHHELD_RESULT;
  }

  return {

    async beforeToolCall(event, ctx) {
      try {
        return await governToolCall(event, ctx);
      } catch (error) {
        return { block: true, blockReason: `The ACS plugin failed: ${(error as Error).message}` };
      }
    },

    async toolResult(event, ctx) {
      try {
        return await governToolResult(event, ctx);
      } catch (error) {
        logger.error(`ACS plugin withheld a tool result: ${(error as Error).message}`);
        return WITHHELD_RESULT;
      }
    },

    // The call record may be read by any registration's result hook.
    async afterToolCall(event, ctx) {
      const callId = event.toolCallId ?? ctx.toolCallId;
      if (callId === undefined) {
        return;
      }
      const runId = ctx.runId ?? event.runId;
      if (runId === undefined) {
        return;
      }
      const decided = decidedCalls.get(callKey(runId, callId));
      if (decided !== undefined) {
        try {
          await runFacts.set(runId, callNamespace(callId), toolCallFact({
            runId,
            sessionKey: decided.run.sessionKey,
            sessionId: decided.run.sessionId,
            toolCallId: callId,
            toolName: event.toolName,
            requestId: decided.requestId,
            ran: decided.ran,
            serverHello: decided.serverHello,
          }));
        } catch (error) {
          logger.error(`ACS plugin could not record tool-call authorization: ${(error as Error).message}`);
        }
      }
    },
  } satisfies Partial<Hooks>;
}
