/**
 * Carries sender identity through admission, messages and lifecycle steps.
 * See mapping.md for step order and the host paths covered by each hook.
 */
import { METHODS, type DecisionFailures, type Step, type StepOutcome, type UserContext } from "./acs-exchange.ts";
import { blockedRun, droppedMessage, reasoningOf, textContent } from "./decisions.ts";
import type { AdmittedRun, HookState, PendingAdmission } from "./hook-state.ts";
import type { ConfirmDecision, CreateHooksOptions, Hooks } from "./openclaw-hooks.ts";
import { channelOf, inboundContent } from "./inbound-message.ts";
import type { AgentContext, BeforeAgentRunEvent, ReplyDispatchEvent } from "./openclaw-types.ts";

/** OpenClaw's `session_end` reasons that end the process, not the session. */
const PROCESS_END_REASONS = new Set(["shutdown", "restart"]);

function deleteWhere<K, V>(map: Map<K, V>, isGone: (value: V) => boolean): void {
  for (const [key, value] of map) {
    if (isGone(value)) {
      map.delete(key);
    }
  }
}

/**
 * A missing failure count means unmeasurable, not zero (§6.4).
 */
function summaryOf(failures: DecisionFailures | undefined): { summary?: { decision_failures: DecisionFailures } } {
  return failures === undefined ? {} : { summary: { decision_failures: failures } };
}

/** ACS `sessionEnd.reason` for OpenClaw's `session_end` reason. */
function sessionEndReasonOf(reason: string | undefined): string {
  switch (reason) {
    case "new":
    case "reset":
    case "deleted":
    case "compaction":
      return "completed";
    case "idle":
    case "daily":
      return "timeout";
    default:
      return "abandoned";
  }
}

/** Maps OpenClaw's trigger to ACS `agentTrigger.trigger_type`. No trigger with a channel sender means a user run. */
function triggerTypeOf(trigger: string | undefined): string {
  switch (trigger) {
    case undefined:
    case "user":
      return "user_message";
    case "cron":
      return "scheduled";
    default:
      return "system";
  }
}

type Origin = {
  /** Absent when no person started the run, such as a heartbeat or system event. */
  userContext?: UserContext;
  channel: string;
  triggerType: string;
  turnTrigger: string;
  /** Whether admission lets this sender use the session for later sends. */
  admitsSession: boolean;
};


type OpenedTurn = Pick<AdmittedRun, "sessionId" | "userContext" | "agentName"> & { turnId: string };
type TurnOutcome = "completed" | "error" | "interrupted" | "denied_at_start";

export function createRunGate({ config, exchange, logger, runFacts, refusals }: CreateHooksOptions, state: HookState, confirmDecision: ConfirmDecision) {
  const { revokeRunFacts, admittedSessions, restored, until, admit, forgetAdmission, runs, liveRunsOfSession, addLiveRun, endLiveRun, undecidedInbound, endedRunOfSession, endedRuns, pendingAdmissions, startedSessions, startedSessionSteps, decidedCalls, sessionIdOfKey, sessionIdOf, auditSubstitution, isAllowed, isRestored, beforeDeadline, runFactsUntil } = state;

  /**
   * A `sessionStart` refusal overrides a concurrent `allow`. A failure-posture
   * allow leaves `sessionStart` undecided for the next run.
   */
  function recordSessionStart(sessionId: string, outcome: StepOutcome, allowed: boolean, steps: { userContext?: UserContext; agentName?: string }): void {
    if (outcome.stage === "delivery") {
      return;
    }
    if (!allowed) {
      startedSessions.set(sessionId, `the Guardian refused this session: ${reasoningOf(outcome.decision)}`);
    } else if (startedSessions.get(sessionId) === undefined) {
      startedSessions.set(sessionId, true);
      startedSessionSteps.set(sessionId, steps);
    }
  }

  /**
   * Runs without a sender omit `user_context` and do not admit a session for later sends.
   */
  function personless(ctx: AgentContext): Origin {
    const scheduled = ctx.trigger === "cron";
    return {
      channel: ctx.channel ?? "",
      triggerType: scheduled ? "scheduled" : "system",
      turnTrigger: scheduled ? "scheduled" : "external_event",
      admitsSession: false,
    };
  }

  /**
   * Scheduled runs inherit the session's admitted sender. Other runs use only the sender OpenClaw names.
   */
  function originOf(event: BeforeAgentRunEvent, ctx: AgentContext, sessionKey: string, sessionId: string): Origin | string {
    const senderId = event.senderId ?? ctx.senderId;
    if (senderId !== undefined) {
      if (ctx.channel === undefined) {
        return "the run carries no channel";
      }
      return {
        userContext: { user_id: senderId, authentication_method: ctx.channel },
        channel: ctx.channel,
        triggerType: triggerTypeOf(ctx.trigger),
        turnTrigger: "user_message",
        admitsSession: true,
      };
    }
    if (ctx.trigger !== "cron" || !isRestored()) {
      return personless(ctx);
    }
    // A scheduled run acts for the person who opened the session it runs in.
    const admitted = admittedSessions.get(sessionKey);
    if (admitted === undefined || admitted.sessionId !== sessionId) {
      return personless(ctx);
    }
    return {
      userContext: admitted.userContext,
      channel: admitted.userContext.authentication_method,
      triggerType: "scheduled",
      turnTrigger: "scheduled",
      // A matching session id proves the restored candidate's session runs.
      admitsSession: !admitted.confirmed,
    };
  }

  /**
   * Blocks a user message the adapter cannot send (README.md#failure-posture).
   * Returns `undefined` when allowed, or the reason the step is blocked.
   */
  async function withoutDecision(sessionId: string | undefined, why: string, deadlineAt: number): Promise<string | undefined> {
    const { decision } = await exchange.withoutDecision(METHODS.userMessage, sessionId, why, deadlineAt);
    return decision.decision === "allow" ? undefined : reasoningOf(decision);
  }

  /** Sends audit-only `turnEnd`; a non-`allow` answer cannot change the ended turn. */
  async function endTurn(turn: OpenedTurn, outcome: TurnOutcome, toolCallCount: number, deadlineAt?: number): Promise<void> {
    try {
      const answer = await exchange.decide({
        method: METHODS.turnEnd,
        sessionId: turn.sessionId,
        userContext: turn.userContext,
        agentName: turn.agentName,
        payload: { turn_id: turn.turnId, outcome, tool_call_count: toolCallCount },
        turnId: turn.turnId,
      }, deadlineAt);
      if (answer.stage === "honoured" && answer.decision.decision !== "allow") {
        auditSubstitution(turn.sessionId, METHODS.turnEnd, answer.requestId, answer.decision.decision, "not_decision_eligible");
      }
    } catch (error) {
      logger.error(`ACS plugin could not send steps/turnEnd: ${(error as Error).message}`);
    }
  }

  /**
   * Returns `undefined` when the run may start, or its block reason. If the
   * adapter already sent `turnStart`, it attempts `turnEnd` with
   * `denied_at_start` before the hook deadline (`turn-end.json`).
   */
  async function governRun(event: BeforeAgentRunEvent, ctx: AgentContext): Promise<string | undefined> {
    const opened: { turn?: OpenedTurn & { refusedAtStart: boolean; deadlineAt: number } } = {};
    let ended: TurnOutcome | undefined = "error";
    try {
      const refusal = await admitRun(event, ctx, opened);
      ended = refusal === undefined ? undefined : "interrupted";
      return refusal;
    } finally {
      const turn = opened.turn;
      if (ended !== undefined && turn !== undefined) {
        await endTurn(turn, turn.refusedAtStart ? "denied_at_start" : ended, 0, turn.deadlineAt);
      }
    }
  }

  /**
   * Orders admissions per session so it sends `sessionStart` once. The final
   * check and state change must stay synchronous to prevent a competing admission.
   */
  function pendingOf(sessionKey: string): PendingAdmission | undefined {
    return [...pendingAdmissions.values()].find((entry) => entry.sessionKey === sessionKey);
  }

  async function admitRun(
    event: BeforeAgentRunEvent,
    ctx: AgentContext,
    opened: { turn?: OpenedTurn & { refusedAtStart: boolean; deadlineAt: number } },
  ): Promise<string | undefined> {
    const deadlineAt = exchange.deadlineFromNow();
    await until(restored(), deadlineAt);
    const { sessionKey, sessionId, runId } = ctx;
    if (sessionKey !== undefined && sessionId !== undefined) {
      sessionIdOfKey.set(sessionKey, sessionId);
    }
    if (sessionKey === undefined || sessionId === undefined || runId === undefined) {
      return withoutDecision(sessionId ?? sessionIdOf(sessionKey), "OpenClaw names no session or run id for the run", deadlineAt);
    }
    const origin = originOf(event, ctx, sessionKey, sessionId);
    if (typeof origin === "string") {
      return withoutDecision(sessionId, origin, deadlineAt);
    }
    const { userContext, channel } = origin;
    const agentName = ctx.agentId;
    for (let earlier = pendingOf(sessionKey); earlier !== undefined; earlier = pendingOf(sessionKey)) {
      await beforeDeadline(earlier.settled, deadlineAt, "admitting the session's run");
    }
    const started = startedSessions.get(sessionId);
    if (typeof started === "string") {
      // A refused session admits no later run. Drop its queued messages.
      undecidedInbound.delete(sessionKey);
      return started;
    }
    let settle!: () => void;
    const pending: PendingAdmission = { sessionKey, ended: false, settled: new Promise<void>((resolve) => (settle = resolve)) };
    pendingAdmissions.set(runId, pending);
    // Capture queued messages for this admission. Later messages wait for it.
    // Use the host prompt only when no message was queued, as with `chat.send`.
    const undecided = undecidedInbound.get(sessionKey) ?? [];
    undecidedInbound.delete(sessionKey);
    let decidedCount = 0;
    /**
     * Put unanswered messages before new arrivals. Do not return answered
     * messages because a refusal would block every later run.
     */
    const leaveUndecided = () => {
      const left = undecided.slice(decidedCount);
      if (left.length > 0) {
        undecidedInbound.set(sessionKey, [...left, ...(undecidedInbound.get(sessionKey) ?? [])]);
      }
    };
    // Session and activation steps precede the turn and have no `turn_id` (`request-envelope.json`).
    const byPerson = origin.triggerType === "user_message";
    const runSteps: Array<Pick<Step, "method" | "payload" | "turnId" | "userContext"> & { undecided?: boolean }> = [
      ...(started === undefined
        ? [{ method: METHODS.sessionStart, payload: { ...(userContext === undefined ? {} : { user_identity: userContext }), platform_context: { channel } } }]
        : []),
      // ACS-Core requires `userMessage` or `agentTrigger`. A user's message identifies the activation.
      ...(byPerson
        ? []
        : [{ method: METHODS.agentTrigger, payload: { trigger_type: origin.triggerType, trigger_source: { channel, prompt: event.prompt } } }]),
      { method: METHODS.turnStart, payload: { turn_id: runId, triggered_by: origin.turnTrigger }, turnId: runId },
      ...(byPerson && undecided.length === 0
        ? [{ method: METHODS.userMessage, payload: textContent(event.prompt), turnId: runId }]
        : []),
      // Each held message keeps its sender, even when the run acts for someone else.
      ...undecided.map((held) => ({ method: METHODS.userMessage, payload: { content: held.content }, turnId: runId, undecided: true, userContext: held.userContext ?? userContext })),
    ];
    let lastDecision!: { step: Pick<Step, "sessionId" | "method">; outcome: StepOutcome };
    try {
      for (const { undecided: isUndecided, ...runStep } of runSteps) {
        const outcome = await exchange.decide({ userContext, agentName, ...runStep, sessionId }, deadlineAt);
        lastDecision = { step: { sessionId, method: runStep.method }, outcome };
        if (isUndecided) {
          decidedCount += 1;
        }
        const allowed = isAllowed(outcome, sessionId, runStep.method);
        if (runStep.method === METHODS.turnStart) {
          opened.turn = { sessionId, userContext, agentName, turnId: runId, refusedAtStart: !allowed, deadlineAt };
        }
        if (runStep.method === METHODS.sessionStart) {
          recordSessionStart(sessionId, outcome, allowed, { userContext, agentName });
        }
        if (!allowed) {
          if (typeof startedSessions.get(sessionId) === "string") {
            undecidedInbound.delete(sessionKey);
          } else {
            leaveUndecided();
          }
          return reasoningOf(outcome.decision);
        }
      }
    } catch (error) {
      leaveUndecided();
      throw error;
    } finally {
      if (pendingAdmissions.get(runId) === pending) {
        pendingAdmissions.delete(runId);
      }
      settle();
    }
    // Keep this check and the run binding synchronous; OpenClaw may end or replace the run during the wait.
    if (pending.ended) {
      leaveUndecided();
      return "the run or its session ended while the Guardian decided";
    }
    const startedAfter = startedSessions.get(sessionId);
    if (typeof startedAfter === "string") {
      leaveUndecided();
      return startedAfter;
    }
    const run: AdmittedRun = {
      sessionKey,
      sessionId,
      userContext,
      agentName,
      toolCallCount: 0,
    };
    runs.set(runId, run);
    addLiveRun(sessionKey, runId);
    endedRunOfSession.delete(sessionKey);
    endedRuns.delete(sessionKey);
    const held = admittedSessions.get(sessionKey);
    const sessionStarted = startedSessions.get(sessionId) === true;
    try {
      if (origin.admitsSession && userContext !== undefined && (held?.sessionId !== sessionId || !held.confirmed || held.sessionStarted !== sessionStarted)) {
        await beforeDeadline(admit(sessionKey, { sessionId, userContext, agentName, sessionStarted }), deadlineAt, "storing the admitted session in OpenClaw's plugin state");
        // OpenClaw may end the run while admission is written. Then it is not
        // admitted, and session cleanup forgets the stored admission.
        if (runs.get(runId) !== run) {
          return "the run or its session ended while it was admitted";
        }
      }
      await runFactsUntil(deadlineAt).set(runId, "admission", {
        runId,
        sessionKey,
        sessionId,
        userContext,
        agentName: agentName ?? null,
      });
      const confirmed = await confirmDecision(lastDecision.step, lastDecision.outcome, deadlineAt);
      if (confirmed.decision.decision !== "allow") {
        runs.delete(runId);
        endLiveRun(sessionKey, runId);
        return reasoningOf(confirmed.decision);
      }
    } catch (error) {
      runs.delete(runId);
      endLiveRun(sessionKey, runId);
      return `OpenClaw did not retain this run's admission context: ${(error as Error).message}`;
    }
    return undefined;
  }

  /**
   * Waits for pending admission before selecting a run. Without an active
   * run, the next `before_agent_run` decides the held message and attachments.
   */
  async function governDispatch(event: ReplyDispatchEvent): Promise<string | undefined> {
    const deadlineAt = exchange.deadlineFromNow();
    const message = event.ctx;
    const sessionKey = message.SessionKey;
    if (sessionKey === undefined) {
      return withoutDecision(undefined, "OpenClaw names no session for the message", deadlineAt);
    }
    const senderId = message.SenderId;
    const inbound = await beforeDeadline(inboundContent(event, config.maxAttachmentBytes), deadlineAt, "reading the message's attachments");
    if ("refused" in inbound) {
      return withoutDecision(sessionIdOf(sessionKey), inbound.refused, deadlineAt);
    }
    // If this wait exceeds the hook deadline, replyDispatch drops the message.
    for (let earlier = pendingOf(sessionKey); earlier !== undefined; earlier = pendingOf(sessionKey)) {
      await beforeDeadline(earlier.settled, deadlineAt, "admitting the session's run");
    }
    const live = [...(liveRunsOfSession.get(sessionKey) ?? [])].flatMap((id) => {
      const run = runs.get(id);
      return run === undefined ? [] : [{ runId: id, run }];
    });
    if (live.length === 0) {
      const waiting = undecidedInbound.get(sessionKey) ?? [];
      if (waiting.length >= config.maxUndecidedMessages) {
        return withoutDecision(sessionIdOf(sessionKey), `the session already holds ${waiting.length} messages no run has taken in`, deadlineAt);
      }
      const sender = senderId === undefined ? undefined : { user_id: senderId, authentication_method: channelOf(message) };
      undecidedInbound.set(sessionKey, [...waiting, { content: inbound.content, ...(sender === undefined ? {} : { userContext: sender }) }]);
      return undefined;
    }
    const { sessionId, agentName } = live[0]!.run;
    if (live.some(({ run }) => run.sessionId !== sessionId)) {
      return withoutDecision(sessionIdOf(sessionKey), "the session's live runs are in different OpenClaw sessions, so the session the message joins cannot be known", deadlineAt);
    }
    // The message keeps its sender. With several live runs, OpenClaw names no
    // target run, so the message carries no turn.
    const sole = live.length === 1 ? live[0]! : undefined;
    const userContext = senderId === undefined ? sole?.run.userContext : { user_id: senderId, authentication_method: channelOf(message) };
    const outcome = await exchange.decide({
      method: METHODS.userMessage,
      sessionId,
      userContext,
      agentName,
      ...(sole === undefined ? {} : { turnId: sole.runId }),
      payload: { content: inbound.content },
    }, deadlineAt);
    if (!isAllowed(outcome, sessionId, METHODS.userMessage)) {
      return reasoningOf(outcome.decision);
    }
    // If all runs end while the Guardian decides, OpenClaw holds the allowed
    // message for its next run and sends it again as that run's prompt.
    return undefined;
  }

  return {
    async beforeAgentRun(event, ctx) {
      let blockedBecause: string | undefined;
      try {
        blockedBecause = await governRun(event, ctx);
      } catch (error) {
        blockedBecause = `the ACS plugin failed: ${(error as Error).message}`;
      }
      if (blockedBecause === undefined) {
        return undefined;
      }
      return blockedRun(blockedBecause);
    },

    // OpenClaw dispatches the message if this hook throws or declines.
    // Return a claimed dispatch for every failure.
    async replyDispatch(event, ctx) {
      let refusedBecause: string | undefined;
      try {
        refusedBecause = await governDispatch(event);
      } catch (error) {
        refusedBecause = `the ACS plugin failed: ${(error as Error).message}`;
      }
      if (refusedBecause === undefined) {
        return undefined;
      }
      logger.error(`ACS plugin dropped an inbound message: ${refusedBecause}`);
      return droppedMessage(ctx, refusedBecause);
    },

    async gatewayStart() {
      await restored();
      await runFacts.pruneOtherProcesses();
    },

    async agentEnd(event, ctx) {
      const runId = event.runId ?? ctx.runId;
      const pending = runId === undefined ? undefined : pendingAdmissions.get(runId);
      if (pending !== undefined) {
        pending.ended = true;
      }
      const run = runId === undefined ? undefined : runs.get(runId);
      if (runId !== undefined) {
        if (run !== undefined) {
          runs.delete(runId);
          deleteWhere(decidedCalls, (call) => call.run === run);
          if (endLiveRun(run.sessionKey, runId)) {
            endedRunOfSession.set(run.sessionKey, runId);
            endedRuns.set(run.sessionKey, run);
          }
        }
        await revokeRunFacts(runId);
      }
      if (runId === undefined || run === undefined) {
        return;
      }
      await endTurn({ ...run, turnId: runId }, event.success === false ? "error" : "completed", run.toolCallCount);
    },

    async sessionEnd(event, ctx) {
      const sessionKey = event.sessionKey ?? ctx.sessionKey;
      const { sessionId } = event;
      // An ordinary reset keeps OpenClaw's session id, so ACS keeps its session (`session-start.json`).
      if (event.nextSessionId === sessionId) {
        return;
      }
      const started = startedSessionSteps.get(sessionId);
      startedSessionSteps.delete(sessionId);
      const admitted = sessionKey === undefined ? undefined : admittedSessions.get(sessionKey);
      // A process restart ends runs but preserves the session and its admission.
      const processEnds = event.reason !== undefined && PROCESS_END_REASONS.has(event.reason);
      if (sessionKey !== undefined) {
        const forget = !processEnds && admitted !== undefined && admitted.sessionId === sessionId
          ? forgetAdmission(sessionKey)
          : undefined;
        const endedRunIds: string[] = [];
        for (const [runId, run] of runs) {
          if (run.sessionKey === sessionKey) {
            runs.delete(runId);
            endedRunIds.push(runId);
          }
        }
        deleteWhere(decidedCalls, (call) => call.run.sessionKey === sessionKey);
        for (const pending of pendingAdmissions.values()) {
          if (pending.sessionKey === sessionKey) {
            pending.ended = true;
          }
        }
        liveRunsOfSession.delete(sessionKey);
        sessionIdOfKey.delete(sessionKey);
        endedRunOfSession.delete(sessionKey);
        endedRuns.delete(sessionKey);
        startedSessions.delete(sessionId);
        await Promise.all(endedRunIds.map((runId) => revokeRunFacts(runId)));
        await forget;
      }
      if (processEnds) {
        return;
      }
      // `sessionEnd` is audit-only (`hooks.md`). The next OpenClaw session id starts a new ACS session.
      const ender = admitted?.sessionId === sessionId ? admitted : started;
      if (ender !== undefined) {
        try {
          const deadlineAt = exchange.deadlineFromNow();
          const failures = await beforeDeadline(exchange.decisionFailures(sessionId), deadlineAt, "reading the session's decision failures from OpenClaw's plugin state")
            .catch((error: unknown) => {
              logger.error(`ACS plugin sends steps/sessionEnd without decision_failures: ${(error as Error).message}`);
              return undefined;
            });
          const outcome = await exchange.decide({
            method: METHODS.sessionEnd,
            sessionId,
            userContext: ender.userContext,
            agentName: ender.agentName,
            payload: { reason: sessionEndReasonOf(event.reason), ...summaryOf(failures) },
          }, deadlineAt);
          if (outcome.stage === "honoured" && outcome.decision.decision !== "allow") {
            auditSubstitution(sessionId, METHODS.sessionEnd, outcome.requestId, outcome.decision.decision, "not_decision_eligible");
          }
        } catch (error) {
          logger.error(`ACS plugin could not send steps/sessionEnd: ${(error as Error).message}`);
        }
      }
      exchange.forget(sessionId);
      await until(
        refusals.delete(sessionId).catch((error: unknown) => logger.error(`ACS plugin could not delete the session's refusal: ${(error as Error).message}`)),
        exchange.deadlineFromNow(),
      );
    },
  } satisfies Partial<Hooks>;
}
