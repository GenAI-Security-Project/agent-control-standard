/**
 * Each observed delivery becomes agentResponse in the session OpenClaw names, with the sending run's identity when available.
 */
import { METHODS, type UserContext } from "./acs-exchange.ts";
import { mediaUrlsOf, textContent } from "./decisions.ts";
import type { AdmittedRun, HeldAdmission, HookState } from "./hook-state.ts";
import type { ContentItem } from "./inbound-message.ts";
import type { CreateHooksOptions, Hooks } from "./openclaw-hooks.ts";
import type { ReplyPayload } from "./openclaw-types.ts";

/** Joins text items, or returns `undefined` if any item is not text. */
function modifiedTextOf(content: unknown): string | undefined {
  if (!Array.isArray(content)) {
    return undefined;
  }
  const lines: string[] = [];
  for (const item of content) {
    const text = item as { type?: unknown; value?: unknown } | null;
    if (text?.type !== "text" || typeof text.value !== "string") {
      return undefined;
    }
    lines.push(text.value);
  }
  return lines.join("\n");
}

/** Marks a reply whose session changed while the Guardian decided it. */
const STALE = Symbol("stale");

function payloadMediaUrls(payload: ReplyPayload): string[] {
  return [...(payload.mediaUrl === undefined ? [] : [payload.mediaUrl]), ...(payload.mediaUrls ?? [])];
}

/** Structured reply fields sent to the Guardian with text and media. */
const STRUCTURED_PARTS = ["attachments", "presentation", "interactive", "location", "btw", "ttsSupplement", "channelData"] as const;

/**
 * Maps reply text and structured fields to `steps/agentResponse` content.
 * Media URLs become `file` items.
 */
function payloadContent(payload: ReplyPayload): ContentItem[] {
  const texts = [payload.text, payload.fallbackText?.text, payload.spokenText].filter((text): text is string => text !== undefined && text !== "");
  const structured = STRUCTURED_PARTS.filter((part) => payload[part] !== undefined).map((part) => JSON.stringify({ [part]: payload[part] }));
  return [
    ...[...texts, ...structured].map((value) => ({ type: "text" as const, value })),
    ...payloadMediaUrls(payload).map((url) => ({ type: "file" as const, value: url })),
  ];
}

/**
 * Only text and media have a reversible mapping; threading and flags stay
 * unchanged. The adapter blocks modifications to fallback text, spoken text,
 * and structured fields because it cannot reconstruct them (§6.5).
 */
function payloadOf(content: unknown, original: ReplyPayload): ReplyPayload | undefined {
  if (!Array.isArray(content) || original.fallbackText !== undefined || original.spokenText !== undefined ||
    STRUCTURED_PARTS.some((part) => original[part] !== undefined)) {
    return undefined;
  }
  const lines: string[] = [];
  const mediaUrls: string[] = [];
  for (const item of content as Array<{ type?: unknown; value?: unknown } | null>) {
    if (item?.type === "text" && typeof item.value === "string") {
      lines.push(item.value);
    } else if (item?.type === "file" && typeof item.value === "string") {
      mediaUrls.push(item.value);
    } else {
      return undefined;
    }
  }
  const { text: _text, mediaUrl: _mediaUrl, mediaUrls: _mediaUrls, ...rest } = original;
  return { ...rest, ...(lines.length > 0 ? { text: lines.join("\n") } : {}), ...(mediaUrls.length > 0 ? { mediaUrls } : {}) };
}

export function createReplyGate({ exchange }: CreateHooksOptions, state: HookState): Pick<Hooks, "replyPayloadSending" | "messageSending"> {
  const { admittedSessions, runs, sessionIdOf, liveRunsOfSession, soleLiveRun, endedRunOfSession, endedRuns, undecidedInbound, refuse, auditSubstitution, isAllowed } = state;

  /**
   * OpenClaw delivers final replies after `agent_end`, so a reply may need the last ended run.
   */
  function authorOf(sessionKey: string, runId: string | undefined): string | undefined {
    if (runId !== undefined) {
      return runId;
    }
    return liveRunsOfSession.has(sessionKey) ? soleLiveRun(sessionKey) : endedRunOfSession.get(sessionKey);
  }

  /** Returns the live or last ended run named by `runId`. */
  function runOf(sessionKey: string, runId: string): AdmittedRun | undefined {
    return runs.get(runId) ?? (endedRunOfSession.get(sessionKey) === runId ? endedRuns.get(sessionKey) : undefined);
  }

  /**
   * A run must confirm a restored admission before a reply can use it.
   */
  function replySession(sessionKey: string | undefined, runId: string | undefined): { sessionKey: string; admitted: HeldAdmission } | string {
    if (sessionKey === undefined) {
      return "OpenClaw names no session for the reply";
    }
    const admitted = admittedSessions.get(sessionKey);
    if (admitted === undefined || !admitted.confirmed) {
      return "no run of this session was admitted in this process";
    }
    // Pending input cannot authorize a reply from a run that skipped `before_agent_run`.
    // An explicit run id still identifies its final reply after `agent_end`, even with pending input.
    const endedRunReplies = runId !== undefined && runId === endedRunOfSession.get(sessionKey);
    if (!liveRunsOfSession.has(sessionKey) && !endedRunReplies && (undecidedInbound.get(sessionKey)?.length ?? 0) > 0) {
      return "the session holds messages no admitted run took in, and has no admitted run";
    }
    return { sessionKey, admitted };
  }

  /**
   * Prevents a run without a sender from inheriting the session's person.
   */
  function personlessRunOf(sessionKey: string | undefined, runId: string | undefined): { runId: string; run: AdmittedRun } | undefined {
    const author = sessionKey === undefined ? runId : authorOf(sessionKey, runId);
    const run = author === undefined ? undefined : sessionKey === undefined ? runs.get(author) : runOf(sessionKey, author);
    return author !== undefined && run !== undefined && run.userContext === undefined ? { runId: author, run } : undefined;
  }

  /**
   * A reply after `turnEnd` carries no `turn_id` (`turn-end.json`).
   */
  function turnOf(sessionKey: string, runId: string | undefined): string | undefined {
    const author = runId ?? soleLiveRun(sessionKey);
    return author !== undefined && liveRunsOfSession.get(sessionKey)?.has(author) === true ? author : undefined;
  }

  type ResponseStep = { sessionId: string; userContext?: UserContext; agentName?: string; turnId?: string };

  /**
   * Returns the reply's `agentResponse` step and checks that its run or
   * session still matches after the decision.
   */
  function stepFor(sessionKey: string | undefined, runId: string | undefined): { step: ResponseStep; isCurrent: () => boolean } | string {
    const personless = personlessRunOf(sessionKey, runId);
    if (personless !== undefined) {
      const { run, runId: author } = personless;
      return {
        step: { sessionId: run.sessionId, agentName: run.agentName, turnId: turnOf(run.sessionKey, author) },
        isCurrent: () => runs.get(author) === run || endedRuns.get(run.sessionKey) === run,
      };
    }
    const found = replySession(sessionKey, runId);
    if (typeof found === "string") {
      return found;
    }
    // A reply acts for the person whose message started its run.
    const author = authorOf(found.sessionKey, runId);
    const run = author === undefined ? undefined : runOf(found.sessionKey, author);
    return {
      step: {
        sessionId: found.admitted.sessionId,
        // This process has no sender for a run it no longer holds. The session's
        // admitted sender may belong to another run.
        userContext: runId !== undefined ? run?.userContext : run?.userContext ?? found.admitted.userContext,
        agentName: found.admitted.agentName,
        turnId: turnOf(found.sessionKey, runId),
      },
      // The session may end or restart while the Guardian decides.
      // Do not send the reply into the new session.
      isCurrent: () => admittedSessions.get(found.sessionKey) === found.admitted,
    };
  }

  /**
   * Sends `agentResponse` for a delivery. Returns `undefined` when blocked or
   * `STALE` if the run or session changed while the Guardian decided.
   */
  async function decideResponse(
    step: ResponseStep,
    content: string,
    mediaUrls: readonly string[],
    isCurrent: () => boolean,
  ): Promise<string | undefined | typeof STALE> {
    const payload = { content: [...(textContent(content).content as unknown[]), ...mediaUrls.map((url) => ({ type: "file", value: url }))] };
    const outcome = await exchange.decide({ ...step, method: METHODS.agentResponse, payload });
    if (!isCurrent()) {
      return STALE;
    }
    if (outcome.decision.decision === "modify") {
      // `message_sending` rewrites text only. It would still send the media.
      const text = mediaUrls.length > 0 ? undefined : modifiedTextOf((outcome.decision.applied_input as { content?: unknown } | undefined)?.content);
      if (text === undefined) {
        auditSubstitution(step.sessionId, METHODS.agentResponse, outcome.requestId, "modify", "modify_unsupported");
      }
      return text;
    }
    return isAllowed(outcome, step.sessionId, METHODS.agentResponse) ? content : undefined;
  }

  return {
    // OpenClaw sends the original payload if this hook throws or times out, so failures must cancel it.
    async replyPayloadSending(event, ctx) {
      const sessionKey = event.sessionKey ?? ctx.sessionKey;
      try {
        const found = stepFor(sessionKey, event.runId ?? ctx.runId);
        if (typeof found === "string") {
          return (await exchange.withoutDecision(METHODS.agentResponse, sessionIdOf(sessionKey), found)).decision.decision === "allow" ? undefined : { cancel: true };
        }
        const { step, isCurrent } = found;
        const outcome = await exchange.decide({ ...step, method: METHODS.agentResponse, payload: { content: payloadContent(event.payload) } });
        if (!isCurrent()) {
          return { cancel: true };
        }
        const { decision } = outcome;
        if (decision.decision === "modify") {
          const payload = payloadOf((decision.applied_input as { content?: unknown } | undefined)?.content, event.payload);
          if (payload !== undefined) {
            return { payload };
          }
          auditSubstitution(step.sessionId, METHODS.agentResponse, outcome.requestId, "modify", "modify_unsupported");
          return { cancel: true };
        }
        return isAllowed(outcome, step.sessionId, METHODS.agentResponse) ? undefined : { cancel: true };
      } catch (error) {
        refuse(sessionKey, METHODS.agentResponse, `the ACS plugin failed: ${error instanceof Error ? error.message : String(error)}`);
        return { cancel: true };
      }
    },

    // Every delivery, including tool sends, uses this hook. OpenClaw sends the
    // original on timeout, so an unsendable step follows the failure posture
    // (§6.4) and unexpected failures cancel it.
    async messageSending(event, ctx) {
      try {
        const found = stepFor(ctx.sessionKey, ctx.runId);
        if (typeof found === "string") {
          return (await exchange.withoutDecision(METHODS.agentResponse, sessionIdOf(ctx.sessionKey), found)).decision.decision === "allow" ? undefined : { cancel: true };
        }
        const decided = await decideResponse(found.step, event.content, mediaUrlsOf(event.metadata), found.isCurrent);
        return decided === STALE || decided === undefined ? { cancel: true } : { content: decided };
      } catch (error) {
        refuse(ctx.sessionKey, METHODS.agentResponse, `the ACS plugin failed: ${error instanceof Error ? error.message : String(error)}`);
        return { cancel: true };
      }
    },
  } satisfies Partial<Hooks>;
}
