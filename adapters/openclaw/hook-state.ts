/**
 * The hooks share admitted sessions, runs, pending messages and tool-call decisions.
 * mapping.md describes the lifecycle of these records.
 */
import type { SessionRefusal, StepOutcome, UserContext } from "./acs-exchange.ts";
import type { SessionConfig } from "./host-adapter.ts";
import type { ContentItem } from "./inbound-message.ts";
import type { CreateHooksOptions } from "./openclaw-hooks.ts";

/** Stores OpenClaw-owned run facts shared across plugin registrations. */
export type RunFactsStore = {
  set(runId: string, namespace: string, value: Record<string, unknown>): Promise<void>;
  setIfAbsent(runId: string, namespace: string, value: Record<string, unknown>): Promise<boolean>;
  get(runId: string, namespace: string): Promise<unknown>;
  consume(runId: string, namespace: string): Promise<unknown>;
  clear(runId: string, namespace?: string): Promise<void>;
  pruneOtherProcesses(): Promise<void>;
};

/**
 * Prevents a second `sessionStart` after restart. The adapter sets the flag
 * when the Guardian allows or does not evaluate `sessionStart`.
 */
export type Admission = { sessionId: string; userContext: UserContext; agentName?: string; sessionStarted?: boolean };

/**
 * A restored admission cannot authorize a send until a run confirms its
 * session id. OpenClaw's send hook gives no session id; a scheduled run does.
 */
export type HeldAdmission = Admission & { confirmed: boolean };

/**
 * Admissions survive restarts. Each write completes before the adapter uses it.
 */
export type AdmissionStore = {
  load(): Promise<Array<[string, Admission]>>;
  put(sessionKey: string, admission: Admission): Promise<void>;
  delete(sessionKey: string): Promise<void>;
};

/**
 * Registrations share session refusals through OpenClaw state (§4.1). Each
 * checks before and after a decision, within the hook deadline.
 */
export type RefusalStore = {
  get(sessionId: string): Promise<SessionRefusal | undefined>;
  put(sessionId: string, refusal: SessionRefusal): Promise<void>;
  delete(sessionId: string): Promise<void>;
};

/** Disables durable admission storage; the in-memory map lasts only for this process. */
export const memoryOnlyAdmissions: AdmissionStore = {
  async load() {
    return [];
  },
  async put() {},
  async delete() {},
};

/** Combines the run id and tool call id because OpenClaw call ids are run-local. */
export function callKey(runId: string, toolCallId: string): string {
  return JSON.stringify([runId, toolCallId]);
}

/** A message held for the session's next run, with sender context when available. */
export type HeldMessage = { content: ContentItem[]; userContext?: UserContext };

/** An admitted run and the sender of its allowed user message. */
export type AdmittedRun = {
  sessionKey: string;
  sessionId: string;
  /** Absent for a run no person started. */
  userContext?: UserContext;
  agentName?: string;
  toolCallCount: number;
};

/**
 * Carries the decision's request reference and ServerHello to the result hook.
 * Another registration can use this record to govern the result.
 */
export type DecidedCall = { run: AdmittedRun; requestId: string | null; ran: boolean; serverHello: SessionConfig | null };

/**
 * Prevents admission if OpenClaw ends the run or session during a decision.
 */
export type PendingAdmission = { sessionKey: string; ended: boolean; settled: Promise<void> };

export type HookStateOptions = Pick<CreateHooksOptions, "audit" | "logger" | "runFacts"> & { store: AdmissionStore };

export function createHookState({ audit, logger, runFacts, store }: HookStateOptions) {
  async function revokeRunFacts(runId: string): Promise<void> {
    try {
      const admission = await runFacts.get(runId, "admission");
      if (admission !== undefined && typeof admission === "object" && admission !== null) {
        await runFacts.set(runId, "admission", { ...(admission as Record<string, unknown>), terminal: true });
      }
    } catch (error) {
      logger.error(`ACS plugin could not mark run facts terminal: ${(error as Error).message}`);
    }
    try {
      await runFacts.clear(runId);
    } catch (error) {
      logger.error(`ACS plugin could not clear run facts: ${(error as Error).message}`);
    }
  }

  /**
   * Each admission retains its sender until OpenClaw ends the session. A send
   * without an admission uses the failure posture; see README.md#openclaw-settings.
   */
  const admittedSessions = new Map<string, HeldAdmission>();
  /**
   * Skips keys changed by this process because their stored rows may be stale.
   */
  const touchedSinceStart = new Set<string>();
  /**
   * Runs wait within their deadline to recover the sender and avoid a second
   * `sessionStart`. Sends do not wait for restoration.
   */
  let restoring: Promise<void> | undefined;
  let restoreDone = false;
  function restored(): Promise<void> {
    restoring ??= (async () => {
      try {
        for (const [sessionKey, admission] of await store.load()) {
          if (!touchedSinceStart.has(sessionKey)) {
            admittedSessions.set(sessionKey, { ...admission, confirmed: false });
            if (admission.sessionStarted === true && startedSessions.get(admission.sessionId) === undefined) {
              startedSessions.set(admission.sessionId, true);
            }
          }
        }
      } catch (error) {
        logger.error(`ACS plugin could not restore admitted sessions: ${(error as Error).message}`);
      } finally {
        restoreDone = true;
        touchedSinceStart.clear();
      }
    })();
    return restoring;
  }

  async function until(promise: Promise<void>, deadlineAt: number): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<void>((resolve) => (timer = setTimeout(resolve, Math.max(0, deadlineAt - performance.now()))));
    await Promise.race([promise, late]).finally(() => clearTimeout(timer));
  }

  /**
   * OpenClaw allows actions when these hooks time out, so each wait must end
   * before the host timeout. The hook catches the rejection and blocks.
   */
  function beforeDeadline<T>(promise: Promise<T>, deadlineAt: number, what: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`${what} did not finish before the hook's deadline`)),
        Math.max(0, deadlineAt - performance.now()),
      );
    });
    return Promise.race([promise, late]).finally(() => clearTimeout(timer));
  }

  /** Bounds each run-fact operation by the hook deadline. */
  function runFactsUntil(deadlineAt: number): RunFactsStore {
    return {
      set: (runId, namespace, value) => beforeDeadline(runFacts.set(runId, namespace, value), deadlineAt, "storing a run fact in OpenClaw's plugin state"),
      setIfAbsent: (runId, namespace, value) => beforeDeadline(runFacts.setIfAbsent(runId, namespace, value), deadlineAt, "storing a run fact in OpenClaw's plugin state"),
      get: (runId, namespace) => beforeDeadline(runFacts.get(runId, namespace), deadlineAt, "reading a run fact from OpenClaw's plugin state"),
      consume: (runId, namespace) => beforeDeadline(runFacts.consume(runId, namespace), deadlineAt, "reading a run fact from OpenClaw's plugin state"),
      clear: (runId, namespace) => beforeDeadline(runFacts.clear(runId, namespace), deadlineAt, "clearing run facts in OpenClaw's plugin state"),
      pruneOtherProcesses: () => beforeDeadline(runFacts.pruneOtherProcesses(), deadlineAt, "pruning run facts in OpenClaw's plugin state"),
    };
  }

  /** Orders writes per key so a delete cannot precede its put. */
  const storeWrites = new Map<string, Promise<void>>();
  function persist(sessionKey: string, write: () => Promise<void>, failure: string): Promise<void> {
    const next = (storeWrites.get(sessionKey) ?? Promise.resolve()).then(write).catch((error: unknown) => {
      logger.error(`ACS plugin could not ${failure}: ${(error as Error).message}`);
    });
    storeWrites.set(sessionKey, next);
    void next.then(() => {
      if (storeWrites.get(sessionKey) === next) {
        storeWrites.delete(sessionKey);
      }
    });
    return next;
  }

  async function admit(sessionKey: string, admission: Admission): Promise<void> {
    touchedSinceStart.add(sessionKey);
    admittedSessions.set(sessionKey, { ...admission, confirmed: true });
    await persist(sessionKey, () => store.put(sessionKey, admission), "store an admitted session");
  }

  async function forgetAdmission(sessionKey: string): Promise<void> {
    touchedSinceStart.add(sessionKey);
    admittedSessions.delete(sessionKey);
    await persist(sessionKey, () => store.delete(sessionKey), "delete an admitted session");
  }
  /** Admitted runs that have not ended, keyed by run id. */
  const runs = new Map<string, AdmittedRun>();
  /**
   * A step with only a session key still needs the session's refusal and failure posture.
   * This map retains the last session id for each key, including runs the adapter did not admit.
   */
  const sessionIdOfKey = new Map<string, string>();
  /** The OpenClaw session id `sessionKey` runs under, when a run of it reached this process. */
  function sessionIdOf(sessionKey: string | undefined): string | undefined {
    return sessionKey === undefined ? undefined : sessionIdOfKey.get(sessionKey) ?? admittedSessions.get(sessionKey)?.sessionId;
  }
  /** Live admitted runs, grouped by session key. */
  const liveRunsOfSession = new Map<string, Set<string>>();
  function addLiveRun(sessionKey: string, runId: string): void {
    liveRunsOfSession.set(sessionKey, new Set([...(liveRunsOfSession.get(sessionKey) ?? []), runId]));
  }
  /** Removes a live run and returns whether it was present. */
  function endLiveRun(sessionKey: string, runId: string): boolean {
    const live = liveRunsOfSession.get(sessionKey);
    const was = live?.delete(runId) ?? false;
    if (live !== undefined && live.size === 0) {
      liveRunsOfSession.delete(sessionKey);
    }
    return was;
  }
  /**
   * Uses the only live run when a step has no run id. With several live runs,
   * OpenClaw identifies none, so the step has no turn.
   */
  function soleLiveRun(sessionKey: string): string | undefined {
    const live = liveRunsOfSession.get(sessionKey);
    return live?.size === 1 ? [...live][0] : undefined;
  }
  /**
   * OpenClaw delivers the final reply after `agent_end`, so the adapter keeps
   * the ended run's sender. The next admitted run replaces this record.
   */
  const endedRunOfSession = new Map<string, string>();
  /** Ended run records needed to identify replies with no person sender. */
  const endedRuns = new Map<string, AdmittedRun>();
  /**
   * Messages survive session rollover because dispatch can precede
   * `session_end`. The next run sends each as `userMessage`; see mapping.md.
   */
  const undecidedInbound = new Map<string, HeldMessage[]>();
  const pendingAdmissions = new Map<string, PendingAdmission>();
  /**
   * `true` records an allowed `sessionStart`. A string records a refusal and
   * blocks admission until OpenClaw ends the session.
   */
  const startedSessions = new Map<string, true | string>();
  /** Who each started session's steps act for, if anyone, for its `sessionEnd`; by OpenClaw session id. */
  const startedSessionSteps = new Map<string, { userContext?: UserContext; agentName?: string }>();
  /** Decided calls whose results have not been read, keyed by `callKey`. */
  const decidedCalls = new Map<string, DecidedCall>();

  /** Logs why the adapter refused a step before asking the Guardian. */
  const refuse = (sessionId: string | undefined, method: string, reason: string) =>
    logger.error(`ACS plugin refused ${method} in session ${JSON.stringify(sessionId ?? null)}: ${reason}`);

  /** §6.5's record of a decision this gate carried out as a block. */
  function auditSubstitution(
    sessionId: string,
    method: string,
    requestId: string | null,
    decision: string,
    reasonCode: string,
  ): void {
    audit.write({
      session_id: sessionId,
      method,
      rpc_id: requestId,
      outcome: "substituted",
      substituted: { decision, reason_code: reasonCode },
    });
  }

  /** Passes `allow`; blocks other decisions and audits unsupported outcomes. */
  function isAllowed(outcome: StepOutcome, sessionId: string, method: string): boolean {
    const { decision } = outcome;
    if (decision.decision === "allow") {
      return true;
    }
    if (outcome.stage === "honoured" && decision.decision !== "deny") {
      auditSubstitution(sessionId, method, outcome.requestId, decision.decision, `${decision.decision}_unsupported`);
    }
    return false;
  }

  return {
    revokeRunFacts,
    admittedSessions,
    restored,
    until,
    admit,
    forgetAdmission,
    runs,
    sessionIdOfKey,
    sessionIdOf,
    liveRunsOfSession,
    addLiveRun,
    endLiveRun,
    soleLiveRun,
    endedRunOfSession,
    endedRuns,
    undecidedInbound,
    pendingAdmissions,
    startedSessions,
    startedSessionSteps,
    decidedCalls,
    refuse,
    auditSubstitution,
    isAllowed,
    isRestored: () => restoreDone,
    beforeDeadline,
    runFactsUntil,
  };
}

export type HookState = ReturnType<typeof createHookState>;
