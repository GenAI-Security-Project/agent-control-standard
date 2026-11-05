/**
 * OpenClaw calls `register` synchronously. Invalid configuration or missing
 * host capabilities register blocking hooks; see README.md#checks-at-load-time.
 * Registrations share admissions, run facts and refusals through plugin state.
 */
import { createGuardianClient } from "./host-adapter.ts";
import { createAdapterAuditSink } from "./audit.ts";
import { createLivenessProbe, type LivenessProbe } from "./liveness.ts";
import { performance } from "node:perf_hooks";
import { createAcsExchange, type DecisionFailures, type FailureCountStore, type SessionRefusal } from "./acs-exchange.ts";
import { parseConfig } from "./config.ts";
import type { Admission, AdmissionStore, RefusalStore, RunFactsStore } from "./hook-state.ts";
import { createBlockingHooks, createHooks, type Hooks } from "./openclaw-hooks.ts";
import type { ToolResultAnswer, ToolResultContext, ToolResultEvent } from "./openclaw-types.ts";

/** The id OpenClaw installs and configures this plugin under: `plugins.entries.acs-guardian-client`. */
export const PLUGIN_ID = "acs-guardian-client";

/** The part of OpenClaw's retained keyed stores this plugin uses. */
type RetainedStore<T> = {
  register(key: string, value: T): Promise<unknown>;
  registerIfAbsent(key: string, value: T): Promise<boolean>;
  lookup(key: string): Promise<T | undefined>;
  consume(key: string): Promise<T | undefined>;
  delete(key: string): Promise<unknown>;
  entries(): Promise<Array<{ key: string; value: T }>>;
  /** Atomically replaces the value; `undefined` leaves it unchanged. */
  update(key: string, next: (current: T | undefined) => T | undefined): Promise<unknown>;
};

type StoredRunFact = {
  processIdentity: string;
  runId: string;
  namespace: string;
  value: Record<string, unknown>;
};

const PROCESS_IDENTITY = `${process.pid}:${performance.timeOrigin}`;
const RUN_FACTS_NAMESPACE = "run-tool-facts";

type PluginApi = {
  runtime?: {
    state?: { openKeyedStore?: <T>(options: { namespace: string; retention: "retained" }) => RetainedStore<T> | Promise<RetainedStore<T>> };
  };
  pluginConfig?: Record<string, unknown>;
  logger: { error(message: string): void; warn(message: string): void; info(message: string): void };
  on(hookName: string, handler: (...args: never[]) => unknown, options?: { priority?: number; timeoutMs?: number }): void;
  registerAgentToolResultMiddleware?(
    handler: (event: ToolResultEvent, ctx: ToolResultContext) => Promise<ToolResultAnswer>,
    options: { runtimes: string[] },
  ): void;
};

/** Open each store on first use so it belongs to the active runtime after startup retires older registrations. */
function admissionsFor(api: PluginApi): AdmissionStore {
  const open = api.runtime?.state?.openKeyedStore;
  if (open === undefined) {
    throw new Error("OpenClaw has no api.runtime.state.openKeyedStore");
  }
  let store: Promise<RetainedStore<Admission>> | undefined;
  const opened = (): Promise<RetainedStore<Admission>> => (store ??= Promise.resolve().then(() => open({ namespace: "admitted-sessions", retention: "retained" })));
  return {
    async load() {
      return (await (await opened()).entries()).map(({ key, value }) => [key, value]);
    },
    async put(sessionKey, admission) {
      await (await opened()).register(sessionKey, admission);
    },
    async delete(sessionKey) {
      await (await opened()).delete(sessionKey);
    },
  };
}

function runFactsFor(api: PluginApi): RunFactsStore {
  const open = api.runtime?.state?.openKeyedStore;
  if (open === undefined) {
    throw new Error("OpenClaw has no api.runtime.state.openKeyedStore");
  }
  let store: Promise<RetainedStore<StoredRunFact>> | undefined;
  const opened = (): Promise<RetainedStore<StoredRunFact>> => (store ??= Promise.resolve().then(() => open({ namespace: RUN_FACTS_NAMESPACE, retention: "retained" })));
  const keyFor = (runId: string, namespace: string) => JSON.stringify([PROCESS_IDENTITY, runId, namespace]);
  const isStoredFact = (value: unknown): value is StoredRunFact => {
    if (value === null || typeof value !== "object") {
      return false;
    }
    const fact = value as Partial<StoredRunFact>;
    return typeof fact.processIdentity === "string" && typeof fact.runId === "string" &&
      typeof fact.namespace === "string" && fact.value !== null && typeof fact.value === "object";
  };
  const isFact = (value: unknown, runId: string, namespace: string): value is StoredRunFact => {
    return isStoredFact(value) && value.processIdentity === PROCESS_IDENTITY &&
      value.runId === runId && value.namespace === namespace;
  };
  return {
    async set(runId, namespace, value) {
      await (await opened()).register(keyFor(runId, namespace), { processIdentity: PROCESS_IDENTITY, runId, namespace, value });
    },
    async setIfAbsent(runId, namespace, value) {
      return (await opened()).registerIfAbsent(keyFor(runId, namespace), { processIdentity: PROCESS_IDENTITY, runId, namespace, value });
    },
    async get(runId, namespace) {
      const fact = await (await opened()).lookup(keyFor(runId, namespace));
      return isFact(fact, runId, namespace) ? fact.value : undefined;
    },
    async consume(runId, namespace) {
      const fact = await (await opened()).consume(keyFor(runId, namespace));
      return isFact(fact, runId, namespace) ? fact.value : undefined;
    },
    async clear(runId, namespace) {
      const current = await opened();
      if (namespace !== undefined) {
        await current.delete(keyFor(runId, namespace));
        return;
      }
      for (const entry of await current.entries()) {
        if (isStoredFact(entry.value) && entry.value.processIdentity === PROCESS_IDENTITY && entry.value.runId === runId) {
          await current.delete(entry.key);
        }
      }
    },
    async pruneOtherProcesses() {
      const current = await opened();
      for (const entry of await current.entries()) {
        if (!isStoredFact(entry.value) || entry.value.processIdentity !== PROCESS_IDENTITY) {
          await current.delete(entry.key);
        }
      }
    },
  };
}

/** Stores each session's §6.4 decision-failure counts in OpenClaw's retained plugin state. */
function failureCountsFor(api: PluginApi): FailureCountStore {
  const open = api.runtime?.state?.openKeyedStore;
  if (open === undefined) {
    throw new Error("OpenClaw has no api.runtime.state.openKeyedStore");
  }
  let store: Promise<RetainedStore<DecisionFailures>> | undefined;
  const opened = (): Promise<RetainedStore<DecisionFailures>> => (store ??= Promise.resolve().then(() => open({ namespace: "decision-failures", retention: "retained" })));
  return {
    async start(sessionUuid) {
      await (await opened()).registerIfAbsent(sessionUuid, {});
    },
    async add(sessionUuid, failureClass) {
      await (await opened()).update(sessionUuid, (counts) =>
        counts === undefined ? undefined : { ...counts, [failureClass]: (counts[failureClass] ?? 0) + 1 });
    },
    async get(sessionUuid) {
      return await (await opened()).lookup(sessionUuid);
    },
    async delete(sessionUuid) {
      await (await opened()).delete(sessionUuid);
    },
  };
}

/** Stores Guardian-refused sessions in OpenClaw's retained plugin state. */
function refusalsFor(api: PluginApi): RefusalStore {
  const open = api.runtime?.state?.openKeyedStore;
  if (open === undefined) {
    throw new Error("OpenClaw has no api.runtime.state.openKeyedStore");
  }
  let store: Promise<RetainedStore<SessionRefusal>> | undefined;
  const opened = (): Promise<RetainedStore<SessionRefusal>> => (store ??= Promise.resolve().then(() => open({ namespace: "refused-sessions", retention: "retained" })));
  return {
    async get(sessionId) {
      const refusal = await (await opened()).lookup(sessionId);
      if (refusal === undefined) {
        return undefined;
      }
      // An unreadable row blocks the session like a Guardian refusal.
      if (typeof refusal?.code !== "number" || typeof refusal.message !== "string") {
        throw new Error("OpenClaw's plugin state holds a refusal of this session that this plugin cannot read");
      }
      return refusal;
    },
    async put(sessionId, refusal) {
      await (await opened()).register(sessionId, refusal);
    },
    async delete(sessionId) {
      await (await opened()).delete(sessionId);
    },
  };
}

/** OpenClaw runs higher priorities first, so this plugin normally runs last. The README names what breaks that. */
const RUN_LAST = { priority: Number.MIN_SAFE_INTEGER };

function missingCapability(api: PluginApi): string | undefined {
  if (api.registerAgentToolResultMiddleware === undefined) {
    return "this OpenClaw offers no api.registerAgentToolResultMiddleware, so tool results cannot be sent as steps/toolCallResult";
  }
  if (api.runtime?.state?.openKeyedStore === undefined) {
    return "this OpenClaw offers no api.runtime.state.openKeyedStore, so separate hook registrations cannot share a run's admission, a tool call's decision or a session's refusal";
  }
  return undefined;
}

function hooksFor(api: PluginApi): { hooks: Hooks; hookTimeoutMs?: number; liveness?: LivenessProbe } {
  try {
    const config = parseConfig(api.pluginConfig ?? {});
    const audit = createAdapterAuditSink({
      path: config.auditLog,
      onError: (error) => api.logger.error(`ACS plugin cannot write its audit log ${config.auditLog}: ${(error as Error).message}`),
    });
    const missing = missingCapability(api);
    if (missing !== undefined) {
      const reason = `ACS plugin blocks every step: ${missing}`;
      api.logger.error(reason);
      return { hooks: createBlockingHooks(reason) };
    }
    const exchange = createAcsExchange({
      client: createGuardianClient(config.guardianUrl, { hmacKey: config.hmacKey }),
      hmacKey: config.hmacKey,
      audit,
      failurePosture: config.failurePosture,
      deadlineMs: config.deadlineMs,
      failureCounts: failureCountsFor(api),
    });
    const hooks = createHooks({
      config,
      exchange,
      audit,
      logger: api.logger,
      admissions: admissionsFor(api),
      runFacts: runFactsFor(api),
      refusals: refusalsFor(api),
    });
    return { hooks, hookTimeoutMs: config.hookTimeoutMs, liveness: createLivenessProbe(exchange, config.pingIntervalMs, api.logger) };
  } catch (error) {
    const reason = `ACS plugin is not configured, so every step is blocked: ${(error as Error).message}`;
    api.logger.error(reason);
    return { hooks: createBlockingHooks(reason) };
  }
}

export default {
  id: PLUGIN_ID,
  name: "Agent Control Standard",
  description: "Sends each agent step, signed, to an ACS Guardian and enforces its decision.",
  register(api: PluginApi): void {
    const { hooks, hookTimeoutMs, liveness } = hooksFor(api);
    // Leave room for the adapter deadline; operator timeout overrides still take precedence.
    const timed = { ...RUN_LAST, ...(hookTimeoutMs === undefined ? {} : { timeoutMs: hookTimeoutMs }) };
    api.on("before_agent_run", hooks.beforeAgentRun, timed);
    api.on("reply_dispatch", hooks.replyDispatch, timed);
    api.on("before_tool_call", hooks.beforeToolCall, timed);
    api.on("after_tool_call", hooks.afterToolCall, RUN_LAST);
    api.on("reply_payload_sending", hooks.replyPayloadSending, timed);
    api.on("message_sending", hooks.messageSending, timed);
    api.on("agent_end", hooks.agentEnd, RUN_LAST);
    api.on("session_end", hooks.sessionEnd, RUN_LAST);
    api.on("gateway_start", async () => {
      liveness?.start();
      await hooks.gatewayStart();
    }, RUN_LAST);
    api.on("gateway_stop", async () => liveness?.stop(), RUN_LAST);
    api.registerAgentToolResultMiddleware?.(hooks.toolResult, { runtimes: ["openclaw"] });
  },
};
