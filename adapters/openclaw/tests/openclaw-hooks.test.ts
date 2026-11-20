import { afterEach, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGuardianClient, WITHHELD_OUTPUT, type HmacKey } from "../host-adapter.ts";
import type { AdapterAuditEvent, AdapterAuditSink } from "../audit.ts";
import { createAcsExchange } from "../acs-exchange.ts";
import type { FailurePosture } from "../config.ts";
import { METHODS, PING_METHOD, type AcsExchange, type FailureCountStore } from "../acs-exchange.ts";
import type { Admission, AdmissionStore, RefusalStore, RunFactsStore } from "../hook-state.ts";
import { createBlockingHooks, createHooks, type Hooks } from "../openclaw-hooks.ts";
import type { BeforeToolCallResult, MediaFact, ToolResultAnswer, ToolResultBlock } from "../openclaw-types.ts";
import { dispatchContext, type Inbound, inboundEvent } from "./inbound.ts";
import { memoryFailureCounts } from "./memory-failure-counts.ts";
import { memoryRefusals } from "./memory-refusals.ts";
import { memoryRunFacts } from "./memory-run-facts.ts";
import { startFakeGuardian, type FakeGuardian, type Reply, type ReceivedStep } from "./fake-guardian.ts";

const KEY: HmacKey = {
  keyId: "example-key",
  secret: Buffer.from("0123456789abcdef0123456789abcdef", "utf8"),
};
const SENDER = "+15550100";
const OTHER_PHONE = "+15550199";
const SESSION_KEY = `agent:main:signal:direct:${SENDER}`;
const SESSION_ID = "session-1";
const AGENT_CTX = { runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID, senderId: SENDER, channel: "signal" };
const TOOL_CTX = { runId: "run-1", sessionKey: SESSION_KEY };
const MESSAGE_CTX = { channelId: "signal", sessionKey: SESSION_KEY };

/** The steps most tests are about; a test of the others asks the fake Guardian to evaluate them. */
const CORE_METHODS = ["steps/userMessage", "steps/toolCallRequest", "steps/agentResponse"];
const ALL_METHODS = [
  "steps/sessionStart",
  "steps/agentTrigger",
  "steps/turnStart",
  "steps/userMessage",
  "steps/toolCallRequest",
  "steps/toolCallResult",
  "steps/agentResponse",
  "steps/turnEnd",
  "steps/subagentStart",
  "steps/subagentStop",
  "steps/sessionEnd",
];

type Setup = { server: FakeGuardian; hooks: Hooks; audit: AdapterAuditEvent[]; errors: string[] };

/** A Guardian answer the test releases, so a hook can be held inside its exchange. */
function heldAnswer(reply: Reply = { decision: { decision: "allow" } }): { reached: Promise<void>; release(): void; answer(): Promise<Reply> } {
  let release!: () => void;
  let markReached!: () => void;
  const reached = new Promise<void>((resolve) => {
    markReached = resolve;
  });
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    reached,
    release,
    async answer() {
      markReached();
      await released;
      return reply;
    },
  };
}

const servers: FakeGuardian[] = [];
afterEach(() => {
  const invalid = servers.flatMap((server) => server.invalidEnvelopes);
  for (const server of servers.splice(0)) {
    server.stop();
  }
  // Every envelope any test sent validates against specification/v0.1.0/.
  expect(invalid).toEqual([]);
});

function setup(
  options: {
    reply?: (step: ReceivedStep) => Reply | Promise<Reply>;
    failurePosture?: FailurePosture;
    onDecisionFailure?: "proceed" | "deny";
    deadlineMs?: number;
    clientKey?: HmacKey;
    methodsEvaluated?: string[] | null;
    admissions?: AdmissionStore;
    runFacts?: RunFactsStore;
    refusals?: RefusalStore;
    failureCounts?: FailureCountStore;
    maxUndecidedMessages?: number;
    maxAttachmentBytes?: number;
    /** The Guardian of another registration of this plugin, instead of a new one. */
    guardian?: FakeGuardian;
  } = {},
): Setup {
  const server = options.guardian ?? startFakeGuardian({
    key: KEY,
    reply: options.reply,
    onDecisionFailure: options.onDecisionFailure,
    methodsEvaluated: options.methodsEvaluated === undefined ? CORE_METHODS : options.methodsEvaluated,
  });
  if (options.guardian === undefined) {
    servers.push(server);
  }
  const events: AdapterAuditEvent[] = [];
  const audit: AdapterAuditSink = {
    path: "memory",
    write(event) {
      events.push(event);
      return true;
    },
  };
  const exchange = createAcsExchange({
    client: createGuardianClient(server.url, { hmacKey: options.clientKey ?? KEY }),
    hmacKey: options.clientKey ?? KEY,
    audit,
    failurePosture: options.failurePosture ?? "closed",
    deadlineMs: options.deadlineMs ?? 2000,
    failureCounts: options.failureCounts ?? memoryFailureCounts(),
  });
  const errors: string[] = [];
  const hooks = createHooks({
    config: {
      maxUndecidedMessages: options.maxUndecidedMessages ?? 20,
      maxAttachmentBytes: options.maxAttachmentBytes ?? 524_288,
    },
    exchange,
    audit,
    logger: { error: (message) => errors.push(message) },
    admissions: options.admissions,
    runFacts: options.runFacts ?? memoryRunFacts(),
    refusals: options.refusals ?? memoryRefusals(),
  });
  return { server, hooks, audit: events, errors };
}

/** Allows every step but the reply, and answers the reply with `answer`. */
function replyAnswer(answer: Reply): (step: ReceivedStep) => Reply {
  return (step) => (step.method === "steps/agentResponse" ? answer : { decision: { decision: "allow" } });
}

/** Answers the tool call with `answer`, every other step with allow. */
function toolDecisionReply(answer: Reply): (step: ReceivedStep) => Reply {
  return (step) => (step.method === "steps/toolCallRequest" ? answer : { decision: { decision: "allow" } });
}

function toolDecision(decision: Record<string, unknown>): (step: ReceivedStep) => Reply {
  return (step) => (step.method === "steps/toolCallRequest" ? { decision } : { decision: { decision: "allow" } });
}

/** `dispatched` when OpenClaw goes on with the message, `dropped` when the plugin claimed it; nothing is sent in its place. */
async function dispatchMessage(hooks: Hooks, message: Partial<Inbound> & { content: string }): Promise<"dispatched" | "dropped"> {
  const notices: string[] = [];
  const result = await hooks.replyDispatch(inboundEvent({ sessionKey: SESSION_KEY, senderId: SENDER, ...message }), dispatchContext(notices));
  if (result === undefined) {
    return "dispatched";
  }
  expect(result).toMatchObject({ handled: true, queuedFinal: false });
  expect(notices).toEqual([]);
  return "dropped";
}

async function startRun(hooks: Hooks): Promise<void> {
  expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toBeUndefined();
}

function callTool(hooks: Hooks, params: Record<string, unknown> = { phone: OTHER_PHONE }): Promise<BeforeToolCallResult> {
  return hooks.beforeToolCall({ toolName: "account-lookup", params }, TOOL_CTX);
}

describe("identity: the sender comes from the channel, never from the model", () => {
  it("sends the run's sender as user_context while the tool parameters name another phone", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(await callTool(hooks)).toEqual({ params: { phone: OTHER_PHONE } });

    expect(server.steps.map((step) => step.method)).toEqual(["steps/userMessage", "steps/toolCallRequest"]);
    const toolStep = server.steps[1]!;
    expect(toolStep.userContext).toEqual({ user_id: SENDER, authentication_method: "signal" });
    expect(toolStep.payload).toEqual({ tool: { name: "account-lookup" }, arguments: { phone: { value: OTHER_PHONE } } });
    expect(server.steps[0]!.payload).toEqual({ content: [{ type: "text", value: "Hello" }] });
    expect(server.badSignatures).toBe(0);
  });

  it("denies a tool call of a run with no recorded sender, without asking the Guardian", async () => {
    const { server, hooks } = setup();
    const result = await hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, { runId: "run-unknown", sessionKey: SESSION_KEY });
    expect(result).toMatchObject({ block: true });
    expect(server.steps).toHaveLength(0);
  });

  it("records no sender for a run whose user message was denied", async () => {
    const { hooks } = setup({ reply: () => ({ decision: { decision: "deny", reasoning: "not today" } }) });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toEqual({
      outcome: "block",
      reason: "not today",
    });
    expect(await callTool(hooks)).toMatchObject({ block: true, blockReason: expect.stringContaining("did not pass before_agent_run") });
  });

  it("sends a run that carries no sender to the Guardian without a person, as agentTrigger", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    const { senderId: _dropped, ...noSender } = AGENT_CTX;
    expect(await hooks.beforeAgentRun({ prompt: "Hello" }, noSender)).toBeUndefined();
    expect(server.steps.find((step) => step.method === "steps/agentTrigger")).toMatchObject({ userContext: undefined, payload: { trigger_type: "system", trigger_source: { prompt: "Hello" } } });
  });

  it("governs a group: each run in one session acts for the person whose message started it", async () => {
    const GROUP_KEY = "agent:main:signal:group:team-1";
    const { server, hooks } = setup();
    const first = { ...AGENT_CTX, sessionKey: GROUP_KEY };
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, first)).toBeUndefined();
    await hooks.agentEnd({ runId: "run-1", success: true }, first);
    const second = { ...first, runId: "run-2", senderId: OTHER_PHONE };
    expect(await hooks.beforeAgentRun({ prompt: "Me too", senderId: OTHER_PHONE }, second)).toBeUndefined();
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, { runId: "run-2", sessionKey: GROUP_KEY, sessionId: SESSION_ID })).toEqual({ params: {} });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/toolCallRequest", userContext: { user_id: OTHER_PHONE, authentication_method: "signal" } });
    expect(new Set(server.steps.map((step) => step.sessionId)).size).toBe(1);
  });

  it("sends nothing to a recipient whose key is a group key in the shape of an account key", async () => {
    const { server, hooks } = setup();
    expect(
      await hooks.messageSending(
        { to: SENDER, content: "hi" },
        { channelId: "signal", sessionKey: `agent:main:signal:group:direct:${SENDER}` },
      ),
    ).toEqual({ cancel: true });
    expect(server.steps).toHaveLength(0);
  });

  it("blocks a tool call of a run that has ended, even under the same run id", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await callTool(hooks)).toMatchObject({ block: true, blockReason: expect.stringContaining("did not pass before_agent_run") });
    expect(server.steps.map((step) => step.method)).toEqual(["steps/userMessage"]);
  });

  it("blocks a run with no run id", async () => {
    const { runId: _dropped, ...noRunId } = AGENT_CTX;
    const { server, hooks } = setup();
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, noRunId)).toMatchObject({ outcome: "block" });
    expect(server.steps).toHaveLength(0);
  });

  it("names the session's sender on every run of the session", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    await hooks.beforeAgentRun({ prompt: "again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" });
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, { runId: "run-2", sessionKey: SESSION_KEY })).toEqual({
      params: {},
    });
    expect(server.steps.at(-1)?.userContext).toEqual({ user_id: SENDER, authentication_method: "signal" });
  });

  it("forgets a run at agent_end", async () => {
    const { hooks } = setup();
    await startRun(hooks);
    hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await callTool(hooks)).toMatchObject({ block: true });
  });

  it("blocks a tool call whose session is not its run's", async () => {
    const { hooks } = setup();
    await startRun(hooks);
    const result = await hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, { runId: "run-1", sessionKey: "another" });
    expect(result).toMatchObject({ block: true });
  });
});

describe("no decision uses a value another hook changed while it waited", () => {
  it.each([
    ["the_run_ends", (hooks: Hooks) => hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX)],
    ["the_session_ends", (hooks: Hooks) => hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID }, { sessionId: SESSION_ID })],
  ])("blocks a tool call when %s while the Guardian decides", async (_name, change) => {
    const held = heldAnswer();
    const { hooks } = setup({ reply: (step) => (step.method === "steps/toolCallRequest" ? held.answer() : { decision: { decision: "allow" } }) });
    await startRun(hooks);
    const call = callTool(hooks);
    await held.reached;
    change(hooks);
    held.release();
    expect(await call).toMatchObject({ block: true });
    expect(await callTool(hooks)).toMatchObject({ block: true });
  });

  it("admits two runs that reach a new session at once, and sends the session's sessionStart once", async () => {
    const held = heldAnswer();
    let first = true;
    const { server, hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: () => {
        if (first) {
          first = false;
          return held.answer();
        }
        return { decision: { decision: "allow" } };
      },
    });
    const runA = hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX);
    await held.reached;
    const runB = hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" });
    held.release();
    expect(await runA).toBeUndefined();
    expect(await runB).toBeUndefined();
    expect(server.steps.filter((step) => step.method === "steps/sessionStart")).toHaveLength(1);
    expect(await callTool(hooks)).toEqual({ params: { phone: OTHER_PHONE } });
  });

  it("sends sessionStart once when three runs of a new session start in the same tick", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    const results = await Promise.all(["run-1", "run-2", "run-3"].map((runId) => hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, runId })));
    expect(results).toEqual([undefined, undefined, undefined]);
    expect(server.steps.filter((step) => step.method === "steps/sessionStart")).toHaveLength(1);
  });

  it.each([
    ["the_run_ends", (hooks: Hooks) => hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX)],
    ["the_session_ends", (hooks: Hooks) => hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID }, { sessionId: SESSION_ID })],
  ])("admits no run when %s while its user message is decided, and leaves the session free", async (_name, change) => {
    const held = heldAnswer();
    let first = true;
    const { hooks } = setup({
      reply: () => {
        if (first) {
          first = false;
          return held.answer();
        }
        return { decision: { decision: "allow" } };
      },
    });
    const run = hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX);
    await held.reached;
    change(hooks);
    held.release();
    expect(await run).toMatchObject({ outcome: "block", reason: "the run or its session ended while the Guardian decided" });
    expect(await callTool(hooks)).toMatchObject({ block: true });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
  });

  it("blocks a tool call that names two different runs", async () => {
    const { hooks } = setup();
    await startRun(hooks);
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, runId: "run-9" }, TOOL_CTX)).toMatchObject({ block: true });
  });

  describe("a group session, where Alice spoke first and Bob speaks now", () => {
    const GROUP_KEY = "agent:main:signal:group:team-1";
    const ALICE = { user_id: SENDER, authentication_method: "signal" };
    const BOB = { user_id: OTHER_PHONE, authentication_method: "signal" };
    const alice = { ...AGENT_CTX, sessionKey: GROUP_KEY };
    const bob = { ...alice, runId: "run-2", senderId: OTHER_PHONE };
    async function aliceThenBob(hooks: Hooks): Promise<void> {
      expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, alice)).toBeUndefined();
      await hooks.agentEnd({ runId: "run-1", success: true }, alice);
      expect(await hooks.beforeAgentRun({ prompt: "Me too", senderId: OTHER_PHONE }, bob)).toBeUndefined();
    }

    it("sends Bob's final reply, after his run ended, as Bob's", async () => {
      const { server, hooks } = setup();
      await aliceThenBob(hooks);
      await hooks.agentEnd({ runId: "run-2", success: true }, bob);
      expect(await hooks.messageSending({ to: "team-1", content: "Done." }, { channelId: "signal", sessionKey: GROUP_KEY, runId: "run-2" })).toEqual({ content: "Done." });
      expect(server.steps.at(-1)).toMatchObject({ method: "steps/agentResponse", userContext: BOB });
    });

    it("sends a relay from Bob's run for no person, since OpenClaw names no sender for it", async () => {
      const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
      await aliceThenBob(hooks);
      const relay = { runId: "run-3", sessionKey: `agent:main:signal:direct:${SENDER}`, sessionId: "session-3", inputProvenance: { kind: "inter_session" as const, sourceSessionKey: GROUP_KEY } };
      const before = server.steps.length;
      expect(await hooks.beforeAgentRun({ prompt: "Relay" }, relay)).toBeUndefined();
      expect(server.steps.slice(before).map((step) => step.userContext)).toEqual(server.steps.slice(before).map(() => undefined));
    });

    it("sends each held message as its own sender's when the next run takes them", async () => {
      const { server, hooks } = setup();
      expect(await dispatchMessage(hooks, { content: "From Bob", sessionKey: GROUP_KEY, senderId: OTHER_PHONE })).toBe("dispatched");
      expect(await dispatchMessage(hooks, { content: "From Alice", sessionKey: GROUP_KEY, senderId: SENDER })).toBe("dispatched");
      expect(await hooks.beforeAgentRun({ prompt: "From Alice", senderId: SENDER }, alice)).toBeUndefined();
      const messages = server.steps.filter((step) => step.method === "steps/userMessage");
      expect(messages.map((step) => step.userContext)).toEqual([BOB, ALICE]);
    });
  });

  it("admits a new sender on a session key whose session OpenClaw ended", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID }, { sessionId: SESSION_ID });
    expect(
      await hooks.beforeAgentRun({ prompt: "Hello", senderId: OTHER_PHONE }, { ...AGENT_CTX, runId: "run-2", senderId: OTHER_PHONE }),
    ).toBeUndefined();
    expect(server.steps.at(-1)?.userContext).toEqual({ user_id: OTHER_PHONE, authentication_method: "signal" });
  });

});

describe("the session, activation and turn steps", () => {
  const denyFor = (method: string) => (step: ReceivedStep): Reply =>
    step.method === method ? { decision: { decision: "deny", reasoning: `no ${method}` } } : { decision: { decision: "allow" } };

  it("sends each step of a run in ACS order, with turn_id only from turnStart to turnEnd", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await callTool(hooks);
    await hooks.messageSending({ to: SENDER, content: "Done." }, MESSAGE_CTX);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);

    expect(server.steps.map((step) => [step.method, step.turnId])).toEqual([
      ["steps/sessionStart", undefined],
      ["steps/turnStart", "run-1"],
      ["steps/userMessage", "run-1"],
      ["steps/toolCallRequest", "run-1"],
      ["steps/agentResponse", "run-1"],
      ["steps/turnEnd", "run-1"],
    ]);
    expect(server.steps[0]!.payload).toEqual({
      user_identity: { user_id: SENDER, authentication_method: "signal" },
      platform_context: { channel: "signal" },
    });
    expect(server.steps[1]!.payload).toEqual({ turn_id: "run-1", triggered_by: "user_message" });
    expect(server.steps[5]!.payload).toEqual({ turn_id: "run-1", outcome: "completed", tool_call_count: 1 });
    expect(server.badSignatures).toBe(0);
  });

  it("reports the session's decision failures by class in sessionEnd's summary (§6.4)", async () => {
    const { server, hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: (step) =>
        step.method === "steps/turnEnd" ? { error: { code: -32603, message: "policy engine down" } }
        : step.method === "steps/toolCallRequest" ? { unsignedDecision: { decision: "allow" } }
        : { decision: { decision: "allow" } },
    });
    await startRun(hooks);
    await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID }, { sessionId: SESSION_ID });
    expect(server.steps.find((step) => step.method === "steps/sessionEnd")).toMatchObject({
      payload: { summary: { decision_failures: { guardian_error: 1, signature_invalid: 1 } } },
    });
  });

  it("reports no failures as an empty count, so the session reads as measured", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID }, { sessionId: SESSION_ID });
    expect(server.steps.find((step) => step.method === "steps/sessionEnd")).toMatchObject({ payload: { summary: { decision_failures: {} } } });
  });

  it("starts a session once, and again after OpenClaw ended it", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await hooks.beforeAgentRun({ prompt: "again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    await hooks.agentEnd({ runId: "run-2", success: true }, AGENT_CTX);
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID, reason: "idle" }, { sessionId: SESSION_ID });
    expect(
      await hooks.beforeAgentRun({ prompt: "new", senderId: SENDER }, { ...AGENT_CTX, runId: "run-3", sessionId: "session-2" }),
    ).toBeUndefined();
    expect(server.steps.filter((step) => step.method === "steps/sessionStart")).toHaveLength(2);
    expect(server.steps.find((step) => step.method === "steps/sessionEnd")).toMatchObject({ payload: { reason: "timeout" }, turnId: undefined });
  });

  it("admits no run of a session the Guardian refused, without asking again", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS, reply: denyFor("steps/sessionStart") });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toMatchObject({
      outcome: "block",
      reason: expect.stringContaining("refused this session"),
    });
    expect(server.steps.map((step) => step.method)).toEqual(["steps/sessionStart"]);
  });

  it("holds a second run while the session's first run is admitted, and refuses both when the Guardian refuses the session", async () => {
    const held = heldAnswer();
    let sessionStarts = 0;
    const { hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: (step) => {
        if (step.method !== "steps/sessionStart") {
          return { decision: { decision: "allow" } };
        }
        sessionStarts += 1;
        return held.answer().then(() => ({ decision: { decision: "deny", reasoning: "no session" } }));
      },
    });
    const runA = hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX);
    await held.reached;
    const runB = hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" });
    held.release();
    expect(await runA).toEqual({ outcome: "block", reason: "no session" });
    expect(await runB).toEqual({ outcome: "block", reason: "the Guardian refused this session: no session" });
    expect(sessionStarts).toBe(1);
    expect(await callTool(hooks)).toMatchObject({ block: true });
  });

  it("asks about the session again after the failure posture let a run through", async () => {
    let first = true;
    const { server, hooks, audit } = setup({
      methodsEvaluated: ALL_METHODS,
      deadlineMs: 1000,
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      reply: (step) => {
        if (step.method === "steps/sessionStart" && first) {
          first = false;
          return { hang: true };
        }
        return { decision: { decision: "allow" } };
      },
    });
    // The Guardian's own timeout ends the wait, so its posture applies (§6.4).
    server.serverHello = { timeout_config: { default_ms: 200 } };
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toBeUndefined();
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    expect(server.steps.filter((step) => step.method === "steps/sessionStart")).toHaveLength(2);
    expect(audit).toContainEqual(expect.objectContaining({ method: "steps/sessionStart", outcome: "proceeded" }));
  });

  it("sends nothing into a session OpenClaw ended while the Guardian decided the reply", async () => {
    const held = heldAnswer();
    const { hooks } = setup({ reply: (step) => (step.method === "steps/agentResponse" ? held.answer() : { decision: { decision: "allow" } }) });
    await startRun(hooks);
    const reply = hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX);
    await held.reached;
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID }, { sessionId: SESSION_ID });
    held.release();
    expect(await reply).toEqual({ cancel: true });
  });

  it("asks about the session again when the Guardian could not answer it", async () => {
    let first = true;
    const { server, hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      deadlineMs: 300,
      reply: (step) => {
        if (step.method === "steps/sessionStart" && first) {
          first = false;
          return { hang: true };
        }
        return { decision: { decision: "allow" } };
      },
    });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    expect(server.steps.filter((step) => step.method === "steps/sessionStart")).toHaveLength(2);
  });

  it.each(["steps/turnStart"])("blocks the run when the Guardian denies %s, before the user message", async (method) => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS, reply: denyFor(method) });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(server.steps.map((step) => step.method)).not.toContain("steps/userMessage");
    expect(await callTool(hooks)).toMatchObject({ block: true });
  });

  it("names a scheduled activation by its trigger", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await hooks.beforeAgentRun({ prompt: "tick", senderId: SENDER }, { ...AGENT_CTX, trigger: "cron" });
    expect(server.steps.find((step) => step.method === "steps/agentTrigger")?.payload).toMatchObject({ trigger_type: "scheduled" });
  });

  it("ends a failed turn as an error, and records a turnEnd answer it cannot apply", async () => {
    const { server, hooks, audit } = setup({ methodsEvaluated: ALL_METHODS, reply: denyFor("steps/turnEnd") });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: false }, AGENT_CTX);
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/turnEnd", payload: { outcome: "error", tool_call_count: 0 } });
    expect(audit).toContainEqual(
      expect.objectContaining({ method: "steps/turnEnd", substituted: { decision: "deny", reason_code: "not_decision_eligible" } }),
    );
  });

  it("decides the final reply OpenClaw delivers after agent_end outside the closed turn", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await hooks.messageSending({ to: SENDER, content: "Done." }, MESSAGE_CTX)).toEqual({ content: "Done." });
    expect(server.steps.slice(-2).map((step) => [step.method, step.turnId])).toEqual([
      ["steps/turnEnd", "run-1"],
      ["steps/agentResponse", undefined],
    ]);
  });

  it("sends a late reply of a run no longer held for no person, not as the session's person", async () => {
    const GROUP_KEY = "agent:main:signal:group:team-1";
    const { server, hooks } = setup();
    const alice = { ...AGENT_CTX, sessionKey: GROUP_KEY };
    const bob = { ...alice, runId: "run-2", senderId: OTHER_PHONE };
    await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, alice);
    await hooks.agentEnd({ runId: "run-1", success: true }, alice);
    await hooks.beforeAgentRun({ prompt: "Me too", senderId: OTHER_PHONE }, bob);
    await hooks.agentEnd({ runId: "run-2", success: true }, bob);
    await hooks.beforeAgentRun({ prompt: "Again", senderId: SENDER }, { ...alice, runId: "run-3" });
    expect(await hooks.messageSending({ to: "team-1", content: "Late." }, { channelId: "signal", sessionKey: GROUP_KEY, runId: "run-2" })).toEqual({ content: "Late." });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/agentResponse", userContext: undefined });
  });

  it("does not put an ended run's reply into the next run's turn", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    await hooks.beforeAgentRun({ prompt: "Next", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" });
    await hooks.messageSending({ to: SENDER, content: "Late." }, { ...MESSAGE_CTX, runId: "run-1" });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/agentResponse", turnId: undefined });
  });

  it.each<[string, string, string[]]>([
    ["steps/turnStart", "denied_at_start", ["steps/turnStart", "steps/turnEnd"]],
    ["steps/userMessage", "interrupted", ["steps/turnStart", "steps/userMessage", "steps/turnEnd"]],
  ])("ends the turn of a run refused at %s as %s", async (method, outcome, sent) => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS, reply: denyFor(method) });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(server.steps.slice(1).map((step) => step.method)).toEqual(sent);
    expect(server.steps.at(-1)).toMatchObject({ turnId: "run-1", payload: { turn_id: "run-1", outcome, tool_call_count: 0 } });
  });

  it.each(["steps/sessionStart", "steps/turnStart", "steps/userMessage"])("blocks a run whose %s the Guardian modifies, recorded as modify_unsupported (§6.5)", async (method) => {
    const { hooks, audit } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: (step) =>
        step.method === method
          ? { decision: { decision: "modify", reasoning: "mask", modifications: { redactions: [{ path: Object.keys(step.payload)[0] === "content" ? "/content/0/value" : `/${Object.keys(step.payload)[0]}`, replacement: "[x]" }] } } }
          : { decision: { decision: "allow" } },
    });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(audit).toContainEqual(expect.objectContaining({ method, substituted: { decision: "modify", reason_code: "modify_unsupported" } }));
  });

  it("opens no turn, and ends none, for a scheduled run refused at its activation", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS, reply: denyFor("steps/agentTrigger") });
    expect(await hooks.beforeAgentRun({ prompt: "Reminder" }, { runId: "run-1", sessionKey: "agent:main:main", sessionId: SESSION_ID, trigger: "cron" })).toMatchObject({ outcome: "block" });
    expect(server.steps.map((step) => step.method)).toEqual(["steps/sessionStart", "steps/agentTrigger"]);
  });

  it("sends no agentTrigger for a run a person's message started: its userMessage is the activation", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    expect(server.steps.map((step) => step.method)).toEqual(["steps/sessionStart", "steps/turnStart", "steps/userMessage"]);
  });

  it("sends the final reply OpenClaw names its ended run for, even when the next message arrived meanwhile", async () => {
    const { hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await dispatchMessage(hooks, { content: "And one more thing", sessionKey: SESSION_KEY, senderId: SENDER, channel: "signal" })).toBe("dispatched");
    expect(await hooks.messageSending({ to: SENDER, content: "Done." }, { ...MESSAGE_CTX, runId: "run-2" })).toEqual({ cancel: true });
    expect(await hooks.messageSending({ to: SENDER, content: "Done." }, { ...MESSAGE_CTX, runId: "run-1" })).toEqual({ content: "Done." });
  });

  it("keeps one ACS session across a reset that keeps OpenClaw's session id", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID, reason: "reset", nextSessionId: SESSION_ID }, { sessionKey: SESSION_KEY, sessionId: SESSION_ID });
    expect(await hooks.beforeAgentRun({ prompt: "Again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    const methods = server.steps.map((step) => step.method);
    expect(methods.filter((method) => method === "steps/sessionStart")).toHaveLength(1);
    expect(methods).not.toContain("steps/sessionEnd");
  });

  it("sends no turnEnd for a run it did not admit", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await hooks.agentEnd({ runId: "run-9", success: true }, AGENT_CTX);
    expect(server.steps).toHaveLength(0);
  });
});

describe("tool decisions", () => {
  it("blocks a deny with the Guardian's reasoning", async () => {
    const { hooks } = setup({ reply: toolDecision({ decision: "deny", reasoning: "only the account holder" }) });
    await startRun(hooks);
    expect(await callTool(hooks)).toEqual({ block: true, blockReason: "only the account holder" });
  });

  it("blocks a modify that cannot be applied, and records the substitution (§6.3)", async () => {
    const { hooks, audit } = setup({
      reply: toolDecision({ decision: "modify", reasoning: "mask", modifications: { parameter_overrides: { missing: "x" } } }),
    });
    await startRun(hooks);
    expect(await callTool(hooks)).toMatchObject({ block: true });
    expect(audit.at(-1)).toMatchObject({ method: "steps/toolCallRequest", outcome: "substituted", substituted: { decision: "modify", reason_code: "modifications_invalid" } });
  });

  it("runs a modify with the Guardian's parameters", async () => {
    const { hooks } = setup({
      reply: toolDecision({ decision: "modify", reasoning: "masked", modifications: { parameter_overrides: { phone: "+1555***" } } }),
    });
    await startRun(hooks);
    expect(await callTool(hooks)).toEqual({ params: { phone: "+1555***" } });
  });

  it("blocks a defer as pending and records the substitution", async () => {
    const { hooks, audit } = setup({
      reply: toolDecision({
        decision: "defer",
        reasoning: "waiting on a check",
        defer_details: { reason: "pending_dependency", resolution_method: "timeout", resolution_timeout_ms: 60000, timeout_decision: "deny" },
      }),
    });
    await startRun(hooks);
    expect(await callTool(hooks)).toEqual({ block: true, blockReason: "Pending: waiting on a check" });
    expect(audit).toContainEqual(expect.objectContaining({ outcome: "substituted", substituted: { decision: "defer", reason_code: "defer_unsupported" } }));
  });
});

describe("ask: an OpenClaw approval of the tool's name and the Guardian's question", () => {
  const ask = (approverId: string, question = "Send a payment of 500?") =>
    toolDecision({
      decision: "ask",
      reasoning: "payment above the limit",
      ask_details: { approver: { type: "human", id: approverId }, question, timeout_seconds: 300 },
    });

  it("asks OpenClaw for an approval of any human approver, and records its resolution", async () => {
    const { hooks, audit } = setup({ reply: ask("approver-1") });
    await startRun(hooks);
    const result = await callTool(hooks, { amount: 500 });
    expect(result).toEqual({
      params: { amount: 500 },
      requireApproval: { title: "account-lookup", description: "Send a payment of 500?", timeoutMs: 300000, allowedDecisions: ["allow-once", "deny"], onResolution: expect.any(Function) },
    });

    await result!.requireApproval!.onResolution!("allow-once");
    await result!.requireApproval!.onResolution!("timeout");
    const askRequestId = (audit.find((event) => event.outcome === "approval") as { rpc_id: unknown } | undefined)?.rpc_id;
    expect(askRequestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(audit.filter((event) => event.outcome === "approval")).toEqual([
      expect.objectContaining({ approval: { requested_approver: { type: "human", id: "approver-1" }, resolution: "allow-once", decision: "allow" } }),
      expect.objectContaining({ approval: { requested_approver: { type: "human", id: "approver-1" }, resolution: "timeout", decision: "deny" } }),
    ]);
  });

  it.each<[string, Record<string, unknown>]>([
    ["message", { action: "send", target: "+529980000102", message: "Hola, su llegada es a las 15:00." }],
    ["pms__update_booking", { booking_ref: "B-1042", check_in: "2026-11-20" }],
  ])("fills the approval of %s the same way: its name, the Guardian's question, no scope", async (toolName, params) => {
    const { hooks } = setup({ reply: ask("+529980000101", "El asistente pide revisión.") });
    await startRun(hooks);
    const result = await hooks.beforeToolCall({ toolName, params }, TOOL_CTX);
    expect(result?.requireApproval).toMatchObject({ title: toolName, description: "El asistente pide revisión." });
    expect(result?.requireApproval).not.toHaveProperty("scope");
    expect(result?.requireApproval).not.toHaveProperty("severity");
    expect(result?.requireApproval).not.toHaveProperty("timeoutReason");
    expect(result?.params).toEqual(params);
  });

  it.each(["agent", "service"])("denies an ask that names an approver of type %s, which no person here may stand in for (§9.2)", async (type) => {
    const { hooks, audit } = setup({
      reply: toolDecision({
        decision: "ask",
        reasoning: "payment above the limit",
        ask_details: { approver: { type, id: "approver-1", endpoint: "https://approvals.example.com", auth: { method: "mtls" } }, question: "Send?", timeout_seconds: 300 },
      }),
    });
    await startRun(hooks);
    const result = await callTool(hooks, { amount: 500 });
    expect(result).toMatchObject({ block: true });
    expect(result?.requireApproval).toBeUndefined();
    expect(audit).toContainEqual(expect.objectContaining({ substituted: { decision: "ask", reason_code: "approver_unavailable" } }));
  });

  it("denies an ask that carries no ask_details", async () => {
    const { hooks } = setup({ reply: toolDecision({ decision: "ask", reasoning: "?" }) });
    await startRun(hooks);
    expect(await callTool(hooks)).toEqual({ block: true, blockReason: expect.stringContaining("ask_details") });
  });

  it.each<[string, Record<string, unknown>]>([
    ["an_ask_that_names_no_approver", { decision: "ask", reasoning: "needs a person", ask_details: { question: "?", timeout_seconds: 60 } }],
    ["a_modify_without_reasoning", { decision: "modify", modifications: { parameter_overrides: { phone: "+1555***" } } }],
    ["a_deny_without_reasoning", { decision: "deny" }],
  ])("blocks %s, which breaks the response schema, whatever the posture says", async (_name, decision) => {
    const { hooks, audit } = setup({ reply: toolDecision(decision), failurePosture: "negotiated", onDecisionFailure: "proceed" });
    await startRun(hooks);
    expect(await callTool(hooks)).toMatchObject({ block: true, blockReason: expect.stringContaining("response-envelope.json") });
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked", failure: { kind: "decision_invalid" } });
  });

  it.each<[string, Record<string, unknown>, boolean]>([
    ["an_allow_without_its_request_id", { decision: "allow" }, false],
    ["a_null_decision", { decision: null }, true],
    ["a_numeric_decision", { decision: 42 }, true],
    ["no_decision_at_all", {}, true],
  ])("blocks a signed result with %s, which breaks the response schema, under a negotiated proceed", async (_name, fields, withRequestId) => {
    const { hooks, audit } = setup({
      reply: (step) =>
        step.method === "steps/toolCallRequest"
          ? { signedResult: { type: "final", acs_version: "0.1.0", ...(withRequestId ? { request_id: step.requestId } : {}), ...fields } }
          : { decision: { decision: "allow" } },
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
    });
    await startRun(hooks);
    expect(await callTool(hooks)).toMatchObject({ block: true, blockReason: expect.stringContaining("response-envelope.json") });
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked", failure: { kind: "decision_invalid" } });
  });

  it("blocks a signed response that carries both a result and an error, which breaks the response envelope", async () => {
    const { hooks, audit } = setup({
      reply: (step) =>
        step.method === "steps/toolCallRequest"
          ? { signedResponse: { result: { type: "final", acs_version: "0.1.0", request_id: step.requestId, decision: "allow" }, error: { code: -32020, message: "evaluation failed" } } }
          : { decision: { decision: "allow" } },
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
    });
    await startRun(hooks);
    expect(await callTool(hooks)).toMatchObject({ block: true, blockReason: expect.stringContaining("response-envelope.json") });
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked", failure: { kind: "decision_invalid" } });
  });

  it("puts the Guardian's context after its question, and freezes the parameters it saw", async () => {
    const { hooks } = setup({
      reply: toolDecision({
        decision: "ask",
        reasoning: "pick one",
        ask_details: { approver: { type: "human", id: "approver-1" }, question: "Send it?", context: "To Maria, +529980000102.", options: ["now", "tomorrow"], timeout_seconds: 60 },
      }),
    });
    await startRun(hooks);
    const result = await callTool(hooks, { text: "x".repeat(600) });
    expect(result?.requireApproval?.description).toBe("Send it?\nTo Maria, +529980000102.");
    expect(result?.params).toEqual({ text: "x".repeat(600) });
  });

  it("denies an ask whose question does not fit OpenClaw's approval, never cutting it", async () => {
    const { hooks, audit } = setup({ reply: ask("approver-1", "q".repeat(513)) });
    await startRun(hooks);
    const result = await callTool(hooks, { amount: 500 });
    expect(result).toEqual({ block: true, blockReason: expect.stringContaining("512") });
    expect(audit).toContainEqual(expect.objectContaining({ substituted: { decision: "ask", reason_code: "approval_text_too_long" } }));
  });
});

describe("message_sending", () => {
  it("sends an allowed reply as the Guardian saw it, naming the session's sender", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "Your order ships today." }, MESSAGE_CTX)).toEqual({
      content: "Your order ships today.",
    });
    expect(server.steps[1]).toMatchObject({
      method: "steps/agentResponse",
      userContext: { user_id: SENDER, authentication_method: "signal" },
      payload: { content: [{ type: "text", value: "Your order ships today." }] },
    });
  });

  it("decides a delivery OpenClaw names no session for by the failure posture, asking the Guardian nothing (§6.4)", async () => {
    const { server, hooks, audit } = setup();
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "Done." }, { channelId: "signal" })).toEqual({ cancel: true });
    expect(server.steps.filter((step) => step.method === "steps/agentResponse")).toEqual([]);
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked", method: "steps/agentResponse", posture_source: "host" });
  });

  it("keeps a session the Guardian refused at sessionStart refused for a run it cannot send", async () => {
    const { hooks } = setup({ failurePosture: "negotiated", methodsEvaluated: ALL_METHODS, reply: (step) => (step.method === "steps/sessionStart" ? { decision: { decision: "deny", reasoning: "no session" } } : { decision: { decision: "allow" } }) });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    const { channel: _dropped, ...noChannel } = { ...AGENT_CTX, runId: "run-2" };
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, noChannel)).toMatchObject({ outcome: "block", reason: expect.stringContaining("refused this session") });
  });

  it("keeps a session the Guardian refused at the handshake refused for a reply it cannot send", async () => {
    const { server, hooks } = setup({ failurePosture: "negotiated" });
    server.handshakeError = { code: -32000, message: "session refused" };
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(await hooks.messageSending({ to: SENDER, content: "secret" }, { ...MESSAGE_CTX, runId: "run-1" })).toEqual({ cancel: true });
    expect(await hooks.replyPayloadSending({ payload: { text: "secret" }, channel: "signal", sessionKey: SESSION_KEY, runId: "run-1" }, { channelId: "signal", sessionKey: SESSION_KEY } as never)).toEqual({ cancel: true });
  });

  it("blocks a message it cannot send, even under the negotiated posture proceed", async () => {
    const { hooks, audit } = setup({ failurePosture: "negotiated", onDecisionFailure: "proceed" });
    await startRun(hooks);
    expect(await dispatchMessage(hooks, { content: "Look", media: [{ path: "/nonexistent.example/photo.png", contentType: "image/png" }] })).toBe("dropped");
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked", posture: "deny", posture_source: "host", failure: { kind: "unsignable" } });
  });

  it("keeps a sessionStart refusal for a tool call OpenClaw names only by its session key", async () => {
    const { hooks } = setup({ failurePosture: "negotiated", onDecisionFailure: "proceed", methodsEvaluated: ALL_METHODS, reply: (step) => (step.method === "steps/sessionStart" ? { decision: { decision: "deny", reasoning: "no session" } } : { decision: { decision: "allow" } }) });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, { runId: "run-9", sessionKey: SESSION_KEY })).toMatchObject({ block: true, blockReason: expect.stringContaining("refused this session") });
  });

  it("applies the negotiated deny to a result another registration cannot send", async () => {
    const runFacts = memoryRunFacts();
    const refusals = memoryRefusals();
    const producer = setup({ runFacts, refusals, failurePosture: "negotiated", onDecisionFailure: "deny", methodsEvaluated: ALL_METHODS });
    const consumer = setup({ runFacts, refusals, failurePosture: "negotiated", guardian: producer.server });
    await startRun(producer.hooks);
    expect(await consumer.hooks.toolResult({ toolCallId: "call-unknown", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "secret" }], details: undefined } }, { runtime: "openclaw", runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID })).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    expect(consumer.audit.at(-1)).toMatchObject({ outcome: "blocked", posture: "deny", posture_source: "negotiated" });
  });

  it("blocks every later step of a run admitted before the Guardian denied its session's sessionStart", async () => {
    let sessionStarts = 0;
    const { hooks } = setup({
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      methodsEvaluated: ["steps/sessionStart"],
      reply: (step) => {
        if (step.method !== "steps/sessionStart") {
          return { decision: { decision: "allow" } };
        }
        sessionStarts += 1;
        return sessionStarts === 1 ? { error: { code: -32603, message: "down" } } : { decision: { decision: "deny", reasoning: "no session" } };
      },
    });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toBeUndefined();
    expect(await hooks.beforeAgentRun({ prompt: "Again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toMatchObject({ outcome: "block" });
    expect(await callTool(hooks)).toMatchObject({ block: true, blockReason: expect.stringContaining("refused this session") });
    expect(await hooks.messageSending({ to: SENDER, content: "secret" }, MESSAGE_CTX)).toEqual({ cancel: true });
  });

  it("withholds, in another registration, the result of a run whose session the Guardian denied at a later sessionStart", async () => {
    const runFacts = memoryRunFacts();
    const refusals = memoryRefusals();
    let sessionStarts = 0;
    const producer = setup({
      runFacts,
      refusals,
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      methodsEvaluated: ["steps/sessionStart", "steps/toolCallRequest"],
      reply: (step) => {
        if (step.method !== "steps/sessionStart") {
          return { decision: { decision: "allow" } };
        }
        sessionStarts += 1;
        return sessionStarts === 1 ? { error: { code: -32603, message: "down" } } : { decision: { decision: "deny", reasoning: "no session" } };
      },
    });
    const consumer = setup({ runFacts, refusals, failurePosture: "negotiated", guardian: producer.server });
    expect(await producer.hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toBeUndefined();
    expect(await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX)).toEqual({ params: {} });
    expect(await producer.hooks.beforeAgentRun({ prompt: "Again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toMatchObject({ outcome: "block" });
    const result = { toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text" as const, text: "secret" }], details: undefined } };
    expect(await consumer.hooks.toolResult(result, { runtime: "openclaw", runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID })).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
  });

  it("keeps the ServerHello saved with a call as the session's posture when the Guardian is gone", async () => {
    const runFacts = memoryRunFacts();
    const refusals = memoryRefusals();
    const producer = setup({ runFacts, refusals, failurePosture: "negotiated", onDecisionFailure: "deny", methodsEvaluated: ALL_METHODS });
    const consumer = setup({ runFacts, refusals, failurePosture: "negotiated", guardian: producer.server });
    await startRun(producer.hooks);
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    const result = { toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text" as const, text: "ok" }], details: undefined } };
    const ctx = { runtime: "openclaw" as const, runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID };
    expect(await consumer.hooks.toolResult(result, ctx)).toBeUndefined();
    producer.server.stop();
    expect(await consumer.hooks.toolResult(result, ctx)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    expect(consumer.audit.at(-1)).toMatchObject({ outcome: "blocked", posture: "deny", posture_source: "negotiated" });
  });

  it("blocks every gate step it cannot send and lets a result follow the posture proceed, recording each", async () => {
    const { server, hooks, audit } = setup({ failurePosture: "negotiated", onDecisionFailure: "proceed", methodsEvaluated: ALL_METHODS });
    const unadmitted = { runId: "run-9", sessionKey: SESSION_KEY, sessionId: SESSION_ID };
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: { a: 1 }, toolCallId: "call-9" }, unadmitted)).toMatchObject({ block: true, blockReason: expect.stringContaining("never saw") });
    expect(await hooks.toolResult({ toolCallId: "call-9", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "ok" }], details: undefined } }, { runtime: "openclaw", ...unadmitted })).toBeUndefined();
    expect(await hooks.messageSending({ to: SENDER, content: "Done." }, { channelId: "signal" })).toEqual({ cancel: true });
    expect(await hooks.replyPayloadSending({ payload: { text: "Done." }, channel: "signal" }, { channelId: "signal" } as never)).toEqual({ cancel: true });
    expect(server.steps.filter((step) => step.method.startsWith("steps/"))).toEqual([]);
    expect(audit.map((entry) => [entry.outcome, entry.method])).toEqual([
      ["blocked", "steps/toolCallRequest"],
      ["proceeded", "steps/toolCallResult"],
      ["blocked", "steps/agentResponse"],
      ["blocked", "steps/agentResponse"],
    ]);
  });

  it("decides every delivery, the operator's old notice text and a part of an earlier reply included", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    expect(await hooks.replyPayloadSending({ payload: { text: "Public. Do not disclose SECRET." }, channel: "signal", sessionKey: SESSION_KEY }, { channelId: "signal", sessionKey: SESSION_KEY } as never)).toBeUndefined();
    const before = server.steps.length;
    expect(await hooks.messageSending({ to: SENDER, content: "Notice" }, MESSAGE_CTX)).toEqual({ content: "Notice" });
    expect(await hooks.messageSending({ to: SENDER, content: "SECRET" }, MESSAGE_CTX)).toEqual({ content: "SECRET" });
    expect(server.steps.slice(before).map((step) => [step.method, step.payload])).toEqual([
      ["steps/agentResponse", { content: [{ type: "text", value: "Notice" }] }],
      ["steps/agentResponse", { content: [{ type: "text", value: "SECRET" }] }],
    ]);
  });

  it("shows the Guardian the media a reply carries, and cancels the whole reply on a rewrite, since only the text can change", async () => {
    const { server, hooks, audit } = setup({ reply: replyAnswer({ decision: { decision: "modify", reasoning: "r", modifications: { redactions: [{ path: "/content/0/value", replacement: "x" }] } } }) });
    await startRun(hooks);
    const media = { mediaUrls: ["https://files.example.com/report.pdf"] };
    // OpenClaw keeps a reply's media when a hook replaces its text, so the reply is cancelled whole.
    expect(await hooks.messageSending({ to: SENDER, content: "Here it is.", metadata: media }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(server.steps.at(-1)?.payload).toEqual({ content: [{ type: "text", value: "Here it is." }, { type: "file", value: "https://files.example.com/report.pdf" }] });
    expect(audit.at(-1)).toMatchObject({ outcome: "substituted", substituted: { decision: "modify", reason_code: "modify_unsupported" } });
  });

  it("cancels a denied reply that carries media, so the media never goes out", async () => {
    const { hooks } = setup({ reply: replyAnswer({ decision: { decision: "deny", reasoning: "no files" } }) });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "Report", metadata: { mediaUrls: ["https://files.example.com/a.pdf"] } }, MESSAGE_CTX)).toEqual({ cancel: true });
  });

  it("sends a reply whose text is the word stale", async () => {
    const { hooks } = setup();
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "stale" }, MESSAGE_CTX)).toEqual({ content: "stale" });
  });

  it("sends an automatic reply that no message call carried as steps/agentResponse", async () => {
    const { server, hooks } = setup({});
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "Your order ships today." }, MESSAGE_CTX)).toEqual({ content: "Your order ships today." });
    expect(server.steps.map((step) => step.method)).toEqual(["steps/userMessage", "steps/agentResponse"]);
  });

  it.each<[string, Reply]>([
    ["deny", { decision: { decision: "deny", reasoning: "foreign link" } }],
    ["ask", { decision: { decision: "ask", reasoning: "r", ask_details: { approver: { type: "human", id: "approver-1" }, timeout_seconds: 60 } } }],
  ])("cancels a reply answered %s, with no text in its place", async (_name, answer) => {
    const { hooks } = setup({ reply: replyAnswer(answer) });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "Pay at https://pay.example.net" }, MESSAGE_CTX)).toEqual({ cancel: true });
  });

  it("sends the Guardian's rewrite of a reply", async () => {
    const { hooks } = setup({
      reply: replyAnswer({ decision: { decision: "modify", reasoning: "masked", modifications: { redactions: [{ path: "/content/0/value", replacement: "The one-time code is ****." }] } } }),
    });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "The one-time code is 4321." }, MESSAGE_CTX)).toEqual({ content: "The one-time code is ****." });
  });

  it("cancels a reply whose rewrite leaves anything but text, audited as modify_unsupported", async () => {
    const { hooks, audit } = setup({
      reply: replyAnswer({ decision: { decision: "modify", reasoning: "odd", modifications: { parameter_overrides: { content: [{ type: "image" }] } } } }),
    });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(audit).toContainEqual(expect.objectContaining({ outcome: "substituted", substituted: { decision: "modify", reason_code: "modify_unsupported" } }));
  });

  it("refuses a run with no text in its place", async () => {
    const { hooks } = setup({ reply: () => ({ decision: { decision: "deny", reasoning: "not today" } }) });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toEqual({ outcome: "block", reason: "not today" });
  });

  it.each([
    ["another_recipient", { to: OTHER_PHONE, content: "hi" }, MESSAGE_CTX],
    ["another_channel", { to: SENDER, content: "hi" }, { ...MESSAGE_CTX, channelId: "sms" }],
  ])("decides a session's delivery addressed to %s as steps/agentResponse, as OpenClaw routes it", async (_name, event, ctx) => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(await hooks.messageSending(event, ctx)).toEqual({ content: "hi" });
    expect(server.steps.map((step) => step.method)).toEqual(["steps/userMessage", "steps/agentResponse"]);
  });

  it("sends nothing in a session no run was admitted to, as in a runtime that skips before_agent_run", async () => {
    const { server, hooks } = setup();
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(server.steps).toHaveLength(0);
  });

  it("sends nothing after OpenClaw ended the session", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID }, { sessionId: SESSION_ID });
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(server.steps.map((step) => step.method)).toEqual(["steps/userMessage"]);
  });

  it("sends nothing in a session whose key names no single sender", async () => {
    const { server, hooks } = setup();
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, { channelId: "signal", sessionKey: "agent:main:main" })).toEqual({
      cancel: true,
    });
    expect(server.steps).toHaveLength(0);
  });

  it("sends nothing with no session key, as for a message an operator or another plugin sends", async () => {
    const { hooks } = setup();
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, { channelId: "signal" })).toEqual({ cancel: true });
  });

  it("governs a message another plugin sends into an admitted session, as the session's reply", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await hooks.messageSending({ to: SENDER, content: "Reminder: the call starts at 15:00" }, MESSAGE_CTX)).toEqual({
      content: "Reminder: the call starts at 15:00",
    });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/agentResponse", userContext: { user_id: SENDER } });
  });
});

/** The agent's owner, and their own direct session. */
const OWNER = OTHER_PHONE;
const OWNER_KEY = `agent:main:signal:direct:${OWNER}`;
const OWNER_AGENT_CTX = { runId: "run-o", sessionKey: OWNER_KEY, sessionId: "session-o", senderId: OWNER, channel: "signal" };
const OWNER_TOOL_CTX = { runId: "run-o", sessionKey: OWNER_KEY };
const THIRD_PHONE = "+15550177";

/** A call of OpenClaw's `message` tool; OpenClaw files its delivery under the recipient's session. */
function sendCall(hooks: Hooks, params: Record<string, unknown>, ctx: Record<string, unknown> = TOOL_CTX, toolCallId = "call-1") {
  return hooks.beforeToolCall({ toolName: "message", params, toolCallId }, ctx);
}

function deliver(
  hooks: Hooks,
  to: string,
  content: string,
  ctx: { channelId: string; sessionKey?: string; accountId?: string; runId?: string } = { channelId: "signal", sessionKey: `agent:main:signal:direct:${to}` },
  metadata?: Record<string, unknown>,
) {
  return hooks.messageSending({ to, content, ...(metadata === undefined ? {} : { metadata }) }, ctx);
}

describe("failure posture closed: no decision, no action", () => {
  const unreachable = async (): Promise<Setup> => {
    const setupResult = setup();
    setupResult.server.stop();
    return setupResult;
  };

  it("blocks a run when the Guardian is unreachable", async () => {
    const { hooks, audit } = await unreachable();
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toEqual({ outcome: "block", reason: expect.any(String) });
    expect(audit).toEqual([expect.objectContaining({ outcome: "blocked", posture_source: "host" })]);
  });

  it("replaces a reply when the Guardian goes away after the run started", async () => {
    const { server, hooks, audit } = setup();
    await startRun(hooks);
    server.stop();
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(audit).toEqual([expect.objectContaining({ outcome: "blocked", method: "steps/agentResponse", posture_source: "host" })]);
  });

  it("blocks a tool call when the Guardian goes away after the run started", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    server.stop();
    expect(await callTool(hooks)).toMatchObject({ block: true });
  });

  it.each<[string, Reply]>([
    ["malformed", { body: "this is not json" }],
    ["unsigned", { unsignedDecision: { decision: "allow" } }],
    ["an_error_without_a_decision", { error: { code: -32603, message: "internal" } }],
    ["a_result_without_a_decision", { decision: { reasoning: "no verdict" } }],
  ])("replaces the reply when the Guardian's answer is %s", async (_name, answer) => {
    const { hooks } = setup({ reply: replyAnswer(answer) });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
  });

  it("replaces the reply itself when the Guardian answers after the deadline", async () => {
    const { hooks } = setup({ reply: replyAnswer({ hang: true }), deadlineMs: 300 });
    await startRun(hooks);
    const startedAt = performance.now();
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(performance.now() - startedAt).toBeLessThan(1500);
  });

  it("blocks when the Guardian cannot verify this host's signature", async () => {
    const wrongKey: HmacKey = { ...KEY, secret: Buffer.from("another secret of thirty-two bytes!", "utf8") };
    const { server, hooks } = setup({ clientKey: wrongKey });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(server.badSignatures).toBe(1);
  });

  it("blocks over a negotiated proceed", async () => {
    const { hooks } = setup({ reply: replyAnswer({ hang: true }), deadlineMs: 300, onDecisionFailure: "proceed" });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
  });
});

describe("failure posture negotiated", () => {
  it("proceeds, audited, when the Guardian negotiated proceed and then went silent past its own timeout", async () => {
    const { server, hooks, audit } = setup({ reply: replyAnswer({ hang: true }), deadlineMs: 1000, onDecisionFailure: "proceed", failurePosture: "negotiated" });
    server.serverHello = { timeout_config: { default_ms: 200 } };
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ content: "hi" });
    expect(audit).toEqual([expect.objectContaining({ outcome: "proceeded", posture: "proceed", posture_source: "negotiated" })]);
  });

  it("blocks, as the host's decision, a step whose wait the hook's own deadline ended before the negotiated timeout (§6.4, #269)", async () => {
    const { hooks, audit } = setup({ reply: replyAnswer({ hang: true }), deadlineMs: 600, onDecisionFailure: "proceed", failurePosture: "negotiated" });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked", posture: "deny", posture_source: "host", failure: { kind: "timeout" } });
  });

  it("blocks when the Guardian negotiated deny", async () => {
    const { hooks } = setup({ reply: replyAnswer({ hang: true }), deadlineMs: 300, onDecisionFailure: "deny", failurePosture: "negotiated" });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
  });
});

describe("an ASK the adapter cannot put to a person", () => {
  it("records no substitution for a Guardian's own deny that carries modifications_invalid", async () => {
    const { hooks, audit } = setup({ reply: toolDecision({ decision: "deny", reasoning: "no", reason_codes: ["modifications_invalid"] }) });
    await startRun(hooks);
    expect(await callTool(hooks)).toMatchObject({ block: true });
    expect(audit.filter((entry) => entry.outcome === "substituted")).toEqual([]);
  });
});

describe("the hooks of an adapter that cannot work", () => {
  it("blocks every step and sends nothing in place of what it blocked", async () => {
    const hooks = createBlockingHooks("not configured");
    const notices: string[] = [];
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toEqual({ outcome: "block", reason: "not configured" });
    expect(await hooks.replyDispatch(inboundEvent({ sessionKey: SESSION_KEY, senderId: SENDER, content: "hi" }), dispatchContext(notices))).toMatchObject({ handled: true, queuedFinal: false });
    expect(notices).toEqual([]);
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, TOOL_CTX)).toEqual({ block: true, blockReason: "not configured" });
    expect(await hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "secret" }], details: undefined } } as never, { runtime: "openclaw" } as never)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    expect(await hooks.replyPayloadSending({ payload: { text: "Report" }, channel: "signal" } as never, {} as never)).toEqual({ cancel: true });
    expect(await hooks.messageSending({ to: SENDER, content: "Report", metadata: { mediaUrls: ["https://files.example.com/a.pdf"] } }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(await hooks.messageSending({ to: SENDER, content: "Report" }, MESSAGE_CTX)).toEqual({ cancel: true });
  });
});

describe("a stalled plugin-state store never outlasts the hook's deadline", () => {
  /** OpenClaw's store, with the operations `stalled` names never answering. */
  function stalledRunFacts(stalled: ReadonlyArray<keyof RunFactsStore>): RunFactsStore {
    const store = memoryRunFacts();
    const never = () => new Promise<never>(() => {});
    return Object.fromEntries(Object.entries(store).map(([name, operation]) => [name, stalled.includes(name as keyof RunFactsStore) ? never : operation])) as RunFactsStore;
  }

  it("blocks a call the Guardian denied when the call's fact cannot be stored", async () => {
    const { hooks } = setup({ runFacts: stalledRunFacts(["setIfAbsent"]), deadlineMs: 1000, reply: toolDecision({ decision: "deny", reasoning: "no" }) });
    await startRun(hooks);
    const startedAt = performance.now();
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX)).toMatchObject({ block: true });
    expect(performance.now() - startedAt).toBeLessThan(3000);
  });

  it("blocks a call the Guardian allowed when the call's fact cannot be stored", async () => {
    const { hooks } = setup({ runFacts: stalledRunFacts(["setIfAbsent"]), deadlineMs: 1000 });
    await startRun(hooks);
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX)).toMatchObject({ block: true, blockReason: expect.stringContaining("before the hook's deadline") });
  });

  it("refuses a run whose admission cannot be stored", async () => {
    const { hooks } = setup({ runFacts: stalledRunFacts(["set"]), deadlineMs: 1000 });
    const startedAt = performance.now();
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(performance.now() - startedAt).toBeLessThan(3000);
  });

  it("withholds a result whose call's fact cannot be read", async () => {
    const { hooks } = setup({ runFacts: stalledRunFacts(["get"]), deadlineMs: 1000 });
    await startRun(hooks).catch(() => {});
    const startedAt = performance.now();
    expect(await hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "secret" }], details: undefined } }, { runtime: "openclaw", runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID }))
      .toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    expect(performance.now() - startedAt).toBeLessThan(3000);
  });
});

describe("a reply that fails verification blocks whatever the posture says (#308)", () => {
  it.each<[string, Reply]>([
    ["tampered", { tamperedDecision: { decision: "deny", reasoning: "no" }, becomes: { decision: "allow" } }],
    ["unsigned", { unsignedDecision: { decision: "allow" } }],
  ])("blocks a %s answer under a negotiated proceed, recorded as signature_invalid", async (_name, answer) => {
    const { hooks, audit } = setup({ reply: toolDecisionReply(answer), onDecisionFailure: "proceed", failurePosture: "negotiated" });
    await startRun(hooks);
    expect(await callTool(hooks)).toMatchObject({ block: true, blockReason: expect.stringContaining("could not be verified") });
    expect(audit.at(-1)).toMatchObject({
      outcome: "blocked",
      method: "steps/toolCallRequest",
      posture: "proceed",
      posture_source: "negotiated",
      failure: { kind: "signature_invalid" },
    });
  });
});

describe("methods the Guardian does not evaluate", () => {
  it("allows a method missing from methods_evaluated without sending it", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ["steps/toolCallRequest"] });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ content: "hi" });
    expect(await callTool(hooks)).toEqual({ params: { phone: OTHER_PHONE } });
    expect(server.steps.map((step) => step.method)).toEqual(["steps/toolCallRequest"]);
  });
});

describe("a session refusal cancels pending decisions", () => {
  describe.each(["same_registration", "another_registration"])("%s during state access", (registration) => {
    it.each(["call_create", "call_run", "call_approval", "session_admission", "run_admission", "result_read"])("blocks after %s finishes", async (phase) => {
      const held = heldAnswer();
      const retained = memoryRunFacts();
      const refusals = memoryRefusals();
      let armed = false;
      let producer: Setup;
      async function pause(at: string) {
        if (armed && phase === at) {
          armed = false;
          await held.answer();
        }
      }
      const runFacts: RunFactsStore = {
        ...retained,
        async setIfAbsent(runId, namespace, value) {
          await pause("call_create");
          return retained.setIfAbsent(runId, namespace, value);
        },
        async set(runId, namespace, value) {
          if (namespace === "admission" && value.terminal !== true) await pause("run_admission");
          if (value.ran === true) await pause("call_run");
          if (value.approvalPending === true) await pause("call_approval");
          await retained.set(runId, namespace, value);
        },
        async get(runId, namespace) {
          const value = await retained.get(runId, namespace);
          if (namespace === "admission" && producer.server.steps.at(-1)?.method === METHODS.toolCallResult) await pause("result_read");
          return value;
        },
      };
      const admissions: AdmissionStore = { load: async () => [], put: async () => pause("session_admission"), delete: async () => {} };
      producer = setup({
        methodsEvaluated: ALL_METHODS, runFacts, refusals, admissions, failurePosture: "negotiated",
        reply: (step) => phase === "call_approval" && step.method === METHODS.toolCallRequest && (step.payload.tool as { name: string }).name === "pending"
          ? { decision: { decision: "ask", reasoning: "approval", ask_details: { approver: { type: "human", id: "reviewer" }, question: "Approve?", timeout_seconds: 60, timeout_disposition: "deny" } } }
          : { decision: { decision: "allow" } },
      });
      const admitting = phase === "session_admission" || phase === "run_admission";
      if (!admitting) {
        await startRun(producer.hooks);
        await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
      }
      const controller = registration === "same_registration" ? producer : setup({ guardian: producer.server, runFacts, refusals });
      if (controller !== producer) await controller.hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, runId: "controller" });
      armed = true;
      const reading = phase === "result_read";
      const pending = admitting
        ? producer.hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)
        : reading
          ? producer.hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "secret" }], details: undefined } }, { runtime: "openclaw", ...AGENT_CTX })
          : producer.hooks.beforeToolCall({ toolName: "pending", params: {}, toolCallId: "pending" }, TOOL_CTX);
      try {
        await Promise.race([held.reached, pending.then(() => { throw new Error("the hook returned before reaching the state operation"); })]);
        const requestId = producer.server.steps.at(-1)!.requestId;
        producer.server.forgetSessions();
        producer.server.handshakeError = { code: -32000, message: "session refused" };
        expect(await controller.hooks.beforeToolCall({ toolName: "refuse-session", params: {} }, { ...TOOL_CTX, runId: controller === producer ? "run-1" : "controller" })).toMatchObject({ block: true });
        expect(await refusals.get(SESSION_ID)).toEqual({ code: -32000, message: "session refused" });
        held.release();
        expect(await pending).toMatchObject(admitting ? { outcome: "block" } : reading ? { result: { content: [{ type: "text", text: WITHHELD_OUTPUT }] } } : { block: true });
        if (!reading) {
          expect(producer.audit).toContainEqual(expect.objectContaining({ request_id: requestId, outcome: "substituted", substituted: { decision: phase === "call_approval" ? "ask" : "allow", reason_code: "guardian_refused" } }));
        }
        expect(await retained.get("run-1", "admission")).toBeUndefined();
      } finally {
        held.release();
        await pending;
      }
    });
  });

  const cases: Array<{ name: string; method: string; start(hooks: Hooks): Promise<unknown>; blocked: object; decision?: Record<string, unknown> }> = [
    { name: "tool_call", method: METHODS.toolCallRequest, start: (hooks) => hooks.beforeToolCall({ toolName: "held-call", params: {}, toolCallId: "held-call" }, TOOL_CTX), blocked: { block: true } },
    { name: "tool_result", method: METHODS.toolCallResult, start: (hooks) => hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "secret" }], details: undefined } }, { runtime: "openclaw", ...AGENT_CTX }), blocked: { result: { content: [{ type: "text", text: WITHHELD_OUTPUT }] } } },
    { name: "inbound_message", method: METHODS.userMessage, start: (hooks) => hooks.replyDispatch(inboundEvent({ sessionKey: SESSION_KEY, senderId: SENDER, content: "pending" }), dispatchContext([])), blocked: { handled: true, queuedFinal: false } },
    { name: "run_admission", method: METHODS.userMessage, start: (hooks) => hooks.beforeAgentRun({ prompt: "pending", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" }), blocked: { outcome: "block" } },
    { name: "reply_payload", method: METHODS.agentResponse, start: (hooks) => hooks.replyPayloadSending({ payload: { text: "secret" }, channel: "signal", sessionKey: SESSION_KEY }, MESSAGE_CTX), blocked: { cancel: true } },
    { name: "message_delivery", method: METHODS.agentResponse, start: (hooks) => hooks.messageSending({ to: SENDER, content: "secret" }, MESSAGE_CTX), blocked: { cancel: true } },
    ...[
      { decision: "modify", reasoning: "replace", modifications: { redactions: [{ path: "/phone", replacement: "[masked]" }] } },
      { decision: "ask", reasoning: "approval", ask_details: { approver: { type: "human", id: "reviewer" }, question: "Approve?", timeout_seconds: 60, timeout_disposition: "deny" } },
      { decision: "defer", reasoning: "wait", defer_details: { reason: "pending_dependency", resolution_method: "timeout", resolution_timeout_ms: 60000, timeout_decision: "deny" } },
    ].map((decision) => ({ name: `tool_${decision.decision}`, method: METHODS.toolCallRequest, start: (hooks: Hooks) => callTool(hooks), blocked: { block: true }, decision })),
  ];

  describe.each(["same_registration", "another_registration"])("%s", (registration) => {
    it.each(cases)("blocks $name when its decision arrives after a session refusal", async ({ name, method, start, blocked, decision }) => {
      const held = heldAnswer(decision === undefined ? undefined : { decision });
      const refusals = memoryRefusals();
      const runFacts = memoryRunFacts();
      let holdNext = false;
      const producer = setup({
        methodsEvaluated: ALL_METHODS,
        failurePosture: "negotiated",
        onDecisionFailure: "proceed",
        runFacts,
        refusals,
        reply: (step) => {
          if (holdNext && step.method === method) {
            holdNext = false;
            return held.answer();
          }
          return { decision: { decision: "allow" } };
        },
      });
      await startRun(producer.hooks);
      await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
      const controller = registration === "same_registration" ? producer : setup({ guardian: producer.server, runFacts, refusals });
      if (controller !== producer) {
        expect(await controller.hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, runId: "controller" })).toBeUndefined();
      }
      holdNext = true;
      const pending = start(producer.hooks);
      try {
        await Promise.race([held.reached, pending.then(() => { throw new Error("the hook returned before reaching the Guardian"); })]);
        const requestId = producer.server.steps.at(-1)!.requestId;
        producer.server.forgetSessions();
        producer.server.handshakeError = { code: -32000, message: "session refused" };
        if (name === "run_admission") {
          expect(await controller.hooks.beforeToolCall({ toolName: "refuse-session", params: {} }, { ...TOOL_CTX, runId: controller === producer ? "run-1" : "controller" })).toMatchObject({ block: true });
        } else {
          expect(await dispatchMessage(controller.hooks, { content: "refuse the session" })).toBe("dropped");
        }
        expect(await refusals.get(SESSION_ID)).toEqual({ code: -32000, message: "session refused" });
        held.release();
        expect(await pending).toMatchObject(blocked);
        expect(producer.audit).toContainEqual(expect.objectContaining({
          method,
          request_id: requestId,
          outcome: "substituted",
          substituted: { decision: decision?.decision ?? "allow", reason_code: "guardian_refused" },
        }));
      } finally {
        held.release();
        await pending;
      }
    });
  });
});

describe("session", () => {
  it("negotiates once per session and again, once, when the Guardian forgot it", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(server.handshakes).toBe(1);
    server.forgetSessions();
    expect(await callTool(hooks)).toEqual({ params: { phone: OTHER_PHONE } });
    expect(server.handshakes).toBe(2);
  });

  it("follows the posture when the Guardian still does not know the session after a new handshake", async () => {
    const { server, hooks } = setup({
      reply: (step) =>
        step.method === "steps/toolCallRequest"
          ? { error: { code: -32003, message: "not negotiated" } }
          : { decision: { decision: "allow" } },
    });
    await startRun(hooks);
    expect(await callTool(hooks)).toMatchObject({ block: true });
    expect(server.handshakes).toBe(2);
  });

  it.each<FailurePosture>(["negotiated", "closed"])("blocks, under %s, a step whose session the Guardian refused at handshake", async (failurePosture) => {
    const { server, hooks, audit } = setup({ failurePosture, onDecisionFailure: "proceed" });
    server.handshakeError = { code: -32000, message: "session refused" };
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(audit[0]).toMatchObject({ outcome: "blocked", failure: { kind: "refused" } });
  });

  it("keeps the last 250 ms of a hook's deadline to record the answer, so an answer inside them counts as late", async () => {
    const { server, hooks, audit } = setup({ deadlineMs: 1000 });
    await startRun(hooks);
    server.delayMs = 850;
    expect(await callTool(hooks)).toMatchObject({ block: true });
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked", posture_source: "host", failure: { kind: "timeout" } });
  });

  it("lets a refused re-handshake replace the session's ServerHello, so a later outage does not proceed", async () => {
    let forget = false;
    const { server, hooks } = setup({
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      reply: (step) => (forget && step.method === "steps/toolCallRequest" ? { error: { code: -32003, message: "not negotiated" } } : { decision: { decision: "allow" } }),
    });
    await startRun(hooks);
    forget = true;
    server.handshakeError = { code: -32000, message: "session refused" };
    expect(await callTool(hooks)).toMatchObject({ block: true });
    server.stop();
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: { phone: OTHER_PHONE }, toolCallId: "call-2" }, TOOL_CTX)).toMatchObject({ block: true });
  });

  it("reads a call's result under its own ServerHello without changing the one later steps use", async () => {
    let failing = false;
    const { server, hooks } = setup({
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      methodsEvaluated: ALL_METHODS,
      reply: (step) => (failing ? { error: { code: -32603, message: "down" } } : { decision: { decision: "allow" } }),
    });
    await startRun(hooks);
    await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    server.forgetSessions();
    server.serverHello = { on_decision_failure: "deny" };
    await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-2" }, TOOL_CTX);
    expect(server.handshakes).toBe(2);
    await hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "ok" }], details: undefined } }, { runtime: "openclaw", runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID });
    failing = true;
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-3" }, TOOL_CTX)).toMatchObject({ block: true });
  });

  it.each<[number, string]>([[-32600, "blocked"], [-32020, "blocked"], [-32603, "proceeded"]])("answers a verified error %d under a negotiated proceed as %s (#308: only -32603 follows the posture)", async (code, outcome) => {
    const { hooks, audit } = setup({
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      reply: (step) => (step.method === "steps/toolCallRequest" ? { error: { code, message: "no" } } : { decision: { decision: "allow" } }),
    });
    await startRun(hooks);
    expect(await callTool(hooks)).toEqual(outcome === "blocked" ? expect.objectContaining({ block: true }) : { params: { phone: OTHER_PHONE } });
    expect(audit.at(-1)).toMatchObject({ outcome });
  });

  it("lets a session's refusal outrank the ServerHello an earlier call was decided under", async () => {
    let forget = false;
    const { server, hooks } = setup({
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      methodsEvaluated: ALL_METHODS,
      reply: (step) => (forget && step.method === "steps/toolCallRequest" ? { error: { code: -32003, message: "not negotiated" } } : { decision: { decision: "allow" } }),
    });
    await startRun(hooks);
    await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    forget = true;
    server.handshakeError = { code: -32000, message: "session refused" };
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-2" }, TOOL_CTX)).toMatchObject({ block: true });
    server.stop();
    expect(await hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "secret" }], details: undefined } }, { runtime: "openclaw", runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID }))
      .toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
  });

  it("negotiates again after a handshake error with a retry in §17.1, such as -32006", async () => {
    const { server, hooks } = setup({ failurePosture: "negotiated", onDecisionFailure: "proceed" });
    server.handshakeError = { code: -32006, message: "timestamp out of window" };
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    server.handshakeError = undefined;
    expect(await hooks.beforeAgentRun({ prompt: "Hello again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    expect(server.handshakes).toBe(2);
  });

  it("keeps a session the Guardian refused at handshake refused, even when the Guardian is later unreachable", async () => {
    const { server, hooks } = setup({ failurePosture: "negotiated", onDecisionFailure: "proceed" });
    server.handshakeError = { code: -32000, message: "session refused" };
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    server.stop();
    expect(await hooks.beforeAgentRun({ prompt: "Hello again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toMatchObject({ outcome: "block" });
    expect(server.handshakes).toBe(1);
  });

  it.each<FailurePosture>(["negotiated", "closed"])("blocks, under %s, every step when the Guardian cannot verify this host's key", async (failurePosture) => {
    const wrongKey: HmacKey = { ...KEY, secret: Buffer.from("another secret of thirty-two bytes!", "utf8") };
    const { server, hooks, audit } = setup({ clientKey: wrongKey, failurePosture, onDecisionFailure: "proceed" });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(server.badSignatures).toBe(1);
    expect(audit[0]).toMatchObject({ outcome: "blocked", failure: { kind: "refused" } });
  });

  it.each<"proceed" | "deny">(["proceed", "deny"])("blocks, under the negotiated %s, a step whose -32003 is followed by a failed handshake, and keeps the verified ServerHello", async (onDecisionFailure) => {
    let forget = false;
    const { server, hooks, audit } = setup({
      failurePosture: "negotiated",
      onDecisionFailure,
      reply: (step) => (forget && step.method === "steps/toolCallRequest" ? { error: { code: -32003, message: "not negotiated" } } : { decision: { decision: "allow" } }),
    });
    await startRun(hooks);
    forget = true;
    server.handshakeError = { code: -32603, message: "down" };
    expect(await callTool(hooks)).toMatchObject({ block: true });
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked", posture: onDecisionFailure, posture_source: "negotiated", failure: { kind: "refused" } });
  });

  it.each<[string, Record<string, unknown>]>([
    ["refuses_the_acs_core_profile", { profiles_accepted: [] }],
    ["offers_no_HMAC_SHA256", { signature_algorithms_supported: [] }],
  ])("keeps the posture of a verified ServerHello that %s, and negotiates again at the next step", async (_name, serverHello) => {
    const { server, hooks, audit } = setup({
      failurePosture: "negotiated",
      onDecisionFailure: "deny",
      reply: (step) => (step.method === "steps/toolCallRequest" ? { error: { code: -32603, message: "down" } } : { decision: { decision: "allow" } }),
    });
    server.serverHello = serverHello;
    await startRun(hooks);
    expect(await callTool(hooks)).toMatchObject({ block: true });
    expect(audit.at(-1)).toMatchObject({
      outcome: "blocked",
      posture: "deny",
      posture_source: "negotiated",
      session_failure: { kind: "server_hello_invalid" },
    });
    expect(server.handshakes).toBeGreaterThan(1);
  });

  it.each<[string, Record<string, unknown>]>([
    ["breaks_handshake_json_with_a_method_that_is_not_a_string", { methods_evaluated: [false] }],
    ["negotiates_another_version_than_offered", { negotiated_version: "1.0.0" }],
  ])("applies the ACS default posture when the signed ServerHello %s (§6.4: a malformed response)", async (_name, serverHello) => {
    const { server, hooks, audit } = setup({ failurePosture: "negotiated", onDecisionFailure: "deny" });
    server.serverHello = serverHello;
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toBeUndefined();
    expect(server.steps).toEqual([]);
    expect(audit[0]).toMatchObject({ outcome: "proceeded", posture_source: "default", session_failure: { kind: "server_hello_invalid" } });
  });

  it("blocks under closed every step whose ServerHello is malformed", async () => {
    const { server, hooks, audit } = setup({ failurePosture: "closed" });
    server.serverHello = { methods_evaluated: [false] };
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(audit[0]).toMatchObject({ outcome: "blocked", posture_source: "host" });
  });

  it("takes handshake.json's default posture for a ServerHello that names none", async () => {
    const { server, hooks, audit } = setup({ failurePosture: "negotiated" });
    server.serverHello = { on_decision_failure: undefined };
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toBeUndefined();
    expect(audit).toEqual([]);
  });

  it("keeps the negotiated deny for every step of the session while a re-handshake after -32003 hangs", async () => {
    let forget = false;
    const { server, hooks, audit } = setup({
      failurePosture: "negotiated",
      onDecisionFailure: "deny",
      deadlineMs: 1000,
      reply: (step) => (forget && step.method === "steps/toolCallRequest" ? { error: { code: -32003, message: "not negotiated" } } : { decision: { decision: "allow" } }),
    });
    await startRun(hooks);
    forget = true;
    server.handshakeHangs = true;
    const first = hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-a" }, TOOL_CTX);
    await Bun.sleep(50);
    const second = hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-c" }, TOOL_CTX);
    expect(await first).toMatchObject({ block: true });
    expect(await second).toMatchObject({ block: true });
    expect(audit.filter((entry) => entry.outcome === "proceeded")).toEqual([]);
    expect(audit.filter((entry) => entry.outcome === "blocked").every((entry) => (entry as { posture: string }).posture === "deny")).toBe(true);
  });

  it("ends the ACS session with OpenClaw's, and governs the reused session key under a new one", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID, reason: "reset" }, { sessionId: SESSION_ID });
    const next = { ...AGENT_CTX, runId: "run-2", sessionId: "session-2" };
    expect(await hooks.beforeAgentRun({ prompt: "Hello again", senderId: SENDER }, next)).toBeUndefined();
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, { runId: "run-2", sessionKey: SESSION_KEY, sessionId: "session-2" })).toEqual({
      params: {},
    });
    expect(await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX)).toEqual({ content: "hi" });
    const ended = server.steps.find((step) => step.method === "steps/sessionEnd");
    expect(ended?.payload).toEqual({ reason: "completed", summary: { decision_failures: {} } });
    const later = server.steps.slice(server.steps.indexOf(ended!) + 1);
    expect(later.every((step) => step.sessionId !== ended!.sessionId)).toBe(true);
    expect(new Set(later.map((step) => step.sessionId)).size).toBe(1);
  });

  it("sends no sessionEnd for a session it admitted no run to", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID }, { sessionId: SESSION_ID });
    expect(server.steps).toHaveLength(0);
  });

  it("blocks a tool call that names another OpenClaw session than its run", async () => {
    const { hooks } = setup();
    await startRun(hooks);
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, { runId: "run-1", sessionId: "session-9" })).toMatchObject({
      block: true,
    });
  });

  it("uses one ACS session id per OpenClaw session key", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    await hooks.messageSending({ to: SENDER, content: "hi" }, MESSAGE_CTX);
    const ids = new Set(server.steps.map((step) => step.sessionId));
    expect(ids.size).toBe(1);
    expect([...ids][0]).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

/** An admission store kept in a map that outlives the hooks, as a store on disk outlives a process. */
function mapStore(): AdmissionStore & { rows: Map<string, Admission> } {
  const rows = new Map<string, Admission>();
  return {
    rows,
    async load() {
      return [...rows];
    },
    async put(sessionKey, admission) {
      rows.set(sessionKey, admission);
    },
    async delete(sessionKey) {
      rows.delete(sessionKey);
    },
  };
}

const NO_SENDER_CTX = { runId: "run-2", sessionKey: SESSION_KEY, sessionId: SESSION_ID, trigger: "cron" };

describe("a run with no channel sender acts for the person OpenClaw names", () => {
  it("governs a scheduled run in a session admitted to its sender as that sender", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    const before = server.steps.length;
    expect(await hooks.beforeAgentRun({ prompt: "Reminder: send the weekly report" }, NO_SENDER_CTX)).toBeUndefined();
    const reminder = server.steps.filter((step) => step.turnId === "run-2");
    expect(server.steps.slice(before).find((step) => step.method === "steps/agentTrigger")?.payload).toMatchObject({ trigger_type: "scheduled" });
    expect(reminder.find((step) => step.method === "steps/turnStart")?.payload).toMatchObject({ triggered_by: "scheduled" });
    expect(server.steps.slice(before).find((step) => step.method === "steps/agentTrigger")).toMatchObject({ userContext: { user_id: SENDER }, payload: { trigger_source: { prompt: "Reminder: send the weekly report" } } });
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, { runId: "run-2", sessionKey: SESSION_KEY })).toMatchObject({
      params: {},
    });
  });

  it("sends a scheduled run in a session nobody was admitted to without a person, as scheduled", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    expect(await hooks.beforeAgentRun({ prompt: "tick" }, { ...NO_SENDER_CTX, sessionKey: "agent:main:cron:job-1:run:r-1" })).toBeUndefined();
    expect(server.steps.find((step) => step.method === "steps/agentTrigger")).toMatchObject({ userContext: undefined, payload: { trigger_type: "scheduled" } });
  });

  it.each(["heartbeat", "system", "hook"])("sends a %s run without a person and as a system activation, and does not admit its session for anyone", async (trigger) => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    expect(await hooks.beforeAgentRun({ prompt: "tick" }, { ...NO_SENDER_CTX, sessionKey: "agent:main:main", trigger })).toBeUndefined();
    expect(server.steps.find((step) => step.method === "steps/agentTrigger")).toMatchObject({ userContext: undefined, payload: { trigger_type: "system" } });
    expect(await hooks.messageSending({ to: SENDER, content: "Hi" }, { channelId: "signal", sessionKey: "agent:main:main" })).toEqual({ content: "Hi" });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/agentResponse", userContext: undefined });
  });

  it("sends a run with no sender after its session was replaced under the same key without the old session's person", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await hooks.beforeAgentRun({ prompt: "tick" }, { ...NO_SENDER_CTX, sessionId: "session-2" })).toBeUndefined();
    expect(server.steps.find((step) => step.method === "steps/agentTrigger" && step.sessionId !== server.steps[0]!.sessionId)).toMatchObject({ userContext: undefined });
  });

  it("does not let a run with no sender admit its session for a person", async () => {
    const { server, hooks } = setup();
    expect(await hooks.beforeAgentRun({ prompt: "tick" }, NO_SENDER_CTX)).toBeUndefined();
    await hooks.agentEnd({ runId: "run-1", success: true }, NO_SENDER_CTX);
    const sent = server.steps.length;
    expect(await hooks.messageSending({ to: OTHER_PHONE, content: "Hi" }, { channelId: "signal" })).toEqual({ cancel: true });
    expect(server.steps).toHaveLength(sent);
  });

  it("governs an inter-session run for no person, whether or not its source session runs", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    const target = { runId: "run-2", sessionKey: `agent:helper:signal:direct:${SENDER}`, sessionId: "session-9" };
    const relayed = { ...target, inputProvenance: { kind: "inter_session" as const, sourceSessionKey: SESSION_KEY } };
    await startRun(hooks);
    const before = server.steps.length;
    expect(await hooks.beforeAgentRun({ prompt: "Relay" }, relayed)).toBeUndefined();
    const relay = server.steps.slice(before);
    expect(relay.map((step) => step.userContext)).toEqual(relay.map(() => undefined));
    expect(relay.find((step) => step.method === "steps/agentTrigger")?.payload).toMatchObject({ trigger_type: "system", trigger_source: { prompt: "Relay" } });
  });

  it("sends a relay into a session another person was admitted to without either person", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    const otherKey = `agent:main:signal:direct:${OTHER_PHONE}`;
    const other = { ...AGENT_CTX, runId: "run-4", sessionKey: otherKey, sessionId: "session-5", senderId: OTHER_PHONE };
    await hooks.beforeAgentRun({ prompt: "Hi", senderId: OTHER_PHONE }, other);
    await hooks.agentEnd({ runId: "run-4", success: true }, other);
    const before = server.steps.length;
    const relay = { runId: "run-5", sessionKey: otherKey, sessionId: "session-5", inputProvenance: { kind: "inter_session" as const, sourceSessionKey: SESSION_KEY } };
    expect(await hooks.beforeAgentRun({ prompt: "Read the history" }, relay)).toBeUndefined();
    expect(server.steps.slice(before).every((step) => step.userContext === undefined)).toBe(true);
  });

  it("sends a relay between equal ids on two channels without either person", async () => {
    const { hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    const telegramKey = `agent:main:telegram:direct:${SENDER}`;
    const relay = { runId: "run-6", sessionKey: telegramKey, sessionId: "session-6", inputProvenance: { kind: "inter_session" as const, sourceSessionKey: SESSION_KEY } };
    expect(await hooks.beforeAgentRun({ prompt: "Relay" }, relay)).toBeUndefined();
  });
});

describe("the agent that runs the session", () => {
  it("names the OpenClaw agent on every step of its run", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, agentId: "main" })).toBeUndefined();
    await callTool(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "Hi" }, MESSAGE_CTX)).toEqual({ content: "Hi" });
    expect(server.steps.length).toBeGreaterThan(0);
    expect(server.steps.every((step) => step.agentName === "main")).toBe(true);
  });
});

describe("admissions outlive the process", () => {
  it("sends to a person admitted before a restart", async () => {
    const store = mapStore();
    const before = setup({ admissions: store });
    await startRun(before.hooks);
    await before.hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID, reason: "shutdown" }, { sessionId: SESSION_ID });
    expect(before.server.steps.map((step) => step.method)).not.toContain("steps/sessionEnd");
    expect(store.rows.get(SESSION_KEY)).toMatchObject({ sessionId: SESSION_ID, userContext: { user_id: SENDER } });

    // A restored row is a candidate: no send until a scheduled run with the
    // same session id proves the session still runs.
    const after = setup({ admissions: store });
    await Bun.sleep(0);
    expect(await after.hooks.messageSending({ to: SENDER, content: "Your reminder" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(await after.hooks.beforeAgentRun({ prompt: "tick" }, { ...NO_SENDER_CTX, sessionId: "session-replaced" })).toBeUndefined();
    await after.hooks.agentEnd({ runId: NO_SENDER_CTX.runId, success: true }, { ...NO_SENDER_CTX, sessionId: "session-replaced" });
    expect(await after.hooks.beforeAgentRun({ prompt: "tick" }, NO_SENDER_CTX)).toBeUndefined();
    expect(await after.hooks.messageSending({ to: SENDER, content: "Your reminder" }, MESSAGE_CTX)).toEqual({ content: "Your reminder" });
  });

  it("sends nothing and admits no run while the store has not answered", async () => {
    const stalled: AdmissionStore = {
      load: () => new Promise(() => {}),
      async put() {},
      async delete() {},
    };
    const { server, hooks } = setup({ admissions: stalled, deadlineMs: 300 });
    expect(await hooks.messageSending({ to: SENDER, content: "Hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(await hooks.beforeAgentRun({ prompt: "tick" }, NO_SENDER_CTX)).toMatchObject({ outcome: "block" });
    // Not even a person's own message: the run cannot know whether its
    // session was started before the restart, so it is refused, not started twice.
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(server.steps).toEqual([]);
  });

  it("does not admit a run whose session ended while its admission was written", async () => {
    let release: () => void = () => {};
    let writing: () => void = () => {};
    const putStarted = new Promise<void>((resolve) => (writing = resolve));
    const slow: AdmissionStore = {
      async load() {
        return [];
      },
      put: () =>
        new Promise<void>((resolve) => {
          release = resolve;
          writing();
        }),
      async delete() {},
    };
    const { hooks } = setup({ admissions: slow });
    const run = hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX);
    await putStarted;
    // The end forgets the session after the write it follows, never before it.
    const ended = hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID, reason: "reset" }, { sessionId: SESSION_ID });
    release();
    await ended;
    expect(await run).toMatchObject({ outcome: "block" });
    expect(await hooks.messageSending({ to: SENDER, content: "Hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
  });

  it("forgets a session OpenClaw ended, in the store too", async () => {
    const store = mapStore();
    const { hooks } = setup({ admissions: store });
    await startRun(hooks);
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID, reason: "reset" }, { sessionId: SESSION_ID });
    expect(store.rows.has(SESSION_KEY)).toBe(false);
    const after = setup({ admissions: store });
    expect(await after.hooks.messageSending({ to: SENDER, content: "Hi" }, MESSAGE_CTX)).toEqual({ cancel: true });
  });

  it("keeps working in memory when the store fails, and says so", async () => {
    const failing: AdmissionStore = {
      async load() {
        throw new Error("disk gone");
      },
      async put() {
        throw new Error("disk gone");
      },
      async delete() {},
    };
    const { hooks, errors } = setup({ admissions: failing });
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "Hi" }, MESSAGE_CTX)).toEqual({ content: "Hi" });
    expect(errors.some((message) => message.includes("could not restore"))).toBe(true);
    expect(errors.some((message) => message.includes("could not store"))).toBe(true);
  });
});

describe("reply_dispatch: a message that joins a running turn is the Guardian's", () => {
  const STEER = { content: "Also, can we talk at 13:00?", sessionKey: SESSION_KEY, senderId: SENDER, channel: "signal" };
  const DISPATCH_CTX = { channelId: "signal", sessionKey: SESSION_KEY, senderId: SENDER };

  it("asks nothing when the session has no running turn: the new run is decided at before_agent_run", async () => {
    const { server, hooks } = setup();
    expect(await dispatchMessage(hooks, STEER)).toBe("dispatched");
    expect(server.steps).toHaveLength(0);
  });

  it("sends a message into a running turn as that turn's userMessage, and lets it join on allow", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    const before = server.steps.length;
    expect(await dispatchMessage(hooks, STEER)).toBe("dispatched");
    expect(server.steps).toHaveLength(before + 1);
    expect(server.steps.at(-1)).toMatchObject({
      method: "steps/userMessage",
      turnId: "run-1",
      userContext: { user_id: SENDER, authentication_method: "signal" },
      payload: { content: [{ type: "text", value: STEER.content }] },
    });
  });

  it("drops a message the Guardian refuses, with no text in its place", async () => {
    const { hooks } = setup({
      reply: (step) => (step.method === "steps/userMessage" && (step.payload as { content: Array<{ value: string }> }).content[0]!.value === STEER.content
        ? { decision: { decision: "deny", reasoning: "no" } }
        : { decision: { decision: "allow" } }),
    });
    await startRun(hooks);
    expect(await dispatchMessage(hooks, STEER)).toBe("dropped");
  });

  it("decides a group member's message that joins another member's turn as that member's userMessage", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(await dispatchMessage(hooks, { ...STEER, senderId: OTHER_PHONE })).toBe("dispatched");
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/userMessage", userContext: { user_id: OTHER_PHONE, authentication_method: "signal" } });
  });

  it("waits for a run still being admitted, then decides the message as that run's", async () => {
    const held = heldAnswer();
    const { server, hooks } = setup({
      reply: (step) => (step.method === "steps/userMessage" && (step.payload as { content: Array<{ value: string }> }).content[0]!.value === "Hello" ? held.answer() : { decision: { decision: "allow" } }),
    });
    const run = hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX);
    await held.reached;
    const dispatch = dispatchMessage(hooks, STEER);
    held.release();
    expect(await run).toBeUndefined();
    expect(await dispatch).toBe("dispatched");
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/userMessage", turnId: "run-1", payload: { content: [{ value: STEER.content }] } });
  });

  it("holds a message that waited for a run whose admission ran out of time, for the session's next run", async () => {
    const held = heldAnswer();
    const { server, hooks } = setup({
      deadlineMs: 1000,
      reply: (step) => (step.method === "steps/userMessage" && (step.payload as { content: Array<{ value: string }> }).content[0]!.value === "Hello" ? held.answer() : { decision: { decision: "allow" } }),
    });
    const first = hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX);
    await held.reached;
    await Bun.sleep(200);
    const dispatch = dispatchMessage(hooks, STEER);
    await Bun.sleep(450);
    const second = hooks.beforeAgentRun({ prompt: "Again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" });
    expect(await first).toMatchObject({ outcome: "block" });
    expect(await dispatch).toBe("dispatched");
    held.release();
    expect(await second).toBeUndefined();
    expect(server.steps.filter((step) => step.turnId === "run-2").map((step) => step.payload)).toContainEqual({ content: [{ type: "text", value: STEER.content }] });
  });

  it("drops a message when the Guardian is unreachable", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    server.stop();
    expect(await dispatchMessage(hooks, STEER)).toBe("dropped");
  });
});

describe("reply_dispatch: no message slips into a run nobody decided it for", () => {
  const LATE = { content: "Send me the code now", sessionKey: SESSION_KEY, senderId: SENDER, channel: "signal" };
  const DISPATCH_CTX = { channelId: "signal", sessionKey: SESSION_KEY, senderId: SENDER };
  const CRON_CTX = { runId: "run-2", sessionKey: SESSION_KEY, sessionId: SESSION_ID, trigger: "cron" };
  const denyLate = (step: { method: string; payload: unknown }) =>
    step.method === "steps/userMessage" && (step.payload as { content: Array<{ value: string }> }).content[0]!.value === LATE.content
      ? { decision: { decision: "deny", reasoning: "no" } }
      : { decision: { decision: "allow" } };

  it("has a scheduled run that starts first decide a message left to before_agent_run, and refuses the run on deny", async () => {
    const { hooks } = setup({ reply: denyLate });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await dispatchMessage(hooks, LATE)).toBe("dispatched");
    expect(await hooks.beforeAgentRun({ prompt: "Reminder: send the weekly report" }, CRON_CTX)).toMatchObject({ outcome: "block" });
  });

  it("has a run decide a second message dispatched before it started, which its prompt does not carry", async () => {
    const { server, hooks } = setup({ reply: denyLate });
    const first = { ...LATE, content: "Hello" };
    expect(await dispatchMessage(hooks, first)).toBe("dispatched");
    expect(await dispatchMessage(hooks, LATE)).toBe("dispatched");
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    const decided = server.steps.filter((step) => step.method === "steps/userMessage").map((step) => (step.payload as { content: Array<{ value: string }> }).content[0]!.value);
    expect(decided).toEqual(["Hello", LATE.content]);
  });

  it("leaves a message for the next run when the run that took it is refused", async () => {
    const { server, hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: (step) =>
        step.method === "steps/agentTrigger" && (step.payload as { trigger_source: { prompt: string } }).trigger_source.prompt === "Reminder"
          ? { decision: { decision: "deny", reasoning: "no" } }
          : { decision: { decision: "allow" } },
    });
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await dispatchMessage(hooks, LATE)).toBe("dispatched");
    expect(await hooks.beforeAgentRun({ prompt: "Reminder" }, CRON_CTX)).toMatchObject({ outcome: "block" });
    expect(await hooks.beforeAgentRun({ prompt: "Something else", senderId: SENDER }, { ...AGENT_CTX, runId: "run-3" })).toBeUndefined();
    expect(server.steps.filter((step) => step.turnId === "run-3" && step.method === "steps/userMessage").map((step) => (step.payload as { content: Array<{ value: string }> }).content[0]!.value)).toEqual([LATE.content]);
  });

  it("sends each held message once, as the person sent it, and not OpenClaw's prompt composed of them", async () => {
    const { server, hooks } = setup();
    expect(await dispatchMessage(hooks, { ...LATE, content: "Hello there" })).toBe("dispatched");
    expect(await dispatchMessage(hooks, { ...LATE, content: "ok" })).toBe("dispatched");
    await hooks.beforeAgentRun({ prompt: "[Signal +15550100] Hello there\n[Signal +15550100] ok", senderId: SENDER }, AGENT_CTX);
    const decided = server.steps.filter((step) => step.method === "steps/userMessage").map((step) => (step.payload as { content: Array<{ value: string }> }).content[0]!.value);
    expect(decided).toEqual(["Hello there", "ok"]);
  });

  it("sends the prompt of a run a person started with nothing held, such as input through chat.send", async () => {
    const { server, hooks } = setup();
    await hooks.beforeAgentRun({ prompt: "From the Control UI", senderId: SENDER }, AGENT_CTX);
    expect(server.steps.filter((step) => step.method === "steps/userMessage").map((step) => step.payload)).toEqual([{ content: [{ type: "text", value: "From the Control UI" }] }]);
  });

  it("does not keep a refused message, so it cannot refuse every later run", async () => {
    const { server, hooks } = setup({ reply: denyLate });
    expect(await dispatchMessage(hooks, { ...LATE, content: "Hello" })).toBe("dispatched");
    expect(await dispatchMessage(hooks, LATE)).toBe("dispatched");
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(await hooks.beforeAgentRun({ prompt: "Hi again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-3" })).toBeUndefined();
    expect(server.steps.filter((step) => step.turnId === "run-3" && step.method === "steps/userMessage")).toHaveLength(1);
  });

  it("drops a message that names no session", async () => {
    const { hooks } = setup();
    expect(await dispatchMessage(hooks, { content: "hi", sessionKey: null })).toBe("dropped");
  });

  it("lets the message's own run carry it, without a second step", async () => {
    const { server, hooks } = setup();
    expect(await dispatchMessage(hooks, LATE)).toBe("dispatched");
    await hooks.beforeAgentRun({ prompt: LATE.content, senderId: SENDER }, AGENT_CTX);
    const userMessages = server.steps.filter((step) => step.method === "steps/userMessage");
    expect(userMessages).toHaveLength(1);
  });

  it("lets a message the Guardian allowed through when its run ends meanwhile, for OpenClaw to send again as a later run prompt", async () => {
    const held = heldAnswer();
    const { hooks } = setup({
      reply: (step) =>
        step.method === "steps/userMessage" && (step.payload as { content: Array<{ value: string }> }).content[0]!.value === LATE.content
          ? held.answer()
          : { decision: { decision: "allow" } },
    });
    await startRun(hooks);
    const dispatch = dispatchMessage(hooks, LATE);
    await held.reached;
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    held.release();
    expect(await dispatch).toBe("dispatched");
  });
});

describe("a tool's result reaches the model only as the Guardian decided it", () => {
  const RESULT_CTX = { runtime: "openclaw" as const, runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID };
  const OUTPUT = "Balance: 120.00";
  const WITHHELD = { result: { content: [{ type: "text" as const, text: WITHHELD_OUTPUT }], details: undefined } };
  const resultDecision = (decision: Record<string, unknown>) => (step: ReceivedStep): Reply =>
    step.method === "steps/toolCallResult" ? { decision } : { decision: { decision: "allow" } };

  function readResult(hooks: Hooks, content: ToolResultBlock[] = [{ type: "text", text: OUTPUT }], ctx: Record<string, unknown> = RESULT_CTX) {
    return hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content, details: undefined } }, ctx as never);
  }

  async function runCall(hooks: Hooks): Promise<BeforeToolCallResult> {
    await startRun(hooks);
    return hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
  }

  it("offers in the ClientHello every step it sends, the result included", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(new Set(server.methodsImplemented as string[])).toEqual(new Set([...Object.values(METHODS), PING_METHOD]));
    expect(server.methodsImplemented).toEqual(expect.arrayContaining(["steps/toolCallResult"]));
    expect(server.methodsImplemented).not.toContain("steps/subagentStart");
    expect(server.methodsImplemented).not.toContain("steps/subagentStop");
  });

  it("sends the result as steps/toolCallResult of the call's turn and passes it on allow", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await runCall(hooks);
    expect(await readResult(hooks)).toBeUndefined();
    const request = server.steps.find((step) => step.method === "steps/toolCallRequest")!;
    const result = server.steps.at(-1)!;
    expect(result).toMatchObject({ method: "steps/toolCallResult", turnId: "run-1", userContext: { user_id: SENDER } });
    expect(result.payload).toEqual({
      tool: { name: "account-lookup" },
      exit_status: "success",
      outputs: [{ value: OUTPUT }],
      request_id_ref: request.requestId,
    });
  });

  it("withholds the result on deny, so the model never reads it", async () => {
    const { hooks } = setup({ methodsEvaluated: ALL_METHODS, reply: resultDecision({ decision: "deny", reasoning: "no balances" }) });
    await runCall(hooks);
    expect(await readResult(hooks)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
  });

  it("withholds the result when the Guardian cannot be reached under a closed posture", async () => {
    const { hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: (step) => (step.method === "steps/toolCallResult" ? { error: { code: -32603, message: "down" } } : { decision: { decision: "allow" } }),
    });
    await runCall(hooks);
    expect(await readResult(hooks)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
  });

  it("delivers the Guardian's rewrite on modify", async () => {
    const { hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: resultDecision({ decision: "modify", reasoning: "masked", modifications: { redactions: [{ path: "/outputs/0/value", replacement: "Balance: ***" }] } }),
    });
    await runCall(hooks);
    expect(await readResult(hooks, [{ type: "text", text: OUTPUT }, { type: "image", data: "aW1n", mimeType: "image/png" }])).toEqual({
      result: { content: [{ type: "text", text: "Balance: ***" }, { type: "image", data: "aW1n", mimeType: "image/png" }], details: undefined },
    });
  });

  it.each<[string, Array<{ type: "text"; text: string }>, string]>([
    ["more blocks than OpenClaw keeps", Array.from({ length: 201 }, (_, i) => ({ type: "text" as const, text: `line ${i}` })), "masked"],
    ["a text longer than OpenClaw keeps", [{ type: "text", text: OUTPUT }], "x".repeat(100_001)],
  ])("withholds a rewrite with %s, audited as modify_unsupported (§6.5)", async (_name, content, replacement) => {
    const { hooks, audit } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: resultDecision({ decision: "modify", reasoning: "masked", modifications: { redactions: [{ path: "/outputs/0/value", replacement }] } }),
    });
    await runCall(hooks);
    expect(await readResult(hooks, content)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    expect(audit.at(-1)).toMatchObject({ outcome: "substituted", substituted: { decision: "modify", reason_code: "modify_unsupported" } });
  });

  it("withholds the result when a rewrite leaves no text or image the model can read", async () => {
    const { hooks, audit } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: resultDecision({ decision: "modify", reasoning: "odd", modifications: { redactions: [{ path: "/outputs" }] } }),
    });
    await runCall(hooks);
    expect(await readResult(hooks)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    expect(audit.at(-1)).toMatchObject({ outcome: "substituted", substituted: { decision: "modify", reason_code: "modify_unsupported" } });
  });

  it.each<[string, Record<string, unknown>]>([
    ["refused", { decision: "deny", reasoning: "no" }],
    ["unapproved", { decision: "ask", reasoning: "check", ask_details: { approver: { type: "human", id: "approver-1" }, question: "Allow?", timeout_seconds: 60 } }],
  ])("asks about a %s call's result too, as blocked, so no result passes unasked", async (_name, decision) => {
    const { server, hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: (step) =>
        step.method === "steps/toolCallRequest"
          ? { decision }
          : step.method === "steps/toolCallResult"
            ? { decision: { decision: "deny", reasoning: "not after a refusal" } }
            : { decision: { decision: "allow" } },
    });
    const answer = await runCall(hooks);
    // A person who denies: OpenClaw records it, and the call does not run.
    await answer?.requireApproval?.onResolution?.("deny");
    expect(await readResult(hooks)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    const request = server.steps.find((step) => step.method === "steps/toolCallRequest")!;
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/toolCallResult", payload: { exit_status: "blocked", request_id_ref: request.requestId } });
  });

  it("waits for an approval's record before it reads the result, as OpenClaw runs the approved call without waiting", async () => {
    let releaseWrite!: () => void;
    const runFacts = memoryRunFacts();
    const slowRunFacts: RunFactsStore = {
      ...runFacts,
      async set(runId, namespace, value) {
        if (value.ran === true) {
          await new Promise<void>((resolve) => (releaseWrite = resolve));
        }
        await runFacts.set(runId, namespace, value);
      },
    };
    const { server, hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      runFacts: slowRunFacts,
      reply: toolDecision({ decision: "ask", reasoning: "check", ask_details: { approver: { type: "human", id: "approver-1" }, question: "Allow?", timeout_seconds: 60 } }),
    });
    const answer = await runCall(hooks);
    void answer!.requireApproval!.onResolution!("allow-once");
    const result = readResult(hooks);
    await Bun.sleep(50);
    releaseWrite();
    expect(await result).toBeUndefined();
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/toolCallResult", payload: { exit_status: "success" } });
  });

  it("withholds the result of a call whose approval is never recorded, without asking", async () => {
    const { server, hooks, errors } = setup({
      methodsEvaluated: ALL_METHODS,
      deadlineMs: 1000,
      reply: toolDecision({ decision: "ask", reasoning: "check", ask_details: { approver: { type: "human", id: "approver-1" }, question: "Allow?", timeout_seconds: 60 } }),
    });
    await runCall(hooks);
    const sent = server.steps.length;
    expect(await readResult(hooks)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    expect(server.steps).toHaveLength(sent);
    expect(errors.at(-1)).toContain("still awaits the record of its approval");
  });

  it("sends an approved call's result, tied to the call", async () => {
    const { server, hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: toolDecision({ decision: "ask", reasoning: "check", ask_details: { approver: { type: "human", id: "approver-1" }, question: "Allow?", timeout_seconds: 60 } }),
    });
    const answer = await runCall(hooks);
    await answer!.requireApproval!.onResolution!("allow-once");
    expect(await readResult(hooks)).toBeUndefined();
    const request = server.steps.find((step) => step.method === "steps/toolCallRequest")!;
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/toolCallResult", payload: { request_id_ref: request.requestId } });
  });

  it("shares an approved call's run fact before a separate result registration reads it", async () => {
    const runFacts = memoryRunFacts();
    const ask = toolDecision({ decision: "ask", reasoning: "check", ask_details: { approver: { type: "human", id: "approver-1" }, question: "Allow?", timeout_seconds: 60 } });
    const producer = setup({ methodsEvaluated: ALL_METHODS, runFacts, reply: ask });
    const consumer = setup({ methodsEvaluated: ALL_METHODS, runFacts });
    await startRun(producer.hooks);
    const approval = await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    expect(approval?.requireApproval).toBeDefined();

    approval?.requireApproval?.onResolution?.("allow-once");
    expect(await readResult(consumer.hooks)).toBeUndefined();

    const toolRequest = producer.server.steps.find((step) => step.method === "steps/toolCallRequest")!;
    expect(consumer.server.steps.at(-1)).toMatchObject({
      method: "steps/toolCallResult",
      turnId: "run-1",
      payload: { exit_status: "success", request_id_ref: toolRequest.requestId },
    });
  });

  it("reports at sessionEnd a decision failure that another registration recorded", async () => {
    const runFacts = memoryRunFacts();
    const failureCounts = memoryFailureCounts();
    const producer = setup({
      methodsEvaluated: ALL_METHODS,
      runFacts,
      failureCounts,
      failurePosture: "negotiated",
      reply: (step) => (step.method === "steps/toolCallResult" ? { error: { code: -32603, message: "down" } } : { decision: { decision: "allow" } }),
    });
    const consumer = setup({ runFacts, failureCounts, failurePosture: "negotiated", guardian: producer.server });
    await startRun(producer.hooks);
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    await readResult(consumer.hooks);
    await producer.hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    await producer.hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID }, { sessionId: SESSION_ID });
    expect(producer.server.steps.find((step) => step.method === "steps/sessionEnd")).toMatchObject({
      payload: { summary: { decision_failures: { guardian_error: 1 } } },
    });
  });

  it("keeps the negotiated deny in a separately registered result middleware when the Guardian fails", async () => {
    const runFacts = memoryRunFacts();
    let down = false;
    const producer = setup({
      methodsEvaluated: ALL_METHODS,
      runFacts,
      failurePosture: "negotiated",
      onDecisionFailure: "deny",
      reply: () => (down ? { error: { code: -32603, message: "down" } } : { decision: { decision: "allow" } }),
    });
    const consumer = setup({ runFacts, failurePosture: "negotiated", guardian: producer.server });
    await startRun(producer.hooks);
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    down = true;
    producer.server.handshakeError = { code: -32603, message: "down" };

    expect(await readResult(consumer.hooks)).toEqual(WITHHELD);
    expect(producer.server.handshakes).toBe(1);
    expect(consumer.audit.at(-1)).toMatchObject({ outcome: "blocked", posture: "deny", posture_source: "negotiated" });
  });

  it("fails a call's result in another registration by the posture its call was decided under, after a renegotiation", async () => {
    const runFacts = memoryRunFacts();
    let down = false;
    const producer = setup({
      methodsEvaluated: ALL_METHODS,
      runFacts,
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      reply: () => (down ? { error: { code: -32603, message: "down" } } : { decision: { decision: "allow" } }),
    });
    const consumer = setup({ runFacts, failurePosture: "negotiated", guardian: producer.server });
    await startRun(producer.hooks);
    producer.server.forgetSessions();
    producer.server.serverHello = { on_decision_failure: "deny" };
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    expect(producer.server.handshakes).toBe(2);
    down = true;
    producer.server.handshakeError = { code: -32603, message: "down" };

    expect(await readResult(consumer.hooks)).toEqual(WITHHELD);
    expect(consumer.audit.at(-1)).toMatchObject({ outcome: "blocked", posture: "deny", posture_source: "negotiated" });
  });

  it("answers a refused session's step within the hook's deadline when OpenClaw's state store stalls", async () => {
    const base = memoryRunFacts();
    let stalled = false;
    const hang = <T,>(work: () => Promise<T>): Promise<T> => (stalled ? new Promise<T>(() => {}) : work());
    const runFacts: RunFactsStore = {
      set: (...args) => hang(() => base.set(...args)),
      setIfAbsent: (...args) => hang(() => base.setIfAbsent(...args)),
      get: (...args) => hang(() => base.get(...args)),
      consume: (...args) => hang(() => base.consume(...args)),
      clear: (...args) => hang(() => base.clear(...args)),
      pruneOtherProcesses: () => base.pruneOtherProcesses(),
    };
    let forget = false;
    const { server, hooks } = setup({
      runFacts,
      deadlineMs: 800,
      reply: (step) => (forget && step.method === "steps/toolCallRequest" ? { error: { code: -32003, message: "not negotiated" } } : { decision: { decision: "allow" } }),
    });
    await startRun(hooks);
    forget = true;
    server.handshakeError = { code: -32000, message: "session refused" };
    stalled = true;
    const startedAt = performance.now();
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-2" }, TOOL_CTX)).toMatchObject({ block: true });
    expect(performance.now() - startedAt).toBeLessThan(1500);
  });

  it("withholds, in another registration, the result of a call whose session the Guardian then refused", async () => {
    const runFacts = memoryRunFacts();
    const refusals = memoryRefusals();
    let forget = false;
    const producer = setup({
      methodsEvaluated: ALL_METHODS,
      runFacts,
      refusals,
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      reply: (step) => (forget && step.method === "steps/toolCallRequest" ? { error: { code: -32003, message: "not negotiated" } } : { decision: { decision: "allow" } }),
    });
    const consumer = setup({ runFacts, refusals, failurePosture: "negotiated", guardian: producer.server });
    await startRun(producer.hooks);
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    forget = true;
    producer.server.handshakeError = { code: -32000, message: "session refused" };
    expect(await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-2" }, TOOL_CTX)).toMatchObject({ block: true });
    producer.server.handshakeError = { code: -32603, message: "down" };
    expect(await readResult(consumer.hooks)).toEqual(WITHHELD);
  });

  it("blocks, in the registration that admitted the run, every later call of a session the Guardian refused to the result middleware's registration", async () => {
    const runFacts = memoryRunFacts();
    const refusals = memoryRefusals();
    let forget = false;
    const producer = setup({
      methodsEvaluated: ALL_METHODS,
      runFacts,
      refusals,
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      reply: (step) => (forget && step.method === "steps/toolCallResult" ? { error: { code: -32003, message: "not negotiated" } } : { decision: { decision: "allow" } }),
    });
    const consumer = setup({ runFacts, refusals, failurePosture: "negotiated", guardian: producer.server });
    await startRun(producer.hooks);
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    forget = true;
    producer.server.handshakeError = { code: -32000, message: "session refused" };
    expect(await readResult(consumer.hooks)).toEqual(WITHHELD);
    producer.server.stop();
    expect(await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-2" }, TOOL_CTX)).toMatchObject({ block: true });
  });

  it("blocks a step whose session's refusal cannot be read from OpenClaw's plugin state", async () => {
    const stalled = { ...memoryRefusals(), get: () => new Promise<never>(() => {}) };
    const { hooks } = setup({ refusals: stalled, deadlineMs: 1000 });
    const startedAt = performance.now();
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block", reason: expect.stringContaining("reading the session's refusal") });
    expect(performance.now() - startedAt).toBeLessThan(3000);
  });

  it("retries a refused session's failed state write before another registration uses the session", async () => {
    const retained = memoryRefusals();
    let writes = 0;
    const refusals: RefusalStore = {
      ...retained,
      async put(sessionId, refusal) {
        if (++writes === 1) throw new Error("state write failed");
        await retained.put(sessionId, refusal);
      },
    };
    const producer = setup({ refusals, failurePosture: "negotiated" });
    await startRun(producer.hooks);
    producer.server.forgetSessions();
    producer.server.handshakeError = { code: -32000, message: "session refused" };
    expect(await callTool(producer.hooks)).toMatchObject({ block: true });
    expect(await retained.get(SESSION_ID)).toBeUndefined();
    expect(await callTool(producer.hooks)).toMatchObject({ block: true });
    expect(await retained.get(SESSION_ID)).toEqual({ code: -32000, message: "session refused" });
    producer.server.handshakeError = undefined;
    const consumer = setup({ guardian: producer.server, refusals: retained, failurePosture: "negotiated" });
    const handshakes = producer.server.handshakes;
    expect(await consumer.hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(producer.server.handshakes).toBe(handshakes);
  });

  it("shares admitted run and call authorization with a separately registered result middleware", async () => {
    const runFacts = memoryRunFacts();
    const producer = setup({ methodsEvaluated: ALL_METHODS, runFacts });
    const consumer = setup({ methodsEvaluated: ALL_METHODS, runFacts });
    await startRun(producer.hooks);
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);

    expect(await readResult(consumer.hooks)).toBeUndefined();
    const toolRequest = producer.server.steps.find((step) => step.method === "steps/toolCallRequest")!;
    expect(consumer.server.steps.at(-1)).toMatchObject({
      method: "steps/toolCallResult",
      turnId: "run-1",
      sessionId: toolRequest.sessionId,
      payload: { tool: { name: "account-lookup" }, exit_status: "success", request_id_ref: toolRequest.requestId },
    });
  });

  it("withholds a result when the admitted run has no matching tool-call decision", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);

    expect(await readResult(hooks)).toEqual(WITHHELD);
    expect(server.steps.map((step) => step.method)).toEqual(["steps/sessionStart", "steps/turnStart", "steps/userMessage"]);
  });

  it.each([
    ["session id", { ...RESULT_CTX, sessionId: "another-session" }],
    ["session key", { ...RESULT_CTX, sessionKey: "agent:main:signal:direct:+15550999" }],
  ])("withholds a result with a mismatched %s", async (_identity, resultContext) => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await runCall(hooks);

    expect(await readResult(hooks, undefined, resultContext)).toEqual(WITHHELD);
    expect(server.steps.map((step) => step.method)).not.toContain("steps/toolCallResult");
  });

  it.each([
    ["call id", { toolCallId: "different-call", toolName: "account-lookup" }],
    ["tool name", { toolCallId: "call-1", toolName: "other-tool" }],
  ])("withholds a result with a mismatched %s", async (_identity, eventIdentity) => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await runCall(hooks);

    expect(await hooks.toolResult({ ...eventIdentity, args: {}, result: { content: [{ type: "text", text: OUTPUT }], details: undefined } }, RESULT_CTX)).toEqual(WITHHELD);
    expect(server.steps.map((step) => step.method)).not.toContain("steps/toolCallResult");
  });

  it("does not consume the call fact for a result with a mismatched session", async () => {
    const { hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await runCall(hooks);

    expect(await readResult(hooks, undefined, { ...RESULT_CTX, sessionId: "another-session" })).toEqual(WITHHELD);
    expect(await readResult(hooks)).toBeUndefined();
  });

  it("blocks run admission when OpenClaw declines to store the admission context", async () => {
    const { hooks, server } = setup({
      runFacts: {
        ...memoryRunFacts(),
        set: async () => { throw new Error("store unavailable"); },
      },
    });

    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX)).toMatchObject({ block: true });
    expect(server.steps.map((step) => step.method)).not.toContain("steps/toolCallRequest");
  });

  it("withholds a result when its run ends while the Guardian is deciding", async () => {
    const pending = heldAnswer();
    const runFacts = memoryRunFacts();
    const producer = setup({ methodsEvaluated: ALL_METHODS, runFacts });
    const consumer = setup({
      methodsEvaluated: ALL_METHODS,
      runFacts,
      reply: (step) => step.method === "steps/toolCallResult" ? pending.answer() : { decision: { decision: "allow" } },
    });
    await startRun(producer.hooks);
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    const result = readResult(consumer.hooks);
    await pending.reached;
    const ending = producer.hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    pending.release();

    expect(await result).toEqual(WITHHELD);
    await ending;
  });

  it("governs independent concurrent call results by their own ids", async () => {
    const runFacts = memoryRunFacts();
    const producer = setup({ methodsEvaluated: ALL_METHODS, runFacts });
    const consumer = setup({ methodsEvaluated: ALL_METHODS, runFacts });
    await startRun(producer.hooks);
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: { id: 1 }, toolCallId: "call-1" }, TOOL_CTX);
    await producer.hooks.beforeToolCall({ toolName: "account-lookup", params: { id: 2 }, toolCallId: "call-2" }, TOOL_CTX);

    const [first, second] = await Promise.all([
      consumer.hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "one" }], details: undefined } }, RESULT_CTX),
      consumer.hooks.toolResult({ toolCallId: "call-2", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "two" }], details: undefined } }, RESULT_CTX),
    ]);
    expect([first, second]).toEqual([undefined, undefined]);
    expect(consumer.server.steps.filter((step) => step.method === "steps/toolCallResult")).toHaveLength(2);
  });

  it("withholds a result outside an admitted run without asking", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    expect(await readResult(hooks)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    await runCall(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    const sent = server.steps.length;
    expect(await readResult(hooks)).toEqual({ result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } });
    expect(server.steps).toHaveLength(sent);
  });

  it("does not send a result as allowed when the Guardian does not evaluate results", async () => {
    const { server, hooks } = setup();
    await runCall(hooks);
    expect(await readResult(hooks)).toBeUndefined();
    expect(server.steps.map((step) => step.method)).not.toContain("steps/toolCallResult");
  });
});

describe("no step the plugin could not have decided passes", () => {
  const RESULT_CTX = { runtime: "openclaw" as const, runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID };
  const WITHHELD: ToolResultAnswer = { result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } };
  const readResult = (hooks: Hooks) =>
    hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "secret" }], details: undefined } }, RESULT_CTX);

  /** Hooks whose exchange throws for `failing` and lets every other step through unsent. */
  function throwingFor(failing: string): { hooks: Hooks; errors: string[]; audit: AdapterAuditEvent[] } {
    const errors: string[] = [];
    const audit: AdapterAuditEvent[] = [];
    const exchange: AcsExchange = {
      async decide(step) {
        if (step.method === failing) {
          throw new Error("exchange broke");
        }
        return { stage: "unevaluated", decision: { decision: "allow" }, requestId: null };
      },
      forget() {},
      serverHelloOf: () => undefined,
      refusalOf: () => undefined,
      adoptRefusal: () => {},
      decisionFailures: async () => undefined,
      ping: async () => {},
      deadlineFromNow: () => performance.now() + 2000,
      withoutDecision: async () => ({ stage: "delivery", decision: { decision: "deny", reasoning: "no decision", reason_codes: ["decision_failure"] }, requestId: null }),
    };
    const hooks = createHooks({
      config: { maxUndecidedMessages: 20, maxAttachmentBytes: 524_288 },
      exchange,
      audit: { path: "memory", write: (event) => (audit.push(event), true) },
      logger: { error: (message) => errors.push(message) },
      runFacts: memoryRunFacts(),
      refusals: memoryRefusals(),
    });
    return { hooks, errors, audit };
  }

  it.each<[string, (hooks: Hooks) => Promise<unknown>, unknown]>([
    ["steps/userMessage", (hooks) => hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX), { outcome: "block", reason: "the ACS plugin failed: exchange broke" }],
    ["steps/toolCallRequest", async (hooks) => (await startRun(hooks), hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, TOOL_CTX)), { block: true, blockReason: "The ACS plugin failed: exchange broke" }],
    ["steps/toolCallResult", async (hooks) => (await startRun(hooks), readResult(hooks)), WITHHELD],
    ["steps/agentResponse", async (hooks) => (await startRun(hooks), hooks.messageSending({ to: SENDER, content: "secret" }, MESSAGE_CTX)), { cancel: true }],
  ])("blocks when the exchange throws at %s", async (method, act, expected) => {
    const { hooks } = throwingFor(method);
    expect(await act(hooks)).toEqual(expected);
  });

  it("cancels a reply when the exchange throws, and logs why", async () => {
    const { hooks, errors } = throwingFor("steps/agentResponse");
    await startRun(hooks);
    expect(await hooks.messageSending({ to: SENDER, content: "secret" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(errors).toEqual([expect.stringContaining("refused steps/agentResponse in session")]);
    expect(errors[0]).toContain("the ACS plugin failed: exchange broke");
  });

  it("drops a message joining a running turn when the exchange throws", async () => {
    let calls = 0;
    const exchange: AcsExchange = {
      async decide() {
        calls += 1;
        if (calls > 3) {
          throw new Error("exchange broke");
        }
        return { stage: "unevaluated", decision: { decision: "allow" }, requestId: null };
      },
      forget() {},
      serverHelloOf: () => undefined,
      refusalOf: () => undefined,
      adoptRefusal: () => {},
      decisionFailures: async () => undefined,
      ping: async () => {},
      deadlineFromNow: () => performance.now() + 2000,
      withoutDecision: async () => ({ stage: "delivery", decision: { decision: "deny", reasoning: "no decision", reason_codes: ["decision_failure"] }, requestId: null }),
    };
    const hooks = createHooks({
      config: { maxUndecidedMessages: 20, maxAttachmentBytes: 524_288 },
      exchange,
      audit: { path: "memory", write: () => true },
      logger: { error: () => {} },
      runFacts: memoryRunFacts(),
      refusals: memoryRefusals(),
    });
    await startRun(hooks);
    expect(await dispatchMessage(hooks, { content: "more", sessionKey: SESSION_KEY, senderId: SENDER })).toBe("dropped");
  });

  it("blocks a run and a result when the ServerHello carries no methods_evaluated list", async () => {
    const { server, hooks } = setup({ methodsEvaluated: null });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(await readResult(hooks)).toEqual(WITHHELD);
    expect(server.steps).toEqual([]);
  });

  it.each<[string, Reply]>([
    ["unsigned", { unsignedDecision: { decision: "allow" } }],
    ["malformed", { body: "not json" }],
    ["late", { hang: true }],
  ])("withholds a result when the answer is %s", async (_name, answer) => {
    // Long enough for the run's own five round trips on a busy runner; only
    // the late answer waits it out.
    const { hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      deadlineMs: 1500,
      reply: (step) => (step.method === "steps/toolCallResult" ? answer : { decision: { decision: "allow" } }),
    });
    await startRun(hooks);
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX)).toEqual({ params: {} });
    expect(await readResult(hooks)).toEqual(WITHHELD);
  });
});

describe("no input reaches a run past the plugin's gates", () => {
  const send = (hooks: Hooks, params: Record<string, unknown>) =>
    hooks.beforeToolCall({ toolName: "sessions_send", params, toolCallId: "call-send" }, TOOL_CTX);

  it.each<[string, Record<string, unknown>]>([
    ["another_person's_session", { sessionKey: `agent:main:signal:direct:${OTHER_PHONE}`, message: "hi", mode: "steer" }],
    ["a_session_named_by_label", { label: "support", message: "hi" }],
    ["a_group_session", { sessionKey: "agent:main:signal:group:abc", message: "hi" }],
  ])("asks the Guardian about sessions_send into %s", async (_name, params) => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(await send(hooks, params)).toEqual({ params });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/toolCallRequest", payload: { tool: { name: "sessions_send" } } });
  });

  it("asks about sessions_send into another session of the run's own sender", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    const params = { sessionKey: `agent:helper:signal:direct:${SENDER}`, message: "hi", mode: "steer" };
    expect(await send(hooks, params)).toEqual({ params });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/toolCallRequest", payload: { tool: { name: "sessions_send" } } });
  });

  // A session switched to another runtime (agentRuntimeOverride, a model
  // override to an unpinned model) runs with no before_agent_run.
  it("blocks and records, under failurePosture closed, every tool call, result and reply of a run that skipped before_agent_run", async () => {
    const { server, hooks, audit } = setup();
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await dispatchMessage(hooks, { content: "next", sessionKey: SESSION_KEY, senderId: SENDER })).toBe("dispatched");
    const sent = server.steps.length;
    const unadmitted = { runId: "run-2", sessionKey: SESSION_KEY, sessionId: SESSION_ID };
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-2" }, unadmitted)).toMatchObject({ block: true });
    // This Guardian does not evaluate toolCallResult, so the step is allowed (handshake.json, methods_evaluated).
    expect(await hooks.toolResult({ toolCallId: "call-2", toolName: "account-lookup", args: {}, result: { content: [{ type: "text", text: "secret" }], details: undefined } }, { runtime: "codex", ...unadmitted })).toBeUndefined();
    expect(await hooks.messageSending({ to: SENDER, content: "secret" }, MESSAGE_CTX)).toEqual({ cancel: true });
    expect(server.steps).toHaveLength(sent);
    expect(audit.filter((entry) => entry.outcome === "blocked").map((entry) => entry.method)).toEqual([
      "steps/toolCallRequest",
      "steps/agentResponse",
    ]);
  });

  it("still sends a reply of the admitted run while it runs", async () => {
    const { hooks } = setup();
    await startRun(hooks);
    expect(await dispatchMessage(hooks, { content: "more", sessionKey: SESSION_KEY, senderId: SENDER })).toBe("dispatched");
    expect(await hooks.messageSending({ to: SENDER, content: "Hi" }, MESSAGE_CTX)).toEqual({ content: "Hi" });
  });

  it("keeps running tool calls whose results went through the middleware", async () => {
    const { hooks } = setup();
    await startRun(hooks);
    await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-1" }, TOOL_CTX);
    await hooks.toolResult({ toolCallId: "call-1", toolName: "account-lookup", args: {}, result: { content: [], details: undefined } }, { runtime: "openclaw", runId: "run-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID });
    await hooks.afterToolCall({ toolName: "account-lookup", toolCallId: "call-1" }, TOOL_CTX);
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-2" }, TOOL_CTX)).toEqual({ params: {} });
  });
});

describe("one deadline bounds everything a hook sends", () => {
  it("blocks a run whose four steps together outlast deadlineMs, each one shorter", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS, deadlineMs: 500 });
    server.delayMs = 200;
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
  });
});

describe("a new ServerHello is read as the first was", () => {
  it("follows the posture when the ServerHello after renegotiation carries no methods_evaluated list", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    server.forgetSessions();
    server.methodsEvaluated = null;
    expect(await callTool(hooks)).toMatchObject({ block: true });
  });
});

describe("messages waiting for a run are bounded and follow the queue mode", () => {
  const DISPATCH_CTX = { channelId: "signal", sessionKey: SESSION_KEY, senderId: SENDER };
  const dispatch = (hooks: Hooks, content: string) => dispatchMessage(hooks, { content });

  // Under followup OpenClaw holds a message decided at dispatch for a run of
  // its own: decided twice, once in each turn it is asked for.
  it("decides a message held under followup at dispatch and again as its own run's prompt", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    const sent = server.steps.length;
    expect(await dispatch(hooks, "Later")).toBe("dispatched");
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await hooks.beforeAgentRun({ prompt: "Later", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    expect(server.steps.slice(sent).filter((step) => step.method === "steps/userMessage").map((step) => step.turnId)).toEqual(["run-1", "run-2"]);
  });

  // The trace that broke a decide-once memory: two "yes" steered into run-1,
  // one more after it ended; run-2's prompt "yes" must still be asked.
  it("asks about a run's prompt whatever was decided with the same text before", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    await dispatch(hooks, "yes");
    await dispatch(hooks, "yes");
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    await dispatch(hooks, "yes");
    const sent = server.steps.length;
    expect(await hooks.beforeAgentRun({ prompt: "yes", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    expect(server.steps.slice(sent).filter((step) => step.method === "steps/userMessage").map((step) => step.turnId)).toEqual(["run-2"]);
  });

  it("asks about a scheduled run's own text as its agentTrigger, even when it equals a message decided before", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    await dispatch(hooks, "Reminder");
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    const sent = server.steps.length;
    expect(await hooks.beforeAgentRun({ prompt: "Reminder" }, NO_SENDER_CTX)).toBeUndefined();
    expect(server.steps.slice(sent).find((step) => step.method === "steps/agentTrigger")).toMatchObject({ payload: { trigger_source: { prompt: "Reminder" } } });
  });

  it("decides each of two waiting messages with the prompt's text, one as the prompt and one on its own", async () => {
    const { server, hooks } = setup();
    expect(await dispatch(hooks, "same")).toBe("dispatched");
    expect(await dispatch(hooks, "same")).toBe("dispatched");
    const sent = server.steps.length;
    expect(await hooks.beforeAgentRun({ prompt: "same", senderId: SENDER }, AGENT_CTX)).toBeUndefined();
    expect(server.steps.slice(sent).filter((step) => step.method === "steps/userMessage")).toHaveLength(2);
  });

  // collect joins several messages into one prompt: no single decision covers it.
  it("decides a joined prompt again under collect", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    const sent = server.steps.length;
    await dispatch(hooks, "first");
    await dispatch(hooks, "second");
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await hooks.beforeAgentRun({ prompt: "first\nsecond", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    expect(server.steps.slice(sent).filter((step) => step.method === "steps/userMessage").map((step) => step.turnId)).toEqual(["run-1", "run-1", "run-2"]);
  });

  it("drops a message beyond maxUndecidedMessages", async () => {
    const { hooks } = setup({ maxUndecidedMessages: 2 });
    expect(await dispatch(hooks, "one")).toBe("dispatched");
    expect(await dispatch(hooks, "two")).toBe("dispatched");
    expect(await dispatch(hooks, "three")).toBe("dropped");
  });

  it("drops what a refused session was sent, so it holds nothing", async () => {
    const { hooks } = setup({
      maxUndecidedMessages: 2,
      methodsEvaluated: ALL_METHODS,
      reply: (step) => (step.method === "steps/sessionStart" ? { decision: { decision: "deny", reasoning: "no" } } : { decision: { decision: "allow" } }),
    });
    await dispatch(hooks, "one");
    await dispatch(hooks, "two");
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block" });
    expect(await dispatch(hooks, "three")).toBe("dispatched");
  });
});

describe("a session is started once, across a restart", () => {
  it("does not send sessionStart again for a session admitted before the restart", async () => {
    const store = mapStore();
    const before = setup({ admissions: store, methodsEvaluated: ALL_METHODS });
    await startRun(before.hooks);
    await before.hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    await before.hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID, reason: "restart" }, { sessionId: SESSION_ID });
    const after = setup({ admissions: store, methodsEvaluated: ALL_METHODS });
    expect(await after.hooks.beforeAgentRun({ prompt: "Again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    expect(after.server.steps.map((step) => step.method)).toEqual(["steps/turnStart", "steps/userMessage"]);
  });

  it("sends sessionStart again when the session before the restart was only let through by the posture", async () => {
    const store = mapStore();
    const before = setup({
      admissions: store,
      methodsEvaluated: ALL_METHODS,
      failurePosture: "negotiated",
      onDecisionFailure: "proceed",
      reply: (step) => (step.method === "steps/sessionStart" ? { error: { code: -32603, message: "down" } } : { decision: { decision: "allow" } }),
    });
    await startRun(before.hooks);
    await before.hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID, reason: "restart" }, { sessionId: SESSION_ID });
    const after = setup({ admissions: store, methodsEvaluated: ALL_METHODS });
    await after.hooks.beforeAgentRun({ prompt: "Again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" });
    expect(after.server.steps[0]?.method).toBe("steps/sessionStart");
  });
});

describe("the gates read a tool's parameters as OpenClaw does", () => {
  const send = (hooks: Hooks, params: Record<string, unknown>) =>
    hooks.beforeToolCall({ toolName: "sessions_send", params, toolCallId: "call-send" }, TOOL_CTX);

  // OpenClaw reads sessionKey, else session_key (readToolStringParam, src/param-key.ts).
  it("asks about sessions_send naming the sender's own session as session_key", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    const params = { session_key: `agent:helper:signal:direct:${SENDER}`, message: "hi" };
    expect(await send(hooks, params)).toEqual({ params });
    expect(server.steps.at(-1)?.method).toBe("steps/toolCallRequest");
  });

});

describe("reply_dispatch: the Guardian sees a message whole, attachments included, before the model", () => {
  const PIXEL = Buffer.from("89504e470d0a1a0a", "hex");
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));
  function attachment(bytes: Buffer, fact: Partial<MediaFact> = {}): MediaFact {
    const dir = mkdtempSync(join(tmpdir(), "acs-openclaw-media-"));
    dirs.push(dir);
    const path = join(dir, "photo.png");
    writeFileSync(path, bytes);
    return { path, contentType: "image/png", kind: "image", ...fact };
  }
  const userMessages = (server: FakeGuardian) => server.steps.filter((step) => step.method === "steps/userMessage").map((step) => step.payload);
  const IMAGE_ITEM = { type: "image", value: { media_type: "image/png", data: PIXEL.toString("base64") } };

  it("sends a message that joins a running turn with its quote, its text and its image", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(await dispatchMessage(hooks, { content: "Read this", quote: "Earlier text", media: [attachment(PIXEL)] })).toBe("dispatched");
    expect(userMessages(server).at(-1)).toEqual({ content: [{ type: "text", value: "Earlier text" }, { type: "text", value: "Read this" }, IMAGE_ITEM] });
  });

  it("holds a message that starts a run with its image, and decides it as the run's userMessage", async () => {
    const { server, hooks } = setup();
    expect(await dispatchMessage(hooks, { content: "Hello", media: [attachment(PIXEL)] })).toBe("dispatched");
    expect(server.steps).toHaveLength(0);
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toBeUndefined();
    expect(userMessages(server)).toEqual([{ content: [{ type: "text", value: "Hello" }, IMAGE_ITEM] }]);
  });

  it("refuses the run when the Guardian denies the image a held message carries", async () => {
    const { hooks } = setup({ reply: (step) => (JSON.stringify(step.payload).includes(PIXEL.toString("base64")) ? { decision: { decision: "deny", reasoning: "no images" } } : { decision: { decision: "allow" } }) });
    expect(await dispatchMessage(hooks, { content: "Hello", media: [attachment(PIXEL)] })).toBe("dispatched");
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, AGENT_CTX)).toMatchObject({ outcome: "block", reason: "no images" });
  });

  it("sends the images OpenClaw hands the hook itself", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(await dispatchMessage(hooks, { content: "See", images: [{ data: PIXEL.toString("base64"), mimeType: "image/png" }] })).toBe("dispatched");
    expect(userMessages(server).at(-1)).toEqual({ content: [{ type: "text", value: "See" }, IMAGE_ITEM] });
  });

  it.each<[string, () => MediaFact, string]>([
    ["over_maxAttachmentBytes", () => attachment(Buffer.alloc(9)), "exceed maxAttachmentBytes (8 bytes)"],
    ["openclaw_could_not_read", () => ({ ...attachment(PIXEL), unresolvedThisTurn: true }), "OpenClaw could not read"],
    ["gone_from_disk", () => ({ path: "/nonexistent.example/photo.png", contentType: "image/png" }), "cannot be read"],
  ])("drops a message with an attachment %s, asking the Guardian nothing", async (_name, fact, reason) => {
    const { server, hooks, errors } = setup({ maxAttachmentBytes: 8 });
    await startRun(hooks);
    const asked = server.steps.length;
    expect(await dispatchMessage(hooks, { content: "Look", media: [fact()] })).toBe("dropped");
    expect(server.steps).toHaveLength(asked);
    expect(errors.join("\n")).toContain(reason);
  });

  it("sends an attachment OpenClaw holds only as a URL as that URL", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(await dispatchMessage(hooks, { content: "Look", media: [{ url: "https://files.example/photo.png", contentType: "image/png", kind: "image", fileName: "photo.png" }] })).toBe("dispatched");
    expect(userMessages(server).at(-1)).toEqual({ content: [
      { type: "text", value: "Look" },
      { type: "image", value: { media_type: "image/png", file_name: "photo.png", url: "https://files.example/photo.png" } },
    ] });
  });

  // OpenClaw dispatches the message when this hook times out.
  it("drops a message whose attachment cannot be read before the hook's deadline", async () => {
    const { hooks, errors } = setup({ deadlineMs: 1000 });
    await startRun(hooks);
    const dir = mkdtempSync(join(tmpdir(), "acs-openclaw-media-"));
    dirs.push(dir);
    const fifo = join(dir, "stalled.png");
    expect(spawnSync("mkfifo", [fifo]).status).toBe(0);
    const startedAt = performance.now();
    expect(await dispatchMessage(hooks, { content: "Look", media: [{ path: fifo, contentType: "image/png" }] })).toBe("dropped");
    expect(performance.now() - startedAt).toBeLessThan(3000);
    expect(errors.join("\n")).toContain("reading the message's attachments did not finish before the hook's deadline");
  });

  // OpenClaw ends the old session after dispatch when the message starts a new one.
  it("keeps a held message's image for the run of the session that replaces the ended one", async () => {
    const { server, hooks } = setup();
    expect(await dispatchMessage(hooks, { content: "Hello", media: [attachment(PIXEL)] })).toBe("dispatched");
    await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId: SESSION_ID, reason: "idle" }, { sessionKey: SESSION_KEY, sessionId: SESSION_ID });
    expect(await hooks.beforeAgentRun({ prompt: "Hello", senderId: SENDER }, { ...AGENT_CTX, sessionId: "session-2" })).toBeUndefined();
    expect(userMessages(server)).toEqual([{ content: [{ type: "text", value: "Hello" }, IMAGE_ITEM] }]);
  });

  it("counts attachments of one message together against maxAttachmentBytes", async () => {
    const { hooks } = setup({ maxAttachmentBytes: 12 });
    expect(await dispatchMessage(hooks, { content: "Two", media: [attachment(PIXEL), attachment(PIXEL)] })).toBe("dropped");
  });

});

describe("reply_payload_sending: the Guardian decides a reply whole", () => {
  const PAYLOAD_CTX = { channelId: "signal", sessionKey: SESSION_KEY, conversationId: SENDER, senderId: SENDER };
  const send = (hooks: Hooks, payload: Record<string, unknown>, ctx: Record<string, unknown> = PAYLOAD_CTX) =>
    hooks.replyPayloadSending({ payload, channel: "signal", sessionKey: SESSION_KEY }, ctx as never);
  const responses = (server: FakeGuardian) => server.steps.filter((step) => step.method === "steps/agentResponse").map((step) => step.payload);

  it("sends a reply's text, structured parts and media to the Guardian, and decides the same delivery's message_sending again", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    const payload = { text: "Here is the plan.\n\nStep one.", mediaUrls: ["https://files.example/plan.png"], presentation: { blocks: [{ type: "text", text: "Approve?" }] } };
    expect(await send(hooks, payload)).toBeUndefined();
    expect(responses(server)).toEqual([{ content: [
      { type: "text", value: payload.text },
      { type: "text", value: JSON.stringify({ presentation: payload.presentation }) },
      { type: "file", value: "https://files.example/plan.png" },
    ] }]);
    expect(await hooks.messageSending({ to: SENDER, content: payload.text, metadata: { mediaUrls: payload.mediaUrls } }, MESSAGE_CTX)).toEqual({ content: payload.text });
    expect(await hooks.messageSending({ to: SENDER, content: "Step one." }, MESSAGE_CTX)).toEqual({ content: "Step one." });
    expect(responses(server)).toHaveLength(3);
  });

  it("decides a reply that carries only media", async () => {
    const { server, hooks } = setup({ reply: replyAnswer({ decision: { decision: "deny", reasoning: "no files" } }) });
    await startRun(hooks);
    expect(await send(hooks, { mediaUrl: "https://files.example/secret.pdf" })).toEqual({ cancel: true });
    expect(responses(server)).toEqual([{ content: [{ type: "file", value: "https://files.example/secret.pdf" }] }]);
  });

  it("applies the Guardian's modify to a payload of text and media, keeping its other fields", async () => {
    const { hooks } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: replyAnswer({ decision: { decision: "modify", reasoning: "mask", modifications: { redactions: [{ path: "/content/0/value", replacement: "[masked]" }] } } }),
    });
    await startRun(hooks);
    expect(await send(hooks, { text: "card 4111", mediaUrls: ["https://files.example/a.png"], replyToId: "m-7" })).toEqual({
      payload: { text: "[masked]", mediaUrls: ["https://files.example/a.png"], replyToId: "m-7" },
    });
  });

  it.each<[string, Record<string, unknown>]>([
    ["a_presentation", { presentation: { blocks: [] } }],
    ["attachments", { attachments: [{ type: "file", url: "https://files.example/b.pdf" }] }],
    ["spoken_text", { spokenText: "card four one one one" }],
  ])("cancels a modified payload that carries %s, which the rewrite cannot keep as decided, audited as modify_unsupported", async (_name, extra) => {
    const { server, hooks, audit } = setup({
      methodsEvaluated: ALL_METHODS,
      reply: replyAnswer({ decision: { decision: "modify", reasoning: "mask", modifications: { redactions: [{ path: "/content/0/value", replacement: "[masked]" }] } } }),
    });
    await startRun(hooks);
    expect(await send(hooks, { text: "card 4111", ...extra })).toEqual({ cancel: true });
    expect((responses(server).at(-1) as { content: unknown[] }).content.length).toBeGreaterThan(1);
    expect(audit.at(-1)).toMatchObject({ outcome: "substituted", substituted: { decision: "modify", reason_code: "modify_unsupported" } });
  });

  it.each<[string, Record<string, unknown>, string]>([
    ["in_a_session_with_no_admitted_run", { channelId: "signal", sessionKey: `agent:main:signal:direct:${OTHER_PHONE}`, conversationId: OTHER_PHONE }, "no run of this session was admitted"],
  ])("cancels a reply %s by the failure posture, asking the Guardian nothing", async (_name, ctx, reason) => {
    const { server, hooks, audit } = setup();
    await startRun(hooks);
    const asked = server.steps.length;
    expect(await hooks.replyPayloadSending({ payload: { text: "hi" }, channel: "signal" }, ctx as never)).toEqual({ cancel: true });
    expect(server.steps).toHaveLength(asked);
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked", failure: { message: expect.stringContaining(reason) } });
  });

  // OpenClaw sends the original payload when this hook outlasts its timeout.
  it("keeps one deadline for the refusal read and the Guardian's answer", async () => {
    let slowRead = false;
    const refusals = memoryRefusals();
    const slow = { ...refusals, get: async (sessionId: string) => (slowRead ? (await Bun.sleep(700), undefined) : refusals.get(sessionId)) };
    const { server, hooks } = setup({ refusals: slow, deadlineMs: 1000 });
    await startRun(hooks);
    slowRead = true;
    server.delayMs = 600;
    const startedAt = performance.now();
    expect(await send(hooks, { text: "hi" })).toEqual({ cancel: true });
    expect(performance.now() - startedAt).toBeLessThan(1250);
  });

  it("cancels a reply when the Guardian is unreachable", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    server.stop();
    expect(await send(hooks, { text: "hi" })).toEqual({ cancel: true });
  });

  it("forgets the decided replies when the session's next run is admitted", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    expect(await send(hooks, { text: "Done." })).toBeUndefined();
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    expect(await hooks.beforeAgentRun({ prompt: "Again", senderId: SENDER }, { ...AGENT_CTX, runId: "run-2" })).toBeUndefined();
    expect(await hooks.messageSending({ to: SENDER, content: "Done." }, MESSAGE_CTX)).toEqual({ content: "Done." });
    expect(responses(server)).toHaveLength(2);
  });
});

describe("the conversation tools are the Guardian's to decide", () => {
  it.each(["conversations_send", "conversations_turn"])("sends %s to the Guardian as toolCallRequest", async (toolName) => {
    const { server, hooks } = setup();
    await startRun(hooks);
    const params = { conversationId: "c-1", message: "hi" };
    expect(await hooks.beforeToolCall({ toolName, params, toolCallId: "call-c" }, TOOL_CTX)).toEqual({ params });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/toolCallRequest", payload: { tool: { name: toolName } } });
  });
});

describe("a run no person started is governed like any other", () => {
  const HEARTBEAT = { runId: "beat-1", sessionKey: "agent:main:main", sessionId: "main-session", trigger: "heartbeat", agentId: "main" };

  it("sends its tool result through the middleware, its final reply after agent_end, and its sessionEnd", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    expect(await hooks.beforeAgentRun({ prompt: "Check the inbox" }, HEARTBEAT)).toBeUndefined();
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {}, toolCallId: "call-h" }, { runId: "beat-1", sessionKey: HEARTBEAT.sessionKey })).toEqual({ params: {} });
    const result = { content: [{ type: "text" as const, text: "two new mails" }], details: undefined };
    expect(await hooks.toolResult({ toolCallId: "call-h", toolName: "account-lookup", args: {}, result }, { runtime: "openclaw", runId: "beat-1", sessionKey: HEARTBEAT.sessionKey, sessionId: HEARTBEAT.sessionId })).toBeUndefined();
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/toolCallResult", userContext: undefined });
    await hooks.agentEnd({ runId: "beat-1", success: true }, HEARTBEAT);
    expect(await hooks.messageSending({ to: OWNER, content: "Two new mails." }, { channelId: "signal", sessionKey: HEARTBEAT.sessionKey, runId: "beat-1" })).toEqual({ content: "Two new mails." });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/agentResponse", userContext: undefined });
    await hooks.sessionEnd({ sessionKey: HEARTBEAT.sessionKey, sessionId: HEARTBEAT.sessionId, reason: "idle" }, { sessionKey: HEARTBEAT.sessionKey, sessionId: HEARTBEAT.sessionId });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/sessionEnd", userContext: undefined });
  });
});

describe("the last review's cases", () => {
  it("sends a heartbeat's reply in a session once admitted to a person without that person", async () => {
    const { server, hooks } = setup();
    await startRun(hooks);
    await hooks.agentEnd({ runId: "run-1", success: true }, AGENT_CTX);
    const beat = { runId: "beat-1", sessionKey: SESSION_KEY, sessionId: SESSION_ID, trigger: "heartbeat" };
    expect(await hooks.beforeAgentRun({ prompt: "Check in" }, beat)).toBeUndefined();
    await hooks.messageSending({ to: SENDER, content: "Anything new?" }, { ...MESSAGE_CTX, runId: "beat-1" });
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/agentResponse", userContext: undefined });
  });
});

describe("a sub-agent's run: OpenClaw names no parent step, so no subagentStart", () => {
  it("governs the run in its own session for no person, and sends no subagentStart", async () => {
    const { server, hooks } = setup({ methodsEvaluated: ALL_METHODS });
    await startRun(hooks);
    const sent = server.steps.length;
    const child = { runId: "child-1", sessionKey: "agent:helper:subagent:bb", sessionId: "child-session", agentId: "helper" };
    expect(await hooks.beforeAgentRun({ prompt: "Summarise the bookings" }, child)).toBeUndefined();
    const steps = server.steps.slice(sent);
    expect(steps.map((step) => step.method)).toEqual(["steps/sessionStart", "steps/agentTrigger", "steps/turnStart"]);
    expect(steps.map((step) => step.userContext)).toEqual([undefined, undefined, undefined]);
    expect(steps[1]!.payload).toMatchObject({ trigger_type: "system", trigger_source: { prompt: "Summarise the bookings" } });
    expect(await hooks.beforeToolCall({ toolName: "account-lookup", params: {} }, { runId: "child-1", sessionKey: child.sessionKey })).toEqual({ params: {} });
  });
});
