/**
 * OpenClaw resolves queue mode in this order: inline directive, session entry,
 * then config (`resolveQueueSettingsCore`,
 * `src/auto-reply/reply/queue/settings.ts:18-34`). The adapter decides a
 * message at `reply_dispatch` before OpenClaw applies queue mode.
 */
import { afterEach, describe, expect, it } from "bun:test";
import { tmpdir } from "node:os";
import plugin from "../acs-plugin.ts";
import { memoryPluginState } from "./memory-plugin-state.ts";
import { dispatchContext, inboundEvent } from "./inbound.ts";
import { startFakeGuardian, type FakeGuardian, type ReceivedStep, type Reply } from "./fake-guardian.ts";

const SENDER = "+15550100";
const SESSION_KEY = `agent:main:signal:direct:${SENDER}`;
const SECRET = "0123456789abcdef0123456789abcdef";
const example = await Bun.file(new URL("../openclaw.json.example", import.meta.url)).json();
const servers: FakeGuardian[] = [];
afterEach(() => {
  const invalid = servers.flatMap((server) => server.invalidEnvelopes);
  servers.splice(0).forEach((server) => server.stop());
  expect(invalid).toEqual([]);
});

function deployed(queue: Record<string, unknown>, reply?: (step: ReceivedStep) => Reply) {
  const server = startFakeGuardian({
    key: { keyId: "default", secret: Buffer.from(SECRET) },
    reply,
    methodsEvaluated: ["steps/userMessage"],
  });
  servers.push(server);
  const settings = { ...structuredClone(example), messages: { queue } };
  const hooks = new Map<string, (...args: unknown[]) => Promise<unknown>>();
  process.env.ACS_QUEUE_TEST_KEY = Buffer.from(SECRET).toString("base64");
  plugin.register({
    pluginConfig: {
      ...settings.plugins.entries["acs-guardian-client"].config,
      hmacSecretEnv: "ACS_QUEUE_TEST_KEY",
      guardianUrl: server.url,
      auditLog: `${tmpdir()}/acs-openclaw-queue-test.jsonl`,
    },
    runtime: { state: memoryPluginState() } as never,
    logger: { error: () => {}, warn: () => {}, info: () => {} },
    on: (name: string, handler: (...args: never[]) => unknown) => hooks.set(name, handler as (...args: unknown[]) => Promise<unknown>),
    registerAgentToolResultMiddleware: () => {},
  });
  const run = { runId: "run-1", sessionKey: SESSION_KEY, sessionId: "session-1", senderId: SENDER, channel: "signal", agentId: "main", modelProviderId: "openai", modelId: "gpt-6-astra" };
  return {
    server,
    start: () => hooks.get("before_agent_run")!({ prompt: "hello", senderId: SENDER }, run),
    dispatch: (content: string) => hooks.get("reply_dispatch")!(inboundEvent({ content, sessionKey: SESSION_KEY, senderId: SENDER }), dispatchContext()),
  };
}

describe("a message joining an admitted run is decided whatever the queue mode", () => {
  // The adapter must decide the message before these queue settings apply.
  it.each([
    ["no_queue_settings", {}],
    ["global_followup", { mode: "followup" }],
    ["global_collect", { mode: "collect" }],
    ["channel_followup", { mode: "steer", byChannel: { signal: "followup" } }],
  ])("under %s", async (_name, queue) => {
    const { server, start, dispatch } = deployed(queue);
    expect(await start()).toBeUndefined();
    expect(await dispatch("Also this")).toBeUndefined();
    expect(server.steps.at(-1)).toMatchObject({ method: "steps/userMessage", turnId: "run-1", payload: { content: [{ value: "Also this" }] } });
  });

  it("drops a message the Guardian refuses at dispatch", async () => {
    const { start, dispatch } = deployed({ mode: "followup" }, (step) =>
      (step.payload as { content: Array<{ value: string }> }).content[0]!.value === "Also this" ? { decision: { decision: "deny", reasoning: "no" } } : { decision: { decision: "allow" } },
    );
    await start();
    expect(await dispatch("Also this")).toMatchObject({ handled: true });
  });
});
