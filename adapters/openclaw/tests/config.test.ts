import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readdirSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import plugin from "../acs-plugin.ts";
import { parseConfig, PluginConfigError } from "../config.ts";
import { dispatchContext, inboundEvent } from "./inbound.ts";
import { memoryPluginState } from "./memory-plugin-state.ts";

const KEY = Buffer.from("0123456789abcdef0123456789abcdef");
const ENV = { ACS_KEY: KEY.toString("base64") };
const VALID = { guardianUrl: "http://127.0.0.1:8787/acs", hmacKeyId: "example-key", hmacSecretEnv: "ACS_KEY" };

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) {
    for (const entry of readdirSync(dir)) {
      unlinkSync(join(dir, entry));
    }
    rmdirSync(dir);
  }
});

function problemsOf(raw: unknown, env: NodeJS.ProcessEnv = ENV): string[] {
  try {
    parseConfig(raw, env);
  } catch (error) {
    if (error instanceof PluginConfigError) {
      return error.problems;
    }
    throw error;
  }
  return [];
}

describe("parseConfig", () => {
  it("fills the defaults", () => {
    const config = parseConfig(VALID, ENV);
    expect(config).toMatchObject({
      guardianUrl: VALID.guardianUrl,
      failurePosture: "negotiated",
      deadlineMs: 5000,
      auditLog: ".acs/audit.jsonl",
    });
    expect(config.hmacKey).toEqual({ keyId: "example-key", secret: KEY });
  });

  it("decodes a secret file as the Guardians do: base64, a trailing newline ignored", () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-openclaw-"));
    dirs.push(dir);
    const hmacSecretFile = join(dir, "hmac-secret");
    writeFileSync(hmacSecretFile, `${KEY.toString("base64")}\n`);
    const { hmacSecretEnv: _unused, ...withoutEnv } = VALID;
    const config = parseConfig({ ...withoutEnv, hmacSecretFile }, {});
    expect(config.hmacKey.secret).toEqual(KEY);
  });

  it.each<[string, Record<string, unknown>, NodeJS.ProcessEnv, string]>([
    ["no_key_id", { ...VALID, hmacKeyId: undefined }, ENV, '"hmacKeyId" is required'],
    ["both_secret_sources", { ...VALID, hmacSecretFile: "/tmp/key" }, ENV, "exactly one"],
    ["no_secret_source", { ...VALID, hmacSecretEnv: undefined }, ENV, "exactly one"],
    ["an_unset_key_env", VALID, {}, "unset or empty"],
    ["an_unreadable_secret_file", { ...VALID, hmacSecretEnv: undefined, hmacSecretFile: "/nonexistent/acs-key" }, ENV, "cannot be read"],
    ["a_removed_hkdf_key", { ...VALID, hkdf: { salt: "" } }, ENV, "unknown keys hkdf"],
    ["an_unknown_key", { ...VALID, roles: ["owner"] }, ENV, "unknown keys roles"],
    ["an_unknown_posture", { ...VALID, failurePosture: "open" }, ENV, "failurePosture"],
    ["a_bad_url", { ...VALID, guardianUrl: "not a url" }, ENV, "guardianUrl"],
    ["a_zero_deadline", { ...VALID, deadlineMs: 0 }, ENV, "deadlineMs"],
    ["a_deadline_no_longer_than_the_state_reserve", { ...VALID, deadlineMs: 250 }, ENV, "above 250"],
    ["a_deadline_as_long_as_the_hook_timeout", { ...VALID, deadlineMs: 15_000 }, ENV, "shorter than"],
    ["a_deadline_longer_than_a_set_hook_timeout", { ...VALID, deadlineMs: 6000, hookTimeoutMs: 5000 }, ENV, "shorter than"],
    ["a_zero_undecided_cap", { ...VALID, maxUndecidedMessages: 0 }, ENV, "maxUndecidedMessages"],
    ["a_removed_approvers_list", { ...VALID, approvers: ["owner"] }, ENV, "unknown keys approvers"],
    ["a_removed_blocked_reply_text", { ...VALID, blockedReplyText: "Not now." }, ENV, "unknown keys blockedReplyText"],
    // The Go Guardian enforces RFC 2104's 32-byte minimum.
    ["a_key_shorter_than_32_bytes", VALID, { ACS_KEY: KEY.subarray(1).toString("base64") }, "at least 32"],
    ["a_key_not_in_base64", VALID, { ACS_KEY: "0123456789abcdef0123456789abcdef!" }, "not standard base64"],
  ])("refuses %s", (_name, raw, env, problem) => {
    expect(problemsOf(raw, env).join("; ")).toContain(problem);
  });
});

describe("the plugin entry", () => {
  type Registered = { name: string; handler: (...args: unknown[]) => unknown; priority?: number; timeoutMs?: number };

  const STATE = memoryPluginState();


  function register(
    pluginConfig: Record<string, unknown>,
    runtime: Record<string, unknown> = { state: STATE },
    hasMiddleware = true,
    hasRunStateStore = true,
  ): { registered: Registered[]; middleware: Array<{ runtimes: string[] }>; errors: string[] } {
    const registered: Registered[] = [];
    const middleware: Array<{ runtimes: string[] }> = [];
    const errors: string[] = [];
    const hostRuntime = { ...runtime };
    if (!hasRunStateStore) delete hostRuntime.state;
    plugin.register({
      pluginConfig,
      runtime: hostRuntime as never,
      logger: { error: (message: string) => errors.push(message), warn: () => {}, info: () => {} },
      on: (name: string, handler: (...args: never[]) => unknown, options?: { priority?: number; timeoutMs?: number }) => {
        registered.push({ name, handler: handler as (...args: unknown[]) => unknown, priority: options?.priority, timeoutMs: options?.timeoutMs });
      },
      ...(hasMiddleware ? { registerAgentToolResultMiddleware: (_handler: unknown, options: { runtimes: string[] }) => middleware.push(options) } : {}),
    });
    return { registered, middleware, errors };
  }

  it("registers its hooks to run last", () => {
    process.env.ACS_OPENCLAW_TEST_KEY = ENV.ACS_KEY;
    const { registered, middleware, errors } = register({ ...VALID, hmacSecretEnv: "ACS_OPENCLAW_TEST_KEY" });
    expect(errors).toEqual([]);
    expect(middleware).toEqual([{ runtimes: ["openclaw"] }]);
    expect(registered.map(({ name }) => name)).toEqual([
      "before_agent_run",
      "reply_dispatch",
      "before_tool_call",
      "after_tool_call",
      "reply_payload_sending",
      "message_sending",
      "agent_end",
      "session_end",
      "gateway_start",
      "gateway_stop",
    ]);
    expect(registered.every(({ priority }) => priority === Number.MIN_SAFE_INTEGER)).toBe(true);
    // Every Guardian-waiting hook requests a timeout longer than `deadlineMs`.
    expect(Object.fromEntries(registered.filter(({ timeoutMs }) => timeoutMs !== undefined).map(({ name, timeoutMs }) => [name, timeoutMs]))).toEqual({
      before_agent_run: 15_000,
      reply_dispatch: 15_000,
      before_tool_call: 15_000,
      reply_payload_sending: 15_000,
      message_sending: 15_000,
    });
  });

  it("blocks every step when its configuration cannot be used", async () => {
    const { registered, errors } = register({ guardianUrl: "http://127.0.0.1:1/acs" });
    expect(errors[0]).toContain('"hmacKeyId" is required');
    const hook = (name: string) => registered.find((entry) => entry.name === name)!.handler;
    expect(await hook("before_tool_call")({ toolName: "x", params: {} }, {})).toMatchObject({ block: true });
    expect(await hook("message_sending")({ to: "x", content: "secret" }, { channelId: "c" })).toEqual({ cancel: true });
    expect(await hook("before_agent_run")({ prompt: "hi" }, {})).toEqual({ outcome: "block", reason: expect.any(String) });
    expect(await hook("reply_dispatch")(inboundEvent({ content: "hi", sessionKey: "s", senderId: "x" }), dispatchContext())).toEqual({ handled: true, queuedFinal: false, counts: { tool: 0, block: 0, final: 0 } });
    expect(await hook("reply_payload_sending")({ payload: { text: "secret" } }, { channelId: "c" })).toEqual({ cancel: true });
  });

  it("blocks every step, sending nothing in its place, when OpenClaw offers no tool-result middleware", async () => {
    process.env.ACS_OPENCLAW_TEST_KEY = ENV.ACS_KEY;
    const dir = mkdtempSync(join(tmpdir(), "acs-openclaw-"));
    dirs.push(dir);
    const config = { ...VALID, hmacSecretEnv: "ACS_OPENCLAW_TEST_KEY", auditLog: join(dir, "audit.jsonl") };
    const { registered, errors } = register(config, undefined, false);
    expect(errors[0]).toContain("no api.registerAgentToolResultMiddleware");
    const hook = (name: string) => registered.find((entry) => entry.name === name)!.handler;
    expect(await hook("message_sending")({ to: "x", content: "secret" }, { channelId: "c" })).toEqual({ cancel: true });
    const notices: string[] = [];
    expect(await hook("reply_dispatch")(inboundEvent({ content: "hi", sessionKey: "s", senderId: "x" }), dispatchContext(notices))).toMatchObject({ handled: true, queuedFinal: false });
    expect(notices).toEqual([]);
  });

  it("registers no blocking hooks for OpenClaw's own settings: a run is not refused for a model, a runtime or a command list", async () => {
    process.env.ACS_OPENCLAW_TEST_KEY = ENV.ACS_KEY;
    const { errors } = register({ ...VALID, hmacSecretEnv: "ACS_OPENCLAW_TEST_KEY" }, { state: STATE, config: { current: () => ({}) }, version: "2099.1.1" });
    expect(errors).toEqual([]);
  });

  it("blocks every step when OpenClaw does not provide plugin-scoped state", async () => {
    const { registered, errors } = register({ ...VALID, hmacSecretEnv: "ACS_OPENCLAW_TEST_KEY" }, undefined, true, false);
    expect(errors[0]).toContain("no api.runtime.state.openKeyedStore");
    const hook = (name: string) => registered.find((entry) => entry.name === name)!.handler;
    expect(await hook("before_tool_call")({ toolName: "x", params: {} }, {})).toMatchObject({ block: true });
  });

  it("declares the tool-result middleware contract OpenClaw checks at registration", async () => {
    const manifest = await Bun.file(new URL("../openclaw.plugin.json", import.meta.url)).json();
    expect(manifest.contracts).toEqual({ agentToolResultMiddleware: ["openclaw"] });
  });

  it("opens the plugin state store only when a hook runs, never at registration", async () => {
    process.env.ACS_OPENCLAW_TEST_KEY = ENV.ACS_KEY;
    let opened = 0;
    const state = { openKeyedStore: (...args: unknown[]) => ((opened += 1), (STATE.openKeyedStore as (...a: unknown[]) => unknown)(...args)) };
    const { registered, errors } = register({ ...VALID, hmacSecretEnv: "ACS_OPENCLAW_TEST_KEY" }, { state });
    expect(errors).toEqual([]);
    await Promise.resolve();
    expect(opened).toBe(0);
    await registered.find((entry) => entry.name === "gateway_start")!.handler({}, {});
    expect(opened).toBe(2);
  });
});
