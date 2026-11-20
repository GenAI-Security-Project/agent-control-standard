import { describe, expect, it } from "bun:test";
import plugin from "../acs-plugin.ts";
import { parseConfig } from "../config.ts";
import { memoryPluginState } from "./memory-plugin-state.ts";

const example = await Bun.file(new URL("../openclaw.json.example", import.meta.url)).json();
const ENV = { ACS_HMAC_SECRET: Buffer.from("0123456789abcdef0123456789abcdef").toString("base64") };

describe("openclaw.json.example", () => {
  it("holds a plugin config the plugin accepts", () => {
    expect(parseConfig(example.plugins.entries["acs-guardian-client"].config, ENV)).toMatchObject({ guardianUrl: "http://127.0.0.1:8787/acs" });
  });

  // OpenClaw registers tool-result middleware only when `plugins.entries` enables the plugin by name.
  // It registers before_agent_run and agent_end only with allowConversationAccess.
  it("enables the plugin by name with conversation access, and the plugin registers its middleware", () => {
    const entry = example.plugins.entries["acs-guardian-client"];
    expect(entry).toMatchObject({ enabled: true, hooks: { allowConversationAccess: true } });
    process.env.ACS_HMAC_SECRET = ENV.ACS_HMAC_SECRET;
    const errors: string[] = [];
    const middleware: unknown[] = [];
    plugin.register({
      pluginConfig: entry.config,
      runtime: { state: memoryPluginState() } as never,
      logger: { error: (message: string) => errors.push(message), warn: () => {}, info: () => {} },
      on: () => {},
      registerAgentToolResultMiddleware: (_handler: unknown, options: unknown) => middleware.push(options),
    });
    expect(errors).toEqual([]);
    expect(middleware).toEqual([{ runtimes: ["openclaw"] }]);
  });
});

const demo = await Bun.file(new URL("../demo/openclaw.json", import.meta.url)).json();

describe("demo/openclaw.json", () => {
  it("holds a plugin config the plugin accepts, enabled by name with conversation access", () => {
    const entry = demo.plugins.entries["acs-guardian-client"];
    expect(entry).toMatchObject({ enabled: true, hooks: { allowConversationAccess: true } });
    expect(parseConfig(entry.config, ENV)).toMatchObject({ failurePosture: "negotiated" });
  });
});
