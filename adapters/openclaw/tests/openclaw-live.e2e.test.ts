/**
 * Runs the adapter in the official image for its installed OpenClaw release.
 * An A2A peer sends a task; the stub model calls `exec`; the reference
 * Guardian applies the stock policy. Tests use the TypeScript Guardian and,
 * when built, the Go Guardian. The container mounts this tree read-only and
 * uses the default `failurePosture`. Tests skip without Docker, except in CI.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GUARDIAN_APPROVER, writeManifest } from "../demo/guardian.ts";
import { startStubModel } from "../demo/stub-model.ts";
import { recordEnvelopes } from "./recorded-envelopes.ts";
import { specificationFailure } from "./emitted-envelope.ts";
import { go, typescript, type RunningGuardian } from "./guardians.ts";

const ADAPTER = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const REPO = new URL("../../..", import.meta.url).pathname.replace(/\/$/, "");
const OPENCLAW_VERSION = JSON.parse(readFileSync(join(ADAPTER, "node_modules/openclaw/package.json"), "utf8")).version as string;
const IMAGE = `ghcr.io/openclaw/openclaw:${OPENCLAW_VERSION}`;
const PEER = "tester";
const PEER_TOKEN = randomBytes(24).toString("hex");
const KEY = { keyId: "live", secret: randomBytes(32) };

type Json = Record<string, unknown>;

function dockerUnavailable(): string | undefined {
  const probe = spawnSync("docker", ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8" });
  return probe.status === 0 ? undefined : "Docker is not available";
}

/** Finds an available loopback port for the gateway, which reads its port from config. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });
}

const unavailable = dockerUnavailable();
if (unavailable !== undefined && process.env.CI !== undefined) {
  throw new Error(`the live OpenClaw run must run in CI: ${unavailable}`);
}
if (unavailable !== undefined) {
  console.log(`skipping the live OpenClaw run: ${unavailable}`);
}
for (const launcher of unavailable === undefined ? [typescript, go] : []) {
  const launcherUnavailable = launcher.unavailable();
  if (launcherUnavailable !== undefined) {
    if (process.env.CI !== undefined && launcher.requiredInCi) {
      throw new Error(`the ${launcher.name} Guardian must run in CI: ${launcherUnavailable}`);
    }
    console.log(`skipping the live OpenClaw run on the ${launcher.name} Guardian: ${launcherUnavailable}`);
    continue;
  }
  describe(`the adapter in a stock OpenClaw ${OPENCLAW_VERSION} gateway, on the ${launcher.name} Guardian`, () => {
    const scratch = mkdtempSync(join(tmpdir(), "acs-openclaw-live-"));
    const auditLog = join(scratch, "audit.jsonl");
    const gatewayLog = join(scratch, "gateway.log");
    const container = `acs-openclaw-live-${process.pid}-${launcher.name.toLowerCase()}`;
    const model = startStubModel(0);
    let guardian: RunningGuardian;
    let askingGuardian: RunningGuardian | undefined;
    let stockUrl: string;
    let proxy: ReturnType<typeof recordEnvelopes>;
    let gateway: string;

    /** Returns the `exec` request for `command` and its result, if one arrived. */
    function envelopesFor(command: string): Json[] {
      const params = (envelope: Json) => envelope.params as { request_id: string; payload: Json };
      const request = proxy.envelopes.find((envelope) =>
        envelope.method === "steps/toolCallRequest" &&
        (params(envelope).payload.arguments as { command?: { value?: unknown } }).command?.value === command);
      if (request === undefined) {
        return [];
      }
      const result = proxy.envelopes.find((envelope) =>
        envelope.method === "steps/toolCallResult" && params(envelope).payload.request_id_ref === params(request).request_id);
      return [request, ...(result === undefined ? [] : [result])];
    }

    const stepsFor = (command: string): string[] => envelopesFor(command).map((envelope) => envelope.method as string);

    function audit(): Json[] {
      return existsSync(auditLog)
        ? readFileSync(auditLog, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as Json)
        : [];
    }

    async function send(text: string, returnImmediately = false): Promise<Json> {
      const response = await fetch(`${gateway}/a2a/v1`, {
        method: "POST",
        headers: { authorization: `Bearer ${PEER_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: crypto.randomUUID(),
          method: "SendMessage",
          params: {
            ...(returnImmediately ? { configuration: { returnImmediately: true } } : {}),
            message: { messageId: crypto.randomUUID(), role: "ROLE_USER", parts: [{ text }] },
          },
        }),
      });
      return ((await response.json()) as { result: { task: Json } }).result.task;
    }

    function openclaw(...args: string[]): string {
      const run = spawnSync("docker", ["exec", container, "openclaw", ...args], { encoding: "utf8" });
      expect(run.status).toBe(0);
      return run.stdout;
    }

    beforeAll(async () => {
      guardian = await launcher.start({ manifestPath: writeManifest(join(scratch, "stock")), onDecisionFailure: "deny", key: KEY });
      if (launcher.asks) {
        askingGuardian = await launcher.start({ manifestPath: writeManifest(join(scratch, "asking"), [GUARDIAN_APPROVER]), onDecisionFailure: "deny", key: KEY });
      }
      stockUrl = guardian.url;
      proxy = recordEnvelopes(stockUrl);
      const port = await freePort();
      gateway = `http://127.0.0.1:${port}`;
      mkdirSync(join(scratch, "state"));
      mkdirSync(join(scratch, "home"));
      mkdirSync(join(scratch, "work"));
      const config = JSON.parse(readFileSync(join(ADAPTER, "demo/openclaw.json"), "utf8"));
      config.gateway.port = port;
      config.plugins.load.paths = [ADAPTER];
      Object.assign(config.plugins.entries["acs-guardian-client"].config, {
        guardianUrl: proxy.url,
        hmacKeyId: KEY.keyId,
        auditLog,
      });
      config.channels.a2a.peers = { [PEER]: { token: PEER_TOKEN } };
      config.models.providers.stub.baseUrl = model.url;
      config.agents.defaults.workspace = join(scratch, "work");
      config.logging = { level: "debug", file: gatewayLog };
      writeFileSync(join(scratch, "openclaw.json"), JSON.stringify(config));
      // The image runs as a separate user and needs write access to this state.
      for (const path of [scratch, join(scratch, "state"), join(scratch, "home"), join(scratch, "work"), join(scratch, "openclaw.json")]) {
        chmodSync(path, 0o777);
      }
      const pulled = spawnSync("docker", ["pull", "--quiet", IMAGE], { encoding: "utf8" });
      expect(pulled.status).toBe(0);
      const started = spawnSync("docker", [
        "run", "-d", "--name", container, "--network", "host",
        "-v", `${REPO}:${REPO}:ro`, "-v", `${scratch}:${scratch}`,
        "-e", `HOME=${join(scratch, "home")}`, "-e", `OPENCLAW_STATE_DIR=${join(scratch, "state")}`,
        "-e", `OPENCLAW_CONFIG_PATH=${join(scratch, "openclaw.json")}`, "-e", `ACS_HMAC_SECRET=${KEY.secret.toString("base64")}`,
        "--entrypoint", "openclaw", IMAGE, "gateway", "run", "--port", String(port),
      ], { encoding: "utf8" });
      expect(started.stderr).toBe("");
      const deadline = Date.now() + 120_000;
      while (!spawnSync("docker", ["logs", container], { encoding: "utf8" }).stdout.includes("[gateway] ready")) {
        if (Date.now() > deadline) {
          throw new Error(`the gateway did not start: ${spawnSync("docker", ["logs", container], { encoding: "utf8" }).stdout}`);
        }
        await Bun.sleep(1000);
      }
    }, 180_000);

    afterAll(() => {
      spawnSync("docker", ["rm", "-f", container]);
      proxy?.stop();
      model.stop();
      guardian?.stop();
      askingGuardian?.stop();
      rmSync(scratch, { recursive: true, force: true });
    });

    it("runs an allowed command and passes its result to the model", async () => {
      expect(await send("run: ls -la")).toMatchObject({ status: { state: "TASK_STATE_COMPLETED" } });
      expect(stepsFor("ls -la")).toEqual(["steps/toolCallRequest", "steps/toolCallResult"]);
    }, 120_000);

    // OpenClaw only logs a warning when it drops an ungranted hook.
    // Most scenarios would still pass with only before_agent_run registered.
    it("passes the message through reply_dispatch and the reply through reply_payload_sending", () => {
      const log = readFileSync(gatewayLog, "utf8");
      for (const hook of ["reply_dispatch", "before_agent_run", "before_tool_call", "reply_payload_sending"]) {
        expect(log).toContain(`running ${hook} (`);
      }
      expect(log).not.toMatch(/acs-guardian-client[^\n]*blocked/);
    });

    if (launcher.evaluatesRunSteps) {
      it("sends the run's session, its turn, the peer's message and the reply, as the Guardian evaluates them", async () => {
        const task = await send("run: echo hello");
        expect(task).toMatchObject({ status: { state: "TASK_STATE_COMPLETED" } });
        const methods = new Set(proxy.envelopes.map((envelope) => envelope.method as string));
        for (const method of ["steps/sessionStart", "steps/turnStart", "steps/userMessage", "steps/agentResponse", "steps/turnEnd"]) {
          expect(methods.has(method)).toBe(true);
        }
        expect(JSON.stringify(task.artifacts)).toContain("hello");
      }, 120_000);
    }

    it("blocks a destructive command before it runs", async () => {
      // This command is harmless if it runs. The test checks whether it creates the marker.
      const marker = join(scratch, "work", "ran");
      const command = `echo rm -rf / && touch ${marker}`;
      expect(await send(`run: ${command}`)).toMatchObject({ status: { state: "TASK_STATE_COMPLETED" } });
      expect(stepsFor(command)).toEqual(["steps/toolCallRequest"]);
      expect(existsSync(marker)).toBe(false);
    }, 120_000);

    it("gives the model, and so the person, the Guardian's redaction of a secret in a result", async () => {
      const task = await send("run: printf 'TOKEN=ghp_ABCDEF123456'");
      const reply = JSON.stringify(task.artifacts);
      expect(reply).toContain("TOKEN=[REDACTED]");
      expect(reply).not.toContain("ghp_ABCDEF123456");
    }, 120_000);

    it.if(launcher.asks)("puts an ASK to a person, and runs the call after they approve it once", async () => {
      proxy.forwardTo(askingGuardian!.url);
      try {
        await send("run: pwd", true);
        let pending: Array<{ id: string; summary: string }> = [];
        for (let attempt = 0; attempt < 60 && pending.length === 0; attempt += 1) {
          await Bun.sleep(1000);
          pending = (JSON.parse(openclaw("approvals", "pending", "--json")) as { approvals: Array<{ id: string; summary: string }> }).approvals;
        }
        expect(pending).toHaveLength(1);
        expect(pending[0]!.summary).toContain("exec");
        expect(pending[0]!.summary).not.toContain("Call:");
        openclaw("approvals", "resolve", pending[0]!.id, "allow-once");
        for (let attempt = 0; attempt < 30 && !audit().some((entry) => entry.outcome === "approval"); attempt += 1) {
          await Bun.sleep(1000);
        }
        expect(audit().find((entry) => entry.outcome === "approval")).toMatchObject({
          method: "steps/toolCallRequest",
          approval: { requested_approver: { type: "human", id: GUARDIAN_APPROVER }, resolution: "allow-once", decision: "allow" },
        });
        // The approved call ran. The policy still withholds its result.
        for (let attempt = 0; attempt < 30 && stepsFor("pwd").length < 2; attempt += 1) {
          await Bun.sleep(1000);
        }
        expect(stepsFor("pwd")).toEqual(["steps/toolCallRequest", "steps/toolCallResult"]);
        expect((envelopesFor("pwd")[1]!.params as { payload: Json }).payload.exit_status).toBe("success");

        // When the person denies the call, OpenClaw does not run it or create the marker.
        const marker = join(scratch, "work", "denied");
        await send(`run: touch ${marker}`, true);
        let denied: Array<{ id: string }> = [];
        for (let attempt = 0; attempt < 60 && denied.length === 0; attempt += 1) {
          await Bun.sleep(1000);
          denied = (JSON.parse(openclaw("approvals", "pending", "--json")) as { approvals: Array<{ id: string }> }).approvals;
        }
        expect(denied).toHaveLength(1);
        openclaw("approvals", "resolve", denied[0]!.id, "deny");
        for (let attempt = 0; attempt < 30 && audit().filter((entry) => entry.outcome === "approval").length < 2; attempt += 1) {
          await Bun.sleep(1000);
        }
        expect(audit().filter((entry) => entry.outcome === "approval").at(-1)).toMatchObject({ approval: { resolution: "deny", decision: "deny" } });
        expect(existsSync(marker)).toBe(false);
      } finally {
        proxy.forwardTo(stockUrl);
      }
    }, 150_000);

    it("sent only envelopes that validate against specification/v0.1.0/", () => {
      expect(proxy.envelopes.length).toBeGreaterThan(0);
      expect(proxy.envelopes.map(specificationFailure).filter((reason) => reason !== undefined)).toEqual([]);
    });

    it("lets the call run, and records it, when the Guardian is down from the session's start, under the default posture", async () => {
      // Without a ServerHello, ACS defaults to `proceed` (§6.4); `closed` would block the call.
      const marker = join(scratch, "work", "ungoverned");
      proxy.forwardTo("http://127.0.0.1:1/acs");
      try {
        expect(await send(`run: touch ${marker}`)).toMatchObject({ status: { state: "TASK_STATE_COMPLETED" } });
        expect(existsSync(marker)).toBe(true);
        expect(audit().filter((entry) => entry.outcome === "proceeded").at(-1)).toMatchObject({ posture: "proceed", posture_source: "default" });
      } finally {
        proxy.forwardTo(stockUrl);
      }
    }, 120_000);
  });
}
