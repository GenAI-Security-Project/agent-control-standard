/**
 * Runs adapter hooks over HTTP against the TypeScript Guardian and, when
 * built, the Go Guardian. Both use the stock AGT policy for OpenClaw's `exec`.
 * A proxy records envelopes and can tamper with signed answers. CI fails if a
 * required Guardian cannot start.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAcsExchange } from "../acs-exchange.ts";
import { GUARDIAN_APPROVER, writeManifest } from "../demo/guardian.ts";
import type { AdapterAuditEvent } from "../audit.ts";
import type { FailurePosture } from "../config.ts";
import { createGuardianClient, toSessionUuid, type HmacKey } from "../host-adapter.ts";
import { createHooks } from "../openclaw-hooks.ts";
import { memoryFailureCounts } from "./memory-failure-counts.ts";
import { memoryRefusals } from "./memory-refusals.ts";
import { memoryRunFacts } from "./memory-run-facts.ts";
import { recordEnvelopes } from "./recorded-envelopes.ts";
import { specificationFailure } from "./emitted-envelope.ts";
import { go, typescript, type RunningGuardian } from "./guardians.ts";

const KEY: HmacKey = { keyId: "e2e", secret: randomBytes(32) };
const SENDER = "+15550100";
const SESSION_KEY = `agent:main:signal:direct:${SENDER}`;

function governed(url: string, failurePosture: FailurePosture = "negotiated") {
  const sessionId = crypto.randomUUID();
  const audit: AdapterAuditEvent[] = [];
  const sink = { path: "memory", write: (event: AdapterAuditEvent) => (audit.push(event), true) };
  const errors: string[] = [];
  const hooks = createHooks({
    config: { maxUndecidedMessages: 20, maxAttachmentBytes: 524_288 },
    exchange: createAcsExchange({ client: createGuardianClient(url, { hmacKey: KEY }), hmacKey: KEY, audit: sink, failurePosture, deadlineMs: 8000, failureCounts: memoryFailureCounts() }),
    audit: sink,
    logger: { error: (message) => errors.push(message) },
    runFacts: memoryRunFacts(),
    refusals: memoryRefusals(),
  });
  const run = { runId: `run-${sessionId}`, sessionKey: SESSION_KEY, sessionId, senderId: SENDER, channel: "signal" };
  const tool = { runId: run.runId, sessionKey: SESSION_KEY, sessionId };
  const call = (toolCallId: string, command: string) => hooks.beforeToolCall({ toolName: "exec", params: { command }, toolCallId }, tool);
  const fetchUrl = (toolCallId: string, url: string) => hooks.beforeToolCall({ toolName: "webfetch", params: { url }, toolCallId }, tool);
  const result = (toolCallId: string, text: string) =>
    hooks.toolResult(
      { toolCallId, toolName: "exec", args: {}, result: { content: [{ type: "text", text }], details: undefined } },
      { runtime: "openclaw", runId: run.runId, sessionKey: SESSION_KEY, sessionId },
    );
  const admit = () => hooks.beforeAgentRun({ prompt: "Tidy the workspace", senderId: SENDER }, run);
  return { hooks, run, sessionId, call, fetchUrl, result, admit, audit, errors };
}

for (const launcher of [typescript, go]) {
  const unavailable = launcher.unavailable();
  if (unavailable !== undefined) {
    if (process.env.CI !== undefined && launcher.requiredInCi) {
      throw new Error(`the ${launcher.name} Guardian must run in CI: ${unavailable}`);
    }
    console.log(`skipping the ${launcher.name} Guardian: ${unavailable}`);
    continue;
  }

  describe(`the OpenClaw adapter on the ${launcher.name} Guardian`, () => {
    const policies = mkdtempSync(join(tmpdir(), "acs-openclaw-policy-"));
    let guardian: RunningGuardian;
    let proxy: ReturnType<typeof recordEnvelopes>;

    beforeAll(async () => {
      guardian = await launcher.start({ manifestPath: writeManifest(join(policies, "stock")), onDecisionFailure: "proceed", key: KEY });
      proxy = recordEnvelopes(guardian.url);
    });
    afterAll(() => {
      proxy?.stop();
      guardian?.stop();
      rmSync(policies, { recursive: true, force: true });
    });

    const stepsOf = (sessionId: string) =>
      proxy.envelopes
        .filter((envelope) => (envelope.params as { metadata: { session_id: string } }).metadata.session_id === toSessionUuid(sessionId))
        .map((envelope) => envelope.method as string)
        .filter((method) => method.startsWith("steps/"));

    it("admits a run, sending its session, trigger, turn and user message where the Guardian evaluates them", async () => {
      const { admit, audit, sessionId } = governed(proxy.url);
      expect(await admit()).toBeUndefined();
      expect(audit).toEqual([]);
      expect(stepsOf(sessionId)).toEqual(
        launcher.evaluatesRunSteps ? ["steps/sessionStart", "steps/turnStart", "steps/userMessage"] : [],
      );
    });

    it("gets an answer to system/ping, unsigned, as §13 allows", async () => {
      const exchange = createAcsExchange({ client: createGuardianClient(proxy.url, { hmacKey: KEY }), hmacKey: KEY, audit: { path: "memory", write: () => true }, failurePosture: "negotiated", deadlineMs: 8000, failureCounts: memoryFailureCounts() });
      await exchange.ping();
      expect(proxy.envelopes.some((envelope) => envelope.method === "system/ping")).toBe(true);
    });

    it("runs an allowed command with exactly the parameters the Guardian saw, and passes its clean result", async () => {
      const { admit, call, result } = governed(proxy.url);
      await admit();
      expect(await call("call-1", "ls")).toEqual({ params: { command: "ls" } });
      expect(await result("call-1", "README.md")).toBeUndefined();
    });

    it("gives the model the Guardian's redaction of a secret in a result", async () => {
      const { admit, call, result } = governed(proxy.url);
      await admit();
      await call("call-2", "cat .env");
      expect(await result("call-2", "TOKEN=ghp_ABCDEF123456")).toEqual({ result: { content: [{ type: "text", text: "TOKEN=[REDACTED]" }], details: undefined } });
    });

    it("blocks a destructive command with the Guardian's reasoning", async () => {
      const { admit, call } = governed(proxy.url);
      await admit();
      expect(await call("call-3", "echo rm -rf /")).toMatchObject({ block: true, blockReason: expect.stringMatching(/destructive/i) });
    });

    it("blocks a call that reaches a host outside the Guardian's egress allowlist, and allows one inside it", async () => {
      const { admit, fetchUrl } = governed(proxy.url);
      await admit();
      expect(await fetchUrl("call-6", "https://evil.example/upload")).toMatchObject({ block: true, blockReason: expect.stringMatching(/egress/i) });
      expect(await fetchUrl("call-7", "https://docs.example.com/guide")).toEqual({ params: { url: "https://docs.example.com/guide" } });
    });

    it("ends the turn and the session, sent where the Guardian evaluates them and recorded only", async () => {
      const { hooks, run, sessionId, admit, audit } = governed(proxy.url);
      await admit();
      await hooks.agentEnd({ runId: run.runId, success: true }, run);
      await hooks.sessionEnd({ sessionKey: SESSION_KEY, sessionId, reason: "idle" }, { sessionId });
      expect(audit).toEqual([]);
      expect(stepsOf(sessionId).slice(-2)).toEqual(launcher.evaluatesRunSteps ? ["steps/turnEnd", "steps/sessionEnd"] : []);
    });

    it("blocks an answer changed on the way, under a negotiated proceed, as signature_invalid (#308)", async () => {
      const { admit, call, audit } = governed(proxy.url);
      await admit();
      proxy.tamperNext("steps/toolCallRequest", { decision: "allow" });
      expect(await call("call-4", "echo rm -rf /")).toMatchObject({ block: true, blockReason: expect.stringContaining("could not be verified") });
      expect(audit.at(-1)).toMatchObject({ outcome: "blocked", posture: "proceed", failure: { kind: "signature_invalid" } });
    });

    it("blocks under failurePosture closed when the Guardian is unreachable, recorded as the host's posture", async () => {
      const { admit, audit } = governed("http://127.0.0.1:1/acs", "closed");
      expect(await admit()).toMatchObject({ outcome: "block" });
      expect(audit[0]).toMatchObject({ outcome: "blocked", posture: "deny", posture_source: "host" });
    });

    it("sent only envelopes that validate against specification/v0.1.0/", () => {
      expect(proxy.envelopes.length).toBeGreaterThan(0);
      const invalid = proxy.envelopes.map(specificationFailure).filter((reason) => reason !== undefined);
      expect(invalid).toEqual([]);
    });

    if (launcher.asks) {
      describe("ASK", () => {
        let askingGuardian: RunningGuardian;
        let askingProxy: ReturnType<typeof recordEnvelopes>;
        beforeAll(async () => {
          askingGuardian = await launcher.start({ manifestPath: writeManifest(join(policies, "asking"), [GUARDIAN_APPROVER]), onDecisionFailure: "proceed", key: KEY, askApprover: GUARDIAN_APPROVER });
          askingProxy = recordEnvelopes(askingGuardian.url);
        });
        afterAll(() => {
          askingProxy?.stop();
          askingGuardian?.stop();
        });

        it("sent only envelopes that validate against specification/v0.1.0/, here too", async () => {
          const { admit, call } = governed(askingProxy.url);
          await admit();
          await call("call-8", "ls");
          expect(askingProxy.envelopes.length).toBeGreaterThan(0);
          expect(askingProxy.envelopes.map(specificationFailure).filter((reason) => reason !== undefined)).toEqual([]);
        });

        it.each<["allow-once" | "deny", "allow" | "deny"]>([
          ["allow-once", "allow"],
          ["deny", "deny"],
        ])("puts the call to a person, and applies and records %s", async (resolution, decision) => {
          const { admit, call, audit } = governed(askingProxy.url);
          await admit();
          const answer = await call("call-5", "ls");
          expect(answer).toMatchObject({ params: { command: "ls" }, requireApproval: { title: "exec", allowedDecisions: ["allow-once", "deny"] } });
          expect(answer?.requireApproval?.description).toEqual(expect.any(String));
          expect(answer?.requireApproval?.description).not.toContain("Call:");
          await answer!.requireApproval!.onResolution!(resolution);
          expect(audit.at(-1)).toMatchObject({
            outcome: "approval",
            method: "steps/toolCallRequest",
            approval: { requested_approver: { type: "human", id: GUARDIAN_APPROVER }, resolution, decision },
          });
        });
      });
    }
  });
}
