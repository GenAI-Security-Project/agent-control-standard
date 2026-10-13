import { describe, expect, it } from "bun:test";
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditUngovernedStep, createAuditSink, createGuardianClient, governStep, type Hookmap } from "host-adapter";
import { convertAuditLog, FAILURE_CLASS_BY_KIND, failureClassOf } from "../packages/guardian/src/audit-to-otlp.ts";
import { loadOtelMapping } from "../packages/guardian/src/otel-trace-exporter.ts";

/**
 * The converter's contract, measured with the Guardian down. The host
 * adapter records the failures only it can see (#37: a Guardian it could
 * not reach, one that answered too late) in its own audit log, and the
 * converter turns that log into the same OTLP/JSON file the Guardian's
 * exporter writes. Here, because it uses two packages: the adapter writes
 * the log for real, against a port nothing listens on, and the converter
 * in the guardian package reads it back.
 *
 * The same deliberately synthetic hookmap packages/host-adapter/test/govern-step.test.ts
 * uses, naming no real host's fields.
 */
const ON_STEP = {
  acs_method: "steps/toolCallRequest",
  tool_name: "$.tool_name",
  arguments: "$.tool_input",
  decisions: {
    allow: { output: { outcome: { value: "go" }, note: { from: "reasoning", type: "string" } } },
    deny: { output: { outcome: { value: "stop" }, note: { from: "reasoning", type: "string" } } },
  },
} as const;

const hookmap: Hookmap = {
  host: "test-host",
  hooks: {
    OnStep: ON_STEP,
    // The same gate scoped to one tool, so a step on any other tool is one
    // the gate declines to ask about -- an `ungoverned` entry.
    OnScopedStep: { ...ON_STEP, tools: ["Bash"] },
  },
};

const payload = { session_id: "sess-1", tool_name: "Bash", tool_input: { command: "ls -la" } };

type OtlpAttribute = { key: string; value: { stringValue?: string } };
type OtlpEvent = { name: string; attributes?: OtlpAttribute[] };
type OtlpSpan = { name: string; attributes?: OtlpAttribute[]; events?: OtlpEvent[] };
type OtlpRequest = { resourceSpans: { scopeSpans: { spans: OtlpSpan[] }[] }[] };

function spansIn(path: string): OtlpSpan[] {
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .flatMap((line) => (JSON.parse(line) as OtlpRequest).resourceSpans.flatMap((rs) => rs.scopeSpans.flatMap((ss) => ss.spans)));
}

function attribute(carrier: OtlpSpan | OtlpEvent | undefined, key: string): string | undefined {
  return carrier?.attributes?.find((a) => a.key === key)?.value.stringValue;
}

type AuditLine = { session_id: string; method: string | null; outcome: string; failure?: { kind: string; message: string } };

function auditLines(path: string): AuditLine[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as AuditLine);
}

/** Non-recursive cleanup: the files a test can create, by name, then the directory. */
function withScratch(run: (auditPath: string, otelPath: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "acs-audit-to-otlp-"));
  const auditPath = join(dir, "audit.jsonl");
  const otelPath = join(dir, "otel.jsonl");
  return run(auditPath, otelPath).finally(() => {
    for (const path of [auditPath, otelPath]) {
      if (existsSync(path)) {
        unlinkSync(path);
      }
    }
    rmdirSync(dir);
  });
}

describe("audit-to-otlp: the host's decision failures become acs.decision.failure spans", () => {
  // Port 1 is closed on any normal machine, so the request never reaches a
  // Guardian and the adapter records a `transport` failure resolved by its
  // `proceed` posture. That one entry is the converter's whole input here.
  it("turns the transport entry a dead Guardian leaves into one unreachable span, reported by the observed agent, fail_open", async () => {
    await withScratch(async (auditPath, otelPath) => {
      const audit = createAuditSink({ path: auditPath });
      await governStep({
        hookEventName: "OnStep",
        payload,
        hookmap,
        guardian: createGuardianClient("http://127.0.0.1:1/acs"),
        session: { config: { timeout_config: { default_ms: 1000 }, on_decision_failure: "proceed" }, failure: undefined },
        sessionId: "sess-1",
        audit,
      });
      const [entry] = auditLines(auditPath);
      expect(entry?.outcome).toBe("proceeded");
      expect(entry?.failure?.kind).toBe("transport");

      const summary = await convertAuditLog(auditPath, otelPath);

      expect(summary).toEqual({ spans: 1, skippedUnmapped: 0, skippedUngoverned: 0, skippedUnreadable: 0 });
      const spans = spansIn(otelPath);
      expect(spans).toHaveLength(1);
      expect(spans[0]?.name).toBe(loadOtelMapping().stepToSpan["steps/toolCallRequest"]!.span_name);
      expect(attribute(spans[0], "acs.session.id")).toBe(entry!.session_id);
      const failure = spans[0]?.events?.find((event) => event.name === "acs.decision.failure");
      expect(attribute(failure, "acs.failure.class")).toBe("unreachable");
      expect(attribute(failure, "acs.failure.reported_by")).toBe("observed_agent");
      expect(attribute(failure, "acs.failure.posture")).toBe("fail_open");
      expect(attribute(failure, "acs.failure.detail")).toBe(entry!.failure!.message);
    });
  });

  it("skips ungoverned entries, and skips and counts entries whose method the mapping does not name", async () => {
    await withScratch(async (auditPath, otelPath) => {
      const audit = createAuditSink({ path: auditPath });
      // A step the scoped gate declined to ask about: not a decision failure,
      // so none of #37's classes describes it.
      auditUngovernedStep({ hookmap, hookEventName: "OnScopedStep", tool: "WebFetch", sessionId: "sess-1", audit });
      // Two posture entries the mapping has no span for: a method with no
      // step_to_span entry, and an entry with no method at all.
      const recorded_at = new Date().toISOString();
      appendFileSync(
        auditPath,
        `${JSON.stringify({ seq: 2, recorded_at, session_id: "sess-1", method: "protocols/MCP/tools/call", rpc_id: 2, outcome: "proceeded", posture: "proceed", posture_source: "negotiated", failure: { kind: "timeout", message: "no decision within 1000ms" } })}\n`,
      );
      appendFileSync(
        auditPath,
        `${JSON.stringify({ seq: 3, recorded_at, session_id: "sess-1", method: null, rpc_id: null, outcome: "blocked", posture: "deny", posture_source: "default", failure: { kind: "host_configuration", message: "no hookmap entry for this hook" } })}\n`,
      );
      expect(auditLines(auditPath).map((line) => line.outcome)).toEqual(["ungoverned", "proceeded", "blocked"]);

      const summary = await convertAuditLog(auditPath, otelPath);

      expect(summary).toEqual({ spans: 0, skippedUnmapped: 2, skippedUngoverned: 1, skippedUnreadable: 0 });
      expect(spansIn(otelPath)).toHaveLength(0);
    });
  });

  it("maps every host failure kind to a class from #37, and anything else to other", () => {
    expect(FAILURE_CLASS_BY_KIND).toEqual({
      timeout: "timeout",
      transport: "unreachable",
      error_without_decision: "guardian_error",
      refused: "guardian_error",
      host_configuration: "observed_agent_error",
      decision_unrenderable: "observed_agent_error",
    });
    expect(failureClassOf("unknown")).toBe("other");
    expect(failureClassOf(undefined)).toBe("other");
  });
});
