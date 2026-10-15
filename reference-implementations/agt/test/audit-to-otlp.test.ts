import { afterEach, describe, expect, it } from "bun:test";
import { appendFileSync, existsSync, linkSync, mkdtempSync, readFileSync, rmdirSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditUngovernedStep, createAuditSink, createGuardianClient, governStep, toSessionUuid, type Hookmap } from "host-adapter";
import {
  CONVERTER_SERVICE_NAME,
  convertAuditLog,
  FAILURE_CLASS_BY_KIND,
  FAILURE_DETAIL_BY_KIND,
  failureClassOf,
  sessionUuid as converterSessionUuid,
} from "../packages/guardian/src/audit-to-otlp.ts";
import { loadOtelMapping, OTEL_SERVICE_NAME, SPAN_LIMITS } from "../packages/guardian/src/otel-trace-exporter.ts";

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

      expect(summary).toEqual({
        converted: 1,
        written: 1,
        skippedUnmapped: 0,
        skippedNoMethod: {},
        skippedReplay: 0,
        skippedUngoverned: 0,
        skippedUnreadable: 0,
      });
      const spans = spansIn(otelPath);
      expect(spans).toHaveLength(1);
      expect(spans[0]?.name).toBe(loadOtelMapping().stepToSpan["steps/toolCallRequest"]!.span_name);
      expect(attribute(spans[0], "acs.session.id")).toBe(toSessionUuid(entry!.session_id));
      const failure = spans[0]?.events?.find((event) => event.name === "acs.decision.failure");
      expect(attribute(failure, "acs.failure.class")).toBe("unreachable");
      expect(attribute(failure, "acs.failure.reported_by")).toBe("observed_agent");
      expect(attribute(failure, "acs.failure.posture")).toBe("fail_open");
      expect(attribute(failure, "acs.failure.detail")).toBe(FAILURE_DETAIL_BY_KIND.transport);
    });
  });

  it("skips ungoverned entries, and counts unmapped methods apart from entries with no method", async () => {
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

      expect(summary).toEqual({
        converted: 0,
        written: 0,
        skippedUnmapped: 1,
        skippedNoMethod: { host_configuration: 1 },
        skippedReplay: 0,
        skippedUngoverned: 1,
        skippedUnreadable: 0,
      });
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
    });
    // A decision did arrive, so observed_agent_error does not fit (#244 review).
    expect(failureClassOf("decision_unrenderable")).toBe("other");
    expect(failureClassOf("unknown")).toBe("other");
    expect(failureClassOf(undefined)).toBe("other");
  });
});

// Review fixes on PR #244. Each test names the finding it pins.
describe("audit-to-otlp: review fixes", () => {
  const SENTINEL = "SENTINEL-ignore-previous-instructions";

  function entryLine(fields: Record<string, unknown>): string {
    return `${JSON.stringify({
      seq: 1,
      recorded_at: new Date().toISOString(),
      session_id: "sess-1",
      method: "steps/toolCallRequest",
      rpc_id: "3f6c1e2a-8b4d-4c1e-9a7f-2d5b6e8c9a01",
      outcome: "proceeded",
      posture: "proceed",
      posture_source: "negotiated",
      failure: { kind: "transport", message: "connect ECONNREFUSED 127.0.0.1:1" },
      ...fields,
    })}\n`;
  }

  function numberAttribute(carrier: OtlpEvent | undefined, key: string): number | undefined {
    const value = (carrier?.attributes?.find((a) => a.key === key)?.value as { intValue?: string | number } | undefined)?.intValue;
    return value === undefined ? undefined : Number(value);
  }

  // #228: posture is the deployment's, and detail is text the emitter writes.
  it("reports a refusal under a proceed posture as guardian_error and fail_open, keeps the code, and copies no message text", async () => {
    await withScratch(async (auditPath, otelPath) => {
      appendFileSync(
        auditPath,
        entryLine({ outcome: "blocked", failure: { kind: "refused", message: `guardian refused the envelope with error -32003: ${SENTINEL}` } }),
      );

      await convertAuditLog(auditPath, otelPath);

      const raw = readFileSync(otelPath, "utf8");
      expect(raw).not.toContain("SENTINEL");
      const failure = spansIn(otelPath)[0]?.events?.find((event) => event.name === "acs.decision.failure");
      expect(attribute(failure, "acs.failure.class")).toBe("guardian_error");
      expect(attribute(failure, "acs.failure.posture")).toBe("fail_open");
      expect(numberAttribute(failure, "acs.failure.error_code")).toBe(-32003);
      expect(attribute(failure, "acs.failure.detail")).toBe(FAILURE_DETAIL_BY_KIND.refused);
    });
  });

  it("files decision_unrenderable under other, with a detail", async () => {
    await withScratch(async (auditPath, otelPath) => {
      appendFileSync(auditPath, entryLine({ failure: { kind: "decision_unrenderable", message: `no hookmap entry: ${SENTINEL}` } }));

      await convertAuditLog(auditPath, otelPath);

      const failure = spansIn(otelPath)[0]?.events?.find((event) => event.name === "acs.decision.failure");
      expect(attribute(failure, "acs.failure.class")).toBe("other");
      expect(attribute(failure, "acs.failure.detail")).toBe(FAILURE_DETAIL_BY_KIND.decision_unrenderable);
    });
  });

  // The batch processor's queue used to overflow inside the synchronous
  // loop: 5000 entries wrote 2560 spans while the summary claimed 5000.
  it("writes every span for a large audit log, and the summary counts what was written", async () => {
    await withScratch(async (auditPath, otelPath) => {
      let lines = "";
      for (let i = 0; i < 5000; i += 1) {
        lines += entryLine({ seq: i + 1, rpc_id: crypto.randomUUID() });
      }
      appendFileSync(auditPath, lines);

      const summary = await convertAuditLog(auditPath, otelPath);

      expect(summary.converted).toBe(5000);
      expect(summary.written).toBe(5000);
      expect(spansIn(otelPath)).toHaveLength(5000);
    });
  });

  // The Guardian's spans carry the derived UUID and the request id; a
  // converter span has to carry the same pair, or #228's pair rules can't
  // join the two files.
  it("carries the same acs.session.id and acs.request_id the Guardian's spans carry", async () => {
    await withScratch(async (auditPath, otelPath) => {
      const rpcId = crypto.randomUUID();
      appendFileSync(auditPath, entryLine({ rpc_id: rpcId }));

      await convertAuditLog(auditPath, otelPath);

      const [span] = spansIn(otelPath);
      expect(attribute(span, "acs.session.id")).toBe(toSessionUuid("sess-1"));
      expect(attribute(span, "acs.request_id")).toBe(rpcId);
    });
  });

  it("derives the session UUID exactly as the host adapter does", () => {
    for (const raw of ["sess-1", "ses_opencode_abc", "6B1F2C9E-4D7A-4E3B-8A51-9C0D2E7F1A36", "セッション-é", ""]) {
      expect({ raw, uuid: converterSessionUuid(raw) }).toEqual({ raw, uuid: toSessionUuid(raw) });
    }
  });

  it("counts an entry with no method by its failure kind, apart from unmapped methods", async () => {
    await withScratch(async (auditPath, otelPath) => {
      appendFileSync(auditPath, entryLine({ method: null, rpc_id: null, outcome: "blocked", posture: "deny", failure: { kind: "host_configuration", message: "x" } }));
      appendFileSync(auditPath, entryLine({ method: "protocols/MCP/tools/call" }));

      const summary = await convertAuditLog(auditPath, otelPath);

      expect(summary.skippedNoMethod).toEqual({ host_configuration: 1 });
      expect(summary.skippedUnmapped).toBe(1);
      expect(summary.written).toBe(0);
    });
  });

  // The posture field has been on every posture entry since the first audit
  // format, so a missing one is a hand-edited log. Inferring it from outcome
  // is the bug this PR fixes, so the entry is skipped and counted instead.
  it("skips and counts an entry with no posture rather than guessing one", async () => {
    await withScratch(async (auditPath, otelPath) => {
      appendFileSync(auditPath, entryLine({ posture: undefined }));

      const summary = await convertAuditLog(auditPath, otelPath);

      expect(summary.skippedUnreadable).toBe(1);
      expect(summary.written).toBe(0);
    });
  });

  // #228: no failure event for a replay, because the pair is the earlier request's.
  it("skips and counts a REPLAY_DETECTED error", async () => {
    await withScratch(async (auditPath, otelPath) => {
      appendFileSync(auditPath, entryLine({ outcome: "blocked", failure: { kind: "refused", message: "guardian refused the envelope with error -32005: replay" } }));

      const summary = await convertAuditLog(auditPath, otelPath);

      expect(summary.skippedReplay).toBe(1);
      expect(summary.written).toBe(0);
    });
  });

  it("ignores sampler environment variables", async () => {
    const saved = process.env.OTEL_TRACES_SAMPLER;
    process.env.OTEL_TRACES_SAMPLER = "always_off";
    try {
      await withScratch(async (auditPath, otelPath) => {
        appendFileSync(auditPath, entryLine({}));
        const summary = await convertAuditLog(auditPath, otelPath);
        expect(summary.written).toBe(1);
      });
    } finally {
      if (saved === undefined) delete process.env.OTEL_TRACES_SAMPLER;
      else process.env.OTEL_TRACES_SAMPLER = saved;
    }
  });
});

// Issue #276 item 4 and the issue #274 service name: the converter's output
// must not depend on OTEL_* variables in the shell that runs it, and its
// spans carry their own producer label.
describe("audit-to-otlp: output does not depend on the environment", () => {
  const AUDIT_LINE = `${JSON.stringify({
    seq: 1,
    recorded_at: "2026-10-15T00:00:00.000Z",
    session_id: "sess-1",
    method: "steps/toolCallRequest",
    rpc_id: "3f6c1e2a-8b4d-4c1e-9a7f-2d5b6e8c9a01",
    outcome: "proceeded",
    posture: "proceed",
    posture_source: "negotiated",
    failure: { kind: "transport", message: "connect ECONNREFUSED 127.0.0.1:1" },
  })}\n`;
  const HOSTILE: Record<string, string> = {
    OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT: "8",
    OTEL_SPAN_EVENT_COUNT_LIMIT: "0",
    OTEL_SPAN_ATTRIBUTE_PER_EVENT_COUNT_LIMIT: "1",
    OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT: "1",
    OTEL_TRACES_SAMPLER: "always_off",
    OTEL_SERVICE_NAME: "zzz",
    OTEL_RESOURCE_ATTRIBUTES: "service.name=evil",
  };
  const saved: Record<string, string | undefined> = {};
  afterEach(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("keeps full ids, the whole failure event, and the converter's own label", async () => {
    for (const [key, value] of Object.entries(HOSTILE)) {
      saved[key] = process.env[key];
      process.env[key] = value;
    }
    await withScratch(async (auditPath, otelPath) => {
      appendFileSync(auditPath, AUDIT_LINE);
      const summary = await convertAuditLog(auditPath, otelPath);
      expect(summary.written).toBe(1);
      const request = JSON.parse(readFileSync(otelPath, "utf8").split("\n")[0]!);
      const resourceSpans = request.resourceSpans[0];
      expect(resourceSpans.resource.attributes).toEqual([{ key: "service.name", value: { stringValue: CONVERTER_SERVICE_NAME } }]);
      expect(resourceSpans.scopeSpans[0].scope.name).toBe(CONVERTER_SERVICE_NAME);
      const span = resourceSpans.scopeSpans[0].spans[0];
      expect(attribute(span, "acs.request_id")).toBe("3f6c1e2a-8b4d-4c1e-9a7f-2d5b6e8c9a01");
      expect(attribute(span, "acs.session.id")).toBe(converterSessionUuid("sess-1"));
      expect(span.droppedAttributesCount ?? 0).toBe(0);
      const event = span.events.find((e: OtlpEvent) => e.name === "acs.decision.failure");
      expect(event).toBeDefined();
      expect(event.droppedAttributesCount ?? 0).toBe(0);
      expect(attribute(event, "acs.failure.class")).toBe("unreachable");
      expect(attribute(event, "acs.failure.posture")).toBe("fail_open");
      expect(attribute(event, "acs.failure.reported_by")).toBe("observed_agent");
      expect(attribute(event, "acs.failure.detail")).toBe(FAILURE_DETAIL_BY_KIND.transport);
    });
  }, 10_000);

  it("labels its spans apart from the Guardian's", () => {
    expect(CONVERTER_SERVICE_NAME).toBe("acs-reference-audit-converter");
    expect(CONVERTER_SERVICE_NAME).not.toBe(OTEL_SERVICE_NAME);
  });

  it("shares one frozen set of span limits with the Guardian", () => {
    expect(Object.isFrozen(SPAN_LIMITS)).toBe(true);
    expect(SPAN_LIMITS).toEqual({
      attributeValueLengthLimit: 4096,
      attributeCountLimit: 128,
      eventCountLimit: 128,
      attributePerEventCountLimit: 128,
      linkCountLimit: 128,
      attributePerLinkCountLimit: 128,
    });
  });
});

// Converting onto an existing file appended OTLP lines to it: onto the audit
// log itself (or a hardlink of it) that corrupts the evidence and shifts the
// next audit seq; twice over the same output it doubles every span; onto the
// Guardian's trace file it merges the two streams. One rule covers all four.
describe("audit-to-otlp: refuses an output that already exists", () => {
  const LINE = `${JSON.stringify({
    seq: 1,
    recorded_at: "2026-10-15T00:00:00.000Z",
    session_id: "sess-1",
    method: "steps/toolCallRequest",
    rpc_id: "3f6c1e2a-8b4d-4c1e-9a7f-2d5b6e8c9a01",
    outcome: "proceeded",
    posture: "proceed",
    posture_source: "negotiated",
    failure: { kind: "transport", message: "connect ECONNREFUSED 127.0.0.1:1" },
  })}\n`;

  /** A fresh directory with the audit log in it, removed whatever the test does. */
  async function inScratch(run: (dir: string, audit: string) => Promise<void>): Promise<void> {
    const dir = mkdtempSync(join(tmpdir(), "acs-audit-exclusive-"));
    const audit = join(dir, "audit.jsonl");
    writeFileSync(audit, LINE);
    try {
      await run(dir, audit);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("refuses to convert a log onto itself and leaves it byte-identical", () =>
    inScratch(async (_dir, audit) => {
      await expect(convertAuditLog(audit, audit)).rejects.toThrow(/^refusing to write/);
      expect(readFileSync(audit, "utf8")).toBe(LINE);
    }));

  it("refuses a hardlink to the log", () =>
    inScratch(async (dir, audit) => {
      const link = join(dir, "otel.jsonl");
      linkSync(audit, link);
      await expect(convertAuditLog(audit, link)).rejects.toThrow(/^refusing to write/);
      expect(readFileSync(audit, "utf8")).toBe(LINE);
    }));

  it("refuses an existing unrelated output, such as the Guardian's trace file", () =>
    inScratch(async (dir, audit) => {
      const guardianTrace = join(dir, "otel-traces.jsonl");
      writeFileSync(guardianTrace, "guardian line\n");
      await expect(convertAuditLog(audit, guardianTrace)).rejects.toThrow(/^refusing to write/);
      expect(readFileSync(guardianTrace, "utf8")).toBe("guardian line\n");
    }));

  it("refuses a dangling symlink and creates nothing at its target", () =>
    inScratch(async (dir, audit) => {
      const target = join(dir, "elsewhere.jsonl");
      const link = join(dir, "otel.jsonl");
      symlinkSync(target, link);
      await expect(convertAuditLog(audit, link)).rejects.toThrow(/^refusing to write/);
      expect(existsSync(target)).toBe(false);
    }));

  it("leaves no output behind when the audit log cannot be read, so the corrected rerun is not refused", () =>
    inScratch(async (dir) => {
      const out = join(dir, "otel.jsonl");
      await expect(convertAuditLog(join(dir, "missing.jsonl"), out)).rejects.toThrow();
      expect(existsSync(out)).toBe(false);
    }));

  it("writes a new output owner-only, creating its directory owner-only", () =>
    inScratch(async (dir, audit) => {
      const out = join(dir, "new-dir", "otel.jsonl");
      const summary = await convertAuditLog(audit, out);
      expect(summary.written).toBe(1);
      expect(statSync(out).mode & 0o777).toBe(0o600);
      expect(statSync(join(dir, "new-dir")).mode & 0o777).toBe(0o700);
    }));
});
