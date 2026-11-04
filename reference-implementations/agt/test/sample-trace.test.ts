import { describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONVERTER_SERVICE_NAME } from "../packages/guardian/src/audit-to-otlp.ts";
import { OTEL_SERVICE_NAME } from "../packages/guardian/src/otel-trace-exporter.ts";
import { generateSampleTrace, REJECTED, SAMPLE_PATH, SCENARIOS } from "../scripts/make-sample-trace.ts";

/**
 * The committed sample trace (issue #266), held to the mapping it claims to
 * follow, and to the exporter that wrote it. If the exporter stops emitting
 * an attribute the mapping requires or makes conditional, every unit test can
 * still pass; a test over real output cannot.
 */

const MAPPING_PATH = new URL("../../../specification/v0.1.0/trace/otel-mapping.json", import.meta.url);

type OtlpValue = { stringValue?: string; intValue?: string | number; arrayValue?: { values?: OtlpValue[] } };
type OtlpAttribute = { key: string; value: OtlpValue };
type OtlpEvent = { name: string; timeUnixNano?: string; attributes?: OtlpAttribute[] };
type OtlpSpan = {
  name: string;
  traceId?: string;
  spanId?: string;
  startTimeUnixNano?: string;
  endTimeUnixNano?: string;
  attributes?: OtlpAttribute[];
  events?: OtlpEvent[];
  status?: { code?: number; message?: string };
};
type OtlpRequest = {
  resourceSpans: {
    resource?: { attributes?: OtlpAttribute[] };
    scopeSpans: { scope?: { name?: string }; spans: OtlpSpan[] }[];
  }[];
};
type LabeledSpan = OtlpSpan & { service?: string; scope?: string };

function spansIn(path: string | URL): LabeledSpan[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .flatMap((line) =>
      (JSON.parse(line) as OtlpRequest).resourceSpans.flatMap((rs) =>
        rs.scopeSpans.flatMap((ss) =>
          ss.spans.map((span) => ({
            ...span,
            service: rs.resource?.attributes?.find((a) => a.key === "service.name")?.value.stringValue,
            scope: ss.scope?.name,
          })),
        ),
      ),
    );
}

function plain(value: OtlpValue): unknown {
  if (value.arrayValue !== undefined) return (value.arrayValue.values ?? []).map(plain);
  if (value.intValue !== undefined) return Number(value.intValue);
  return value.stringValue;
}

function attributes(carrier: { attributes?: OtlpAttribute[] } | undefined): Record<string, unknown> {
  return Object.fromEntries((carrier?.attributes ?? []).map((a) => [a.key, plain(a.value)]));
}

/** What a span says once the values that differ between runs are taken out:
 * ids, timestamps, elapsed time, and which export batch it landed in. */
function normalize(spans: LabeledSpan[]): unknown[] {
  return spans
    .map((span) => ({
      service: span.service,
      scope: span.scope,
      name: span.name,
      attributes: attributes(span),
      status: span.status ?? {},
      events: (span.events ?? []).map((event) => {
        const { "acs.failure.elapsed_ms": _elapsed, ...rest } = attributes(event);
        return { name: event.name, attributes: rest };
      }),
    }))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

type MappingSchema = {
  properties: {
    step_to_span: { default: Record<string, { span_name: string; required_attributes: string[] }> };
    step_span_attributes: { properties: { required_attributes: { default: string[] } } };
    decision_failure_event: { properties: { attribute_values: { default: Record<string, string[]> } } };
  };
};
const MAPPING = JSON.parse(readFileSync(MAPPING_PATH, "utf8")) as MappingSchema;
const STEP_BY_SPAN_NAME = Object.fromEntries(
  Object.entries(MAPPING.properties.step_to_span.default).map(([method, entry]) => [entry.span_name, entry]),
);

/** Required attributes a span reported by the host audit converter cannot
 * carry, and why. Anything not named here is required of every span. */
const CONVERTER_EXEMPT: Readonly<Record<string, string>> = {
  "gen_ai.tool.name": "the host audit log records no tool name (issue #274)",
};

const SPANS = spansIn(SAMPLE_PATH);
/** The spans for steps the Guardian governed. A rejected request is recorded
 * under a name outside step_to_span (issue #283), so the mapping's step
 * rules do not apply to it; its own test is below. */
const STEP_SPANS = SPANS.filter((span) => span.name !== "guardian.rejected_request");

function spanFor(requestId: string): OtlpSpan | undefined {
  return SPANS.find((span) => attributes(span)["acs.request_id"] === requestId);
}

function failureOf(span: OtlpSpan | undefined): Record<string, unknown> | undefined {
  const event = span?.events?.find((e) => e.name === "acs.decision.failure");
  return event === undefined ? undefined : attributes(event);
}

describe("the committed sample trace matches the mapping", () => {
  it("names every step span with a step_to_span value", () => {
    expect(STEP_SPANS.length).toBeGreaterThan(0);
    for (const span of STEP_SPANS) {
      expect({ name: span.name, mapped: span.name in STEP_BY_SPAN_NAME }).toEqual({ name: span.name, mapped: true });
    }
  });

  it("labels converter spans as the converter and every other span as the Guardian", () => {
    for (const span of SPANS) {
      const fromConverter = failureOf(span)?.["acs.failure.reported_by"] === "observed_agent";
      const expected = fromConverter ? CONVERTER_SERVICE_NAME : OTEL_SERVICE_NAME;
      expect({ span: span.name, service: span.service, scope: span.scope }).toEqual({ span: span.name, service: expected, scope: expected });
    }
  });

  it("carries every required attribute, apart from the named converter exemptions", () => {
    const always = MAPPING.properties.step_span_attributes.properties.required_attributes.default;
    for (const span of STEP_SPANS) {
      const present = attributes(span);
      const fromConverter = failureOf(span)?.["acs.failure.reported_by"] === "observed_agent";
      for (const attribute of [...always, ...STEP_BY_SPAN_NAME[span.name]!.required_attributes]) {
        if (fromConverter && attribute in CONVERTER_EXEMPT) continue;
        expect({ span: span.name, attribute, present: attribute in present }).toEqual({ span: span.name, attribute, present: true });
      }
    }
  });

  it("carries a conditional attribute exactly when the request carried its source", () => {
    for (const scenario of SCENARIOS) {
      const present = attributes(spanFor(scenario.requestId));
      expect({ scenario: scenario.name, capability: "acs.capability" in present }).toEqual({
        scenario: scenario.name,
        capability: scenario.capability !== undefined,
      });
      expect({ scenario: scenario.name, ref: "acs.request_id_ref" in present }).toEqual({
        scenario: scenario.name,
        ref: scenario.requestIdRef !== undefined,
      });
    }
  });

  // A sample whose decisions are all policy failures would pass every check
  // above and still show a reader nothing true, so each one is pinned.
  it("records the decision each scenario was built to produce, and none from a policy failure", () => {
    for (const scenario of SCENARIOS) {
      const decision = attributes(spanFor(scenario.requestId)?.events?.find((e) => e.name === "acs.decision"));
      expect({ scenario: scenario.name, decision: decision["acs.decision"] }).toEqual({ scenario: scenario.name, decision: scenario.decision });
      expect(String(decision["acs.reason_codes"] ?? "")).not.toContain("runtime_error");
    }
  });

  it("links the result to its request through acs.request_id_ref", () => {
    const result = SCENARIOS.find((scenario) => scenario.requestIdRef !== undefined)!;
    expect(attributes(spanFor(result.requestId))["acs.request_id_ref"]).toBe(result.requestIdRef);
    expect(spanFor(result.requestIdRef!)).toBeDefined();
  });

  // This Guardian always names a rule and never sends policy_version, so the
  // padding it exercises is the version column: one "" per reference.
  it("pads the policy and provenance columns to a common length", () => {
    const denied = attributes(spanFor(SCENARIOS.find((s) => s.name === "denied")!.requestId));
    const decision = attributes(spanFor(SCENARIOS.find((s) => s.name === "denied")!.requestId)?.events?.find((e) => e.name === "acs.decision"));
    const ids = decision["acs.policy.ids"] as string[];
    expect(ids.length).toBeGreaterThan(0);
    expect((decision["acs.policy.versions"] as string[]).length).toBe(ids.length);
    expect((decision["acs.policy.rule_ids"] as string[]).length).toBe(ids.length);
    expect(decision["acs.policy.versions"]).toEqual(ids.map(() => ""));
    expect((denied["acs.provenance.source_id"] as string[]).length).toBe((denied["acs.provenance.origin"] as string[]).length);
    expect(denied["acs.provenance.source_id"]).toContain("");
  });

  it("uses only failure classes, postures and reporters the mapping lists, and covers the failures it holds", () => {
    const allowed = MAPPING.properties.decision_failure_event.properties.attribute_values.default;
    const seen = new Set<string>();
    for (const span of SPANS) {
      const failure = failureOf(span);
      if (failure === undefined) continue;
      for (const key of ["acs.failure.class", "acs.failure.posture", "acs.failure.reported_by"]) {
        expect({ key, value: failure[key], listed: allowed[key]!.includes(String(failure[key])) }).toEqual({
          key,
          value: failure[key],
          listed: true,
        });
      }
      seen.add(`${failure["acs.failure.class"]}/${failure["acs.failure.reported_by"]}`);
    }
    // The sample holds no step the Guardian answered with an error.
    expect([...seen].sort()).toEqual(["timeout/guardian", "unreachable/observed_agent"]);
  });

  it("holds one span per step, and keeps the forged request apart from the call whose ids it claimed", () => {
    for (const scenario of SCENARIOS) {
      const underPair = SPANS.filter((span) => attributes(span)["acs.request_id"] === scenario.requestId);
      expect({ scenario: scenario.name, spans: underPair.length }).toEqual({ scenario: scenario.name, spans: 1 });
    }
    const rejected = SPANS.filter((span) => span.name === "guardian.rejected_request");
    expect(rejected).toHaveLength(1);
    const claimed = attributes(rejected[0]);
    expect(claimed["guardian.rejected.claimed_request_id"]).toBe(REJECTED.claimedRequestId);
    expect(claimed["guardian.rejected.reason"]).toBe(REJECTED.reason);
    expect(claimed["acs.request_id"]).toBeUndefined();
    expect(rejected[0]?.events ?? []).toEqual([]);
  });
});

describe("the committed sample trace is current", () => {
  it("is what the generator writes today, once ids and timestamps are set aside", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-sample-trace-"));
    try {
      const fresh = join(dir, "sample.jsonl");
      await generateSampleTrace(fresh);
      expect(normalize(spansIn(fresh))).toEqual(normalize(SPANS));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);
});
