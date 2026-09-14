import { describe, expect, it } from "bun:test";
import { loadMapping } from "guardian";
import { renderTraceRows } from "../src/render.ts";
import { checkTracePillar, METHODS_IN_SCOPE, type TraceRow } from "../src/trace-pillar.ts";

const rows = checkTracePillar();

/** The one row named `attribute` -- most attributes in scope appear on
 * exactly one span, so a bare filter-and-assert-length-one is the natural
 * lookup. `gen_ai.tool.name` and `acs.session.id` are the two exceptions
 * (each required on more than one span) and are asserted separately below,
 * by their full row set rather than through this helper. */
function only(attribute: string): TraceRow {
  const matches = rows.filter((r) => r.attribute === attribute);
  expect(matches).toHaveLength(1);
  return matches[0]!;
}

describe("checkTracePillar resolves every row against the v0.1.0 schema files at runtime", () => {
  it("gen_ai.tool.name is emittable on both spans that require it -- `tool.name` is required in both hook payloads that carry it", () => {
    const toolName = rows.filter((r) => r.attribute === "gen_ai.tool.name");
    // steps/toolCallRequest's gen_ai.tool.call and steps/toolCallResult's gen_ai.tool.result.
    expect(toolName.map((r) => r.span).sort()).toEqual(["gen_ai.tool.call", "gen_ai.tool.result"]);
    for (const row of toolName) {
      expect(row.emittableByWireConsumer).toBe(true);
      expect(row.wireSource).not.toBeNull();
      expect(row.reason).toBeUndefined();
    }
  });

  it("acs.capability is NOT emittable -- present but optional, and the reason names the optionality rather than claiming absence", () => {
    const row = only("acs.capability");
    expect(row.span).toBe("gen_ai.tool.call");
    expect(row.emittableByWireConsumer).toBe(false);
    // The field EXISTS on the wire (hooks/tool-call-request.json declares
    // "capability") -- this is the "present but optional" case, not the "no
    // such property" case, and wireSource must say so by being non-null.
    expect(row.wireSource).not.toBeNull();
    expect(row.wireSource).toContain("tool-call-request.json");
    expect(row.reason).toMatch(/optional/i);
    expect(row.reason).not.toMatch(/no wire source/i);
  });

  it("acs.decision is emittable -- AcsResult.decision is unconditionally required", () => {
    const row = only("acs.decision");
    expect(row.span).toBe("acs.decision");
    expect(row.emittableByWireConsumer).toBe(true);
    expect(row.wireSource).toContain("response-envelope.json");
    expect(row.reason).toBeUndefined();
  });

  it("acs.evaluator is NOT emittable -- present at AcsResult.metadata.evaluator, but optional there, not absent", () => {
    // AcsResult.properties.metadata.properties DOES declare `evaluator`
    // (response-envelope.json, verified by reading it) -- this is the
    // "present but optional" case, the same as acs.capability above, not
    // "no such property at all". `metadata` itself is absent from
    // `AcsResult.required`, and `metadata`'s own schema declares no
    // `required` list either, which is what makes the row red: a
    // conformant envelope may omit `metadata` entirely, or include it
    // without `evaluator`.
    const row = only("acs.evaluator");
    expect(row.span).toBe("acs.decision");
    expect(row.emittableByWireConsumer).toBe(false);
    expect(row.wireSource).not.toBeNull();
    expect(row.wireSource).toContain("AcsResult.metadata.evaluator");
    expect(row.reason).toMatch(/optional/i);
    expect(row.reason).not.toMatch(/no wire source/i);
  });

  it("all four conditional decision attributes are present-but-optional -- none is absent from AcsResult", () => {
    // acs.reasoning is a direct AcsResult sibling of acs.decision;
    // acs.confidence, acs.evaluator_version and acs.model_id sit one level
    // deeper, at AcsResult.metadata.<name>, exactly like acs.evaluator
    // above -- all four verified present in response-envelope.json, all
    // four optional (metadata is optional on AcsResult, and unconditionally
    // required by neither AcsResult's own `required` nor metadata's).
    for (const attribute of ["acs.reasoning", "acs.confidence", "acs.evaluator_version", "acs.model_id"]) {
      const row = only(attribute);
      expect(row.emittableByWireConsumer).toBe(false);
      expect(row.wireSource).not.toBeNull();
      expect(row.reason).toMatch(/optional/i);
      expect(row.reason).not.toMatch(/no wire source/i);
    }

    expect(only("acs.reasoning").wireSource).toContain("AcsResult.reasoning");
    expect(only("acs.confidence").wireSource).toContain("AcsResult.metadata.confidence");
    expect(only("acs.evaluator_version").wireSource).toContain("AcsResult.metadata.evaluator_version");
    expect(only("acs.model_id").wireSource).toContain("AcsResult.metadata.model_id");
  });

  it("acs.provenance.origin is emittable -- provenance.json's own `required` list includes `origin`", () => {
    const row = only("acs.provenance.origin");
    expect(row.emittableByWireConsumer).toBe(true);
    expect(row.wireSource).toContain("provenance.json");
  });

  it("emittableByWireConsumer is false wherever wireSource is null -- an invariant of buildRow, currently unexercised by real data", () => {
    // Every one of these 17 rows resolves against a declared
    // response-envelope.json or provenance.json property -- v0.1.0 declares
    // every field otel-mapping.json names in scope here, it just does not
    // make most of the decision-event ones required. So `wireSource === null`
    // currently holds for zero of the 17 rows -- asserted explicitly (not
    // merely assumed) so this test cannot pass by accident, and the
    // invariant stays checked because buildRow's "no such property" branch
    // is still real, reachable code (the renderer has its own synthetic-row
    // test for exactly that branch, below).
    const noWireSource = rows.filter((r) => r.wireSource === null);
    expect(noWireSource).toHaveLength(0);
    for (const row of noWireSource) {
      expect(row.emittableByWireConsumer).toBe(false);
    }
  });

  it("every not-emittable row carries a reason, and every emittable row carries none", () => {
    for (const row of rows) {
      expect(row.reason !== undefined).toBe(!row.emittableByWireConsumer);
    }
  });

  it("covers exactly the right SET of spans with the right count each -- not just the right total, which a dropped span and a duplicated one could both still satisfy", () => {
    const spanCounts: Record<string, number> = {};
    for (const row of rows) {
      spanCounts[row.span] = (spanCounts[row.span] ?? 0) + 1;
    }
    expect(spanCounts).toEqual({
      "gen_ai.tool.call": 2, // steps/toolCallRequest: gen_ai.tool.name, acs.capability
      "gen_ai.tool.result": 2, // steps/toolCallResult: gen_ai.tool.name, acs.exit_status
      "acs.session": 1, // steps/sessionStart: acs.session.id
      "acs.session.end": 1, // steps/sessionEnd: acs.session.reason
      "acs.message.user": 2, // steps/userMessage: acs.session.id, acs.content.types
      "acs.message.agent": 2, // steps/agentResponse: acs.session.id, acs.agent.id
      "acs.decision": 6, // decision_event: 2 required + 4 conditional
      "(every step span, when Provenance is attached)": 1, // provenance_attributes.required
    });
    expect(rows).toHaveLength(17);
  });

  it("every row names a real span, never blank", () => {
    for (const row of rows) {
      expect(row.span.length).toBeGreaterThan(0);
    }
  });

  it("the frozen METHODS_IN_SCOPE list is exactly mapping.yaml's non-null acs_method values -- self-checking rather than true-for-now", () => {
    const mapping = loadMapping("mapping.yaml");
    const declaredMethods = Object.values(mapping.intervention_points)
      .map((row) => row.acs_method)
      .filter((method): method is string => method !== null)
      .sort();
    const scopedMethods: string[] = [...METHODS_IN_SCOPE].sort();
    expect(scopedMethods).toEqual(declaredMethods);
  });
});

describe("renderTraceRows", () => {
  it("is a pure function of the rows it is handed -- rendering twice produces the same string", () => {
    expect(renderTraceRows(rows)).toBe(renderTraceRows(rows));
  });

  it("names every row's attribute in the rendered table", () => {
    const table = renderTraceRows(rows);
    for (const row of rows) {
      expect(table).toContain(row.attribute);
    }
  });

  it("renders '(no wire source)' for a synthetic row whose wireSource is genuinely null", () => {
    // None of today's real 17 rows has a null wireSource (see the check
    // suite's own test above), so this exercises render.ts's fallback
    // branch directly rather than leaving it untested by accident of
    // today's schema facts.
    const synthetic: TraceRow = {
      attribute: "acs.made_up",
      span: "acs.decision",
      wireSource: null,
      emittableByWireConsumer: false,
      reason: "no wire source for acs.made_up",
    };
    expect(renderTraceRows([synthetic])).toContain("(no wire source)");
  });

  it("renders the reason inline for a not-emittable row, not as a separate footnote system", () => {
    const table = renderTraceRows(rows);
    const capabilityReason = only("acs.capability").reason!;
    expect(table).toContain(capabilityReason);
  });

  it("RenderOptions.color is opt-in, and stripping the ANSI codes back out recovers exactly the plain render", () => {
    // A fixture, not `rows`: none of today's real 17 has wireSource ===
    // null (the check suite's own test above), which is the only case this
    // renderer colours -- against the real data, `color: true` currently
    // produces byte-identical output to the plain render, and this test
    // would pass without exercising the colour path at all.
    const fixture: TraceRow[] = [
      { attribute: "gen_ai.tool.name", span: "gen_ai.tool.call", wireSource: "hooks/tool-call-request.json#tool.name", emittableByWireConsumer: true },
      { attribute: "acs.made_up", span: "acs.decision", wireSource: null, emittableByWireConsumer: false, reason: "no wire source for acs.made_up" },
    ];

    const plain = renderTraceRows(fixture);
    const colored = renderTraceRows(fixture, { color: true });
    expect(colored).not.toBe(plain);
    expect(colored).toContain("[33m"); // YELLOW -- the null-wireSource row's colour
    expect(colored).toContain("[0m"); // RESET

    const stripped = colored.replace(/\x1b\[\d+m/g, "");
    expect(stripped).toBe(plain);
  });

  it("is still a pure function of the rows it is handed when colour is on -- rendering the real 17 rows twice with color:true produces the same string", () => {
    // Separate from the fixture test above: even though `color: true`
    // happens to be a no-op against today's real data (nothing here is
    // painted), purity still holds and is worth asserting against the
    // actual `rows`, not only the synthetic fixture.
    expect(renderTraceRows(rows, { color: true })).toBe(renderTraceRows(rows, { color: true }));
  });
});
