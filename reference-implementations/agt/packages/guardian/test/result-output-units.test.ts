import { describe, expect, it } from "bun:test";
import { assemblePostToolCallUnits, type ToolCallResultEnvelope } from "../src/assemble-snapshot.ts";

describe("assemblePostToolCallUnits", () => {
  const envelopeOf = (outputs: unknown[]) =>
    ({
      params: { payload: { tool: { name: "Bash" }, outputs: outputs.map((value) => ({ value })) } },
    }) as unknown as ToolCallResultEnvelope;

  it("cuts one single-output snapshot per string leaf", () => {
    const units = assemblePostToolCallUnits(envelopeOf(["a", { b: ["c"], d: 1 }]), ["secret"]);
    expect(units.map((unit) => unit.pointer)).toEqual(["/outputs/0/value", "/outputs/1/value/b/0"]);
    expect(units.map((unit) => unit.snapshot.tool_result.outputs)).toEqual([[{ value: "a" }], [{ value: "c" }]]);
    expect(units[0]!.snapshot.input.ifc.source_labels).toEqual(["secret"]);
  });

  it("refuses a result with too many strings rather than judging part of it", () => {
    const outputs = Array.from({ length: 257 }, (_, index) => `line ${index}`);
    expect(() => assemblePostToolCallUnits(envelopeOf(outputs), [])).toThrow(/more than 256 strings/);
  });

  it("refuses an output nested too deeply to judge", () => {
    let nested: unknown = "deep";
    for (let level = 0; level < 40; level++) nested = [nested];
    expect(() => assemblePostToolCallUnits(envelopeOf([nested]), [])).toThrow(/nested deeper than/);
  });
});
