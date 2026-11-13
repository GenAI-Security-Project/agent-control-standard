import { describe, expect, it } from "bun:test";
import { renderUpstreamDiff } from "../src/render-upstream-diff.ts";
import type { SurfaceDiff } from "../src/diff-surfaces.ts";

const diff = (over: Partial<SurfaceDiff> = {}): SurfaceDiff => ({
  surface: "verdict enum",
  field: "/2",
  pinned: undefined,
  upstream: "quarantine",
  ...over,
});

describe("renderUpstreamDiff -- what moved, in AGT's own terms", () => {
  it("says the contract has not moved when nothing did", () => {
    const out = renderUpstreamDiff([]);

    expect(out).toContain("no watched surface moved");
    expect(out).not.toContain("|");
  });

  it("names the surface, the field, and both sides", () => {
    const out = renderUpstreamDiff([diff()]);

    expect(out).toContain("verdict enum");
    expect(out).toContain("/2");
    expect(out).toContain("quarantine");
  });

  it("renders an absent side as absent rather than as empty", () => {
    expect(renderUpstreamDiff([diff()])).toContain("(absent)");
  });

  it("groups rows under the surface they belong to, each surface once", () => {
    const out = renderUpstreamDiff([diff(), diff({ field: "/3", upstream: "escalate_hard" })]);

    expect(out.match(/verdict enum/g)).toHaveLength(1);
  });

  it("counts what it found, so a reader can tell one moved field from twenty", () => {
    expect(renderUpstreamDiff([diff(), diff({ field: "/3" })])).toContain("2 fields moved");
  });

  it("is a surface diff and never a coverage cell -- it names no intervention point and no verdict column", () => {
    const out = renderUpstreamDiff([diff()]);

    expect(out).not.toContain("pre_tool_call");
    expect(out).not.toContain("expressed");
  });
});
