import { describe, expect, it } from "bun:test";
import { diffSurfaces } from "../src/diff-surfaces.ts";
import { asPinned, asUpstream, SURFACE_NAMES, type SurfaceSnapshot } from "../src/surfaces.ts";

const base = (): SurfaceSnapshot =>
  Object.fromEntries(SURFACE_NAMES.map((n) => [n, n === "verdict enum" ? ["allow", "deny"] : { unchanged: true }])) as SurfaceSnapshot;

const withSurface = (name: string, value: unknown): SurfaceSnapshot => ({ ...base(), [name]: value }) as SurfaceSnapshot;

describe("diffSurfaces -- one row per field that moved", () => {
  it("reports nothing when both sides are the same", () => {
    expect(diffSurfaces(asPinned(base()), asUpstream(base()))).toEqual([]);
  });

  it("names the surface, the field, and what it was against what it is", () => {
    const diffs = diffSurfaces(asPinned(base()), asUpstream(withSurface("verdict enum", ["allow", "deny", "quarantine"])));

    expect(diffs).toEqual([
      { surface: "verdict enum", field: "/2", pinned: undefined, upstream: "quarantine" },
    ]);
  });

  it("reports a removed enum value as upstream undefined", () => {
    const diffs = diffSurfaces(asPinned(base()), asUpstream(withSurface("verdict enum", ["allow"])));

    expect(diffs).toEqual([{ surface: "verdict enum", field: "/1", pinned: "deny", upstream: undefined }]);
  });

  it("reports a changed nested field by its JSON pointer", () => {
    const diffs = diffSurfaces(
      asPinned(asPinned(withSurface("snapshot.schema.json", { properties: { tool_call: { type: "object" } } }))),
      asUpstream(withSurface("snapshot.schema.json", { properties: { tool_call: { type: "string" } } })),
    );

    expect(diffs).toEqual([
      { surface: "snapshot.schema.json", field: "/properties/tool_call/type", pinned: "object", upstream: "string" },
    ]);
  });

  it("reports an added optional field rather than failing on it", () => {
    const diffs = diffSurfaces(
      asPinned(withSurface("manifest.schema.json", { properties: {} })),
      asUpstream(withSurface("manifest.schema.json", { properties: { retries: { type: "number" } } })),
    );

    expect(diffs).toEqual([
      { surface: "manifest.schema.json", field: "/properties/retries", pinned: undefined, upstream: { type: "number" } },
    ]);
  });

  it("walks every surface, not only the first that moved", () => {
    const upstream = { ...base(), "verdict enum": ["allow"], "reserved-reasons.json": { changed: true } } as SurfaceSnapshot;
    const surfaces = diffSurfaces(asPinned(base()), asUpstream(upstream)).map((d) => d.surface);

    expect(new Set(surfaces)).toEqual(new Set(["verdict enum", "reserved-reasons.json"]));
  });
});
