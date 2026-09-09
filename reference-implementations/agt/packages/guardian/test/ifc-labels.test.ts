import { describe, expect, it } from "bun:test";
import { createMemorySessionContextStore } from "../src/session-context-store.ts";
import { persistIfcLabels, supplySourceLabels } from "../src/ifc-labels.ts";

describe("persistIfcLabels / supplySourceLabels — the round trip AGT delegates", () => {
  // A fresh session reports the lattice floor, not `[]` -- `emptySessionState`
  // seeds `ifc_labels: ["public"]` (packages/guardian/src/session-context.ts),
  // because AGT's own IFC gate denies a zero-label flow outright.
  it("supplies the seeded floor for a session that has none", () => {
    const store = createMemorySessionContextStore();
    expect(supplySourceLabels(store, "sess-a")).toEqual(["public"]);
  });

  it("gives back at the next step what AGT emitted at this one", () => {
    const store = createMemorySessionContextStore();
    persistIfcLabels(store, "sess-a", ["confidential"]);
    expect(supplySourceLabels(store, "sess-a")).toEqual(["confidential"]);
  });

  it("replaces rather than accumulates, because AGT's labels are the propagated set", () => {
    const store = createMemorySessionContextStore();
    persistIfcLabels(store, "sess-a", ["internal"]);
    persistIfcLabels(store, "sess-a", ["secret"]);
    expect(supplySourceLabels(store, "sess-a")).toEqual(["secret"]);
  });

  it("leaves what it has alone when a verdict carries no labels at all", () => {
    const store = createMemorySessionContextStore();
    persistIfcLabels(store, "sess-a", ["secret"]);
    persistIfcLabels(store, "sess-a", undefined);
    expect(supplySourceLabels(store, "sess-a")).toEqual(["secret"]);
  });

  it("clears them when a verdict carries an explicitly empty set", () => {
    const store = createMemorySessionContextStore();
    persistIfcLabels(store, "sess-a", ["secret"]);
    persistIfcLabels(store, "sess-a", []);
    expect(supplySourceLabels(store, "sess-a")).toEqual([]);
  });

  it("keeps two sessions' labels apart", () => {
    const store = createMemorySessionContextStore();
    persistIfcLabels(store, "sess-a", ["secret"]);
    // The lattice floor, not `[]` -- sess-b has no history of its own, so
    // it reads back the seed.
    expect(supplySourceLabels(store, "sess-b")).toEqual(["public"]);
  });

  // The return type is `IfcLabels`, which is `readonly`, so the honest version
  // of this line -- `supplySourceLabels(...).push("public")` -- no longer
  // compiles. That is the first guard and the better one. The cast is how this
  // test still measures the second: a runtime copy, which is what holds when a
  // caller casts the readonly away or calls from JavaScript.
  it("hands back a copy, so a caller who casts the readonly away still cannot edit the store", () => {
    const store = createMemorySessionContextStore();
    persistIfcLabels(store, "sess-a", ["secret"]);
    (supplySourceLabels(store, "sess-a") as string[]).push("public");
    expect(supplySourceLabels(store, "sess-a")).toEqual(["secret"]);
  });

  it("takes a copy on write too, so mutating the caller's array afterward leaves the store alone", () => {
    const store = createMemorySessionContextStore();
    const labels = ["secret"];
    persistIfcLabels(store, "sess-a", labels);
    labels.push("public");
    expect(supplySourceLabels(store, "sess-a")).toEqual(["secret"]);
  });
});
