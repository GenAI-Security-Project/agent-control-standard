import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readdirSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  appliedRequestPath,
  createFileAppliedRequestStore,
  createMemoryAppliedRequestStore,
  InvalidRequestIdError,
} from "../src/applied-request-store.ts";

// Two derived ids and the random ids a retry replaced them with. Real UUIDs,
// because the store keys a filename on the derived one.
const DERIVED = "0b0f8f2e-6f4a-8d3a-9c21-7f1e2a3b4c5d";
const OTHER_DERIVED = "1c1e9a3f-7a5b-8e4b-8d32-8a2f3b4c5d6e";
const RETRY = "9d2a4c1e-3b7f-4e8a-a1c2-5f6e7d8c9b0a";

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-applied-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  // Named removal only, the posture of session-config.test.ts next door: a
  // stray file (a temp file a crashed `set` left behind) fails loudly here
  // rather than being swept away.
  while (dirs.length > 0) {
    const dir = dirs.pop() as string;
    for (const entry of readdirSync(dir)) {
      unlinkSync(join(dir, entry));
    }
    rmdirSync(dir);
  }
});

describe("createMemoryAppliedRequestStore", () => {
  it("holds nothing for a call that was asked about once", () => {
    expect(createMemoryAppliedRequestStore().get(DERIVED)).toBeUndefined();
  });

  it("returns the request the host acted on, per call", () => {
    const store = createMemoryAppliedRequestStore();
    store.set(DERIVED, RETRY);
    expect(store.get(DERIVED)).toBe(RETRY);
    expect(store.get(OTHER_DERIVED)).toBeUndefined();
  });
});

describe("createFileAppliedRequestStore — the record across processes", () => {
  it("survives the process that wrote it: a second store reads the first's record", () => {
    const dir = scratch();
    createFileAppliedRequestStore({ dir }).set(DERIVED, RETRY);

    // A *different* store instance, standing in for the result gate's process.
    expect(createFileAppliedRequestStore({ dir }).get(DERIVED)).toBe(RETRY);
  });

  it("keeps calls apart", () => {
    const dir = scratch();
    createFileAppliedRequestStore({ dir }).set(DERIVED, RETRY);
    expect(createFileAppliedRequestStore({ dir }).get(OTHER_DERIVED)).toBeUndefined();
  });

  it("returns undefined before any retry, without creating anything", () => {
    const dir = scratch();
    expect(createFileAppliedRequestStore({ dir }).get(DERIVED)).toBeUndefined();
    expect(readdirSync(dir)).toEqual([]);
  });

  it("leaves exactly one file per retried call and no temp file behind", () => {
    const dir = scratch();
    createFileAppliedRequestStore({ dir }).set(DERIVED, RETRY);
    expect(readdirSync(dir)).toEqual([`${DERIVED}.json`]);
    expect(appliedRequestPath(dir, DERIVED)).toBe(join(dir, `${DERIVED}.json`));
  });

  it("treats a malformed record as no record, so the result falls back to the derived id", () => {
    const dir = scratch();
    writeFileSync(appliedRequestPath(dir, DERIVED), "not json\n");
    expect(createFileAppliedRequestStore({ dir }).get(DERIVED)).toBeUndefined();

    writeFileSync(appliedRequestPath(dir, DERIVED), JSON.stringify({ applied_request_id: "not-a-uuid" }));
    expect(createFileAppliedRequestStore({ dir }).get(DERIVED)).toBeUndefined();
  });

  it("refuses a key that is not a uuid, before it touches the filesystem", () => {
    const dir = scratch();
    const store = createFileAppliedRequestStore({ dir });
    expect(() => store.get("../escape")).toThrow(InvalidRequestIdError);
    expect(() => store.set("../escape", RETRY)).toThrow(InvalidRequestIdError);
    expect(() => store.set(DERIVED, "../escape")).toThrow(InvalidRequestIdError);
    expect(readdirSync(dir)).toEqual([]);
  });

  it("reports a write it cannot make and does not throw, so the step keeps its decision", () => {
    // A directory path that is already a file: mkdir fails, and so does the
    // write. The step that retried still has a decision to act on, and the
    // report is what says the next result may name the wrong request.
    const dir = scratch();
    const blocked = join(dir, "applied");
    writeFileSync(blocked, "");
    const reported: unknown[] = [];
    const store = createFileAppliedRequestStore({ dir: blocked, onError: (error) => reported.push(error) });

    expect(() => store.set(DERIVED, RETRY)).not.toThrow();
    expect(reported).toHaveLength(1);
    expect(store.get(DERIVED)).toBeUndefined();
  });
});
