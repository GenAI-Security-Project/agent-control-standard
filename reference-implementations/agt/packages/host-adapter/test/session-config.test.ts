import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  createFileSessionConfigStore,
  createMemorySessionConfigStore,
  InvalidSessionIdError,
  sessionConfigPath,
  type SessionConfig,
} from "../src/session-config.ts";

const HELLO: SessionConfig = {
  negotiated_version: "0.1.0",
  methods_evaluated: ["steps/toolCallRequest"],
  selected_transport: "http",
  timeout_config: { default_ms: 5000 },
  on_decision_failure: "deny",
};

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-session-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  // Named removal only: unlink what we know about, then rmdir. A stray file
  // fails loudly instead of being swept away by a recursive delete.
  while (dirs.length > 0) {
    const dir = dirs.pop() as string;
    for (const entry of readdirSync(dir)) {
      unlinkSync(join(dir, entry));
    }
    rmdirSync(dir);
  }
});

describe("createFileSessionConfigStore — the session config store across processes", () => {
  it("survives the process that wrote it: a second store reads the first's config", () => {
    const dir = scratch();
    createFileSessionConfigStore({ dir, sessionId: "sess-1" }).set(HELLO);

    // A *different* store instance, standing in for the next hook's process.
    expect(createFileSessionConfigStore({ dir, sessionId: "sess-1" }).get()).toEqual(HELLO);
  });

  it("keeps sessions apart", () => {
    const dir = scratch();
    createFileSessionConfigStore({ dir, sessionId: "sess-1" }).set(HELLO);
    expect(createFileSessionConfigStore({ dir, sessionId: "sess-2" }).get()).toBeUndefined();
  });

  it("returns undefined before any handshake, without creating anything", () => {
    const dir = scratch();
    expect(createFileSessionConfigStore({ dir, sessionId: "sess-1" }).get()).toBeUndefined();
    expect(readdirSync(dir)).toEqual([]);
  });

  it("creates the directory on first write", () => {
    const base = scratch();
    const dir = join(base, "nested", "sessions");
    createFileSessionConfigStore({ dir, sessionId: "sess-1" }).set(HELLO);
    expect(existsSync(sessionConfigPath(dir, "sess-1"))).toBe(true);
    // Clean up the nested tree by name, deepest first. The parent is
    // resolved with dirname(), not a ".." path segment.
    unlinkSync(sessionConfigPath(dir, "sess-1"));
    rmdirSync(dir);
    rmdirSync(dirname(dir));
  });

  // Total on read: a corrupt or unreadable file degrades to "not negotiated",
  // which the caller resolves to the spec default. It must never throw --
  // a throw here would take out the hook process and, with it, the decision.
  it("returns undefined for a file that is not JSON, and does not throw", () => {
    const dir = scratch();
    mkdirSync(dir, { recursive: true });
    writeFileSync(sessionConfigPath(dir, "sess-1"), "{not json");
    expect(createFileSessionConfigStore({ dir, sessionId: "sess-1" }).get()).toBeUndefined();
  });

  it("returns undefined for JSON that is not an object", () => {
    const dir = scratch();
    mkdirSync(dir, { recursive: true });
    writeFileSync(sessionConfigPath(dir, "sess-1"), "42");
    expect(createFileSessionConfigStore({ dir, sessionId: "sess-1" }).get()).toBeUndefined();
  });

  it("returns undefined for an object missing on_decision_failure", () => {
    const dir = scratch();
    mkdirSync(dir, { recursive: true });
    writeFileSync(sessionConfigPath(dir, "sess-1"), JSON.stringify({ timeout_config: { default_ms: 1 } }));
    expect(createFileSessionConfigStore({ dir, sessionId: "sess-1" }).get()).toBeUndefined();
  });

  it("round-trips fields it does not name", () => {
    const dir = scratch();
    const extended = { ...HELLO, profiles_accepted: ["ACS-Core"], skew_window_ms: 1000 };
    createFileSessionConfigStore({ dir, sessionId: "sess-1" }).set(extended);
    expect(createFileSessionConfigStore({ dir, sessionId: "sess-1" }).get()).toEqual(extended);
  });

  // `set()` is the one method here that is not total, and deliberately so:
  // `get()` swallows everything because a throw there would kill the hook
  // process and take the decision with it, while a write that fails is a real
  // deployment fault whose caller has to hear about it -- it is what makes
  // handshake() able to hand the negotiated ServerHello back for the current
  // step instead of silently losing the posture. That contract had no direct
  // test; only its consequences did.
  it("throws rather than swallowing when the config cannot be written", () => {
    const base = scratch();
    // A regular file standing where a parent directory should be, so
    // `mkdirSync(dir, {recursive: true})` throws ENOTDIR -- reliably and
    // cross-platform, with no permission games and no root-dependent
    // behaviour. (Pointing `dir` straight at the file instead throws too,
    // but as EEXIST on macOS -- checked, not assumed. The nested form is the
    // one that produces the same code everywhere, and it is also the real
    // fault: ACS_SESSION_DIR resolving under something that is not a
    // directory.)
    const blocker = join(base, "not-a-directory");
    writeFileSync(blocker, "x");
    const dir = join(blocker, "sessions");
    const store = createFileSessionConfigStore({ dir, sessionId: "sess-1" });

    expect(() => store.set(HELLO)).toThrow(/ENOTDIR/);
    // And `get()` stays total across the same fault, which is the pairing
    // that matters: the write is loud, the read is silent, and the caller
    // resolves undefined to the ACS default.
    expect(store.get()).toBeUndefined();
  });

  it("leaves no partial file behind: a reader only ever sees a complete config", () => {
    const dir = scratch();
    const store = createFileSessionConfigStore({ dir, sessionId: "sess-1" });
    store.set(HELLO);
    store.set({ ...HELLO, on_decision_failure: "proceed" });
    // The rename is atomic, so no .tmp files survive a completed write.
    expect(readdirSync(dir)).toEqual(["sess-1.json"]);
    expect(createFileSessionConfigStore({ dir, sessionId: "sess-1" }).get()?.on_decision_failure).toBe("proceed");
  });
});

describe("createFileSessionConfigStore — session_id is untrusted input", () => {
  // session_id arrives in a host payload and becomes part of a path. These
  // must be impossible, not unlikely.
  const badSessionIds = ["..", ".", "../escape", "a/b", "a\\b", "", "sess\nid", "a".repeat(129)];
  for (const bad of badSessionIds) {
    it(`rejects ${JSON.stringify(bad)}`, () => {
      expect(() => createFileSessionConfigStore({ dir: scratch(), sessionId: bad })).toThrow(InvalidSessionIdError);
    });
  }

  it("accepts the shapes a real host sends", () => {
    const dir = scratch();
    for (const ok of ["demo", "sess-1", "3f2b9c10-4d5e-6f70-8a9b-0c1d2e3f4a5b", "a_b.c-d"]) {
      expect(() => createFileSessionConfigStore({ dir, sessionId: ok })).not.toThrow();
    }
  });

  // Asserting only the 129-character rejection would pass for a pattern
  // whose bound is anywhere at or below 128 -- an off-by-one that tightened
  // the limit would not fail anything. Both sides of the boundary, asserted
  // together, are what actually locate it.
  it("accepts exactly 128 characters and rejects 129 — both sides of the boundary", () => {
    const dir = scratch();
    expect(() => createFileSessionConfigStore({ dir, sessionId: "a".repeat(128) })).not.toThrow();
    expect(() => createFileSessionConfigStore({ dir, sessionId: "a".repeat(129) })).toThrow(InvalidSessionIdError);
  });
});

describe("createMemorySessionConfigStore — the in-memory store", () => {
  it("still satisfies the same interface", () => {
    const store = createMemorySessionConfigStore();
    expect(store.get()).toBeUndefined();
    store.set(HELLO);
    expect(store.get()).toEqual(HELLO);
  });
});
