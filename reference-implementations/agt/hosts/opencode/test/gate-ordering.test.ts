/**
 * The order of the one exchange both gates run.
 *
 * `"tool.execute.before"` and `"tool.execute.after"` share one function,
 * `runExchange` (acs-plugin.ts); the two hook methods are edges that name
 * their event and assemble their own payload. A single edit to `runExchange`
 * reorders both gates at once, silently, and every step of that order is
 * there for a measured reason.
 *
 * So this file pins the order itself, as behaviour, from outside the plugin --
 * the same four faults asked at both gates, each one arranged so that only one
 * ordering can produce the observed answer:
 *
 *   - `assertUsableTool` first, ahead of everything: asked with a
 *     malformed `tool` and an unusable `sessionID` at once, so the message says
 *     which of the two checks ran first. `Array.prototype.includes` answers a
 *     silent `false` for a malformed needle, so a `tools` check that ran first
 *     would return cleanly instead -- the exact fail-open this ordering closes.
 *   - `assertUsableSessionId` BEFORE `governsTool`'s early return, which is
 *     the reverse of the order this file used to pin. The skip files an audit
 *     entry now, that entry is filed against a session, and a record filed
 *     under an empty session id joins to nothing. So an out-of-scope tool
 *     with an unusable `sessionID` must throw, where it used to return
 *     cleanly -- asserted directly below, because it is the whole of what the
 *     move changed.
 *   - `governsTool`'s early return before `resolveSessionConfig`: an
 *     out-of-scope tool with a USABLE `sessionID` returns cleanly, touches
 *     nothing, and (with the `fetch` spy) asks nothing -- which is what still
 *     makes an ungoverned tool cost no handshake. It writes the one audit
 *     entry that says the step went ungoverned, and that is asserted here
 *     too: the record is what the skip must not skip.
 *   - `assertUsableSessionId` before `resolveSessionConfig`/`governStep`: a
 *     governed tool with the same unusable `sessionID`, which must throw
 *     without a single request going out. `buildEnvelope` throws on a missing
 *     `session_id` too, but that throw lands in `governStep`'s stage-"request"
 *     catch and is answered by the negotiated posture, where a `proceed` is an
 *     ungoverned step -- so "it throws eventually" is not what is being pinned
 *     here; "it throws before anything is asked" is.
 *
 * No live Guardian is stood up, and the `fetch` spy is why: every case below
 * is supposed to end before the first request. Standing one up would make the
 * suite slower and the assertion weaker -- a case that wrongly proceeded would
 * then get an answer rather than being caught not asking.
 *
 * Per-gate coverage of the individual faults already exists (request-gate.test.ts
 * and result-gate.test.ts each pin their own `tool`/`sessionID`/`tools`
 * behaviour). This file adds the order between them, asked identically at
 * both gates -- which is what a shared `runExchange` makes a single property
 * rather than two.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AcsPlugin } from "../acs-plugin.ts";

// "bash" is the tool opencode.hookmap.yaml scopes both gates to (`tools:
// [bash]`), and "read" is one of the real OpenCode tool names measured beside
// it that neither gate lists -- the same pair request-gate.test.ts and
// result-gate.test.ts use for their own skip tests.
const GOVERNED_TOOL = "bash";
const UNLISTED_TOOL = "read";

// One case below reaches the audit sink -- the out-of-scope skip, which files
// the entry that says the step went ungoverned -- and the rest end before
// `governStep` is called. The redirect is unconditional either way, the same
// discipline the other two gate suites keep: an entry written to the
// developer's own `.acs/audit.jsonl` would carry raw tool arguments.
const SCRATCH_DIR = mkdtempSync(join(tmpdir(), "acs-gate-ordering-test-"));
const AUDIT_LOG = join(SCRATCH_DIR, "audit.jsonl");

beforeAll(() => {
  process.env.ACS_AUDIT_LOG = AUDIT_LOG;
});

// Cleared per test, not per file, so a claim about what this log holds is a
// claim about this case and not about whichever case ran before it. Measured
// while checking that the assertions below actually catch a reordering: with
// the sessionID check moved past the handshake, the one case that then
// reaches `governStep` writes an entry -- and every later test's assertion
// failed too, on a path the reordering never touched. Several failures, most
// of them naming nothing about the defect. The claim is worth asserting; the
// coupling is not part of it.
beforeEach(() => {
  rmSync(AUDIT_LOG, { force: true });
});

afterAll(() => {
  delete process.env.ACS_AUDIT_LOG;
  rmSync(SCRATCH_DIR, { recursive: true, force: true });
});

type Hooks = Awaited<ReturnType<typeof AcsPlugin>>;

/**
 * One gate, reduced to what differs between them: its event name, a live object
 * shaped the way OpenCode hands THAT gate one, and how the hook is called.
 * Everything the assertions below check is shared, which is the point.
 */
type Gate = {
  readonly hook: "tool.execute.before" | "tool.execute.after";
  /** The ACS method the shipped hookmap maps this hook to -- what an audit
   * entry for this gate must name, since that log's readers know ACS and no
   * host's event names. */
  readonly acsMethod: string;
  /** The `tools` list the SHIPPED hookmap declares for this gate, which the
   * ungoverned entry records beside the tool that missed it. Per gate, not
   * one constant: since V9 the request gate governs `webfetch` too and the
   * result gate still governs `bash` alone, and an entry naming the wrong
   * gate's list would misreport which declaration let the tool through. */
  readonly tools: readonly string[];
  readonly freshLive: () => Record<string, unknown>;
  readonly fire: (hooks: Hooks, tool: unknown, sessionID: string, live: Record<string, unknown>) => Promise<void>;
};

const GATES: readonly Gate[] = [
  {
    hook: "tool.execute.before",
    acsMethod: "steps/toolCallRequest",
    tools: ["bash", "webfetch"],
    // The mutable `{args}` OpenCode hands the request gate -- the only place it
    // puts them at that gate.
    freshLive: () => ({ args: { command: "ls -la" } }),
    fire: (hooks, tool, sessionID, live) =>
      hooks["tool.execute.before"]!(
        { tool: tool as string, sessionID, callID: "c1" },
        live as unknown as { args: unknown },
      ),
  },
  {
    hook: "tool.execute.after",
    acsMethod: "steps/toolCallResult",
    tools: ["bash"],
    // The whole live `{title, output, metadata}` object, shaped as a real
    // `bash` result is (`metadata.exit`/`metadata.output`, measured on
    // OpenCode 1.18.15 -- opencode.hookmap.yaml's own table).
    freshLive: () => ({
      title: "ls -la",
      output: "a\nb\n",
      metadata: { output: "a\nb\n", exit: 0, truncated: false },
    }),
    fire: (hooks, tool, sessionID, live) =>
      hooks["tool.execute.after"]!(
        { tool: tool as string, sessionID, callID: "c1", args: { command: "ls -la" } },
        live as unknown as { title: string; output: string; metadata: unknown },
      ),
  },
];

for (const gate of GATES) {
  describe(`the shared exchange's order, at "${gate.hook}"`, () => {
    it("refuses a malformed `tool` first, ahead of the `tools` check AND of the sessionID check", async () => {
      const hooks = await AcsPlugin({} as never);
      const live = gate.freshLive();
      const untouched = gate.freshLive();

      const fetchSpy = spyOn(globalThis, "fetch");
      try {
        // Both faults at once. A `tools` check that ran first would read
        // `undefined` as "not in this gate's list" and return cleanly; a
        // sessionID check that ran first would name the session id.
        let thrown: unknown;
        try {
          await gate.fire(hooks, undefined, "", live);
        } catch (error) {
          thrown = error;
        }

        expect(thrown).toBeInstanceOf(Error);
        expect((thrown as Error).message).toContain("no usable tool name");
        expect((thrown as Error).message).not.toContain("no usable sessionID");
        // The event name is carried from the hook method through `runExchange` into
        // the message -- so a gate handing the shared function the wrong
        // literal is visible here too.
        expect((thrown as Error).message).toContain(`"${gate.hook}"`);

        expect(live).toEqual(untouched);
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(existsSync(AUDIT_LOG)).toBe(false);
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("returns for a tool this gate does not govern before negotiating a session, and records the skip", async () => {
      const hooks = await AcsPlugin({} as never);
      const live = gate.freshLive();
      const untouched = gate.freshLive();

      const fetchSpy = spyOn(globalThis, "fetch");
      try {
        // A USABLE sessionID beside an out-of-scope tool: the clean return is
        // only possible if the `tools` skip runs before
        // `resolveSessionConfig`, which is what makes an ungoverned tool cost
        // no handshake round trip.
        await expect(gate.fire(hooks, UNLISTED_TOOL, "ses-ordering-skip", live)).resolves.toBeUndefined();

        expect(live).toEqual(untouched);
        expect(fetchSpy).not.toHaveBeenCalled();

        // Nothing asked, and one line written. The shim's own skip is one
        // call earlier than `governStep`'s, so this is the call site that
        // actually runs on this host -- a shim that returned here without
        // filing the entry would leave an ungoverned session looking like a
        // quiet one, which is the whole reason the outcome exists.
        expect(existsSync(AUDIT_LOG)).toBe(true);
        const entries = readFileSync(AUDIT_LOG, "utf8")
          .split("\n")
          .filter((line) => line.length > 0)
          .map((line) => JSON.parse(line) as Record<string, unknown>);
        expect(entries).toEqual([
          {
            seq: 1,
            recorded_at: expect.any(String),
            session_id: "ses-ordering-skip",
            // The gate's own ACS method -- so this assertion also catches a
            // hook method handing `runExchange` the other gate's event name.
            method: gate.acsMethod,
            rpc_id: null,
            outcome: "ungoverned",
            ungoverned: { tool: UNLISTED_TOOL, tools: gate.tools },
          },
        ]);
      } finally {
        fetchSpy.mockRestore();
      }
    });

    // The ordering this file used to pin in reverse, and the one thing the
    // move actually changed: an out-of-scope tool no longer returns cleanly
    // when the session id is unusable. It cannot -- the entry above is filed
    // against a session, and one filed under an empty id joins to nothing.
    it("refuses an unusable `sessionID` even for a tool this gate does not govern, recording nothing", async () => {
      const hooks = await AcsPlugin({} as never);
      const live = gate.freshLive();
      const untouched = gate.freshLive();

      const fetchSpy = spyOn(globalThis, "fetch");
      try {
        await expect(gate.fire(hooks, UNLISTED_TOOL, "", live)).rejects.toThrow(/no usable sessionID/);

        expect(live).toEqual(untouched);
        expect(fetchSpy).not.toHaveBeenCalled();
        // A refusal, not a skip: no entry, because there is no honest one to
        // write. An `ungoverned` line naming an empty session would be a
        // record nothing can be joined to, which is worse than the throw.
        expect(existsSync(AUDIT_LOG)).toBe(false);
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("refuses an unusable `sessionID` for a governed tool before any request goes out", async () => {
      const hooks = await AcsPlugin({} as never);
      const live = gate.freshLive();
      const untouched = gate.freshLive();

      const fetchSpy = spyOn(globalThis, "fetch");
      try {
        let thrown: unknown;
        try {
          await gate.fire(hooks, GOVERNED_TOOL, "", live);
        } catch (error) {
          thrown = error;
        }

        expect(thrown).toBeInstanceOf(Error);
        expect((thrown as Error).message).toContain("no usable sessionID");
        expect((thrown as Error).message).toContain(`"${gate.hook}"`);

        // Not merely "it throws": nothing was asked. `resolveSessionConfig`'s
        // handshake is the first thing that would have gone over the wire, and
        // `governStep` would have answered `buildEnvelope`'s own throw with the
        // negotiated posture instead of refusing.
        expect(live).toEqual(untouched);
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(existsSync(AUDIT_LOG)).toBe(false);
      } finally {
        fetchSpy.mockRestore();
      }
    });
  });
}
