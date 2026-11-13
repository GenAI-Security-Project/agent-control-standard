import { describe, expect, it } from "bun:test";
import {
  modificationDocumentOf,
  withResultOutput,
  type AcsDecision,
  type HostOutputLocation,
} from "host-adapter";
// A deliberate deep import: `resolveModify` is not on the adapter's public
// barrel and should not be -- that barrel is documented as "the whole contract
// a shim relies on", and no shim relies on this. But the gate below is about
// what `resolveModify` actually does, and re-implementing its branch inline
// instead would make the assertion a tautology for the one decision it most
// needed to cover. Same test-only precedent test/redaction.test.ts and
// test/envelope-log-sink-roundtrip.test.ts already set for reaching past a
// package's barrel.
import { resolveModify } from "../packages/host-adapter/src/decision-modify.ts";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Glob } from "bun";

/**
 * Strips comments before matching, so these gates assert what the package
 * boundaries actually claim -- no AGT or host vocabulary *used in code*
 * (imports, types, calls) -- rather than the much weaker and much more
 * brittle claim "never mentioned anywhere, including prose". Doc comments
 * routinely explain a module's boundary by naming the exact vocabulary it
 * must stay clear of (see hosts/claude-code/acs-hook.ts: "must not reach
 * into AGT -- it never imports `agt-bridge`..."). A gate that fires on
 * that sentence is a gate the next person deletes rather than fixes,
 * which is worse than no gate at all.
 *
 * Line comments are stripped to end-of-line unless the "//" is
 * immediately preceded by ":" -- an `https://`-style URL that happens to
 * sit inside a comment or string, not a line-comment delimiter.
 */
function stripComments(src: string): string {
  const noBlockComments = src.replace(/\/\*[\s\S]*?\*\//g, "");
  return noBlockComments.replace(/(?<!:)\/\/.*$/gm, "");
}

/**
 * True when `relativePath` has a `test` path segment anywhere, including at
 * the very start. `Glob.scanSync` returns paths relative to the scanned
 * root, with no leading slash, so a `test/` directory sitting directly under
 * that root (e.g. scanning `packages/foo/src` with a `packages/foo/src/test/`
 * subdirectory) produces a path like `test/bar.ts` -- no `/test/` substring
 * for a plain `.includes("/test/")` check to find. Anchoring on `(^|/)`
 * catches that case as well as the nested one, without false-positiving on a
 * segment that merely starts with "test" (`testing/`, `latest/`).
 */
function isUnderTestDir(relativePath: string): boolean {
  return /(^|\/)test\//.test(relativePath);
}

/**
 * Every non-test `.ts` file under `dir`, with comments stripped.
 *
 * The emptiness check is what stops all four gates below from passing
 * vacuously. A *renamed* directory already
 * failed loudly -- `Glob.scanSync` throws ENOENT -- but a directory that
 * still exists with no non-test `.ts` under it would sail through with zero
 * assertions, and a gate that cannot fail is worse than no gate: it reads as
 * enforcement in the README while enforcing nothing.
 */
function readSourceFiles(dir: string): { file: string; code: string }[] {
  const files = [...new Glob("**/*.ts").scanSync(dir)].filter((f) => !isUnderTestDir(f));
  expect({ dir, sourceFiles: files.length > 0 }).toEqual({ dir, sourceFiles: true });
  return files.map((f) => ({ file: f, code: stripComments(readFileSync(`${dir}/${f}`, "utf8")) }));
}

/**
 * Escapes regex metacharacters in `term`, so `assertNoVocabulary`'s "whole
 * word" claim holds literally, not just for terms with no special
 * characters. `tool.execute` is the term that makes this matter: unescaped,
 * `\btool.execute\b`'s `.` matches any character, so it would also match
 * `tool_execute`, `tool execute`, `toolXexecute` -- over-matching that
 * happens to be safe today (nothing in this codebase writes any of those),
 * but a future term with `[`, `(`, or `$` would either throw building the
 * `RegExp` or silently mean something other than what its author wrote. The
 * doc above says "whole word", not "regex fragment", so the code is made to
 * agree with the doc rather than the other way around.
 */
function escapeRegExp(term: string): string {
  return term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Asserts none of `terms` appears as a whole word (case-insensitive) in
 * any non-test `.ts` file's code under `dir`. Whole-word matching, not
 * bare substring: "opa" as a substring would false-positive on ordinary
 * English words like "opaque"; a gate that fails on that is exactly the
 * "annoyingly false" failure mode this suite exists to avoid. Each
 * assertion diffs `{file, term, found}` against `{file, term, found:
 * false}` on failure, so the failing file and the offending term are
 * both in the test output -- no separate message plumbing needed.
 */
function assertNoVocabulary(dir: string, terms: string[]): void {
  for (const { file, code } of readSourceFiles(dir)) {
    for (const term of terms) {
      const found = new RegExp(`\\b${escapeRegExp(term)}\\b`, "i").test(code);
      expect({ file, term, found }).toEqual({ file, term, found: false });
    }
  }
}

describe("architectural invariants", () => {
  /**
   * The claim the whole M×N argument rests on: a host implements ACS once
   * (packages/host-adapter) and is governable by any conformant runtime. That
   * collapse is only real if the adapter never leaks policy-runtime (AGT)
   * vocabulary into its own code.
   *
   * Scope, deliberately: packages/host-adapter/src only.
   *   - hosts/claude-code/ is not scanned here. A host shim is
   *     host-specific by definition, and its own doc comment is allowed
   *     to name AGT in prose (acs-hook.ts's header does, explaining what
   *     it must not import). The invariant that actually matters for that
   *     file is an import-graph one ("never imports agt-bridge or
   *     guardian's server-side pieces"), not "never mentions the word" --
   *     a different claim this suite doesn't make for host shims.
   *   - host-adapter/package.json's devDependency on `guardian` is a
   *     test-only wiring choice: packages/host-adapter/test/*.test.ts spin
   *     up a real Guardian for end-to-end coverage (see client.test.ts's
   *     and build-envelope.test.ts's own comments). This gate reads only
   *     `.ts` source under src/, never package.json and never test/, so
   *     that dependency is correctly out of scope.
   */
  it("host adapter's source contains zero AGT-specific code", () => {
    assertNoVocabulary("packages/host-adapter/src", [
      "agt",
      "AgentControl",
      "rego",
      "opa",
      "intervention_point",
      "verdict",
    ]);
  });

  /**
   * The other half of that boundary: the adapter is promised to a second
   * host *unchanged*, so it must not name the first host's output fields
   * either. Declaring Claude Code's wire shape here -- a mandatory
   * `permissionDecision`, a returned `{ hookSpecificOutput }` -- would make
   * one host's vocabulary the shared module's public API, and a second host
   * would have to inherit it or fork the module.
   *
   * Every name the gate below lists now lives in hosts/claude-code/: all but
   * one as data in claude-code.hookmap.yaml's output paths, and the remaining
   * one -- the wrapper -- in acs-hook.ts, which is what wraps, and in the
   * hookmap as the dotted prefix those paths sit under. Stated by relation
   * rather than by count on purpose: a fixed count is exactly the kind of
   * claim that goes stale the moment a name is added. Same scope note as the
   * gate above -- non-test `.ts` under packages/host-adapter/src only, with
   * comments stripped, so a doc comment may still explain the boundary it
   * must not cross in code.
   */
  it("the host adapter's source names no host output field", () => {
    assertNoVocabulary("packages/host-adapter/src", [
      "permissionDecision",
      "permissionDecisionReason",
      "updatedInput",
      // The field this list would have been weakest without: the result gate
      // is where the adapter builds a replacement for a host's tool output,
      // so `updatedToolOutput` is the name it would be most natural to reach
      // for -- and a gate that listed only the four fields the request gate
      // uses while omitting this one would look like coverage while quietly
      // losing it. It lives in claude-code.hookmap.yaml as data and in
      // acs-hook.ts as a checked path, and nowhere else.
      "updatedToolOutput",
      "hookSpecificOutput",
      // The same gap this list closes for `updatedToolOutput` -- opencode's
      // own deny channel, `refuse.reason` in opencode.hookmap.yaml, is a
      // field name this adapter must stay just as ignorant of as Claude
      // Code's. It lives in that hookmap as data and nowhere in
      // packages/host-adapter/src.
      "refuse",
    ]);
  });

  /**
   * What makes a second host cost zero AGT code: the bridge that knows AGT
   * must never learn a specific host's wire shape, or adding a host would
   * mean touching this package too.
   */
  it("AGT bridge's source contains zero host-specific code", () => {
    assertNoVocabulary("packages/agt-bridge/src", [
      "claude",
      "opencode",
      "hookSpecificOutput",
      "permissionDecision",
      "stdin",
    ]);
  });

  /**
   * An ACS-first reader must be able to trace one action end to end without
   * reading AGT source. The Inspector is that reader's tool, so the claim
   * is only real if the tool itself knows nothing about AGT and nothing
   * about any particular host: it renders ACS envelopes as data. Both term
   * lists from the two gates above apply to it at once.
   */
  it("the Envelope Inspector's source contains zero AGT vocabulary and zero host vocabulary", () => {
    assertNoVocabulary("packages/inspector/src", [
      "agt",
      "AgentControl",
      "rego",
      "opa",
      "intervention_point",
      "verdict",
      // The three AGT verdict names. Listing the word "verdict" without the
      // verdicts themselves is not enough: a badge could read
      // `ALLOW (policy fired -- ACS "warn")` and still pass this gate. ACS
      // has no `warn` disposition, so that string would teach a reader
      // AGT's vocabulary from an ACS-first tool -- exactly the leak this
      // gate exists to prevent.
      //
      // `allow`/`deny`/`ask`/`modify`/`defer` are deliberately not here --
      // they are ACS's own dispositions and the Inspector must name them.
      // These three are AGT's alone.
      "warn",
      "escalate",
      "transform",
      "claude",
      "opencode",
      "hookSpecificOutput",
      "permissionDecision",
      "stdin",
    ]);
  });

  /**
   * Envelopes must be inspectable on the wire. If the Inspector imported the
   * Guardian's types, "inspectable" would be a claim about our own type
   * graph instead: any third-party reader of the envelope log has only the
   * file. So does this one.
   *
   * "host-adapter" is on this list because the Inspector also tails the
   * audit log, a host-side artifact, and declares its own AuditEntry rather
   * than importing the adapter's, for exactly the same reason it re-declares
   * EnvelopeLogEntry rather than importing the Guardian's (see
   * tail-audit-log.ts's module doc). Without this third entry, the gate
   * would still pass -- but it would no longer be testing the claim this
   * test makes, and a gate that passes without covering what it claims to
   * cover is worse than no gate: it looks like coverage while quietly
   * losing it.
   */
  it("the Envelope Inspector imports nothing from the Guardian, the AGT bridge, or the host adapter", () => {
    for (const { file, code } of readSourceFiles("packages/inspector/src")) {
      for (const spec of ["guardian", "agt-bridge", "host-adapter"]) {
        const found = importsSpecifier(code, spec);
        expect({ file, spec, found }).toEqual({ file, spec, found: false });
      }
    }
  });

  /**
   * This is the same boundary from the host's side. The vocabulary gate
   * above deliberately excludes `hosts/`, because a host shim is
   * host-specific by definition and its doc comment may name the policy
   * runtime in prose -- but the invariant that *does* bind it is an
   * import-graph one, exactly as that exclusion says: "never imports
   * agt-bridge or guardian's server-side pieces, only host-adapter's public
   * surface". acs-hook.ts's own header asserts the property; this is what
   * checks it.
   *
   * That claim is what makes a second host cost zero policy-runtime code: a
   * shim reaching into the Guardian in-process would be governable by that
   * Guardian and nothing else, which undoes the M×N collapse this
   * architecture depends on. It passes today with one shim, and starts
   * biting the moment there are two.
   *
   * `isUnderTestDir` excludes hosts/claude-code/test/, which is the only
   * place that legitimately imports `guardian` -- it stands up a real one to
   * prove the wire contract end to end, the same test-only precedent
   * packages/host-adapter/test/ already sets.
   *
   * Known and left as is: `importsSpecifier` matches the specifier by
   * substring, so a future shim importing a local file whose name merely
   * contains "guardian" (`./guardian-defaults.ts`, say) would trip this gate
   * spuriously. That is deliberate. The substring match is what catches the
   * real hole -- a relative reach-around like
   * `from "../../packages/guardian/src/index.ts"`, which no exact-match
   * check on a bare package name would see, and which is asserted directly
   * in "the import gate itself" below. A false positive here is a loud
   * failure with the offending file named, which someone renames a file to
   * fix; the alternative trades that for a silent hole. Anyone hitting it
   * should read this comment before "fixing" the regex.
   */
  it("every host shim imports the adapter only -- never the Guardian, never the AGT bridge", () => {
    const scanned = readSourceFiles("hosts");

    // Asserted, not assumed. `readSourceFiles`'s emptiness check stops the
    // gate passing vacuously on zero files, but not on the wrong ones: this
    // gate passes today partly because `Glob.scanSync` does not descend into
    // hosts/claude-code/node_modules. A globbing change that started
    // returning vendored `.ts` files would bury the shim among hundreds of
    // them; one that stopped returning the shim would leave a gate that scans
    // something irrelevant and always passes. Pinned to the exact list, so a
    // second shim has to be added here consciously.
    expect(scanned.map(({ file }) => file).sort()).toEqual([
      "claude-code/acs-hook.ts",
      "opencode/acs-plugin.ts",
      "opencode/apply-opencode-output.ts",
    ]);

    for (const { file, code } of scanned) {
      for (const spec of ["agt-bridge", "guardian"]) {
        const found = importsSpecifier(code, spec);
        expect({ file, spec, found }).toEqual({ file, spec, found: false });
      }
    }
  });

  /**
   * This package knows ACS and hookmaps, nothing else -- the first gate above
   * catches Claude Code's wire vocabulary leaking into the shared adapter;
   * this one catches OpenCode's. New gates are added at the end of this
   * describe block, not inserted between existing ones, because README.md's
   * own "Status" section refers to gates by count and by ordinal --
   * inserting one in the middle would silently make those references wrong.
   *
   * `attachments` is the term this list catches: it is the field OpenCode's
   * result payload carries at runtime and does not declare in its own
   * published type (hosts/opencode/acs-plugin.ts, checked against 1.18.15's
   * type -- the same gap `outputs.mirrors` exists to let a hookmap declare
   * instead of the adapter hard-coding), so a shortcut in result-output.ts
   * naming it explicitly -- rather than treating it as an opaque sibling the
   * clone-and-patch approach never has to read by name -- is the mistake
   * this gate exists to catch. `tool.execute` (the hook name OpenCode's own
   * runtime dispatches on) and `callID` (its per-call identifier) sit beside
   * it for the same reason.
   *
   * Two more OpenCode-shaped terms are deliberately not in this list, and the
   * reason is the gate's own validity, same as the exclusions on the gate
   * above:
   *
   *   - `sessionID` case-insensitively matches `sessionId`, which several
   *     adapter files use for ACS's own `metadata.session_id` -- gating it
   *     would fail on day one, for a term that names ACS's vocabulary, not
   *     OpenCode's.
   *   - `metadata` appears in build-envelope.ts and handshake.ts as the ACS
   *     envelope's own `metadata` block -- the exact same collision.
   *
   * Listing either would produce a gate that fails for the wrong reason, and
   * "loosen the gate until it passes" is how a gate stops meaning anything.
   * What protects the adapter's isolation for those two is that they are ACS
   * vocabulary the adapter is *supposed* to speak, not a gate.
   */
  it("the adapter names no OpenCode field", () => {
    assertNoVocabulary("packages/host-adapter/src", ["tool.execute", "callID", "attachments"]);
  });

  /**
   * Placed last for the same reason the previous gate is: so this comment
   * does not go stale by renumbering when another gate is appended.
   *
   * `acs-plugin.ts` must export exactly one symbol, because OpenCode's
   * plugin loader hands every exported function of a plugin module its own
   * registration context -- a live `client`, `directory`, `worktree`, and
   * `$` (its shell executor) -- and calls each one as a candidate plugin
   * factory, not only the export shaped like `Plugin`. A second export is a
   * hazard whose severity depends on its shape: a function export that fails
   * its own validation on the first argument surfaces as a caught, non-fatal
   * `error` log line while `AcsPlugin` itself still registers -- but a
   * non-function export produces `error="Plugin export is not a function"`,
   * and the factory is never called at all. A single exported constant would
   * silently disable governance for the whole session, and nothing in
   * OpenCode's own log line -- byte-identical in shape whether the fault is
   * harmless or total -- would say so.
   *
   * `applyOpenCodeOutput` lives in its own module (`apply-opencode-output.ts`,
   * imported into `acs-plugin.ts`, tested directly by
   * `apply-opencode-output.test.ts`) specifically so `acs-plugin.ts` has exactly
   * one export for OpenCode's loader to find. This gate is what keeps that
   * true going forward, mechanically: a second export added here -- for a
   * new helper, a re-exported type, anything -- fails this test rather than
   * silently reopening the hazard.
   */
  it("hosts/opencode/acs-plugin.ts exports exactly one symbol, so OpenCode's plugin loader has no second export to mis-invoke as a candidate factory", () => {
    const file = readSourceFiles("hosts").find(({ file }) => file === "opencode/acs-plugin.ts");
    expect(file).toBeDefined();
    expect(exportedNames(file!.code)).toEqual(["AcsPlugin"]);
  });

  /**
   * This is the gate that turns "unreachable by accident" into "unreachable
   * by construction".
   *
   * `governStep` refuses -- throws, rather than skipping -- a gate whose
   * entry declares a `tools` list when its caller names no scoped tool
   * (`GovernStepInput.scopedTool`, packages/host-adapter/src/govern-step.ts).
   * acs-hook.ts names none: its own settings.json matcher already scopes
   * both gates -- `^(Bash|WebFetch)$` at the request gate, `^Bash$` at the
   * result gate -- so it has never needed to.
   *
   * `scripts/verify-zero-diff.sh` once held that shut mechanically by
   * freezing `hosts/claude-code/[^/]+\.(ts|yaml)$`, and this comment used to
   * say so in the present tense. It is past tense now. That script diffs
   * against `slice/v4`, this host's hookmap has since changed under the
   * frozen pattern, and `bun run verify:zero-diff` exits 1 from this HEAD
   * naming `hosts/claude-code/claude-code.hookmap.yaml` among the paths that
   * moved -- with nothing in `.github/workflows/` running it either. So the
   * freeze proved the claim at the commit it was written against and does
   * not hold from here. What holds the property today is THIS TEST, which is
   * why the sentence is worth reading rather than deleting.
   *
   * The consequence itself is unchanged: while acs-hook.ts passes no scoped
   * tool, a `tools` list anywhere in this hookmap is a throw on every call at
   * the gate that declares it -- exit 2, no audit entry. Fail closed, not
   * fail open: the tool call does not run ungoverned, and no audit entry
   * claims it did. A broken deployment, not a bypass. Verified directly,
   * with the real shim run as a subprocess against a live Guardian, across
   * every combination of hookmap configuration, gate, and tool.
   *
   * Scoped to gates where `emptyOutputIsHonest` is false, which is narrower
   * than the truth above -- deliberately, and this is the part to read
   * before adding a `tools` line anywhere in this hookmap. This gate is not
   * widened to match, on purpose: it refuses a narrower thing (`tools`
   * where an empty render is not an honest answer) for a reason that
   * outlives the freeze. That fault is about the shim's own applier -- an
   * unlisted tool's empty output reaching `asClaudeCodeOutput` as an
   * absence it treats as a throw rather than a no-op -- and would still be
   * a fault the day acs-hook.ts starts naming a scoped tool. The
   * throw-on-every-call consequence above would evaporate that same day, and
   * a gate written for it would then be refusing something legitimate. That
   * is the sense in which the reason outlives the freeze, and the freeze has
   * now gone first. Written down here,
   * where whoever adds the line will read it, rather than enforced by a
   * check that expires.
   *
   * Lives here because it is about two artifacts at once, which is what
   * this file is for: the claim needs Claude Code's hookmap and the
   * adapter's skip to state at all, and neither host's own suite owns both
   * halves -- the same shape as the gate directly above it, which is about
   * hosts/opencode/acs-plugin.ts's export count and also lives here rather
   * than under hosts/opencode/test/.
   *
   * `hooksWhereEmptyOutputIsDishonest`, one function down, is why the flag
   * is read out of acs-hook.ts's source text rather than imported: that file
   * is inside the pattern `scripts/verify-zero-diff.sh` freezes, so when this
   * gate was written, adding an export there was not available. That
   * constraint is historical for the reason stated above -- the freeze does
   * not hold from this HEAD -- and the source-text read is what shipped.
   */
  it("Claude Code's hookmap declares no `tools` at a gate where an empty render is not an answer", () => {
    const SHIM = "hosts/claude-code/acs-hook.ts";
    const HOOKMAP = "hosts/claude-code/claude-code.hookmap.yaml";

    const dishonestGates = hooksWhereEmptyOutputIsDishonest(readFileSync(SHIM, "utf8"));
    // The emptiness check every gate in this file carries, for the same
    // reason: a parser that silently found nothing would make this test pass
    // while asserting about no gate at all, which is worse than no gate.
    expect({ shim: SHIM, foundGates: dishonestGates.length > 0 }).toEqual({ shim: SHIM, foundGates: true });

    const hookmap = Bun.YAML.parse(readFileSync(HOOKMAP, "utf8")) as {
      hooks?: Record<string, { tools?: unknown } | undefined>;
    };
    const declared = dishonestGates.map((hookEventName) => ({
      hookEventName,
      // `?? "(none declared)"` collapses YAML's `null` (a key written bare)
      // and an absent key, which mean the same thing everywhere else in this
      // repo -- and neither is what this gate refuses.
      tools: hookmap.hooks?.[hookEventName]?.tools ?? "(none declared)",
    }));

    // The assertion is the `expect` below; this throw is what tells whoever
    // trips it why, since an object diff can name the gate but not the
    // consequence.
    for (const { hookEventName, tools } of declared) {
      if (tools !== "(none declared)") {
        throw new Error(
          `${HOOKMAP}'s "hooks.${hookEventName}" declares "tools": ${JSON.stringify(tools)}. TWO SEPARATE ` +
            `FAULTS, and the first one fires first. (1) governStep REFUSES a gate whose entry declares a ` +
            `"tools" list when its caller named no scoped tool, and ${SHIM} passes none -- so this is a throw ` +
            `on EVERY call at this gate, for the listed tool as much as for an unlisted one, exit 2 with no ` +
            `audit entry. Measured with "tools: [Bash]" at PostToolUse, invoked for Bash. That shim passes no ` +
            `scoped tool, and while scripts/verify-zero-diff.sh still held this host at +0/-0 it could not be ` +
            `taught to; that freeze does not hold from this HEAD (the script exits 1 here and no workflow runs ` +
            `it), so teaching the shim to tell is now an ordinary code change -- but until it is taught, ` +
            `declaring "tools" at any gate is this throw. See GovernStepInput.scopedTool ` +
            `(packages/host-adapter/src/govern-step.ts). (2) Even once it does tell, this hook is one where ` +
            `${SHIM} declares "emptyOutputIsHonest: false": governStep returns an EMPTY rendered output for a ` +
            `tool a gate's list does not name (the "ungoverned" member of GovernedStep -- see its "output" ` +
            `field for the measurement), that shim's asClaudeCodeOutput throws rather than writing one, and ` +
            `main().catch exits 2 -- so every call to an UNLISTED tool becomes a blocking stop, not the silent ` +
            `skip a list is added for. Both are fail-closed, so nothing runs ungoverned, and neither is what a ` +
            `"tools" list means anywhere else. Scope this gate by its host's own matcher (settings.json, ` +
            `"^(Bash|WebFetch)$") as it already is.`,
        );
      }
    }
    expect(declared).toEqual(dishonestGates.map((hookEventName) => ({ hookEventName, tools: "(none declared)" })));
  });

  /**
   * A single `renderMatrix()` wired to what are now separate renderers --
   * the coverage matrix, the trace-pillar rows, and eventually an
   * upstream-diff renderer -- is retired for good. `render.ts`'s own module
   * header records why: a coverage claim rendered by the same function as
   * everything else beside it is a coverage claim whose subject is whatever
   * was rendered. This gate is what keeps that retirement mechanical rather
   * than a sentence someone can quietly stop reading.
   *
   * `readSourceFiles` strips comments and excludes `test/` before this runs,
   * so the gate cannot fire on `render.ts`'s own header explaining the split
   * (which names `renderMatrix` in prose), or on this comment -- a gate that
   * matched documentation of the rule it enforces is the kind the next
   * person deletes rather than fixes.
   *
   * Scanned the same way the package-scoped gates above are: each package's
   * `src`, plus `hosts`. Asserted per file (`{dir, file, found}`) rather than
   * as one boolean, so a failure names the offending file.
   */
  it("nothing in this repository is named renderMatrix -- the split that happened before anything inherited it", () => {
    const dirs = [
      "packages/agt-bridge/src",
      "packages/conformance/src",
      "packages/guardian/src",
      "packages/host-adapter/src",
      "packages/inspector/src",
      "hosts",
    ];
    for (const dir of dirs) {
      for (const { file, code } of readSourceFiles(dir)) {
        const found = code.includes("renderMatrix");
        expect({ dir, file, found }).toEqual({ dir, file, found: false });
      }
    }
  });
});

/**
 * True when `code` names a module specifier containing `spec` in any position
 * that actually creates a dependency on it.
 *
 * `from "…"` alone is the one form nobody reaching for a forbidden import by
 * accident would use. Each alternative below is a real hole a narrower
 * check would leave:
 *
 *   from "guardian"              the static named/default import
 *   import "guardian"            the bare side-effect import, no `from`
 *   import("guardian")           dynamic, and `await import("guardian")`
 *   import("guardian").EnvelopeLogEntry
 *                                type position -- erased at build, still a
 *                                compile-time dependency on the Guardian's
 *                                type graph, which is exactly what the gate
 *                                above forbids
 *   require("guardian")          CJS interop
 *
 * `\(?` covers the parenthesised and unparenthesised forms in one pass, and
 * the `i` flag closes the last hole: module resolution is case-insensitive on
 * macOS, so `from "Guardian"` resolves here and the case-sensitive gate said
 * nothing about it.
 */
function importsSpecifier(code: string, spec: string): boolean {
  return new RegExp(`(?:from|import|require)\\s*\\(?\\s*["'][^"']*${spec}[^"']*["']`, "i").test(code);
}

/**
 * Every name a top-level `export` binds in `code`, in source order. Two
 * shapes, matched in one pass so source order is preserved across both:
 *
 *   1. A declaration -- `export (default )?(async )?(function|const|class|
 *      type|interface|let|var) NAME`.
 *   2. A named-export list -- `export { a, b as c }`, with or without a
 *      trailing `from "…"` (a re-export). Each entry contributes its local
 *      name (the part before `as`, if any): that is the binding a reader of
 *      this file sees, and it is what OpenCode's loader would find and try
 *      to call regardless of which module the value originally came from.
 *
 * The list form is matched too, because the gate this function backs exists
 * to catch a second export appearing where none is expected, and a
 * re-export list is exactly as valid a way to introduce one as a second
 * declaration. Mutation-tested: `const spurious = 1; export { spurious };`
 * beside a working factory counts as two.
 *
 * Deliberately narrower than the two shapes above in other ways -- the same
 * pragmatism `assertNoVocabulary` and `importsSpecifier` above already
 * apply, a regex precise enough for the shapes this codebase actually
 * writes, not a full TS parser and not every legal export form (a bare
 * `export default someExpression;` with no declaration keyword is still
 * unmatched). Callers pass comment-stripped code (this suite's own
 * `readSourceFiles` already does that), so a doc comment that happens to
 * contain the word "export" -- this file has several -- is never mistaken
 * for a declaration.
 */
function exportedNames(code: string): string[] {
  const pattern =
    /^export\s+(?:default\s+)?(?:async\s+)?(?:function\*?|const|class|type|interface|let|var)\s+([A-Za-z_$][\w$]*)|^export\s*\{([^}]*)\}/gm;
  const names: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(code)) !== null) {
    if (match[1] !== undefined) {
      names.push(match[1]);
      continue;
    }
    const entries = match[2]!
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    for (const entry of entries) {
      names.push(entry.split(/\s+as\s+/)[0]!.trim());
    }
  }
  return names;
}

/**
 * The hook names whose `HOOK_EXPECTATIONS` entry in
 * hosts/claude-code/acs-hook.ts declares `emptyOutputIsHonest: false` -- the
 * gates where that shim treats an output carrying no `hookSpecificOutput`
 * wrapper as a thing it must not write, and throws instead.
 *
 * Read out of the shim's source rather than imported, because `acs-hook.ts`
 * exports none of this and, when this was written, was frozen --
 * `scripts/verify-zero-diff.sh` failed on any change to it, so "export the
 * table for the test" was not available. That freeze is past tense: the
 * script diffs against `slice/v4`, this host's files have since changed under
 * its frozen pattern, `bun run verify:zero-diff` exits 1 from this HEAD, and
 * nothing in `.github/workflows/` runs it. The source-text read is what
 * shipped and is what the gate above depends on; the constraint that produced
 * it is history. The same pragmatism `exportedNames` and `importsSpecifier`
 * above already apply: a regex precise enough for the shape this codebase
 * actually writes, with its own meta-tests below, not a TypeScript parser.
 *
 * Comments are stripped first, so the several doc comments in that file that
 * discuss `emptyOutputIsHonest` in prose are never mistaken for a
 * declaration.
 */
function hooksWhereEmptyOutputIsDishonest(source: string): string[] {
  const code = stripComments(source);
  // Every `  SomeName: {` at exactly two-space indent -- one entry of the
  // `HOOK_EXPECTATIONS` object literal -- paired with where it starts.
  const entryStarts = [...code.matchAll(/^ {2}([A-Za-z_$][\w$]*): \{$/gm)].map((m) => ({
    name: m[1]!,
    index: m.index!,
  }));
  const names = new Set<string>();
  for (const declaration of code.matchAll(/emptyOutputIsHonest:\s*(true|false)/g)) {
    if (declaration[1] !== "false") {
      continue;
    }
    // The entry this declaration sits inside is the nearest one that opened
    // before it. Nothing re-joins or re-parses: the match indices are the
    // only ordering used.
    const owner = entryStarts.filter((start) => start.index < declaration.index!).at(-1);
    if (owner !== undefined) {
      names.add(owner.name);
    }
  }
  return [...names];
}

describe("the import gate itself", () => {
  /**
   * A gate is only worth having if it bites. These are the exact forms a
   * narrower regex would miss, asserted directly against the matcher so a
   * future simplification cannot quietly reopen one of them.
   */
  it("catches every import form, in any case", () => {
    const caught = [
      'import { EnvelopeLogEntry } from "guardian";',
      'import "guardian";',
      'const g = await import("guardian");',
      'type E = import("guardian").EnvelopeLogEntry;',
      'const g = require("guardian");',
      'import { EnvelopeLogEntry } from "Guardian";',
      'export { x } from "../../guardian/src/index.ts";',
    ].map((line) => ({ line, found: importsSpecifier(line, "guardian") }));

    expect(caught).toEqual(caught.map(({ line }) => ({ line, found: true })));
  });

  it("stays quiet on code that merely mentions the word", () => {
    const ignored = [
      'const label = "guardian";',
      "const guardian = startGuardian();",
      'import { renderEnvelopeLogEntry } from "./render.ts";',
    ].map((line) => ({ line, found: importsSpecifier(line, "guardian") }));

    expect(ignored).toEqual(ignored.map(({ line }) => ({ line, found: false })));
  });
});

describe("the host-vocabulary gate itself", () => {
  /**
   * Adding "refuse" to the term list above is worth nothing if the gate it
   * was added to cannot actually catch it -- a term added to a list nobody
   * exercises is exactly the "reads as coverage while enforcing nothing"
   * failure this whole suite exists to avoid (see `readSourceFiles`'s own
   * emptiness-check comment). Run against a scratch directory rather than
   * the real `packages/host-adapter/src` -- the real tree is what the gate
   * above already exercises, and it must stay clean; this checks the check,
   * the same split "the import gate itself" and "the source-file filter
   * itself" already make for their own helpers.
   */
  function withScratchSourceFile(code: string, fn: (dir: string) => void): void {
    const dir = mkdtempSync(join(tmpdir(), "acs-invariants-vocab-"));
    try {
      writeFileSync(join(dir, "leak.ts"), code);
      fn(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("catches 'refuse' when it appears in real code, not just when it's declared forbidden", () => {
    withScratchSourceFile('export function refuse(reason: string): void {\n  throw new Error(reason);\n}\n', (dir) => {
      expect(() => assertNoVocabulary(dir, ["refuse"])).toThrow();
    });
  });

  it("stays quiet when 'refuse' appears only in a comment, which stripComments removes", () => {
    withScratchSourceFile("// this module must never refuse to compile\nexport const ok = true;\n", (dir) => {
      expect(() => assertNoVocabulary(dir, ["refuse"])).not.toThrow();
    });
  });

  it("stays quiet on ordinary code naming none of the forbidden terms", () => {
    withScratchSourceFile("export function allow(): boolean {\n  return true;\n}\n", (dir) => {
      expect(() => assertNoVocabulary(dir, ["refuse"])).not.toThrow();
    });
  });

  /**
   * `tool.execute` is the first forbidden term carrying a regex
   * metacharacter, so it closes two different gaps at once:
   *
   *   - It pins that the term the gate above lists is one the gate can
   *     actually catch (the same argument as "catches 'refuse'..." above,
   *     applied to the OpenCode gate's own term rather than assumed to carry
   *     over).
   *   - It proves `escapeRegExp` is doing real work, not merely present.
   *     Without escaping, the literal `.` would compile to a regex `.` --
   *     any character -- so `"tool_execute"` (underscore, a different term
   *     nobody asked to forbid) would trip the same gate as
   *     `"tool.execute"` (dot, the real term). Escaped, only the literal dot
   *     matches.
   */
  it("catches 'tool.execute' literally, without over-matching its dot as regex 'any character'", () => {
    withScratchSourceFile('export const hookName = "tool.execute";\n', (dir) => {
      expect(() => assertNoVocabulary(dir, ["tool.execute"])).toThrow();
    });
    withScratchSourceFile('export const hookName = "tool_execute";\n', (dir) => {
      expect(() => assertNoVocabulary(dir, ["tool.execute"])).not.toThrow();
    });
  });
});

describe("the export-count gate itself", () => {
  /**
   * Mutation-tested: proves `exportedNames` actually distinguishes one
   * export from two, rather than always returning a fixed-length answer
   * that would let the real gate above pass no matter what `acs-plugin.ts`
   * exports. The case -- a second export appearing beside a working factory
   * -- is reproduced here directly, on a scratch file rather than the real
   * `hosts/opencode/acs-plugin.ts`: this checks the check, the same split
   * "the import gate itself" and "the host-vocabulary gate itself" already
   * make for their own helpers.
   */
  it("counts exactly one export on a file that declares one", () => {
    expect(exportedNames('export const AcsPlugin = async () => ({});\n')).toEqual(["AcsPlugin"]);
  });

  it("counts two exports, in source order, on a file that declares two -- the exact shape this gate exists to catch", () => {
    expect(
      exportedNames(
        'export function applyOpenCodeOutput(output, live) {}\n\nexport const AcsPlugin = async () => ({});\n',
      ),
    ).toEqual(["applyOpenCodeOutput", "AcsPlugin"]);
  });

  it("does not count a plain function or const that is not exported", () => {
    expect(exportedNames('function helper() {}\nconst AcsPlugin = async () => ({});\n')).toEqual([]);
  });

  it("does not mistake the word \"export\" inside a comment for a declaration", () => {
    // Mirrors this suite's own convention: callers pass comment-stripped
    // code, so a doc comment is never a source of a false export -- proven
    // here the same way "stays quiet when 'refuse' appears only in a
    // comment" proves it for assertNoVocabulary, just without needing
    // stripComments as an extra step, since the fixture is written already
    // comment-free at the code level being tested (a raw block comment
    // would not match `^export\s+...` at a line start regardless).
    expect(exportedNames('// acs-plugin.ts exports exactly one symbol\nexport const AcsPlugin = 1;\n')).toEqual([
      "AcsPlugin",
    ]);
  });

  it("does not count an import naming a symbol also used as an export's type", () => {
    expect(
      exportedNames('import { applyOpenCodeOutput } from "./apply-opencode-output.ts";\n\nexport const AcsPlugin = 1;\n'),
    ).toEqual(["AcsPlugin"]);
  });

  /**
   * The named-export list form (`export { a, b }`) matters because the gate
   * exists to catch a second export appearing however it is written, and a
   * list is exactly as valid a way to introduce one as a second declaration.
   * Reproduced here with the same mutation asserted against the real gate
   * below: without list-form matching, `const spurious = 1; export {
   * spurious };` beside a real factory export would leave `exportedNames`
   * returning a single-element array, and the gate would pass with the
   * hazard live.
   */
  it("counts a named-export list as an export", () => {
    expect(
      exportedNames('const spurious = 1;\nexport { spurious };\n\nexport const AcsPlugin = async () => ({});\n'),
    ).toEqual(["spurious", "AcsPlugin"]);
  });

  it("takes the local name from an aliased export-list entry, not the exported-as name", () => {
    expect(exportedNames('const spurious = 1;\nexport { spurious as notSpurious };\n')).toEqual(["spurious"]);
  });

  it("counts every entry in a multi-name export list", () => {
    expect(exportedNames('export { a, b, c };\n')).toEqual(["a", "b", "c"]);
  });

  it("counts a pure re-export list (`export { x } from \"…\"`) the same way", () => {
    expect(exportedNames('export { helper } from "./helper.ts";\n')).toEqual(["helper"]);
  });

  it("preserves source order across a mix of declarations and export lists", () => {
    expect(
      exportedNames('export { early };\nconst early = 1;\nexport const AcsPlugin = 1;\nexport { late };\nconst late = 1;\n'),
    ).toEqual(["early", "AcsPlugin", "late"]);
  });
});

/**
 * The gate that reads `emptyOutputIsHonest` out of Claude Code's shim is
 * only worth having if the reading is right, and it reads source text
 * because that shim exports none of this and, at the time, was frozen -- see
 * `hooksWhereEmptyOutputIsDishonest` above for why that is past tense and what
 * holds the property now. So the parser gets
 * the same split treatment `exportedNames` and `importsSpecifier` already
 * have: the gate asserts about the real file, these assert about the
 * parser.
 *
 * The fixture below is the shape hosts/claude-code/acs-hook.ts actually
 * writes -- an object literal of two-space-indented entries, each with a
 * method and a flag -- not a minimal one, because the failure mode this
 * guards against is a parser that attributes a flag to the wrong entry.
 */
describe("the empty-render-honesty reader itself", () => {
  const TABLE =
    "const HOOK_EXPECTATIONS: Record<string, HookExpectation> = {\n" +
    "  PreToolUse: {\n" +
    "    assertDecisions(decisions, path, hookEventName) {\n" +
    "      return decisions;\n" +
    "    },\n" +
    "    emptyOutputIsHonest: false,\n" +
    "  },\n" +
    "  PostToolUse: {\n" +
    "    assertDecisions(decisions, path, hookEventName) {\n" +
    "      return decisions;\n" +
    "    },\n" +
    "    emptyOutputIsHonest: true,\n" +
    "  },\n" +
    "};\n";

  it("names the entry whose flag is false, and only that one", () => {
    expect(hooksWhereEmptyOutputIsDishonest(TABLE)).toEqual(["PreToolUse"]);
  });

  it("names nothing when every entry's flag is true -- so the gate cannot pass by finding a false positive", () => {
    const allHonest = TABLE.replace("emptyOutputIsHonest: false", "emptyOutputIsHonest: true");
    expect(hooksWhereEmptyOutputIsDishonest(allHonest)).toEqual([]);
  });

  it("attributes the flag to the entry it sits inside, not to the first entry in the table", () => {
    // The mutation that matters: move `false` to the second entry. A parser
    // that reported "the first entry" or "every entry" would pass the test
    // above and be wrong here -- and wrong in the direction that lets a
    // `tools` key land on the gate that exits 2.
    const secondIsDishonest = TABLE.replace("emptyOutputIsHonest: false", "emptyOutputIsHonest: true").replace(
      "    emptyOutputIsHonest: true,\n  },\n};\n",
      "    emptyOutputIsHonest: false,\n  },\n};\n",
    );
    expect(hooksWhereEmptyOutputIsDishonest(secondIsDishonest)).toEqual(["PostToolUse"]);
  });

  it("ignores the flag named in a doc comment, since comments are stripped first", () => {
    // hosts/claude-code/acs-hook.ts's own header discusses
    // `emptyOutputIsHonest` in prose several times; a reader that counted
    // those would name gates that do not exist.
    const commented =
      "/**\n * `emptyOutputIsHonest: false` is what makes an absent wrapper a throw.\n */\n" +
      "const HOOK_EXPECTATIONS = {\n  PostToolUse: {\n    emptyOutputIsHonest: true,\n  },\n};\n";
    expect(hooksWhereEmptyOutputIsDishonest(commented)).toEqual([]);
  });
});

describe("the source-file filter itself", () => {
  /**
   * `Glob.scanSync`'s relative paths never carry a leading slash, so a
   * `test/` directory sitting directly under the scanned root -- rather than
   * nested deeper -- produces a path with no `/test/` substring at all. No
   * scanned package has such a directory today (each puts `test/` as a
   * sibling of `src/`, never inside it), so this was stricter-than-intended
   * rather than a real hole, but it is still the exact case a bare
   * `.includes("/test/")` misses.
   */
  it("excludes a test/ segment at the start of the path, not only when nested", () => {
    const paths = ["test/invariants.test.ts", "src/test/helper.ts", "packages/foo/test/bar.ts"].map((path) => ({
      path,
      excluded: isUnderTestDir(path),
    }));

    expect(paths).toEqual(paths.map(({ path }) => ({ path, excluded: true })));
  });

  it("does not exclude a segment that merely starts with the letters 'test'", () => {
    const paths = ["latest/foo.ts", "testing/bar.ts", "src/index.ts"].map((path) => ({
      path,
      excluded: isUnderTestDir(path),
    }));

    expect(paths).toEqual(paths.map(({ path }) => ({ path, excluded: false })));
  });
});

/**
 * `hosts/opencode/acs-plugin.ts` decides what a hookmap must declare for each
 * decision by consulting two hand-written tables -- `CARRIED_AT_REQUEST_GATE`
 * and `CARRIED_AT_RESULT_GATE` -- which say, per gate per decision, which
 * decision field that decision actually arrives carrying (or `null` for "it
 * carries nothing this host could land, so refusing is its only honest shape").
 *
 * Those tables are a fail-open generator if they are wrong. Two concrete ways
 * they can be wrong, both silent without this gate:
 *
 *   - the result gate's table could claim `ask`/`defer` carry `applied_output`.
 *     `withResultOutput` returns both untouched, so the sink the gate demanded
 *     would be unfillable and a real `ask` would deliver the tool's output in
 *     the leaf and its mirror.
 *   - the request gate's table could claim `modify` carries `applied_input`.
 *     That is true only while the entry declares `arguments:` -- an entry
 *     declaring `outputs:` gets an output location, and `resolveModify` fills
 *     `applied_output` instead.
 *
 * A table hand-derived from another package's behaviour can go stale the
 * moment that package changes, and the failure direction is silent
 * (over-refusal is loud; under-refusal is a delivered secret). This gate is
 * what makes it loud in both directions: for every decision name at both
 * gates it asks the adapter what that decision ends up carrying, and asserts
 * the answer matches the table the shim is enforcing.
 *
 * Which adapter function answers depends on the decision. `withResultOutput`
 * decides `allow`/`deny`/`ask`/`defer`. `modify` is `resolveModify`'s -- it is
 * the only decision whose table entry differs between the two gates, since
 * `resolveModify` decides which field a `modify` carries off exactly the
 * `outputLocation` presence the two tables differ on. This gate calls
 * `resolveModify` itself rather than hand-seeding the field it asserts,
 * because re-implementing that branch inline would make the request-gate
 * assertion a tautology: `withResultOutput(x, undefined)` returns `x` by
 * identity regardless of whether the branch under test is correct.
 *
 * Lives here, not in hosts/opencode/test/, for the reason this file states
 * for its own sibling gates: the claim needs two artifacts at once -- the
 * shim's table and the adapter's behaviour -- and neither package's own
 * suite owns both. Same placement argument as the `tools`-at-PreToolUse gate
 * and the export-count gate above.
 *
 * This package's boundary -- knowing ACS and hookmaps, nothing else -- is
 * not at risk from this file naming `applied_input`/`applied_output`: those
 * are ACS's own decision-message vocabulary, not any host's field names, and
 * the vocabulary gates above deliberately scope to
 * `packages/host-adapter/src` rather than to this suite.
 */
describe("the shim's decision tables match the adapter's actual behaviour", () => {
  /**
   * The tables as `hosts/opencode/acs-plugin.ts` declares them. Duplicated
   * here rather than exported: `acs-plugin.ts` exports exactly one symbol, and
   * the export-count gate above exists precisely because a second export
   * disables governance for a whole OpenCode session. So the shim's copy stays
   * module-private and this gate re-states it -- which is also what makes the
   * assertion meaningful, since a gate importing the value it checks would
   * only ever be asserting that a constant equals itself.
   *
   * A divergence between this copy and the shim's is a real risk, and it is
   * covered: every entry below is asserted against the adapter, so a shim
   * table that drifts away from this one drifts away from the adapter too and
   * fails hosts/opencode/test/acs-plugin.test.ts's own accept cases.
   */
  const EXPECTED_CARRIED = {
    "tool.execute.before": { allow: undefined, deny: null, ask: null, defer: null, modify: "applied_input" },
    // `ask`/`defer` carry `applied_output` at the RESULT gate and nothing at
    // the request gate, and that asymmetry is the claim: a step that has
    // already run leaves nothing to ask about and nothing to hold pending, so
    // `withholdsAtResultGate` folds both onto the withholding side there while
    // the request gate keeps its three-valued reading.
    "tool.execute.after": {
      allow: undefined,
      deny: "applied_output",
      ask: "applied_output",
      defer: "applied_output",
      modify: "applied_output",
    },
  } as const;

  const OUTPUT_LOCATION: HostOutputLocation = {
    payload: { result: { output: "SECRET", metadata: { output: "SECRET", exit: 0 } } },
    outputs: { from: "$.result.output", within: "$.result" },
  };

  /**
   * A real envelope and a real `modifications` block per gate, so
   * `resolveModify` below takes its success path rather than its
   * `modifications_invalid` deny -- and so each gate exercises the branch it
   * actually takes.
   *
   * The two differ because `modificationDocumentOf` (build-envelope.ts) makes
   * them differ, and its own doc comment says why: a request payload's pointers
   * address the arguments bag, so the document is that bag unwrapped; a result
   * payload's pointers address the payload itself (`/outputs/0/value`), so the
   * document is the payload. Handing the result gate a request-shaped document
   * is the exact hazard that comment records -- every result-gate `modify`
   * failing closed as `deny(modifications_invalid)` -- so getting this right
   * here is part of what makes the assertion real rather than a shape that
   * happens to survive.
   */
  const envelopeOf = (payload: Record<string, unknown>) =>
    ({ params: { payload } }) as unknown as Parameters<typeof modificationDocumentOf>[0];

  const MODIFY_INPUT = {
    "tool.execute.before": {
      envelope: envelopeOf({ tool: { name: "bash" }, arguments: { command: { value: "echo ghp_ABCDEF123456" } } }),
      modifications: { parameter_overrides: { command: "echo [REDACTED]" } },
    },
    "tool.execute.after": {
      envelope: envelopeOf({ tool: { name: "bash" }, exit_status: "success", outputs: [{ value: "SECRET" }] }),
      modifications: { redactions: [{ path: "/outputs/0/value", replacement: "[REDACTED]" }] },
    },
  } as const;

  /**
   * What the adapter actually leaves on a decision of this name at this gate,
   * composed the way `governStep`'s own `render()` composes it: the result gate
   * passes an output location, the request gate passes `undefined`.
   *
   * `modify` is handed an `applied_input`/`applied_output` the way
   * `validateDecision` would have left one, because `withResultOutput` throws
   * on a `modify` carrying neither -- that throw is itself part of the
   * behaviour this asserts, and it is checked separately below.
   */
  function carriedByAdapter(hookEventName: keyof typeof EXPECTED_CARRIED, decisionName: string): string | null | undefined {
    const location = hookEventName === "tool.execute.after" ? OUTPUT_LOCATION : undefined;
    const seed: Record<string, unknown> = { decision: decisionName, reasoning: "why" };
    let arriving = seed as unknown as AcsDecision;
    if (decisionName === "modify") {
      // `resolveModify` itself, not a hand-seeded stand-in for it. This is
      // the branch that decides which field a `modify` carries, and it
      // decides it off exactly the same `outputLocation` presence the two
      // tables differ on -- so calling it is the only way this row is not
      // asserting a constant against itself.
      const input = MODIFY_INPUT[hookEventName];
      arriving = resolveModify(
        { decision: "modify", reasoning: "why", modifications: input.modifications } as unknown as AcsDecision,
        modificationDocumentOf(input.envelope),
        location,
      ) as unknown as AcsDecision;
      // Sanity: the rewrite really was applicable, so a `deny` substitution
      // (resolveModify's own failure path) is not what this row measured.
      expect((arriving as unknown as { decision: string }).decision).toBe("modify");
    }
    const projected = withResultOutput(arriving, location) as Record<string, unknown>;
    const carries = ["applied_input", "applied_output"].filter((field) => projected[field] !== undefined);
    if (carries.length === 0) {
      return null;
    }
    expect({ decisionName, carries }).toEqual({ decisionName, carries: [carries[0]!] });
    return carries[0]!;
  }

  it.each(["tool.execute.before", "tool.execute.after"] as const)(
    "%s: every decision the shim's table names carries what the table says it carries",
    (hookEventName) => {
      const expected = EXPECTED_CARRIED[hookEventName];
      for (const [decisionName, declared] of Object.entries(expected)) {
        if (declared === undefined) {
          // `allow` is the one decision both tables deliberately omit. Asserted
          // rather than skipped: if the adapter ever started attaching a
          // replacement to an `allow`, the shim would be leaving a landable
          // decision unchecked.
          expect({ decisionName, carries: carriedByAdapter(hookEventName, decisionName) }).toEqual({
            decisionName,
            carries: null,
          });
          continue;
        }
        expect({ hookEventName, decisionName, carries: carriedByAdapter(hookEventName, decisionName) }).toEqual({
          hookEventName,
          decisionName,
          carries: declared,
        });
      }
    },
  );

  it("the result gate's `modify` entry rests on a throw, and that throw is real", () => {
    // `CARRIED_AT_RESULT_GATE` says `modify` carries `applied_output`. That is
    // true only because `withResultOutput` refuses to return a result-gate
    // `modify` that does not -- result-output.ts calls that guard "a call-site
    // invariant" rather than a structural one, so the table's correctness rests
    // on it and this pins it.
    expect(() =>
      withResultOutput({ decision: "modify", reasoning: "why" } as unknown as AcsDecision, OUTPUT_LOCATION),
    ).toThrow(/carrying no applied output/);
  });

  it("a request gate genuinely gets no output location, which is what makes its table differ", () => {
    // The other half of the same fact: the two tables differ for `modify`
    // only because the request gate passes no location.
    // `assertEntryMatchesGate` (acs-plugin.ts) is what keeps a request-gate
    // entry from acquiring one.
    const projected = withResultOutput(
      { decision: "deny", reasoning: "why" } as unknown as AcsDecision,
      undefined,
    ) as Record<string, unknown>;
    expect(projected.applied_output).toBeUndefined();
  });
});
