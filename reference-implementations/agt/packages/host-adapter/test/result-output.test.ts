import { describe, expect, it } from "bun:test";
import { loadHookmap } from "../src/build-envelope.ts";
import {
  assertOutputIsReplaceable,
  projectAppliedOutput,
  replacingOutput,
  WITHHELD_OUTPUT,
  type HostOutputLocation,
} from "../src/result-output.ts";

/**
 * `replacingOutput`'s discipline is to patch a clone of the object a hookmap
 * names, so every sibling survives by construction. On a host where one
 * sibling is a genuine mirror of the leaf -- its own copy of the same text,
 * not merely a neighbouring field -- that discipline is exactly the property
 * that leaks: the clone preserves the mirror untouched, and the mirror still
 * carries the plaintext.
 *
 * The example paths below (`$.result.output`, `$.result.metadata.output`)
 * are a stand-in shape, not any real host's field names -- this module names
 * no host field, and neither does this test.
 */
describe("replacingOutput — a leaf can have mirrors", () => {
  const location: HostOutputLocation = {
    payload: { result: { output: "SECRET", metadata: { output: "SECRET", exit: 0 } } },
    outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata.output"] },
  };

  it("patches every declared mirror as well as the leaf", () => {
    expect(replacingOutput(location, "[REDACTED]")).toEqual({
      output: "[REDACTED]",
      metadata: { output: "[REDACTED]", exit: 0 },
    });
  });

  // The post-condition only scans for an undeclared duplicate once a hookmap
  // has already declared at least one mirror -- firing on two
  // independently-equal fields with nothing declared broke a shipped host
  // (see the dedicated describe block below). The case this test pins is
  // "declared one, missed another."
  it("refuses when one mirror is declared but a second, undeclared one is left holding the original", () => {
    const partial: HostOutputLocation = {
      payload: {
        result: {
          output: "SECRET",
          metadata: { output: "SECRET" }, // declared below
          echo: { output: "SECRET" }, // NOT declared
        },
      },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata.output"] },
    };
    expect(() => replacingOutput(partial, "[REDACTED]")).toThrow(/still holds/);
  });

  // The degenerate case the substring form got wrong. A tool that produced no
  // output must still be replaceable -- otherwise every empty result is
  // withheld, since an empty string is a "substring" of every replacement.
  it("does not refuse an empty leaf just because the empty string is everywhere", () => {
    const empty: HostOutputLocation = {
      payload: { result: { output: "", metadata: { output: "", exit: 0 } } },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata.output"] },
    };
    expect(replacingOutput(empty, "[REDACTED]")).toEqual({
      output: "[REDACTED]",
      metadata: { output: "[REDACTED]", exit: 0 },
    });
  });

  // More than one declared mirror -- the loop has to leave none of them
  // holding the original, not merely the first.
  it("patches every mirror in a list of more than one, leaving none of them holding the original", () => {
    const twoMirrors: HostOutputLocation = {
      payload: {
        result: {
          output: "SECRET",
          echo: { output: "SECRET" },
          log: { last: { output: "SECRET" } },
        },
      },
      outputs: {
        from: "$.result.output",
        within: "$.result",
        mirrors: ["$.result.echo.output", "$.result.log.last.output"],
      },
    };
    expect(replacingOutput(twoMirrors, "[REDACTED]")).toEqual({
      output: "[REDACTED]",
      echo: { output: "[REDACTED]" },
      log: { last: { output: "[REDACTED]" } },
    });
  });

  // A mirror is a further path inside `within`, the same container the leaf
  // lives in -- not an arbitrary path anywhere in the payload.
  it("refuses a declared mirror that names a path outside `within`", () => {
    const outside: HostOutputLocation = {
      payload: { result: { output: "SECRET" }, other: { output: "SECRET" } },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.other.output"] },
    };
    expect(() => replacingOutput(outside, "[REDACTED]")).toThrow(/is not inside/);
  });

  it("does not mutate the payload the host handed us, mirror included", () => {
    replacingOutput(location, "[REDACTED]");
    expect(location.payload.result).toEqual({ output: "SECRET", metadata: { output: "SECRET", exit: 0 } });
  });

  // Claude Code's hookmap declares no `mirrors` at all -- `mirrors` is
  // optional, and an entry that never names one must behave as though the
  // post-condition were not there at all: nothing left over for it to catch.
  it("still works exactly as before when no `mirrors` are declared at all", () => {
    const noMirrors: HostOutputLocation = {
      payload: { tool_response: { stdout: "SECRET", stderr: "", interrupted: false } },
      outputs: { from: "$.tool_response.stdout", within: "$.tool_response" },
    };
    expect(replacingOutput(noMirrors, "[REDACTED]")).toEqual({
      stdout: "[REDACTED]",
      stderr: "",
      interrupted: false,
    });
  });
});

/**
 * Structural equality alone cannot distinguish "one field is a copy of
 * another" from "two fields independently hold the same value," and the
 * second case is the ordinary one for a silent command: Claude Code's real
 * `tool_response` is `{stdout, stderr, interrupted, isImage,
 * noOutputExpected}`, and `touch`, `mkdir`, `cd`, `export`, a successful
 * `grep -q` all produce `stdout === "" && stderr === ""` -- two
 * independently-empty fields, not a mirror. The post-condition only scans
 * for an undeclared duplicate once a hookmap has declared at least one
 * mirror (see the describe block above); a hookmap declaring none, like
 * Claude Code's, is never scanned at all.
 */
describe("replacingOutput — two independently-equal fields are not a mirror", () => {
  it("does not refuse two independently-equal fields when no mirrors are declared", () => {
    const location: HostOutputLocation = {
      payload: { result: { output: "", sibling: "" } },
      outputs: { from: "$.result.output", within: "$.result" },
    };
    expect(replacingOutput(location, "[REDACTED]")).toEqual({ output: "[REDACTED]", sibling: "" });
  });

  // The exact shape, loaded from the shipped hookmap file rather than typed
  // out by hand, so this test tracks the real file rather than a belief
  // about it: an empty stdout beside an empty stderr, at the result gate,
  // must not become a blocking preflight stop.
  it("does not block a silent command through the shipped Claude Code hookmap shape at the result gate", () => {
    const hookmap = loadHookmap("hosts/claude-code/claude-code.hookmap.yaml");
    const outputs = hookmap.hooks.PostToolUse?.outputs;
    if (outputs === undefined) {
      throw new Error('test fixture assumption broken: "PostToolUse" declares no "outputs" block');
    }

    const location: HostOutputLocation = {
      payload: {
        tool_response: { stdout: "", stderr: "", interrupted: false, isImage: false, noOutputExpected: true },
      },
      outputs,
    };

    // The preflight -- `governStep`'s own guard, run before any decision is
    // sought -- must not block the deployment over this shape.
    expect(() => assertOutputIsReplaceable(location)).not.toThrow();

    // And an actual withholding replacement must still be buildable, every
    // sibling field intact.
    expect(replacingOutput(location, WITHHELD_OUTPUT)).toEqual({
      stdout: WITHHELD_OUTPUT,
      stderr: "",
      interrupted: false,
      isImage: false,
      noOutputExpected: true,
    });
  });
});

/**
 * A declared mirror gets none of the leaf's own three guards for free, which
 * is a fail-open of the exact shape this module closes for the leaf,
 * reachable from a one-token hookmap typo. Each guard here mirrors one of
 * `replacingOutput`'s existing leaf checks; see that function's own doc
 * comment for the mapping.
 */
describe("replacingOutput — a declared mirror gets the leaf's own three guards", () => {
  it("refuses a mirror equal to `within` itself, rather than writing a stray key", () => {
    const location: HostOutputLocation = {
      payload: { result: { output: "SECRET", metadata: { output: "SECRET" } } },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result"] },
    };
    expect(() => replacingOutput(location, "[REDACTED]")).toThrow(/names the same object as "outputs\.within"/);
  });

  it("refuses a mirror that resolves to no value in the payload (a hookmap typo)", () => {
    const location: HostOutputLocation = {
      payload: { result: { output: "SECRET", metadata: { output: "SECRET" } } },
      // "outpt" -- a typo for "output". The payload only has "metadata.output".
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata.outpt"] },
    };
    expect(() => replacingOutput(location, "[REDACTED]")).toThrow(/resolves to no value in this payload/);
  });

  it("refuses an object-valued mirror a string replacement would clobber", () => {
    const location: HostOutputLocation = {
      payload: { result: { output: "SECRET", metadata: { output: "SECRET", exit: 0 } } },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata"] },
    };
    expect(() => replacingOutput(location, "[REDACTED]")).toThrow(
      /is a string where this tool produced a object/,
    );
  });

  it("refuses a mirror that overlaps the leaf itself", () => {
    const location: HostOutputLocation = {
      payload: { result: { output: "SECRET" } },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.output"] },
    };
    expect(() => replacingOutput(location, "[REDACTED]")).toThrow(
      /are not disjoint \(equal, ancestor, or descendant\)/,
    );
  });

  // The overlap has to be refused explicitly and before any patch, not left
  // to whichever symptom declaration order happens to produce: without this
  // check, descendant-then-ancestor would silently collapse the descendant's
  // edit while ancestor-then-descendant would throw `patchedClone`'s
  // generic, unrelated "no object to descend through" -- two different
  // symptoms for the same mistake. Both orders throw the same explicit
  // refusal here.
  it("refuses two overlapping mirrors the same way regardless of declaration order", () => {
    const payload = { result: { output: "SECRET", m: { output: "SECRET" } } };

    const descendantFirst: HostOutputLocation = {
      payload,
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.m.output", "$.result.m"] },
    };
    const ancestorFirst: HostOutputLocation = {
      payload,
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.m", "$.result.m.output"] },
    };

    expect(() => replacingOutput(descendantFirst, "[REDACTED]")).toThrow(
      /are not disjoint \(equal, ancestor, or descendant\)/,
    );
    expect(() => replacingOutput(ancestorFirst, "[REDACTED]")).toThrow(
      /are not disjoint \(equal, ancestor, or descendant\)/,
    );
  });
});

/**
 * `assertOutputIsReplaceable` calls `replacingOutput` with `WITHHELD_OUTPUT`
 * before any decision is sought (`governStep`'s own preflight, see
 * govern-step.ts). So a hookmap entry that declares a mirror but misses
 * another is refused there too -- not as a withholding deny, but as a
 * blocking stop for the deployment: the same throw, reached one route
 * earlier.
 */
describe("replacingOutput — the same refusal, reached from the preflight", () => {
  it("blocks the deployment at the preflight when one mirror is declared and a second is missed", () => {
    const location: HostOutputLocation = {
      payload: {
        result: {
          output: "SECRET",
          metadata: { output: "SECRET" }, // declared
          echo: { output: "SECRET" }, // NOT declared
        },
      },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata.output"] },
    };
    expect(() => assertOutputIsReplaceable(location)).toThrow(/still holds/);
  });

  it("passes the preflight once every mirror is declared", () => {
    const location: HostOutputLocation = {
      payload: { result: { output: "SECRET", metadata: { output: "SECRET" } } },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata.output"] },
    };
    expect(() => assertOutputIsReplaceable(location)).not.toThrow();
  });

  // A hookmap declaring no mirrors passes the preflight too, even though the
  // payload below has two independently-equal fields -- exactly the shape
  // that broke a shipped host.
  it("passes the preflight when no mirrors are declared, even with two independently-equal fields", () => {
    const location: HostOutputLocation = {
      payload: { result: { output: "", sibling: "" } },
      outputs: { from: "$.result.output", within: "$.result" },
    };
    expect(() => assertOutputIsReplaceable(location)).not.toThrow();
  });
});

/**
 * Gating post-condition 2 on `mirrors.length > 0` (the describe block above)
 * exempts a host that declares no mirrors, but it narrows the "holds the
 * same value means is a copy" conflation to mirror-declaring hosts rather
 * than removing it -- see `result-output.ts`'s own prose beside the scan for
 * why neither the conflation nor this over-refusal is fixable from a payload
 * alone. These two cases are known, deliberate over-refusals, not a
 * regression to chase -- a future reader who reproduces one of these should
 * not spend an afternoon looking for a bug that isn't here.
 */
describe("replacingOutput — the over-refusal the scan narrows but cannot remove", () => {
  // An unrelated field inside `within`, but outside the declared mirror,
  // that happens to be empty too.
  it("refuses when an unrelated field coincidentally holds the same empty value too (recorded, not closed)", () => {
    const location: HostOutputLocation = {
      payload: {
        result: {
          output: "",
          metadata: { output: "", error: "" }, // "error" is coincidence, not a copy of "output"
          title: "ls -q",
        },
      },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata.output"] },
    };
    // Blocked at the preflight -- exactly the "blocking stop, no audit" shape
    // a genuine leak gets, for a field that never held a copy of anything.
    expect(() => assertOutputIsReplaceable(location)).toThrow(/still holds/);
  });

  // An unrelated sibling outside `metadata` entirely, coincidentally equal
  // to a non-empty leaf.
  it("refuses when an unrelated field coincidentally holds the same non-empty value too (recorded, not closed)", () => {
    const location: HostOutputLocation = {
      payload: {
        result: {
          output: "ok",
          metadata: { output: "ok" },
          status: "ok", // coincidence, not a copy of "output"
        },
      },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata.output"] },
    };
    expect(() => replacingOutput(location, "[REDACTED]")).toThrow(/still holds/);
  });
});

/**
 * The leaf mask (excluding the leaf's own field from the undeclared-duplicate
 * scan, so a modification that never touched the leaf does not pre-empt
 * `projectAppliedOutput`'s own landing check with this function's "still
 * holds" message) has to extend to every declared mirror too, not the leaf
 * alone. With a mirror declared, a modification targeting something other
 * than the leaf (`/exit_status`, `/tool/name`) leaves the mirror position
 * patched with `original` as well as the leaf -- and an unmasked mirror
 * position would make the scan fire the same misleading message one field
 * over.
 */
describe("projectAppliedOutput — the leaf mask extends to declared mirrors", () => {
  it("reports the landing check's own message, not a false mirror refusal, when a modification never touches the leaf", () => {
    const location: HostOutputLocation = {
      payload: { result: { output: "SECRET", metadata: { output: "SECRET" }, exit_status: "success" } },
      outputs: { from: "$.result.output", within: "$.result", mirrors: ["$.result.metadata.output"] },
    };
    // The leaf is untouched in the applied document (still "SECRET"); only
    // `exit_status` changed. Both the leaf's own field and the declared
    // mirror's are left holding `original` by this -- correctly, since
    // nothing was ever asked to change either of them.
    const appliedDocument = { tool: { name: "t" }, exit_status: "failure", outputs: [{ value: "SECRET" }] };
    const originalDocument = { tool: { name: "t" }, exit_status: "success", outputs: [{ value: "SECRET" }] };

    expect(() => projectAppliedOutput(appliedDocument, originalDocument, location)).toThrow(
      /exactly as the step produced it/,
    );
  });
});

/**
 * The bundle check and its `withoutProjectedLeaf` helper, added to
 * `projectAppliedOutput`, are covered only indirectly elsewhere, through
 * validate-decision.test.ts's exercise of the whole `resolveModify` path.
 * This is the direct coverage: the bundle check itself, called straight
 * against `projectAppliedOutput`, and `withoutProjectedLeaf`'s fallback
 * branch -- reached only through `originalDocument`, since
 * `appliedDocument`'s own `outputs[0]` shape is already validated earlier in
 * the same function.
 */
describe("projectAppliedOutput — the bundle check, called directly", () => {
  const location: HostOutputLocation = {
    payload: { result: { output: "SECRET" } },
    outputs: { from: "$.result.output", within: "$.result" },
  };
  const originalDocument = { tool: { name: "t" }, exit_status: "success", outputs: [{ value: "SECRET" }] };

  it("lands a leaf-only rewrite with nothing left to catch", () => {
    const appliedDocument = { tool: { name: "t" }, exit_status: "success", outputs: [{ value: "[REDACTED]" }] };
    expect(projectAppliedOutput(appliedDocument, originalDocument, location)).toEqual({ output: "[REDACTED]" });
  });

  it("denies when the leaf lands but the document changed somewhere else too", () => {
    const appliedDocument = { tool: { name: "t" }, exit_status: "failure", outputs: [{ value: "[REDACTED]" }] };
    expect(() => projectAppliedOutput(appliedDocument, originalDocument, location)).toThrow(
      /changed more of the ACS result payload than the one leaf/,
    );
  });

  // `withoutProjectedLeaf`'s fallback branch: `originalDocument.outputs` is
  // not the `[{value}, ...]` shape the projected leaf lives in, so it falls
  // back to comparing `originalDocument` untouched rather than throwing --
  // and the untouched fallback still reports the mismatch as a real
  // difference, rather than pretending a leaf was found where none was.
  //
  // Only `originalDocument` can exercise this branch through
  // `projectAppliedOutput`'s public surface: `appliedDocument`'s own
  // `outputs[0]` is already required to be a plain object carrying "value" by
  // the check earlier in that function, so it always takes the other branch
  // (the leaf zeroed out, not the untouched document) -- which is exactly why
  // this is the fallback's only reachable shape of test here, and why it
  // denies rather than passing quietly: an eligible document compared against
  // an ineligible one can never serialise the same.
  it("does not crash when the original document's own outputs shape is malformed, and still reports the difference", () => {
    const appliedDocument = { tool: { name: "t" }, exit_status: "success", outputs: [{ value: "[REDACTED]" }] };
    const malformedOriginal = { tool: { name: "t" }, exit_status: "success", outputs: "not-the-projected-shape" };
    expect(() => projectAppliedOutput(appliedDocument, malformedOriginal, location)).toThrow(
      /changed more of the ACS result payload than the one leaf/,
    );
  });
});
