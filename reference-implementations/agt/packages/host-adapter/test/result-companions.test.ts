import { describe, expect, it } from "bun:test";
import { mkdtempSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHookmap } from "../src/build-envelope.ts";
import {
  assertOutputIsReplaceable,
  replacingOutput,
  withheldOutput,
  withResultOutput,
  WITHHELD_OUTPUT,
  type HostOutputLocation,
} from "../src/result-output.ts";

/**
 * A host's result object can carry more than one field the model reads. The
 * policy evaluates one of them, the leaf. A companion is another text field in
 * the same object that is not a copy of the leaf. A withholding replaces every
 * companion that holds text along with the leaf, and a redaction leaves them as
 * the host produced them.
 *
 * The paths below are the shape of Claude Code's Bash result, which is what the
 * shipped hookmap declares, but this module names no host field.
 */
const SECRET = "ghp_ABCDEF123456";

function bash(response: Record<string, unknown>, companions: string[] = ["$.tool_response.stderr"]): HostOutputLocation {
  return {
    payload: { tool_response: response },
    outputs: { from: "$.tool_response.stdout", within: "$.tool_response", companions },
  };
}

const FULL = { stdout: `TOKEN=${SECRET}`, stderr: `warn ${SECRET}`, interrupted: false, isImage: false };

describe("withheldOutput", () => {
  it("replaces the leaf and a companion that holds text, keeping every other field", () => {
    expect(withheldOutput(bash(FULL))).toEqual({
      stdout: WITHHELD_OUTPUT,
      stderr: WITHHELD_OUTPUT,
      interrupted: false,
      isImage: false,
    });
  });

  it("replaces the companion when the leaf is already empty", () => {
    expect(withheldOutput(bash({ ...FULL, stdout: "" }))).toEqual({
      stdout: WITHHELD_OUTPUT,
      stderr: WITHHELD_OUTPUT,
      interrupted: false,
      isImage: false,
    });
  });

  it("leaves an empty companion empty", () => {
    expect(withheldOutput(bash({ ...FULL, stderr: "" }))).toEqual({
      stdout: WITHHELD_OUTPUT,
      stderr: "",
      interrupted: false,
      isImage: false,
    });
  });

  it("skips a companion the payload does not carry, and adds no field", () => {
    const { stderr: _stderr, ...withoutStderr } = FULL;
    const out = withheldOutput(bash(withoutStderr));
    expect(out).toEqual({ stdout: WITHHELD_OUTPUT, interrupted: false, isImage: false });
    expect("stderr" in out).toBe(false);
  });

  it("withholds a companion when the leaf is absent, and adds no leaf", () => {
    const { stdout: _stdout, ...withoutStdout } = FULL;
    const out = withheldOutput(bash(withoutStdout));
    expect(out).toEqual({ stderr: WITHHELD_OUTPUT, interrupted: false, isImage: false });
    expect("stdout" in out).toBe(false);
  });

  it("throws when the leaf is absent and no companion holds text", () => {
    expect(() => withheldOutput(bash({ stderr: "", interrupted: false }))).toThrow(/nothing to withhold/);
    expect(() => withheldOutput(bash({ interrupted: false }))).toThrow(/nothing to withhold/);
  });

  it("throws on a companion that holds something other than text", () => {
    const location = bash(FULL, ["$.tool_response.interrupted"]);
    expect(() => withheldOutput(location)).toThrow(/holds a boolean, not text/);
  });

  it("patches a nested companion and a mirror together with the leaf", () => {
    const location: HostOutputLocation = {
      payload: { result: { output: "S", metadata: { output: "S", log: { tail: "T" } }, exit: 0 } },
      outputs: {
        from: "$.result.output",
        within: "$.result",
        mirrors: ["$.result.metadata.output"],
        companions: ["$.result.metadata.log.tail"],
      },
    };
    expect(withheldOutput(location)).toEqual({
      output: WITHHELD_OUTPUT,
      metadata: { output: WITHHELD_OUTPUT, log: { tail: WITHHELD_OUTPUT } },
      exit: 0,
    });
  });

  it("does not mutate the payload it was handed", () => {
    const location = bash({ ...FULL });
    withheldOutput(location);
    expect(location.payload).toEqual({ tool_response: FULL });
  });

  it("is replacingOutput, unchanged, when no companions are declared", () => {
    const location = bash(FULL, []);
    expect(withheldOutput(location)).toEqual(replacingOutput(location, WITHHELD_OUTPUT));
    expect(withheldOutput(location).stderr).toBe(FULL.stderr);

    const undeclared: HostOutputLocation = {
      payload: location.payload,
      outputs: { from: "$.tool_response.stdout", within: "$.tool_response" },
    };
    expect(withheldOutput(undeclared)).toEqual(replacingOutput(undeclared, WITHHELD_OUTPUT));
  });

  it("still throws what replacingOutput throws when there is no leaf and no companions", () => {
    const location = bash({ stderr: "x" }, []);
    expect(() => withheldOutput(location)).toThrow(/resolves to no value/);
  });

  it("still throws what replacingOutput throws when `within` is not an object", () => {
    const location: HostOutputLocation = {
      payload: { tool_response: "plain text" },
      outputs: { from: "$.tool_response.stdout", within: "$.tool_response", companions: ["$.tool_response.stderr"] },
    };
    expect(() => withheldOutput(location)).toThrow(/does not resolve to an object/);
  });
});

describe("withheldOutput rejects a companion that cannot be patched safely", () => {
  it("outside `within`", () => {
    expect(() => withheldOutput(bash(FULL, ["$.tool_input.command"]))).toThrow(/is not inside/);
  });

  it("equal to `within`", () => {
    expect(() => withheldOutput(bash(FULL, ["$.tool_response"]))).toThrow(/names the same object/);
  });

  it("equal to the leaf", () => {
    expect(() => withheldOutput(bash(FULL, ["$.tool_response.stdout"]))).toThrow(/not disjoint/);
  });

  it("overlapping a mirror", () => {
    const location: HostOutputLocation = {
      payload: { r: { out: "S", meta: { out: "S" } } },
      outputs: { from: "$.r.out", within: "$.r", mirrors: ["$.r.meta.out"], companions: ["$.r.meta"] },
    };
    expect(() => withheldOutput(location)).toThrow(/mirror .* not disjoint/);
  });

  it("overlapping another companion, whichever is listed first", () => {
    const payload = { r: { out: "S", a: { b: "x" } } };
    for (const companions of [["$.r.a", "$.r.a.b"], ["$.r.a.b", "$.r.a"], ["$.r.a", "$.r.a"]]) {
      const location: HostOutputLocation = { payload, outputs: { from: "$.r.out", within: "$.r", companions } };
      expect(() => withheldOutput(location)).toThrow(/companions .* not disjoint/);
    }
  });
});

describe("a redaction leaves companions as produced", () => {
  it("replacingOutput patches the leaf alone", () => {
    expect(replacingOutput(bash(FULL), "TOKEN=[REDACTED]")).toEqual({
      stdout: "TOKEN=[REDACTED]",
      stderr: FULL.stderr,
      interrupted: false,
      isImage: false,
    });
  });
});

describe("the callers that build a withholding", () => {
  it("assertOutputIsReplaceable asks withheldOutput, so a bad companion fails at preflight", () => {
    expect(() => assertOutputIsReplaceable(bash(FULL))).not.toThrow();
    expect(() => assertOutputIsReplaceable(bash(FULL, ["$.tool_input.command"]))).toThrow(/is not inside/);
    expect(() => assertOutputIsReplaceable(bash(FULL, ["$.tool_response.interrupted"]))).toThrow(/not text/);
  });

  it("withResultOutput withholds companions on deny, ask and defer", () => {
    for (const decision of ["deny", "ask", "defer"]) {
      const out = withResultOutput({ decision }, bash(FULL)) as { applied_output?: Record<string, unknown> };
      expect(out.applied_output).toEqual({
        stdout: WITHHELD_OUTPUT,
        stderr: WITHHELD_OUTPUT,
        interrupted: false,
        isImage: false,
      });
    }
  });

  it("withResultOutput leaves allow alone and passes a modify through untouched", () => {
    expect(withResultOutput({ decision: "allow" }, bash(FULL))).toEqual({ decision: "allow" });
    const modify = { decision: "modify", applied_output: { stdout: "TOKEN=[REDACTED]", stderr: FULL.stderr } };
    expect(withResultOutput(modify, bash(FULL))).toBe(modify);
  });
});

describe("outputs.companions at load time", () => {
  function withHookmapFile(content: string, fn: (path: string) => void): void {
    const dir = mkdtempSync(join(tmpdir(), "acs-hookmap-companions-"));
    const path = join(dir, "hookmap.yaml");
    writeFileSync(path, content);
    try {
      fn(path);
    } finally {
      unlinkSync(path);
      rmdirSync(dir);
    }
  }
  const POST_TOOL_USE =
    "host: claude-code\nhooks:\n  PostToolUse:\n    acs_method: steps/toolCallResult\n" +
    "    tool_name: $.tool_name\n    exit_status: { literal: success }\n" +
    "    decisions:\n" +
    "      allow: { output: { x: { value: y } } }\n" +
    "      deny: { output: { x: { value: y } } }\n";
  const outputsWith = (companions: string): string =>
    `${POST_TOOL_USE}    outputs: { from: $.tool_response.stdout, within: $.tool_response, companions: ${companions} }\n`;

  it("accepts a well-formed list", () => {
    withHookmapFile(outputsWith("[$.tool_response.stderr]"), (path) => {
      expect(loadHookmap(path).hooks.PostToolUse?.outputs?.companions).toEqual(["$.tool_response.stderr"]);
    });
  });

  it("throws when it is not a list of non-empty strings", () => {
    for (const bad of ["42", "[1]", '[""]', "stderr"]) {
      withHookmapFile(outputsWith(bad), (path) => {
        expect(() => loadHookmap(path)).toThrow(/"hooks\.PostToolUse\.outputs\.companions" is /);
      });
    }
  });

  it("throws when an entry is not a field inside `within`", () => {
    for (const bad of ["[$.tool_input.command]", "[$.tool_response]", "[$.tool_response.]"]) {
      withHookmapFile(outputsWith(bad), (path) => {
        expect(() => loadHookmap(path)).toThrow(/companions" entry .* is not a field inside "outputs\.within"/);
      });
    }
  });
});

describe("the shipped Claude Code hookmap", () => {
  const outputs = loadHookmap("hosts/claude-code/claude-code.hookmap.yaml").hooks.PostToolUse?.outputs;

  it("declares stderr as a companion of stdout", () => {
    expect(outputs?.from).toBe("$.tool_response.stdout");
    expect(outputs?.companions).toEqual(["$.tool_response.stderr"]);
  });

  it("withholds both on a real Bash result, and leaves a silent command alone", () => {
    if (outputs === undefined) {
      throw new Error('test fixture assumption broken: "PostToolUse" declares no "outputs" block');
    }
    const full = { stdout: `a ${SECRET}`, stderr: `b ${SECRET}`, interrupted: false, isImage: false, noOutputExpected: false };
    const withheld = withheldOutput({ payload: { tool_response: full }, outputs });
    expect(withheld).toEqual({
      stdout: WITHHELD_OUTPUT,
      stderr: WITHHELD_OUTPUT,
      interrupted: false,
      isImage: false,
      noOutputExpected: false,
    });
    expect(JSON.stringify(withheld)).not.toContain(SECRET);

    const silent = { stdout: "", stderr: "", interrupted: false, isImage: false, noOutputExpected: true };
    expect(withheldOutput({ payload: { tool_response: silent }, outputs })).toEqual({ ...silent, stdout: WITHHELD_OUTPUT });
  });
});
