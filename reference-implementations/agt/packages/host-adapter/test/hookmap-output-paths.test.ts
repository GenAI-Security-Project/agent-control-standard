import { describe, expect, it } from "bun:test";
import { mkdtempSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHookmap, type Hookmap } from "../src/build-envelope.ts";
import { renderDecision } from "../src/render-decision.ts";

/**
 * `renderDecision` throws when a decision's output declares one path twice, or
 * one path under another, or a path with an empty or reserved segment. It
 * throws when a decision for that entry arrives, and the delivery posture
 * answers the throw: under `proceed` the decision is dropped and the step runs
 * as though it had never been made. These tests pin that `loadHookmap` asks the
 * same question at load time, so the hookmap never gets to govern.
 */

function withHookmapFile(content: string, fn: (path: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "acs-hookmap-output-paths-"));
  const path = join(dir, "hookmap.yaml");
  writeFileSync(path, content);
  try {
    fn(path);
  } finally {
    unlinkSync(path);
    rmdirSync(dir);
  }
}

const HEAD =
  "host: test-host\nhooks:\n  PreToolUse:\n    acs_method: steps/toolCallRequest\n    tool_name: $.tool_name\n" +
  "    arguments: $.tool_input\n    decisions:\n";
const ALLOW = '      allow: { output: { "x.decision": { value: allow } } }\n';
const DENY = '      deny: { output: { "x.decision": { value: deny } } }\n';

/** A hookmap whose `modify` entry carries the given output block. */
const withModify = (output: string): string => `${HEAD}${ALLOW}${DENY}      modify: { output: { ${output} } }\n`;

describe("loadHookmap rejects an output block whose paths collide", () => {
  it("when one path sits under another, parent first", () => {
    const text = withModify('"a.b": { value: 1 }, "a.b.c": { value: 2 }');
    withHookmapFile(text, (path) => {
      expect(() => loadHookmap(path)).toThrow(/"hooks\.PreToolUse\.decisions\.modify" output paths "a\.b" and "a\.b\.c" collide/);
    });
  });

  it("when one path sits under another, child first", () => {
    const text = withModify('"a.b.c": { value: 2 }, "a.b": { value: 1 }');
    withHookmapFile(text, (path) => {
      expect(() => loadHookmap(path)).toThrow(/output paths "a\.b\.c" and "a\.b" collide/);
    });
  });

  it("when the colliding paths are not adjacent in the block", () => {
    const text = withModify('"a.b": { value: 1 }, "z": { value: 0 }, "a.b.c.d": { value: 2 }');
    withHookmapFile(text, (path) => {
      expect(() => loadHookmap(path)).toThrow(/output paths "a\.b" and "a\.b\.c\.d" collide/);
    });
  });

  // The posture's own fallback render uses `allow` and `deny`, so a collision
  // there is the one case where the answer to a failure would itself fail.
  it("in the allow entry, which the delivery posture renders", () => {
    const text = `${HEAD}      allow: { output: { "x.a": { value: 1 }, "x.a.b": { value: 2 } } }\n${DENY}`;
    withHookmapFile(text, (path) => {
      expect(() => loadHookmap(path)).toThrow(/"hooks\.PreToolUse\.decisions\.allow" output paths/);
    });
  });
});

describe("loadHookmap rejects an output path that names no field", () => {
  for (const [name, key] of [
    ["an empty segment in the middle", "a..b"],
    ["a trailing dot", "a."],
    ["a leading dot", ".a"],
    ["a reserved segment at the end", "a.__proto__"],
    ["a reserved segment at the start", "constructor.x"],
    ["a reserved segment in the middle", "a.prototype.b"],
  ] as const) {
    it(`for ${name}`, () => {
      withHookmapFile(withModify(`"${key}": { value: 1 }`), (path) => {
        expect(() => loadHookmap(path)).toThrow(/names the segment .*, which addresses no field/);
      });
    });
  }
});

describe("loadHookmap accepts output blocks that can be written together", () => {
  it("for sibling paths, and for names that merely start the same way", () => {
    for (const output of [
      '"a.b": { value: 1 }, "a.c": { value: 2 }',
      '"a.b": { value: 1 }, "a.bc": { value: 2 }',
      '"a.b": { value: 1 }, "ab.c": { value: 2 }',
      '"a": { value: 1 }, "b": { value: 2 }',
    ]) {
      withHookmapFile(withModify(output), (path) => {
        expect(() => loadHookmap(path)).not.toThrow();
      });
    }
  });

  it("for the hookmaps this tree ships", () => {
    for (const path of ["hosts/claude-code/claude-code.hookmap.yaml", "hosts/opencode/opencode.hookmap.yaml"]) {
      expect(() => loadHookmap(path)).not.toThrow();
    }
  });
});

/**
 * The check is only worth having while it is the same question
 * `renderDecision` asks. So every block above is also handed to the renderer as
 * the parsed YAML, bypassing `loadHookmap`: what load rejects must be what
 * render throws on, and what load accepts must render.
 */
describe("what loadHookmap rejects is what renderDecision throws on", () => {
  const rendered = (output: string): (() => unknown) => {
    const hookmap = Bun.YAML.parse(withModify(output)) as Hookmap;
    return () => renderDecision("PreToolUse", { decision: "modify" }, hookmap);
  };

  it("throws for every rejected block", () => {
    for (const output of [
      '"a.b": { value: 1 }, "a.b.c": { value: 2 }',
      '"a.b.c": { value: 2 }, "a.b": { value: 1 }',
      '"a..b": { value: 1 }',
      '"a.__proto__": { value: 1 }',
    ]) {
      expect(rendered(output)).toThrow();
    }
  });

  it("renders every accepted block", () => {
    for (const output of ['"a.b": { value: 1 }, "a.c": { value: 2 }', '"a.b": { value: 1 }, "a.bc": { value: 2 }']) {
      expect(rendered(output)).not.toThrow();
    }
  });
});
