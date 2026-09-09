import { describe, expect, it } from "bun:test";
import { applyModifications, ModificationsInvalidError } from "../src/modifications.ts";

const ARGS = { command: "echo ghp_ABCDEF123456", timeout: 30 };

describe("applyModifications — §6.3", () => {
  it("overrides named arguments and leaves the rest", () => {
    expect(applyModifications(ARGS, { parameter_overrides: { command: "echo [REDACTED]" } }))
      .toEqual({ command: "echo [REDACTED]", timeout: 30 });
  });

  it("replaces a redacted field with its replacement, defaulting to [REDACTED]", () => {
    expect(applyModifications(ARGS, { redactions: [{ path: "/command" }] }))
      .toEqual({ command: "[REDACTED]", timeout: 30 });
    expect(applyModifications(ARGS, { redactions: [{ path: "/command", replacement: "***" }] }))
      .toEqual({ command: "***", timeout: 30 });
  });

  it("does not mutate the arguments it was given", () => {
    const original = { command: "keep me" };
    applyModifications(original, { parameter_overrides: { command: "changed" } });
    expect(original).toEqual({ command: "keep me" });
  });

  // The only multi-segment path used elsewhere in this suite ("/env/TOKEN")
  // sits in a disjointness test that denies, so it never reaches the apply
  // loop. This applies a depth-2 redaction for real and checks both halves:
  // the new value, and that the nested object it descended into is left
  // alone -- the half a shallow clone would break.
  it("applies a depth-2 redaction without mutating the nested object it descends into", () => {
    const original = { env: { TOKEN: "secret", OTHER: "keep" } };
    const result = applyModifications(original, { redactions: [{ path: "/env/TOKEN" }] });

    expect(result).toEqual({ env: { TOKEN: "[REDACTED]", OTHER: "keep" } });
    expect(original).toEqual({ env: { TOKEN: "secret", OTHER: "keep" } });
    expect(original.env).not.toBe(result.env);
  });

  it("throws on a modifications object that violates §6.3", () => {
    expect(() => applyModifications(ARGS, { modified_content: "x", redactions: [{ path: "/command" }] }))
      .toThrow(ModificationsInvalidError);
  });

  // The same rule as validateDecision's own test for this, pinned here at
  // the applyModifications level directly.
  it("throws on a redaction with an empty path", () => {
    expect(() => applyModifications(ARGS, { redactions: [{ path: "" }] })).toThrow(ModificationsInvalidError);
    expect(() => applyModifications(ARGS, { redactions: [{ path: "/" }] })).toThrow(ModificationsInvalidError);
  });

  // A missing/non-string path must fail closed with a clean
  // ModificationsInvalidError, not a bare JS error surfaced from deep
  // inside the apply loop -- regardless of whether parameter_overrides is
  // also present.
  it("throws a clean ModificationsInvalidError on a missing or non-string redaction path, not raw JS error text", () => {
    expect(() => applyModifications(ARGS, { redactions: [{}] })).toThrow(ModificationsInvalidError);
    expect(() => applyModifications(ARGS, { redactions: [{ path: 42 }] })).toThrow(ModificationsInvalidError);
  });

  it("throws rather than creating an absent target, at either depth", () => {
    expect(() => applyModifications(ARGS, { parameter_overrides: { cmd: "x" } })).toThrow(ModificationsInvalidError);
    expect(() => applyModifications(ARGS, { redactions: [{ path: "/env/TOKEN" }] })).toThrow(ModificationsInvalidError);
    // Depth 2 where the first segment exists and the second does not.
    expect(() => applyModifications({ env: { OTHER: "x" } }, { redactions: [{ path: "/env/TOKEN" }] }))
      .toThrow(ModificationsInvalidError);
  });

  // A single-segment path still replaces the whole array wholesale; a
  // multi-segment path now legally descends into it via a real index.
  it("still replaces an array wholesale when the path names it directly", () => {
    expect(applyModifications({ items: ["a", "b"] }, { redactions: [{ path: "/items" }] }))
      .toEqual({ items: "[REDACTED]" });
    expect(applyModifications({ items: ["a", "b"] }, { redactions: [{ path: "/items/0" }] }))
      .toEqual({ items: ["[REDACTED]", "b"] });
  });

  it("applies a redaction addressing an array element", () => {
    const applied = applyModifications(
      { outputs: [{ value: "TOKEN=ghp_ABCDEF123456" }] },
      { redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=[REDACTED]" }] },
    );
    expect(applied).toEqual({ outputs: [{ value: "TOKEN=[REDACTED]" }] });
    expect(Array.isArray((applied as { outputs: unknown }).outputs)).toBe(true);
  });

  // The reason array descent is rejected without a real index: a naive
  // setAtPath rewrites the array as {"0": …}. That is not the edit that was
  // asked for, and it would reach the host as an object where it expects a
  // list.
  //
  // The object path guards that the caller's arguments are never mutated
  // twice over -- see "applies a depth-2 redaction..." above, which checks
  // both the new value and `original.env !== result.env`. The array path
  // guards it here for the first time: `setAtPath`'s array branch clones
  // with `target.slice()` before assigning the index, and a version that
  // assigned into `target` itself would still produce the right value here
  // while silently corrupting the arguments object a later step reuses --
  // the exact defect class this module exists to close, just moved from
  // the write to the clone.
  it("keeps an array an array, leaves its siblings alone, and does not mutate the original array", () => {
    const original = { outputs: [{ value: "a" }, { value: "TOKEN=ghp_REALSECRET" }] };
    const applied = applyModifications(original, {
      redactions: [{ path: "/outputs/1/value", replacement: "[REDACTED]" }],
    });

    expect(applied).toEqual({ outputs: [{ value: "a" }, { value: "[REDACTED]" }] });
    // The secret must still be sitting in the caller's own object after
    // applyModifications returns -- not just "the return value looked
    // right".
    expect(original).toEqual({ outputs: [{ value: "a" }, { value: "TOKEN=ghp_REALSECRET" }] });
    expect(original.outputs).not.toBe((applied as { outputs: unknown }).outputs);
  });

  it("rejects an index past the end rather than growing the array", () => {
    expect(() =>
      applyModifications({ outputs: [{ value: "a" }] }, { redactions: [{ path: "/outputs/7/value" }] }),
    ).toThrow(/addresses "\/outputs\/7", which is not present in the ACS document these pointers address/);
  });

  it("rejects a non-numeric segment into an array", () => {
    expect(() =>
      applyModifications({ outputs: [{ value: "a" }] }, { redactions: [{ path: "/outputs/value" }] }),
    ).toThrow(/addresses "\/outputs\/value", which is not present in the ACS document these pointers address/);
  });

  // "-" is RFC 6901's append token. Appending is not redacting.
  it("rejects the JSON-pointer append token", () => {
    expect(() =>
      applyModifications({ outputs: [{ value: "a" }] }, { redactions: [{ path: "/outputs/-/value" }] }),
    ).toThrow(/addresses "\/outputs\/-", which is not present in the ACS document these pointers address/);
  });

  // This is the module's stated reason for requiring the canonical digit
  // form instead of `Object.prototype.hasOwnProperty.call(array, segment)`:
  // arrays own "length", so a bare existence check would accept it as a
  // target. Left unguarded, `setAtPath` would compute `Number("length")` ->
  // `NaN`, write the replacement to the string key "NaN", and
  // applyModifications would return successfully with the original value
  // still sitting at index 0 -- a reported-as-applied modify that redacted
  // nothing, the worst defect class this project exists to catch.
  it("rejects the array's own \"length\" property rather than treating it as a target", () => {
    expect(() =>
      applyModifications({ outputs: [{ value: "a" }] }, { redactions: [{ path: "/outputs/length" }] }),
    ).toThrow(/addresses "\/outputs\/length", which is not present in the ACS document these pointers address/);
  });

  // RFC 6901 §4 defines an array index as either "0" or a non-zero digit
  // followed by more digits -- "01" is not a legal index token at all, not
  // a legal-but-out-of-range one. A two-element array is required here: on
  // a one-element array "01"'s numeric value (1) already fails the
  // `< length` bound, so the test would pass for the wrong reason (the
  // bound rule, not the leading-zero rule) and a relaxed pattern like
  // /^\d+$/ would slip through undetected.
  it("rejects a leading zero in an array index, even when the numeric value is in range", () => {
    expect(() =>
      applyModifications(
        { outputs: [{ value: "a" }, { value: "b" }] },
        { redactions: [{ path: "/outputs/01/value" }] },
      ),
    ).toThrow(/addresses "\/outputs\/01", which is not present in the ACS document these pointers address/);
  });

  // An argument whose value is legitimately absent-looking must still be
  // editable: `hasOwnProperty`, not truthiness or `!== undefined`, is what
  // decides existence, so a null-valued argument is a real target.
  it("treats a null-valued argument as present", () => {
    expect(applyModifications({ command: null }, { parameter_overrides: { command: "echo hi" } }))
      .toEqual({ command: "echo hi" });
  });
});

// Reserved-segment coverage at this level, directly against `applyModifications`
// -- the deny-with-reasoning shape for the identical checks is already pinned
// through `validateDecision` (validate-decision.test.ts), but nothing else
// here exercises `applyModifications` itself against a reserved redaction
// path or override key. `isReservedSegment` is imported
// (`reserved-segments.ts`), the one shared predicate every module-private
// copy of the name list now draws from -- see that module's own header.
//
// These tests assert the message, not only the error class. `ARGS` (line 4)
// owns none of `__proto__`, `constructor`, or `prototype`, so a version of
// these six tests that only checked `.toThrow(ModificationsInvalidError)`
// would pass for the wrong reason: `assertTargetExists` (below the reserved
// check, in source order) throws that identical error class for an absent
// target regardless of whether the reserved-segment check ever ran -- with
// `RESERVED_SEGMENTS` emptied entirely, this file's suite still passes. The
// message text is what discriminates the two: a reserved-segment refusal
// contains `names the reserved segment "<name>"`; an absent-target refusal
// contains `is not present in the ACS document` instead, naming neither of
// the three names. Regex-matched against the full segment name, not merely a
// substring, so a looser check that fired on any of the three could not
// silently cover for the others.
describe("reserved segments -- redaction paths and parameter_overrides keys", () => {
  for (const segment of ["__proto__", "constructor", "prototype"]) {
    it(`throws for a redaction path naming "${segment}" because it is reserved, not because the target is absent`, () => {
      expect(() => applyModifications(ARGS, { redactions: [{ path: `/${segment}` }] })).toThrow(
        new RegExp(`names the reserved segment "${segment}"`),
      );
    });

    it(`throws for a parameter_overrides key naming "${segment}" because it is reserved, not because the target is absent`, () => {
      expect(() => applyModifications(ARGS, { parameter_overrides: { [segment]: "y" } })).toThrow(
        new RegExp(`names the reserved segment "${segment}"`),
      );
    });
  }
});

describe("every modification has to land at its own target", () => {
  it("denies a parameter_override that rewrites a value to itself", () => {
    expect(() =>
      applyModifications({ command: "cat .env" }, { parameter_overrides: { command: "cat .env" } }),
    ).toThrow(ModificationsInvalidError);
  });

  it("denies a bundle whose non-leaf half changes nothing", () => {
    const document = { outputs: [{ value: "SECRET" }], exit_status: "success" };
    expect(() =>
      applyModifications(document, {
        redactions: [
          { path: "/outputs/0/value", replacement: "[REDACTED]" },
          { path: "/exit_status", replacement: "success" },
        ],
      }),
    ).toThrow(ModificationsInvalidError);
  });

  it("still applies a bundle where every modification changes its own target", () => {
    const document = { outputs: [{ value: "SECRET" }], exit_status: "success" };
    expect(
      applyModifications(document, {
        redactions: [
          { path: "/outputs/0/value", replacement: "[REDACTED]" },
          { path: "/exit_status", replacement: "failure" },
        ],
      }),
    ).toEqual({ outputs: [{ value: "[REDACTED]" }], exit_status: "failure" });
  });
});
