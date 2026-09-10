/**
 * reserved-segments.ts's own tests: `isReservedSegment` and `findReservedKey`
 * in isolation, before either is exercised through a caller
 * (`modifications.ts`'s redaction/override checks, or a host applier's
 * rendered-value walk). See that module's own header for the duplication
 * this file's subjects retire and the two-job distinction that stays split.
 */
import { describe, expect, it } from "bun:test";
import { findReservedKey, isReservedSegment } from "../src/reserved-segments.ts";

describe("isReservedSegment", () => {
  it("is true for exactly the three JavaScript prototype-machinery names", () => {
    expect(isReservedSegment("__proto__")).toBe(true);
    expect(isReservedSegment("constructor")).toBe(true);
    expect(isReservedSegment("prototype")).toBe(true);
  });

  it("is false for an ordinary field name, including ones a bare property read would resolve on any object", () => {
    // "toString"/"hasOwnProperty" resolve through the prototype chain on
    // any plain object, exactly like the three reserved names do -- but
    // unlike them, assigning to one doesn't repoint anything; it just
    // shadows an inherited method with an ordinary own property. Not
    // reserved, and this module doesn't claim it is.
    expect(isReservedSegment("env")).toBe(false);
    expect(isReservedSegment("command")).toBe(false);
    expect(isReservedSegment("toString")).toBe(false);
    expect(isReservedSegment("hasOwnProperty")).toBe(false);
  });
});

describe("findReservedKey", () => {
  it("finds nothing in a value that owns none of the three names, at any depth", () => {
    expect(findReservedKey({ env: { PATH: "/bin" }, list: [{ a: 1 }] }, "value")).toBeUndefined();
  });

  it("finds nothing for a primitive, null, or undefined value", () => {
    expect(findReservedKey("x", "value")).toBeUndefined();
    expect(findReservedKey(42, "value")).toBeUndefined();
    expect(findReservedKey(null, "value")).toBeUndefined();
    expect(findReservedKey(undefined, "value")).toBeUndefined();
  });

  it("finds a reserved key owned at the top level", () => {
    const value = JSON.parse('{"__proto__":{"polluted":true}}') as Record<string, unknown>;
    expect(findReservedKey(value, "args")).toEqual({ path: "args.__proto__", key: "__proto__" });
  });

  it("finds a reserved key nested inside a plain object, at any depth", () => {
    const value = { env: { nested: { constructor: "x" } } };
    expect(findReservedKey(value, "args")).toEqual({
      path: "args.env.nested.constructor",
      key: "constructor",
    });
  });

  it("finds a reserved key nested inside an array element", () => {
    const value = { items: [{ safe: 1 }, { prototype: "x" }] };
    expect(findReservedKey(value, "result")).toEqual({ path: "result.items[1].prototype", key: "prototype" });
  });

  it("does not throw -- callers word and type their own refusal", () => {
    // Detection only, never a throw: modifications.ts needs
    // ModificationsInvalidError, apply-opencode-output.ts needs its own
    // mergeInPlace-specific wording, and neither is this module's contract
    // to keep -- see this file's own header (findReservedKey's doc comment).
    const value = JSON.parse('{"__proto__":{}}') as Record<string, unknown>;
    expect(() => findReservedKey(value, "args")).not.toThrow();
  });
});
