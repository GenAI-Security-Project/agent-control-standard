/**
 * The three JavaScript prototype-machinery names this codebase refuses
 * wherever a hookmap path, a rendered output path, or a rendered value's own
 * key could name one instead of a real field -- and the one place that list,
 * and the walker that checks a value against it, are defined.
 * `isReservedSegment` below is the one definition that `hookmap-path.ts`,
 * `render-decision.ts`, `modifications.ts`, and any host applier that
 * recurses into a rendered value all import, rather than each keeping its
 * own copy of the same three names.
 *
 * Two different jobs use these three names, and only the name list is
 * shared between them -- the checks themselves stay apart, on purpose:
 *
 *   - Path segments: refusing a path (already split into segments) whose
 *     segment names prototype machinery rather than resolving further into
 *     it. `hookmap-path.ts`'s `pathSegments` (a reader of the hookmap's own
 *     JSONPath-lite notation) and `render-decision.ts`'s `place` (a writer
 *     over dotted output paths that creates levels as it descends) both do
 *     this, each against its own path notation, each staying local to its
 *     own module -- folding them into one shared resolver would merge two
 *     different path languages rather than de-duplicate one.
 *     `modifications.ts`'s own redaction-path check (`pointerSegments`, a
 *     third path notation -- RFC 6901 JSON pointers) and its
 *     `parameter_overrides` key check are the same structural job: a caller
 *     with a name already in hand (a split path segment, or one object's own
 *     top-level key) asking "is this name reserved", not a caller descending
 *     into an arbitrarily nested value. Both stay local to
 *     `modifications.ts` for the same reason `place` stays local to
 *     `render-decision.ts` -- they reuse the name list below, nothing more.
 *   - Value trees: refusing a rendered value that owns a reserved key
 *     anywhere inside it, at any depth, once that value is about to be
 *     trusted rather than merely addressed by one named path.
 *     `findReservedKey` below is that walker, for any host applier that
 *     recurses into a rendered value in place. It does not throw: unlike the
 *     three-name list, a refusal's wording and error class are a fact about
 *     the caller, not about the walk. `modifications.ts` throws
 *     `ModificationsInvalidError` for every violation it finds (its own
 *     documented contract); a host applier throws its own error worded
 *     around its own measured hazard (a recursive in-place merge that reads
 *     a rendered value back through the prototype chain). Neither vocabulary
 *     is this module's to speak: an ACS §6.3 error class is fine for this
 *     package to use, since it names neither a host output field nor policy-
 *     runtime vocabulary, but a caller's error class and wording are a fact
 *     about that caller's own contract with its own callers, and this module
 *     has no way to know which contract a given caller needs to honour. So
 *     `findReservedKey` answers the one question every caller actually
 *     shares -- "does this value own a reserved key, and where" -- and
 *     returns, leaving the throw, the class, and the words to whoever asked.
 *
 * Sharing the three names across both jobs is fine and desirable, which is
 * why this file holds them once. Sharing the checks is not, because they
 * check different things -- a path a caller is about to resolve or write
 * into, against a value a caller is about to trust as a whole.
 *
 * The name list itself stays module-private rather than exported.
 * `ReadonlySet<string>` is a compile-time-only restriction; the underlying
 * object is a real, mutable `Set` at runtime, so an exported one could be
 * cast back to `Set<string>` and have `.delete()` called on it, silently
 * disabling one reserved name for the rest of the process. `isReservedSegment`
 * below is the read-only surface: a predicate a caller can query, never a
 * reference it can mutate.
 */
const RESERVED_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);

/** True when `name` is one of the three names above. The only way to read
 * this file's list from outside it -- see the header just above for why the
 * `Set` itself stays module-private rather than being exported. */
export function isReservedSegment(name: string): boolean {
  return RESERVED_SEGMENTS.has(name);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Walks `value` through every plain object and array it contains, at any
 * depth, and returns the first own key found that satisfies
 * `isReservedSegment` -- `{path, key}`, `path` being `label` extended by
 * every segment descended through to reach it (`args.env.__proto__`,
 * `result[2].prototype`) -- or `undefined` if none is found.
 *
 * Checks own keys only (`Object.keys`), never inherited ones: a value read
 * off the wire through `JSON.parse` can carry `__proto__` as an ordinary
 * own, enumerable data property -- `JSON.parse` never sets the real
 * `[[Prototype]]` link -- and that is exactly the shape this walker exists
 * to catch. Recurses into arrays too, so a reserved key nested inside a list
 * element is found the same way one nested inside an object field is.
 *
 * Stops at the first hit -- depth-first, keys in `Object.keys` order at each
 * level -- rather than collecting every violation: one reserved key already
 * means the value as a whole cannot be trusted, and every caller of this
 * function refuses on the first violation it finds for the same reason
 * `modifications.ts`'s own `assertValidModifications` does (it throws on the
 * first violation found and never partially validates).
 *
 * Does not throw. See this file's own header for why: the wording and the
 * error class both belong to the caller, not to the walk.
 */
export function findReservedKey(value: unknown, label: string): { path: string; key: string } | undefined {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const hit = findReservedKey(value[index], `${label}[${index}]`);
      if (hit !== undefined) {
        return hit;
      }
    }
    return undefined;
  }
  if (!isPlainObject(value)) {
    return undefined;
  }
  for (const key of Object.keys(value)) {
    if (isReservedSegment(key)) {
      return { path: `${label}.${key}`, key };
    }
    const hit = findReservedKey(value[key], `${label}.${key}`);
    if (hit !== undefined) {
      return hit;
    }
  }
  return undefined;
}
