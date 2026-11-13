/**
 * apply-opencode-output.ts -- `applyOpenCodeOutput`, the twin of the Claude
 * Code shim's own `asClaudeCodeOutput` (hosts/claude-code/acs-hook.ts) and a
 * module that knows exactly four OpenCode-shaped keys (`refuse`, `reason`,
 * `args`, `result`). Named for the host it applies to rather than
 * generically, so a reader is not invited to move it into
 * packages/host-adapter/: that package must not know any host's own field
 * names, and this module's whole reason to exist is that it does.
 *
 * A separate file from acs-plugin.ts, and not merely for tidiness.
 * OpenCode's plugin loader hands its own registration context to every
 * exported function of a plugin module, not only the one shaped like
 * `Plugin`, and calls each as a candidate factory. A second export next to
 * `AcsPlugin` is therefore live surface, not an inert convenience: a
 * non-function export placed beside a working factory produces
 * `error="Plugin export is not a function"`, and the factory is never
 * called at all -- one exported constant silently disables governance for
 * the whole session. That failure logs the byte-identical `level=ERROR
 * message="failed to load plugin" path=...` line a genuinely broken
 * hookmap also produces (one of the faults `assertHostAcceptsEveryDecision`,
 * acs-plugin.ts, exists to catch), with only the `error=` payload
 * differing -- so an operator watching logs cannot tell "a second,
 * harmless export got mis-invoked" from "the plugin never registered and
 * every tool call this session makes is now completely ungoverned" without
 * reading the payload character by character. The fix is not to make the
 * mis-invocation safer; it is to remove the second export, so OpenCode has
 * exactly one candidate to call. `hosts/opencode/acs-plugin.ts` exports
 * only `AcsPlugin`, and `test/invariants.test.ts` pins that mechanically.
 *
 * This file may name OpenCode's own types freely, but it may not reach
 * into `agt-bridge` or `guardian`'s server-side pieces, only
 * `host-adapter`'s public surface -- `test/invariants.test.ts`'s "every
 * host shim imports the adapter only" gate checks this file by name too,
 * alongside `acs-plugin.ts`.
 *
 * `isPlainObject` is duplicated here rather than imported from
 * `acs-plugin.ts`. The reserved-segment guard below is not duplicated the
 * same way: `findReservedKey` lives on `host-adapter`'s public surface
 * because a security invariant any host applier might need belongs in the
 * package both hosts run, not in this host's own source (the name list it
 * walks stays module-private inside `reserved-segments.ts`, importable by
 * nothing outside it, not even this file). `isPlainObject` is a
 * three-line structural-typing helper with no such invariant to drift, and
 * `acs-plugin.ts` needs its own copy of it regardless, so keeping two
 * small, identical functions is simpler and more honest than an import
 * whose only purpose is to avoid a few lines of duplication.
 */
import { findReservedKey, type HostOutput } from "host-adapter";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * True when `ACS_DEBUG` asks for the stderr line in pass 2b (below) to
 * fire. Unset or empty both mean "off", and so does the literal string
 * "0" -- an env var is always a string, so a bare truthiness check on it
 * would treat "0" as on, the one value every shell convention this flag is
 * meant to follow uses to mean off.
 */
function isDebugEnabled(): boolean {
  const value = process.env.ACS_DEBUG;
  return value !== undefined && value !== "" && value !== "0";
}

/**
 * Refuses `value` if it, or anything nested inside it, owns a reserved
 * prototype-machinery key (`__proto__`/`constructor`/`prototype`) -- called
 * from pass 1, below, on `output.args` and `output.result`, before
 * `mergeInPlace` ever runs.
 *
 * The walk itself is `host-adapter`'s `findReservedKey` (imported above),
 * not a copy kept here: the three reserved names live in one place shared
 * by every host applier that needs this check. `findReservedKey` does not
 * throw -- the wording and the error class below are this file's own,
 * because they describe this applier's specific hazard rather than a
 * generic one -- this function is the thin, host-specific wrapper that
 * turns a hit into the refusal below.
 *
 * `mergeInPlace` needs this and `Object.assign` would not. A value that
 * reaches this applier came off the Guardian's wire through `JSON.parse`,
 * which -- unlike an object literal in source -- gives `__proto__` an
 * ordinary own, enumerable property; `Object.keys`/`Object.entries` list
 * it like any other field. `mergeInPlace` walks those keys and, for each
 * one, reads `target[key]` and recurses when both sides are plain
 * objects. Read on a plain object with no own `__proto__` property,
 * `target["__proto__"]` resolves through the prototype chain to
 * `Object.prototype` itself, which `isPlainObject` accepts as a plain
 * object. The recursive call that follows then does not touch `target` at
 * all; every assignment inside it lands on `Object.prototype`, global to
 * the whole process -- and this host is one long-lived plugin object per
 * session, not a fresh subprocess per hook, so the blast radius is the
 * rest of the session, not one invocation. `Object.assign(target, source)`
 * never recurses, so it can only ever repoint `target`'s own `__proto__`
 * (itself refused elsewhere, in `render-decision.ts`'s `place`), never
 * write through it onto the shared one.
 *
 * Measured end to end, through the shipped hookmap and the unmodified
 * adapter: a `modify` decision whose `modifications.parameter_overrides`
 * carries an override value with `__proto__` intact reaches
 * `applied_input` unexamined (an override's own keys are checked against
 * these same three names, but the value at each key is applied verbatim),
 * `renderDecision` copies it into `args`, and without this check
 * `applyOpenCodeOutput` would merge it: `Object.prototype` itself gains
 * the attacker's field, observable on an unrelated, later, cleanly-allowed
 * tool call in the same process.
 *
 * Recurses through arrays too (an override value could as easily nest the
 * key inside a list element as inside an object), and refuses on the
 * first reserved key found anywhere in the tree, at any depth --
 * consistent with `assertNoReservedSegments` in `modifications.ts`, which
 * refuses the same way rather than trying to salvage the rest of a render.
 */
function assertNoReservedSegments(value: unknown, label: string): void {
  const hit = findReservedKey(value, label);
  if (hit !== undefined) {
    throw new Error(
      `apply-opencode-output: cannot apply rendered "${label}" -- it owns the reserved key ${JSON.stringify(hit.key)} at ` +
        `"${hit.path}", which addresses prototype machinery rather than a field this applier can merge. A ` +
        `recursive in-place merge (mergeInPlace, above) that touched this key would write through the ` +
        `prototype chain onto Object.prototype itself, global to this whole long-lived plugin process -- ` +
        `refused rather than merged.`,
    );
  }
}

/**
 * What this applier is allowed to touch: the live object OpenCode handed
 * the hook that is applying a rendered `HostOutput` -- tagged by which
 * gate is calling, rather than a bag with two optional fields a caller
 * asks the presence of. The request gate hands `{gate: "request", args}`;
 * the result gate hands `{gate: "result", result}`; a caller with neither
 * would have nothing for this function to do, so neither variant allows
 * that.
 *
 * The tag is the dispatch mechanism below, and knowing which of the two
 * checks that use it is actually load-bearing matters. `live.gate ===
 * "request"` is a plain property read, which resolves through the
 * prototype chain exactly like reading `live.args` directly would. What
 * comparing `gate` buys is real but narrower than immune: `args`/`result`
 * are `HostOutput`'s own field names, the exact vocabulary a rendered
 * decision -- and therefore the one pollution vector this codebase
 * actually produces (`assertNoReservedSegments`'s own doc comment, above)
 * -- could plausibly collide with; `gate` is neither, so nothing this
 * codebase's own attack surface writes to `Object.prototype` today lands
 * on it. But a `live.gate` read is only as trustworthy as `live` actually
 * owning a `gate` property, which holds today only because
 * `acs-plugin.ts`'s two hook methods each construct `live` as a fully
 * typed object literal with no cast, and hand it to that file's shared
 * `runExchange`.
 *
 * `Object.hasOwn(live, "args")` / `Object.hasOwn(live, "result")`, run
 * beside the `gate` compare in both pass 1 and pass 3 below, are what is
 * actually immune, on any key, regardless of what `Object.prototype`
 * carries -- own-key checks do not resolve through the chain at all. A
 * future call site that narrows the type with an unsafe cast could hand
 * this function a `live` whose `gate` says `"request"` while its `args`
 * field is actually absent, and if `Object.prototype.gate` were ever
 * polluted to match, the `gate` compare alone would be fooled the same
 * way a direct `live.args !== undefined` read would be.
 * `Object.hasOwn(live, ...)` is what still refuses that `live` correctly
 * regardless, matching pass 1's `Object.getOwnPropertyNames` basis and
 * pass 3's `Object.hasOwn(output, ...)` basis exactly.
 */
export type LiveHookObjects =
  | { gate: "request"; args: Record<string, unknown> }
  | { gate: "result"; result: Record<string, unknown> };

/**
 * Merges `source` onto `target`, in place and recursively through every
 * pair of matching plain-object fields.
 *
 * A shallow `Object.assign` is functionally correct for the shipped
 * hookmap -- every field `applied_output`/`applied_input` carries is
 * present in the merge source -- but it replaces a nested object like
 * `result.metadata` with a brand-new reference rather than mutating the
 * one already there. This applier's entire contract with OpenCode is
 * "mutate what you were handed," and nothing here can prove OpenCode
 * re-reads `metadata` off `result` after the hook returns rather than
 * holding a reference it took earlier: the one measurement on record
 * (opencode.hookmap.yaml's own header) covers mutating `metadata.output`
 * in place, and says nothing about a wholesale replacement of `metadata`
 * itself. A deep, in-place merge is immune to the question rather than
 * resting on an unmeasured assumption about which OpenCode actually does.
 *
 * A field present on `source` but absent on `target` is added. A field on
 * `target` whose value is not itself a plain object matching a plain
 * object on `source` is overwritten wholesale -- which is what every
 * actual non-container sibling here needs (a redacted `output` string;
 * `exit`, `truncated`), and covers arrays too: `isPlainObject` excludes
 * them, so `attachments` replaces rather than merges element-wise.
 */
function mergeInPlace(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(source)) {
    const existing = target[key];
    if (isPlainObject(existing) && isPlainObject(value)) {
      mergeInPlace(existing, value);
    } else {
      target[key] = value;
    }
  }
}

/**
 * Applies what `governStep` rendered onto the objects OpenCode handed this
 * hook -- the one piece of host semantics this file owns.
 *
 * The Claude Code shim writes the rendered `HostOutput` to stdout; this
 * host has no document to write. Its hooks return `void`, and the only
 * channel back to OpenCode is mutating `live.args`/`live.result` in place,
 * or throwing. So the same `HostOutput`, from the same `renderDecision`, is
 * applied instead of printed here, and the hookmap still decides which
 * disposition does which -- this function knows nothing about ACS
 * decisions, only about the four keys `opencode.hookmap.yaml` is allowed
 * to render.
 *
 * Validated whole, then applied whole. Every key of `output` is checked
 * before any assignment happens, in one pass with no side effects -- a
 * half-applied mutation (an argument rewritten while the redaction it
 * arrived beside was dropped because a later key turned out to be
 * unapplicable) is the one outcome worse than a refusal, the same rule
 * govern-step.ts states for writing half an output at the seam that
 * renders it for this host. A key this applier cannot honour throws
 * rather than being skipped, for the identical reason `renderDecision` and
 * `buildEnvelope` never skip a hookmap fault they could quietly ignore: a
 * silently-dropped field is a governed decision that only partially
 * arrived.
 *
 * Validation is also about shape, not only about which keys are present.
 * `output.args`/`output.result` are checked to be plain objects in the
 * same pass, before anything is merged: neither `Object.assign` nor
 * `mergeInPlace` throws on a non-object right-hand side, so a hookmap
 * sourcing `args` from a decision field that is not itself an object (a
 * `reasoning` string, say, where `applied_input` belongs) would otherwise
 * merge the string's own characters onto index keys while the actual
 * rewrite never lands -- reached silently instead of refused.
 *
 * Validation also walks into the shape, recursively, for one specific
 * hazard: `assertNoReservedSegments` (above) refuses an `args`/`result`
 * that owns a `__proto__`/`constructor`/`prototype` key at any depth, in
 * this same pass, before `mergeInPlace` -- which reads the rendered value
 * back through the prototype chain, unlike a shallow `Object.assign` --
 * ever runs on it. See that function's own doc comment for the hazard
 * this closes.
 *
 * Both passes below check `output`'s and `live`'s keys the same way:
 * `Object.getOwnPropertyNames(output)` and `Object.hasOwn`, rather than a
 * plain property read, on both objects. An ordinary property read
 * resolves through the prototype chain on an object that owns no field of
 * that name, so a polluted `Object.prototype.args` (the exact vector
 * `assertNoReservedSegments` closes upstream) could otherwise be read as a
 * real field on an object that was never handed one, and merged. Own-key
 * checks do not resolve through the chain at all, which is why both
 * passes use them -- see `LiveHookObjects`'s own doc comment for which of
 * the checks on the `live` side is actually load-bearing.
 *
 * The four keys, and why `result` is the whole container rather than a
 * leaf: `applied_output` is the whole patched clone of the object at the
 * result gate's `outputs.within`, mirror included, not the one leaf
 * `outputs.from` names. This host's own sink for it is `result` itself --
 * a string field would be a leaf; `result` here is the live `{title,
 * output, metadata, attachments}` object, the same relation the request
 * gate's `args` already has to `outputs.within`'s counterpart on that
 * side. Landing the leaf and its mirror together is why this merges the
 * whole container onto the live object rather than reaching one field
 * deep: a partial merge that touched `result.output` alone and left
 * `result.metadata.output` (the mirror) unpatched would leave the secret
 * sitting in OpenCode's own session record while the model saw the
 * redaction -- clean-looking, and a leak. `applied_output` already
 * carries both, patched together (result-output.ts's `replacingOutput`);
 * this function's job is only to land the container it is handed, not to
 * know which of its fields matter.
 *
 *   - `refuse` -- this host's only deny channel at the request gate:
 *     `output.status`/`output.decision` on that gate's own output object
 *     are both accepted and ignored by OpenCode, and the tool runs
 *     regardless, so throwing is what stops it. At the result gate
 *     `refuse` is the wrong channel and `result` (below) is the deny
 *     channel instead -- a throw there makes OpenCode discard this
 *     plugin's mutations and rebuild `metadata` from its own pre-hook
 *     copy, so the tool's output survives in OpenCode's session record
 *     however early the throw fires. Either way this key is never applied
 *     to anything -- it is read and thrown, before any assignment.
 *     `refuse.reason` is a `from:` field and therefore conditional; this
 *     host's load-time gate (`assertHostAcceptsEveryDecision`, in
 *     `acs-plugin.ts`) is what guarantees `refuse` itself is never
 *     entirely absent for a real request-gate `deny`/`ask`/`defer`.
 *   - `reason` -- declared-inert on this host: `reason.text` is declared
 *     on every disposition only because an empty `output` block fails
 *     `assertRenderableDecisions` upstream, not because OpenCode reads an
 *     explanation back from anywhere. Neither `args` nor `result` carries
 *     a field this host reads prose into, and the one channel that does
 *     carry text is `refuse`'s own thrown message. So this key is handled
 *     without pretending it was delivered (never assigned to `live.args`
 *     or `live.result`) and without being silently dropped either: it is
 *     written to stderr, honestly labelled as undelivered, but only when
 *     `ACS_DEBUG` is set -- an observe-only `allow` synthesizes
 *     `reasoning` for every governed step, so an unconditional stderr line
 *     here would fire on the common path of ordinary operation rather
 *     than only when something is actually being lost quietly. If this
 *     host ever grows a real sink for it, this is where that sink gets
 *     named.
 *   - `args` -- merged onto `live.args`, only when `live.gate ===
 *     "request"` (and `live` owns an `args` field -- see
 *     `LiveHookObjects`'s own doc comment for why both are checked). This
 *     is where a request-gate `modify`'s rewrite lands, and the only
 *     place it can: the same load-time gate requires `args: { from:
 *     applied_input }` on any `modify` the request gate declares, unless
 *     that `modify` refuses outright instead, because a `modify` with
 *     nowhere to land renders nothing, runs the tool unrewritten, and is
 *     still reported `stage: "honoured"`.
 *   - `result` -- merged onto `live.result`, only when `live.gate ===
 *     "result"` (same, for `result`). See above for why this is the whole
 *     container, not a leaf. This is the result gate's deny channel, the
 *     counterpart to `refuse` at the request gate, and the same load-time
 *     gate (`assertHostAcceptsEveryDecision`, in `acs-plugin.ts`)
 *     guarantees a result-gate `deny`/`modify` either declares `result: {
 *     from: applied_output }` -- that key, that source, a declaration
 *     that can actually render, and a hook that declares an `outputs`
 *     block for it to be filled from -- or declares an unconditional
 *     refusal instead, which throws through `refuse` above. `ask`/`defer`
 *     at that gate get only the second option: nothing ever attaches an
 *     `applied_output` to either of them (`withResultOutput`,
 *     result-output.ts), so a sink on one renders nothing however
 *     correctly it is written. Without it, a decision carrying a
 *     perfectly good `applied_output` renders nothing this function can
 *     land, and this applier applies nothing and throws nothing while the
 *     tool's output is delivered.
 *
 * A key this render declares that is none of the four above -- or one of
 * `args`/`result` at a gate that was not handed the live half it targets,
 * or one of `args`/`result` whose rendered value is not itself a plain
 * object -- throws rather than being skipped, naming the key, so a
 * hookmap fault of this shape (or a call from the wrong gate) fails
 * loudly instead of quietly discarding or corrupting whatever it could
 * not place.
 */
export function applyOpenCodeOutput(output: HostOutput, live: LiveHookObjects): void {
  // Pass 1: validate every key AND every value shape this applier is about
  // to touch. No assignment happens in this loop -- only a throw (refusing
  // everything) or falling through to pass 2 (applying everything). That
  // ordering is the whole "all-or-nothing" guarantee: a key or a shape that
  // cannot be honoured is discovered before any live object has been
  // touched, regardless of where in `output` it sits.
  //
  // `Object.getOwnPropertyNames(output)`, not `Object.keys(output)` -- own,
  // regardless of enumerability, matching pass 3's `Object.hasOwn(output,
  // ...)` basis exactly. See this function's own doc comment for the gap
  // this closes.
  for (const key of Object.getOwnPropertyNames(output)) {
    if (key === "refuse" || key === "reason") {
      continue;
    }
    // `Object.hasOwn(live, ...)` beside the `gate` compare, in this pass and
    // in pass 3 below -- see `LiveHookObjects`'s own doc comment for which
    // of the two is actually load-bearing (`Object.hasOwn`, not `gate`) and
    // why, and for why both passes check the same compound condition so a
    // key pass 1 accepts is never one pass 3 then silently declines to
    // apply.
    if (key === "args" && live.gate === "request" && Object.hasOwn(live, "args")) {
      if (!isPlainObject(output.args)) {
        throw new Error(
          `apply-opencode-output: cannot apply rendered "args" -- expected an object, got ${JSON.stringify(output.args)}. ` +
            `A hookmap field sourcing "args" from a decision field that is not itself an object (e.g. "reasoning" ` +
            `where "applied_input" belongs) would otherwise merge its characters onto index keys instead of ` +
            `throwing, and the actual rewrite would never land.`,
        );
      }
      // Before any assignment, same as the shape check above. See
      // assertNoReservedSegments's own doc comment for the attack this
      // closes.
      assertNoReservedSegments(output.args, "args");
      continue;
    }
    if (key === "result" && live.gate === "result" && Object.hasOwn(live, "result")) {
      if (!isPlainObject(output.result)) {
        throw new Error(
          `apply-opencode-output: cannot apply rendered "result" -- expected an object, got ${JSON.stringify(output.result)}`,
        );
      }
      assertNoReservedSegments(output.result, "result");
      continue;
    }
    throw new Error(
      `apply-opencode-output: cannot apply rendered key ${JSON.stringify(key)} at this gate -- opencode.hookmap.yaml ` +
        `declares an output field this applier has no live object to land it in`,
    );
  }

  // Pass 2a: the refusal, if this decision has one. Checked before any
  // assignment: a `refuse` alongside an `args`/`result` rewrite is not a
  // shape any decision on this host's hookmap renders today, but this
  // function does not assume that -- it throws before touching `live`
  // either way, the same discipline pass 1 already applies to an unknown key.
  const refusal = output.refuse as { reason?: unknown } | undefined;
  if (refusal !== undefined) {
    throw new Error(typeof refusal.reason === "string" ? refusal.reason : "denied by policy");
  }

  // Pass 2b: reason.text -- declared-inert on this host (see this
  // function's own doc comment and opencode.hookmap.yaml's header).
  // Surfaced on stderr only under ACS_DEBUG (see the doc comment above for
  // why an unconditional line here would be noise, not a diagnostic);
  // never applied to either live object, and never silently ignored when
  // the flag is set.
  const reason = output.reason as { text?: unknown } | undefined;
  if (reason !== undefined && isDebugEnabled()) {
    console.error(
      `apply-opencode-output: reason.text is declared-inert on this host (opencode.hookmap.yaml) and was not delivered ` +
        `to OpenCode -- reasoning: ${JSON.stringify(reason.text)}`,
    );
  }

  // Pass 3: the assignment. Nothing above threw, so every key `output`
  // carries is one this applier is about to land, and `args`/`result` are
  // both already known to be plain objects.
  //
  // Never both at once: a render naming both `args` and `result` always
  // fails pass 1, above, since `live` is a discriminated union rather than
  // a bag with two optional fields -- whichever of the two keys does not
  // match this call's `live.gate` has no live half to land in, and falls
  // to that loop's final, unconditional throw. So at most one of the two
  // `if`s just below ever actually merges anything for a single call --
  // what lands together, always, is `result`'s own leaf and its mirror,
  // merged in place rather than replacing a nested reference
  // (mergeInPlace, above), never a rewritten `args` beside a landed
  // `result`.
  //
  // `Object.hasOwn(output, ...)`, not `output.args !== undefined` (see
  // this function's own doc comment): an own-key check on a value that
  // arrived over the wire cannot be fooled by a polluted
  // `Object.prototype`, exactly like pass 1's `Object.getOwnPropertyNames`
  // above it. `live.gate === ...` narrows the type and documents which
  // variant this call has; `Object.hasOwn(live, ...)` beside it is the
  // check that is actually immune to a polluted `Object.prototype` on the
  // `live` side, on any key -- see `LiveHookObjects`'s own doc comment for
  // why. Both run in the same compound condition pass 1 already used to
  // decide this key was applicable, so nothing pass 1 accepted is
  // silently declined here.
  if (Object.hasOwn(output, "args") && live.gate === "request" && Object.hasOwn(live, "args")) {
    mergeInPlace(live.args, output.args as Record<string, unknown>);
  }
  if (Object.hasOwn(output, "result") && live.gate === "result" && Object.hasOwn(live, "result")) {
    mergeInPlace(live.result, output.result as Record<string, unknown>);
  }
}
