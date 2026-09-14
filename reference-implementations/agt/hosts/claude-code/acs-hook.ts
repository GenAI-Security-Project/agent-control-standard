/**
 * acs-hook.ts -- Claude Code's PreToolUse hook shim.
 *
 * Thin, and actually thin: read the hook JSON Claude Code sends on stdin,
 * hand it to `resolveSessionConfig` -> `governStep` (both from `host-adapter`,
 * packages/host-adapter), wrap the output that comes back into the JSON Claude
 * Code expects, and write it to stdout. This file branches on nothing about a
 * decision: inspecting the response for one, and tracking which stage of an
 * exchange failed, are both `govern-step.ts`'s job, host-agnostically, and
 * everything it has to preserve is documented there rather than here -- so a
 * second shim gets it by calling the function instead of by copying this
 * file. What remains here is the wiring a Claude Code hook process needs
 * (stdin, stdout, exit code, which hookmap file to load) plus the one thing
 * the adapter must not know: this host's own output shape. A second host
 * arrives as another shim this thin against the same, unchanged adapter;
 * any logic added here is logic that host would have to duplicate.
 *
 * This file is host-specific by definition (it may name Claude Code
 * freely) but must not reach into AGT -- it never imports `agt-bridge` or
 * `guardian`'s server-side pieces, only `host-adapter`'s public surface,
 * and talks to the Guardian only over HTTP, through the client role
 * `createGuardianClient` returns.
 *
 * Claude Code's hook protocol (measured in the v1 runbook of the standalone
 * repository, github.com/afogel/ACS_reference_implementation, docs/demos/v1-runbook.md):
 * stdin is one
 * JSON object `{ session_id, transcript_path, cwd, hook_event_name, tool_name,
 * tool_input }`; stdout is one JSON object
 * `{ hookSpecificOutput: { hookEventName, permissionDecision, ... } }`;
 * the process **always exits 0** for a real decision -- "deny" travels in
 * the JSON body, not the exit code. Exit 2 means "blocking error" to
 * Claude Code and exit 1 means "non-blocking error"; neither is how a
 * policy deny is expressed, so getting this wrong would make a deny look
 * like a crash.
 *
 * On failure there are exactly two exit shapes, never a third.
 *
 *   - Exit 2 ("blocking error"), stderr only, empty stdout: this shim
 *     cannot trust its own input or its own configuration enough to make a
 *     governed decision at all -- stdin is not JSON, the payload is missing
 *     a string `hook_event_name`/`session_id`, the hookmap fails to load,
 *     or `session_id` is unsafe to use as a path segment. Every one of
 *     those is a broken deployment, not a policy question, and a loud,
 *     blocking stop beats a silent, ungoverned proceed.
 *
 *     Exit 1 never appears anywhere in this file, including for anything
 *     unexpected that escapes `main`. Claude Code reads exit 1
 *     ("non-blocking error") as "the hook did not fire" and proceeds --
 *     ungoverned and unaudited -- and a governance hook that cannot read
 *     its own input has no honest reason to prefer "proceed" to "block". A
 *     `session_id` that is present but unsafe already blocks (the case just
 *     above); treating a missing `session_id` any differently would put two
 *     members of the same class -- "this deployment's `session_id` cannot
 *     be used" -- on opposite sides of the fail-open/fail-closed line.
 *   - Exit 0, a decision on stdout: every remaining case, with no
 *     exception. A Guardian that is down, a response carrying an error
 *     instead of a decision, a request that times out, or a decision this
 *     host cannot even render (an unrecognised decision string, or a
 *     hookmap gap) all leave this hook with nothing it can honour. A
 *     `deny` that arrives is honoured regardless of what follows, and a
 *     delivery failure never gets dressed up as one. Every such failure is
 *     resolved by the deployment's own negotiated `on_decision_failure`
 *     posture (`applyFailurePosture`) -- proceed or deny -- and every
 *     fail-open `proceed` taken this way is written to the audit log
 *     first, so the bypass is visible rather than silent. The posture's
 *     own "allow"/"deny" is guaranteed renderable: loadHookmap doesn't just
 *     require both to exist in every hookmap's `decisions` block, it
 *     shape-checks every entry it accepts, and `assertHostAcceptsEveryDecision`
 *     below then checks each accepted value against what Claude Code honours
 *     at that event -- so this tier can never recurse into itself, and
 *     can never emit a value the host will silently discard.
 *
 *     They are resolved the same way; they are not recorded as the same
 *     thing. The posture takes one of three `stage`s (failure-posture.ts's
 *     FailureStage), because "no request was ever built", "a request went
 *     out and nothing came back", and "a decision arrived and this host
 *     could not express it" are three different incidents, and an audit
 *     entry that files one under another sends an incident review to the
 *     wrong process. Which stage a failure belongs to is `governStep`'s to
 *     know -- each stage is its own guarded step there, so the stage is
 *     wherever the failure was caught, not something re-inferred afterwards
 *     from leftover variables.
 */
import { fileURLToPath } from "node:url";
import {
  createAuditSink,
  createFileSessionConfigStore,
  createGuardianClient,
  DEFAULT_TIMEOUT_MS,
  governStep,
  loadHookmap,
  resolveSessionConfig,
  toSessionUuid,
  withholdsAtResultGate,
  type Hookmap,
  type HostOutput,
  type SessionConfigStore,
} from "host-adapter";

// Override with ACS_HOOKMAP_PATH to point this shim at a different hookmap
// -- e.g. a test proving the exit-2 path for a hookmap that fails to load,
// without touching the real file every other test and the real deployment
// read off this default.
const HOOKMAP_PATH = process.env.ACS_HOOKMAP_PATH ?? fileURLToPath(new URL("./claude-code.hookmap.yaml", import.meta.url));

// Matches packages/guardian/src/main.ts's own default port -- the runbook
// and this shim agree on 8787 without either hardcoding the other's value.
// Override with ACS_GUARDIAN_URL when the Guardian runs on a different
// host/port (e.g. in tests, which start a Guardian on an ephemeral port).
const DEFAULT_GUARDIAN_URL = "http://localhost:8787/acs";

/**
 * Claude Code's own output shape, which lives here and nowhere else.
 *
 * The adapter renders into a shape it does not name: `renderDecision` reads
 * the hookmap's dotted output paths and assembles the object they describe,
 * knowing ACS decisions and nothing about this host. That is what lets a
 * second host arrive as a shim and a hookmap rather than a fork of the
 * shared module -- and it is only true while these names appear on this side
 * of the seam. Both appear as data in claude-code.hookmap.yaml's output paths;
 * here they appear as the wrapper this shim adds and the one output path whose
 * declared value this shim has to check against Claude Code's own enum.
 */
const HOOK_SPECIFIC_OUTPUT = "hookSpecificOutput";
const PERMISSION_DECISION_PATH = `${HOOK_SPECIFIC_OUTPUT}.permissionDecision`;
// The result gate's two, and the reason they are here rather than one gate's
// worth: `updatedToolOutput` is what withholds a tool result, and `decision` is
// the top-level (unwrapped) key Claude Code reads a block from. Both appear as
// data in claude-code.hookmap.yaml's output paths; here they appear as the paths
// whose declared values this shim has to check.
const UPDATED_TOOL_OUTPUT = "updatedToolOutput";
const UPDATED_TOOL_OUTPUT_PATH = `${HOOK_SPECIFIC_OUTPUT}.${UPDATED_TOOL_OUTPUT}`;
const TOP_LEVEL_DECISION_PATH = "decision";
const BLOCK = "block";

/**
 * The only three `permissionDecision` values Claude Code accepts on a
 * PreToolUse hookSpecificOutput -- the same three claude-code.hookmap.yaml's
 * own header comment names ("Claude Code's PreToolUse hookSpecificOutput
 * only accepts permissionDecision \"allow\" | \"deny\" | \"ask\" (see Claude
 * Code's own hook docs)"). The hookmap says it; this set is what checks it.
 */
const ACCEPTED_PERMISSION_DECISIONS = new Set(["allow", "deny", "ask"]);

/** One decision's declared rule, as this shim reads it off a loaded hookmap. */
type DeclaredRule = { output?: Record<string, { value?: unknown; from?: string } | null> } | null;

/** The declared source for one output path of one decision, or undefined. */
function declaredAt(rule: DeclaredRule | undefined, outputPath: string): { value?: unknown; from?: string } | undefined {
  // loadHookmap has already guaranteed a well-formed output block here; this
  // reads it defensively anyway, because a hookmap it rejects is exactly what
  // the gates below must name rather than crash on.
  return rule?.output?.[outputPath] ?? undefined;
}

/**
 * What this shim expects of ONE hook, and why there is a table rather than a
 * single rule.
 *
 * Claude Code's two gates are not symmetric, so neither "every decision
 * declares a `permissionDecision`" nor "every rendered output carries a
 * wrapper" holds across both. Each hook states its own answer:
 *
 *   - `PreToolUse` decides whether a step runs, and answers with
 *     `permissionDecision`. An output Claude Code reads no decision from lets
 *     the tool call PROCEED, so a missing or unrecognised value there is a
 *     fail-open and an output with no wrapper is half an output.
 *   - `PostToolUse` sees what a step produced, and has no permission to grant.
 *     Its clean answer is genuinely nothing -- "deliver the output unchanged"
 *     -- so refusing an empty output there would exit 2 on every clean tool
 *     call. Its withholding entries are the ones that need checking instead,
 *     because `block` alone reports a withholding that never happened.
 *
 * Neither refusal is relaxed; each is asked of the gate it belongs to. A hook
 * this table has no entry for is a THROW, not a skip: an unchecked hook is an
 * unchecked fail-open, which is the whole reason these gates exist.
 */
type HookExpectation = {
  /**
   * Throws unless every decision this hook declares renders something Claude
   * Code actually honours at this event.
   */
  assertDecisions: (decisions: Record<string, DeclaredRule | undefined>, path: string, hookEventName: string) => void;
  /**
   * Whether an output carrying no `hookSpecificOutput` wrapper is a decision
   * this host can honestly write for this hook -- true only where "nothing to
   * change" is an answer rather than an absence.
   */
  emptyOutputIsHonest: boolean;
};

const HOOK_EXPECTATIONS: Record<string, HookExpectation> = {
  /**
   * A one-character typo in the hookmap (`{ value: dney }`) renders a real
   * policy deny as
   * `{"hookSpecificOutput":{...,"permissionDecision":"dney",...}}` with exit 0.
   * Claude Code does not recognise the value, so it treats the hook as having
   * produced no decision at all and PROCEEDS: a policy that fired and denied
   * becomes an allowed tool call, silently, behind plausible-looking JSON and a
   * success exit code. Same shape as every other fail-open found here -- the
   * host receives no honoured decision and the tool call runs ungoverned.
   *
   * Two cases this catches that a per-entry `permissionDecision` field check
   * could not, both of which the hookmap's generic output shape admits, and
   * both of which are the same bypass by another route:
   *
   *   - An entry declaring no `permissionDecision` path at all. Legal for a hook
   *     whose output has no such field; for this one it renders JSON Claude Code
   *     reads as no decision.
   *   - An entry sourcing it `from:` a decision field instead of a literal.
   *     Present-looking in the YAML, absent at runtime whenever the decision
   *     does not carry that field.
   */
  PreToolUse: {
    assertDecisions(decisions, path, hookEventName) {
      for (const [decision, rule] of Object.entries(decisions)) {
        const permissionDecision = declaredAt(rule, PERMISSION_DECISION_PATH)?.value;
        if (typeof permissionDecision !== "string" || !ACCEPTED_PERMISSION_DECISIONS.has(permissionDecision)) {
          throw new Error(
            `acs-hook: ${path}'s "hooks.${hookEventName}.decisions.${decision}" must declare a literal ` +
              `"${PERMISSION_DECISION_PATH}" output field, and declares ${JSON.stringify(permissionDecision)}, ` +
              `which Claude Code does not accept -- it accepts exactly "allow", "deny" or "ask". Claude Code reads ` +
              `a missing or unrecognised value as no decision at all and lets the tool call proceed, so this ` +
              `hookmap would silently turn decisions into ungoverned tool calls.`,
          );
        }
      }
    },
    emptyOutputIsHonest: false,
  },
  /**
   * The result gate's own expectation, and it is about the entries that
   * withhold.
   *
   * Rendering deny as Claude Code's documented `{"decision":"block","reason":…}`
   * was tested directly against 2.1.227: the model received the real stdout AND
   * the block reason. The tool has already run and its result has already
   * formed, so `block` on its own REPORTS a suppression that did not happen:
   * it logs a withholding and performs none. Only the replacing output
   * withholds anything, so an entry declaring one of the two without the other
   * is a hookmap that would log a withholding while delivering the secret.
   *
   * Asked of every entry that withholds here, not of `deny` by name, and the
   * membership question is the adapter's to answer: `withholdsAtResultGate` is
   * the same rule that decides which arriving decisions get a replacing output
   * to render with, so a shim keeping its own copy could accept a hookmap whose
   * `ask` declares a block the adapter never hands it anything to withhold with
   * -- the exact log-line-pretending-to-be-a-suppression this check exists to
   * refuse, reintroduced by the two ends drifting. Beyond `deny` the members are
   * `ask` and `defer`: at an event where the tool has already run there is no
   * permission left to seek and no pending state to hold an output in, so
   * neither can be carried out and both withhold instead
   * (claude-code.hookmap.yaml's own entries say what that costs).
   *
   * Both halves of the rule are refused, in both directions. An entry that
   * withholds must declare the block AND the replacement -- one without the
   * other is either a log line pretending to be a suppression or a suppression
   * with nothing in the transcript saying why. And a declared block with no
   * replacement is refused whichever entry declares it, including one this rule
   * calls a delivery: an `allow` written that way would be the same false
   * report.
   *
   * `allow` and `modify` need no check beyond that: neither claims to withhold
   * anything, and `loadHookmap` has already established that every entry
   * renders something.
   */
  PostToolUse: {
    assertDecisions(decisions, path, hookEventName) {
      for (const [decision, rule] of Object.entries(decisions)) {
        const named = `"hooks.${hookEventName}.decisions.${decision}"`;
        const blockValue = declaredAt(rule, TOP_LEVEL_DECISION_PATH)?.value;
        const declaresReplacement = declaredAt(rule, UPDATED_TOOL_OUTPUT_PATH) !== undefined;
        if (blockValue === BLOCK && !declaresReplacement) {
          throw new Error(
            `acs-hook: ${path}'s ${named} declares "${TOP_LEVEL_DECISION_PATH}: ${BLOCK}" without a ` +
              `"${UPDATED_TOOL_OUTPUT_PATH}" output field to replace the output with. The tool has already run at ` +
              `this event, so a block injects a reason and suppresses nothing: an entry declared this way would ` +
              `report a withholding that never happened while the original output was delivered.`,
          );
        }
        if (withholdsAtResultGate(decision) && blockValue !== BLOCK) {
          throw new Error(
            `acs-hook: ${path}'s ${named} must declare a literal "${TOP_LEVEL_DECISION_PATH}" output field of ` +
              `${JSON.stringify(BLOCK)}, and declares ${JSON.stringify(blockValue)} -- an ACS ` +
              `"${decision}" cannot be carried out at an event where the tool has already run, so what it can ` +
              `do is withhold the output, and Claude Code reads the block that says so from the top level of ` +
              `this event's output, beside the "${HOOK_SPECIFIC_OUTPUT}" wrapper rather than inside it.`,
          );
        }
      }
    },
    emptyOutputIsHonest: true,
  },
};

/**
 * This shim's expectation of `hookEventName`, or a throw.
 *
 * A hook present in the hookmap that this shim has no expectation for is not
 * skipped: it would be a hook whose declared decisions nothing checks and whose
 * rendered output nothing checks, at an event whose semantics this shim has
 * never been taught. That is an unchecked fail-open, and the whole reason the
 * gates below exist is that this project has found nine of them.
 */
function expectationFor(hookEventName: string): HookExpectation {
  // `hasOwnProperty`, not a bare index: a hookmap naming a hook `toString` or
  // `constructor` would otherwise read an inherited function off
  // Object.prototype, pass the `undefined` check, and then fail on a missing
  // `assertDecisions` -- an unrelated TypeError in place of the message that
  // says which hook is unknown. Same reasoning as render-decision.ts's
  // RESERVED_SEGMENTS.
  const expectation = Object.prototype.hasOwnProperty.call(HOOK_EXPECTATIONS, hookEventName)
    ? HOOK_EXPECTATIONS[hookEventName]
    : undefined;
  if (expectation === undefined) {
    throw new Error(
      `acs-hook: hook "${hookEventName}" is one this shim has no expectation for, so nothing here can say what ` +
        `Claude Code accepts at that event or whether an empty output is an answer there. A hook nothing checks ` +
        `is a hook nothing governs, so it is refused rather than passed through. Teach this shim the event ` +
        `(HOOK_EXPECTATIONS) before mapping it in the hookmap.`,
    );
  }
  return expectation;
}

/**
 * Wraps the adapter's host-agnostic output into the exact JSON Claude Code
 * expects, adding the one field that is not a function of the decision: the
 * name of the hook that asked.
 *
 * `hookEventName` is deliberately not in the hookmap. Every output field
 * declared there is copied from the decision or is a literal; this one is
 * neither -- it is the raw host event name that produced the original
 * request, the same string passed to buildEnvelope, carried through
 * unchanged. Adding it here keeps the adapter's contract exactly "the output
 * is a function of the decision and the hookmap".
 *
 * It goes first, and any field the hookmap declared under the wrapper
 * follows; a field the hookmap declared outside the wrapper (a top-level key
 * alongside it) travels untouched, which is the second half of what the
 * generic output shape bought.
 *
 * A rendered output with no wrapper object in it is a throw rather than a
 * repair AT A GATE THAT DECIDES WHETHER A STEP RUNS: writing
 * `{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}` would hand Claude
 * Code JSON it reads as no decision at all, and it would then let the tool call
 * proceed. Half an output is the one thing this hook must never write. It is
 * also unreachable there by construction, because
 * `assertHostAcceptsEveryDecision` requires every one of that hook's decisions
 * to declare a literal UNDER this wrapper. Still a throw rather than a repair,
 * and it escapes to `main().catch`, which exits 2 and blocks -- so even the
 * unreachable failure mode is a stopped tool call rather than an ungoverned one.
 *
 * It is also unreachable by construction now that the gate below reads the
 * declared output path: `assertHostAcceptsEveryDecision` requires every
 * renderable decision to declare a literal under this wrapper, so the wrapper
 * is always an object by the time a decision is rendered. Still a throw rather
 * than a repair, and it escapes to `main().catch`, which exits 2 and blocks --
 * so even the unreachable failure mode is a stopped tool call rather than an
 * ungoverned one.
 */
function asClaudeCodeOutput(rendered: HostOutput, hookEventName: string): HostOutput {
  const expectation = expectationFor(hookEventName);
  const wrapper = rendered[HOOK_SPECIFIC_OUTPUT];

  // The runtime half of the result gate's two-part withholding rule, and the case
  // `emptyOutputIsHonest` would otherwise wave through. An empty wrapper means
  // "nothing to change, deliver the output as the tool produced it" -- which is
  // the honest answer for a clean result and a LIE beside `decision: block`. The
  // tool has already run, so the block injects a reason and suppresses nothing:
  // that output reports a withholding that did not happen while Claude Code
  // delivers the original.
  //
  // `assertHostAcceptsEveryDecision` already refuses a HOOKMAP that declares the
  // block without a replacement. This is the other half: a hookmap that declares
  // both, and a decision that reached here carrying no replacement to render into
  // the field it declared. Neither gate implies the other -- one reads the YAML,
  // one reads the bytes about to go to stdout -- and this is the one a change
  // anywhere upstream of the render could reopen.
  if (rendered[TOP_LEVEL_DECISION_PATH] === BLOCK) {
    const replacement =
      typeof wrapper === "object" && wrapper !== null && !Array.isArray(wrapper)
        ? (wrapper as Record<string, unknown>)[UPDATED_TOOL_OUTPUT]
        : undefined;
    if (replacement === undefined) {
      throw new Error(
        `acs-hook: the rendered output for hook "${hookEventName}" carries ` +
          `"${TOP_LEVEL_DECISION_PATH}": "${BLOCK}" with no "${UPDATED_TOOL_OUTPUT_PATH}" to replace the tool's ` +
          `output with. The tool has already run at this event, so a block injects a reason and suppresses ` +
          `nothing: writing this would report a withholding that never happened while the original output was ` +
          `delivered`,
      );
    }
  }

  if (wrapper === undefined && expectation.emptyOutputIsHonest) {
    return { ...rendered, [HOOK_SPECIFIC_OUTPUT]: { hookEventName } };
  }
  if (typeof wrapper !== "object" || wrapper === null || Array.isArray(wrapper)) {
    throw new Error(
      `acs-hook: the rendered output for hook "${hookEventName}" has no "${HOOK_SPECIFIC_OUTPUT}" object for ` +
        `Claude Code to read a decision from, so there is no output this host could honestly write`,
    );
  }
  return { ...rendered, [HOOK_SPECIFIC_OUTPUT]: { hookEventName, ...(wrapper as Record<string, unknown>) } };
}

/**
 * Thrown when this shim cannot trust its own input or its own configuration
 * enough to make a governed decision at all -- stdin that is not a hook
 * payload, a payload missing a usable `hook_event_name`/`session_id`, a
 * hookmap that fails to load, or a `session_id` unsafe to use as a path
 * segment. `main().catch` below exits 2 ("blocking error") for all of it,
 * which stops the tool call and surfaces stderr instead of silently letting
 * it through.
 *
 * This class does not select the exit code: exit 2 is the only non-zero
 * code this shim produces. It still names the failure class deliberately,
 * so a future edit that adds a failure here has to decide whether it
 * belongs to this class rather than inheriting a default by accident.
 */
class BlockingConfigurationError extends Error {
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause));
    this.name = "BlockingConfigurationError";
  }
}

/**
 * The only three `permissionDecision` values Claude Code accepts on a
 * PreToolUse hookSpecificOutput -- the same three claude-code.hookmap.yaml's
 * own header comment names ("Claude Code's PreToolUse hookSpecificOutput
 * only accepts permissionDecision \"allow\" | \"deny\" | \"ask\" (see Claude
 * Code's own hook docs)"). The hookmap says it; until now nothing checked it.
 */

/**
 * Rejects a hookmap that does not declare, for every decision, a literal
 * `permissionDecision` this host actually accepts -- and this is a fail-open
 * guard, not a tidiness check.
 *
 * A one-character typo in the hookmap (`{ value: dney }`) renders a real
 * policy deny as
 * `{"hookSpecificOutput":{...,"permissionDecision":"dney",...}}` with exit 0.
 * Claude Code does not recognise the value, so it treats the hook as having
 * produced no decision at all and proceeds: a policy that fired and denied
 * becomes an allowed tool call, silently, behind plausible-looking JSON and a
 * success exit code. Same shape as every other fail-open found here -- the
 * host receives no honoured decision and the tool call runs ungoverned.
 *
 * Two cases this catches that a per-entry `permissionDecision` field check
 * could not, both of which enter through the hookmap's generic output shape
 * and both of which are the same bypass by another route:
 *
 *   - An entry declaring no `permissionDecision` path at all. Legal for a host
 *     whose output has no such field; for this one it renders JSON Claude Code
 *     reads as no decision.
 *   - An entry sourcing it `from:` a decision field instead of a literal.
 *     Present-looking in the YAML, absent at runtime whenever the decision
 *     does not carry that field.
 *
 * `loadHookmap` deliberately stops one step short of all of this: it checks
 * that every declared entry renders something at all (a non-empty `output`
 * block whose every field names a literal `value` or a non-empty `from`),
 * but never checks a value against a host's enum, because the adapter must
 * not know one -- or, since the output shape is generic, any host's field
 * names at all. That boundary is enforced mechanically by
 * test/invariants.test.ts's vocabulary gate over packages/host-adapter/src.
 * This shim is host-specific by definition and already names Claude Code
 * freely, so the enum and the path live here and only here.
 *
 * Every hook in the hookmap is checked, and a hook with no expectation is a
 * throw rather than a skip -- `expectationFor` states why.
 *
 * Raised as a BlockingConfigurationError, so it exits 2 ("blocking error")
 * like every other broken-configuration case rather than exiting 0 with an
 * output the host will discard.
 */
function assertHostAcceptsEveryDecision(hookmap: Hookmap, path: string): void {
  for (const [hookEventName, entry] of Object.entries(hookmap.hooks ?? {})) {
    const decisions = (entry as { decisions?: Record<string, DeclaredRule> } | null)?.decisions ?? {};
    expectationFor(hookEventName).assertDecisions(decisions, path, hookEventName);
  }
}

async function main(): Promise<void> {
  // Step 1: read the hook payload. A hook fired, so something governs this
  // tool call or nothing does -- and a shim that cannot read its own input
  // is in no position to say which. Unparseable stdin and a payload with no
  // usable `hook_event_name`/`session_id` are the same broken deployment as
  // an unloadable hookmap below, and they block the same way (exit 2), not
  // with the exit-1 "the hook didn't fire" that let the call through.
  let payload: Record<string, unknown>;
  let hookEventName: string;
  let sessionId: string;
  try {
    payload = JSON.parse(await Bun.stdin.text()) as Record<string, unknown>;
    if (typeof payload?.hook_event_name !== "string") {
      throw new Error('acs-hook: stdin payload is missing a string "hook_event_name" field');
    }
    if (typeof payload.session_id !== "string") {
      throw new Error('acs-hook: stdin payload is missing a string "session_id" field');
    }
    hookEventName = payload.hook_event_name;
    sessionId = payload.session_id;
  } catch (error) {
    throw new BlockingConfigurationError(error);
  }

  // Step 2: a hookmap that fails to load, a hookmap declaring a decision
  // value this host cannot emit, or an unsafe session_id all make a governed
  // decision impossible -- a broken deployment, not a policy question -- so
  // all three become a BlockingConfigurationError and exit 2, not the silent
  // proceed a non-blocking exit code would produce. Nothing is written
  // anywhere before this succeeds: createFileSessionConfigStore's
  // InvalidSessionIdError throws synchronously, before its first write.
  let hookmap: Hookmap;
  let store: SessionConfigStore;
  try {
    hookmap = loadHookmap(HOOKMAP_PATH);
    assertHostAcceptsEveryDecision(hookmap, HOOKMAP_PATH);
    store = createFileSessionConfigStore({
      dir: process.env.ACS_SESSION_DIR ?? ".acs/sessions",
      sessionId,
    });
  } catch (error) {
    throw new BlockingConfigurationError(error);
  }

  // Step 3: the audit log -- total by construction, so building it cannot
  // itself throw, and a write to it never happens unless a fail-open
  // proceed (or a negotiated fail-closed deny) actually occurs below.
  const audit = createAuditSink({ path: process.env.ACS_AUDIT_LOG ?? ".acs/audit.jsonl" });

  const guardianUrl = process.env.ACS_GUARDIAN_URL ?? DEFAULT_GUARDIAN_URL;
  const guardian = createGuardianClient(guardianUrl);

  // Step 4: this session's negotiated config, and whatever went wrong getting
  // it -- one call, and this shim is told both rather than running the
  // negotiation and then interrogating whatever it threw. What that
  // resolution has to preserve -- a handshake failure is not this step's
  // failure; a config that arrived and could not be persisted still governs
  // the step that negotiated it -- is stated where it happens, in
  // `resolveSessionConfig`, so a second host inherits it instead of
  // re-deriving it from an `instanceof` and an `error.config`.
  //
  // metadata.session_id is schema-constrained to "uuid" (the same rule
  // buildEnvelope's own toSessionUuid honours); the store itself keys on the
  // raw host session_id, per the session config store's own contract.
  // agentId is the hookmap's own `host` field -- the same identity
  // buildEnvelope sends for the step call, so the two never diverge.
  // Bounded by the ACS default timeout: there is no
  // negotiated timeout yet, since negotiating one is what this call is for --
  // without a bound, a Guardian that accepts the connection and never answers
  // would hang this hook until Claude Code's own hook timeout kills the
  // process.
  const session = await resolveSessionConfig(
    {
      guardian,
      agentId: hookmap.host,
      sessionId: toSessionUuid(sessionId),
      timeoutMs: DEFAULT_TIMEOUT_MS,
    },
    store,
  );

  // Step 5: resolve the attempt. One call, one answer, and this shim branches
  // on nothing: `governStep` builds the ACS request, asks the Guardian for a
  // decision, honours whatever arrives, and renders it -- answering any failure
  // along the way with this session's negotiated posture, audited, at the stage
  // that failed. There are exactly two ways it can end, and both are handled
  // here: an output to write, or a throw that reaches `main().catch` and exits
  // 2. Which stage a failure belongs to, and what response the failure-mode
  // rules produce for it, is stated once inside `governStep`, host-agnostically,
  // so a second host inherits it by calling the function rather than
  // reimplementing it.
  const governed = await governStep({ hookEventName, payload, hookmap, guardian, session, sessionId, audit });

  process.stdout.write(JSON.stringify(asClaudeCodeOutput(governed.output, hookEventName)));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  // Exit 2 ("blocking error") for everything, with no second tier. Anything
  // that reaches here is either a BlockingConfigurationError (this shim
  // cannot trust its input or its configuration) or something unforeseen
  // escaping `main` -- and in both cases the honest answer to "should this
  // tool call run?" is "this hook cannot say", which Claude Code must read
  // as a block, not as the hook never having fired.
  process.exit(2);
});
