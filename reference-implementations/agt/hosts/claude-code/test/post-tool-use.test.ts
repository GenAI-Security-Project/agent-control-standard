import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
// Test-only import, the same precedent hook.test.ts and packages/host-adapter/test/
// set: stands up a real Guardian, over real HTTP, against the real pinned
// policy bundle, so the claim below is about what a Claude Code process
// actually reads back rather than about a hand-copied decision shape.
import { startGuardian, type StartedGuardian } from "guardian";

/**
 * The result gate, end to end: a real Claude Code `PostToolUse` payload on
 * stdin, a real Guardian in front of the real pinned AGT bundle, and the
 * exact JSON the shim writes on stdout.
 *
 * Why the assertions here are whole-object literals: Claude Code silently
 * discards a replacement that does not match the tool's own output schema
 * and delivers the original (confirmed by hand against 2.1.227's actual
 * behavior). A hook that answered `updatedToolOutput: "[REDACTED]"` -- a
 * plain string, the natural reading of "redact the output" -- produced
 *
 *   PostToolUse hook returned updatedToolOutput that does not match Bash's
 *   output shape; using original output. [{"expected":"object", ...}]
 *
 * on stderr while the model received the real secret. So a redaction is
 * only a redaction if every sibling field survives, and a test that
 * asserted only `updatedToolOutput.stdout` would pass while the replacement
 * was declined and the token delivered. That single whole-object assertion
 * is what stands between this deployment and Claude Code quietly handing
 * the secret to the model.
 *
 * The shape below is `Bash`'s real one, captured from a live 2.1.227
 * payload: `{stdout, stderr, interrupted, isImage, noOutputExpected}`.
 *
 * Measured, not assumed. The mutation that isolates these tests: make
 * `result-output.ts`'s `patchedClone` build a fresh object (`{}`) instead of
 * spreading the container it was handed -- i.e. construct a new output
 * object rather than patch a clone, which is the one thing that module
 * forbids. `updatedToolOutput` comes back as `{"stdout":
 * "TOKEN=[REDACTED]"}` with all four siblings gone: the exact shape Claude
 * Code discards, so the model would receive the real token.
 *
 * The count is the part of a claim like this that rots, so it is
 * re-measured as the file grows: against 492 tests the mutation gives 478
 * pass / 13 fail, six of them in this file -- every test here except the
 * `allow` one, which deliberately asserts that no replacement is emitted at
 * all and so has no object to lose siblings from. The other seven are
 * `validate-decision.test.ts`'s projection cases and `govern-step.test.ts`'s
 * preflight case, which assert the same whole object one and two seams
 * earlier.
 *
 * What still does not notice, and is the real point here: the per-hook
 * render literals in packages/host-adapter/test/render-decision.test.ts,
 * which assert hand-written `applied_output` fixtures and so cannot tell a
 * projection from a construction.
 */
const SHIM_PATH = fileURLToPath(new URL("../acs-hook.ts", import.meta.url));

/**
 * The scratch tree this suite is allowed to touch. The shim negotiates a
 * session and can audit a fail-open, both of which default under
 * the process cwd -- which would scatter real files into the repo on every
 * run. Every test here uses one session id, so `sessions/<id>.json` is the only
 * file any of them can create; an `audit.jsonl` would mean a delivery failure
 * happened, and the test that saw it should fail on its own assertions rather
 * than on a leftover file.
 */
const SESSION = "post-1";

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-post-tool-use-"));
  dirs.push(dir);
  return dir;
}

/** Removes exactly what a run can leave behind, by name, never recursively --
 * the cleanup posture of posture.test.ts and wire-shape.test.ts next door. */
function cleanupScratch(dir: string): void {
  const sessionsDir = join(dir, "sessions");
  for (const file of [join(dir, "audit.jsonl"), join(sessionsDir, `${SESSION}.json`)]) {
    if (existsSync(file)) {
      unlinkSync(file);
    }
  }
  if (existsSync(sessionsDir)) {
    rmdirSync(sessionsDir);
  }
  rmdirSync(dir);
}

afterEach(() => {
  while (dirs.length > 0) {
    cleanupScratch(dirs.pop() as string);
  }
});

/** The real `tool_response` object Claude Code 2.1.227 delivers for `Bash`. */
function toolResponse(stdout: string): Record<string, unknown> {
  return { stdout, stderr: "", interrupted: false, isImage: false, noOutputExpected: false };
}

/** The real `PostToolUse` payload shape, with `tool_name: "Bash"` -- what
 * Claude Code sends and what policy/manifest.yaml registers. */
function postToolUsePayload(stdout: string): Record<string, unknown> {
  return {
    session_id: SESSION,
    transcript_path: "/path/to/transcript.jsonl",
    cwd: "/current/dir",
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_input: { command: "cat .env" },
    tool_response: toolResponse(stdout),
  };
}

/** Spawns the real shim as a subprocess -- exactly how Claude Code invokes it
 * -- feeds it `payload` on stdin, and returns what it wrote. */
async function runHook(
  payload: Record<string, unknown>,
  guardianUrl: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const dir = scratch();
  const proc = Bun.spawn({
    cmd: ["bun", "run", SHIM_PATH],
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: {
      ...process.env,
      ACS_GUARDIAN_URL: guardianUrl,
      ACS_SESSION_DIR: join(dir, "sessions"),
      ACS_AUDIT_LOG: join(dir, "audit.jsonl"),
    },
  });
  proc.stdin.write(JSON.stringify(payload));
  proc.stdin.end();
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { stdout, stderr, exitCode };
}

/**
 * A stub Guardian that negotiates a real session and then answers the step
 * call with `decision`.
 *
 * Used only for the decisions the shipped bundle does not produce at this gate
 * -- a result-gate `deny`, a `modify` whose redaction addresses a field the
 * result payload does not have, and an `ask` or a `defer` arriving where the
 * step has already run. Every one of them is a decision this host must answer
 * correctly, and a suite that could only exercise the bundle's own `allow` and
 * `modify` would leave them unpinned. Same precedent, and the same
 * `handshake/hello` branch, as wire-shape.test.ts.
 *
 * `on_decision_failure: "proceed"` in that branch is load-bearing for the two
 * ask/defer tests below rather than incidental: it is the ACS default and the
 * posture this deployment ships, and it is the posture under which the gap
 * those tests pin was a delivery. Under `deny` they would pass with the fix
 * reverted, because the posture would withhold what the gate failed to.
 */
async function answering<T>(decision: Record<string, unknown>, body: (url: string) => Promise<T>): Promise<T> {
  const stub = Bun.serve({
    port: 0,
    async fetch(req) {
      const rpc = (await req.json()) as { id: string | number; method: string };
      if (rpc.method === "handshake/hello") {
        return Response.json({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            negotiated_version: "0.1.0",
            methods_evaluated: ["steps/toolCallResult"],
            selected_transport: "http",
            timeout_config: { default_ms: 5000 },
            on_decision_failure: "proceed",
          },
        });
      }
      return Response.json({ jsonrpc: "2.0", id: rpc.id, result: decision });
    },
  });
  try {
    return await body(`http://localhost:${stub.port}/acs`);
  } finally {
    stub.stop(true);
  }
}

let guardian: StartedGuardian;

beforeAll(async () => {
  guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
});

afterAll(async () => {
  await guardian.close();
});

describe("the result gate, end to end through the real shim and a real Guardian", () => {
  it("redacts a secret out of tool output, preserving every sibling field", async () => {
    const out = await runHook(postToolUsePayload("TOKEN=ghp_ABCDEF123456"), guardian.url);

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });

    // Every sibling survives. This is the assertion that stands between a
    // redaction and Claude Code silently restoring the original: a replacement
    // carrying `stdout` alone is not the tool's output shape, so it would be
    // discarded and the token delivered, with only a warning line to show it.
    //
    // Pinned as the whole stdout object, not just the replacement: a
    // `permissionDecision` leaking in from the request gate's rule, or a stray
    // `decision: block` beside the wrapper, are both changes a
    // replacement-only assertion would not see.
    //
    // `additionalContext` carries the sentence explaining the redaction, and
    // the hookmap's `modify` entry declares it (`from: reasoning`). The pinned
    // bundle's own transform verdict carries no message -- AGT writes one only
    // where a rule has something to report about the text it matched -- so
    // this string is composed from the rule that decided rather than copied
    // from upstream. Until it was, this literal recorded a redaction the model
    // read with nothing in the transcript explaining it.
    expect(JSON.parse(out.stdout)).toEqual({
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        additionalContext:
          "Secrets in this output were replaced before the model saw them. " +
          "Policy: redaction_applied, from AGT's stock bundle (agt_stock).",
        updatedToolOutput: {
          stdout: "TOKEN=[REDACTED]",
          stderr: "",
          interrupted: false,
          isImage: false,
          noOutputExpected: false,
        },
      },
    });

    // The redaction is only real if the original does not survive anywhere in
    // what the host is told to deliver -- including in a field nothing above
    // names.
    expect(out.stdout).not.toContain("ghp_ABCDEF123456");
  });

  // The reason a redaction gives for itself, end to end through the real shim.
  // This mirrors `PreToolUse`'s `modify`: a rewrite is the only decision that
  // changes what runs while the transcript says nothing, and at this gate the
  // stakes are higher, because what the model reads is the rewritten text
  // itself. Without a reason it is handed altered output with nothing saying
  // it was altered, and `[REDACTED]` reads as the command's own answer.
  //
  // A stub Guardian, because the pinned bundle's redaction verdict carries no
  // `reasoning` for the conditional field to render (see the first test): the
  // hookmap entry is what is under test here, not what this bundle happens to
  // send.
  it("says why it redacted, in the field this event reads a reason from", async () => {
    const out = await answering(
      {
        decision: "modify",
        reasoning: "token pattern matched in tool output",
        modifications: { redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=[REDACTED]" }] },
      },
      (url) => runHook(postToolUsePayload("TOKEN=ghp_ABCDEF123456"), url),
    );

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
    expect(JSON.parse(out.stdout)).toEqual({
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        updatedToolOutput: {
          stdout: "TOKEN=[REDACTED]",
          stderr: "",
          interrupted: false,
          isImage: false,
          noOutputExpected: false,
        },
        additionalContext: "token pattern matched in tool output",
      },
    });
    expect(out.stdout).not.toContain("ghp_ABCDEF123456");
  });

  it("leaves clean output alone, with no updatedToolOutput at all", async () => {
    // An `allow` must not emit an `updatedToolOutput` key: an unnecessary
    // replacement is a chance to get the shape wrong for no benefit, and the
    // hookmap's `allow` entry declares only a conditional `additionalContext`,
    // so a clean result renders an empty wrapper and the output is delivered
    // exactly as the tool produced it.
    const out = await runHook(postToolUsePayload("total 0\n"), guardian.url);

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
    const wrapper = (JSON.parse(out.stdout) as { hookSpecificOutput: Record<string, unknown> }).hookSpecificOutput;
    expect("updatedToolOutput" in wrapper).toBe(false);
    expect(JSON.parse(out.stdout)).toEqual({ hookSpecificOutput: { hookEventName: "PostToolUse" } });
  });

  // The result gate's `deny`, and the reason it needs a test of its own:
  // `decision: block` alone injects a reason and suppresses nothing. The tool
  // has already run and its result has already formed, so a deny that carries
  // no replacing output reports a withholding that never happened while the
  // secret is delivered -- the same "reported but never took effect" hazard as
  // any decision that claims a change without producing one.
  //
  // So the withholding is itself a shape-preserving replacement, built the same
  // way the redaction above is: a clone of the object the host handed us, with
  // the one leaf the hookmap named replaced. A withheld output that Claude Code
  // declines is not a withholding at all.
  it("withholds the output on a deny, with every sibling field still in place", async () => {
    const out = await answering({ decision: "deny", reasoning: "secret in output" }, (url) =>
      runHook(postToolUsePayload("TOKEN=ghp_ABCDEF123456"), url),
    );

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
    expect(JSON.parse(out.stdout)).toEqual({
      decision: "block",
      reason: "secret in output",
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        updatedToolOutput: {
          stdout: "[OUTPUT WITHHELD BY POLICY]",
          stderr: "",
          interrupted: false,
          isImage: false,
          noOutputExpected: false,
        },
      },
    });
    expect(out.stdout).not.toContain("ghp_ABCDEF123456");
  });

  // AN ASK AT THE RESULT GATE, and the reason it is a withholding rather than a
  // question. Claude Code has no way to ask a human about an output that
  // already exists -- there is no permission left to grant at this event and no
  // pending state to hold a formed result in -- so the only part of an ask this
  // host can act on is that the output is not deliverable as it stands. The
  // hookmap says so with the same three fields `deny` uses, and says at the site
  // what that costs.
  //
  // WHAT THIS PINS, and it is not the mapping alone. Before it, the result
  // gate's `decisions` block named `allow`, `deny` and `modify` and no more, so
  // an ask arriving here threw at the render, `governStep`'s render stage caught
  // it, and the negotiated posture answered -- which under the shipped default
  // (`proceed`) DELIVERED the output in full, recorded as a decision that could
  // not be rendered. The request gate fails both closed; this gate failed open,
  // and the asymmetry was the defect.
  //
  // `ask_details` IS WHAT MAKES THIS TEST BITE. An ask carrying no usable
  // `ask_details` never reaches a render as an ask at all: `resolveAsk`
  // substitutes a deny for it, which withholds through the entry that was always
  // there, and this test would then pass against the unfixed gate. Well-formed
  // and unexpired is the only shape that reaches the hookmap's own `ask` entry.
  it("withholds the output on an ask, which this host cannot put to a human at all", async () => {
    const out = await answering(
      {
        decision: "ask",
        reasoning: "a human should see this output first",
        ask_details: { approver: "security-team", question: "release this output?", timeout_seconds: 300 },
      },
      (url) => runHook(postToolUsePayload("TOKEN=ghp_ABCDEF123456"), url),
    );

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
    expect(JSON.parse(out.stdout)).toEqual({
      decision: "block",
      // The policy's own sentence, not a substitution's: an ask that arrived
      // intact renders through the hookmap's `ask` entry, so what reaches the
      // transcript is what the Guardian said rather than an expiry message.
      reason: "a human should see this output first",
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        updatedToolOutput: {
          stdout: "[OUTPUT WITHHELD BY POLICY]",
          stderr: "",
          interrupted: false,
          isImage: false,
          noOutputExpected: false,
        },
      },
    });
    expect(out.stdout).not.toContain("ghp_ABCDEF123456");
  });

  // A DEFER INSIDE ITS WINDOW, which is the half `resolveDefer` deliberately
  // does not touch: an unexpired defer is returned exactly as it arrived, so
  // this host is handed a live "not yet" for an output that already exists. It
  // has no state to hold one in, so "not yet" and "not at all" are the same
  // delivery here, and the request gate above already reads a defer that way
  // for the same reason -- ACS's own defer-details.json defaults an unresolved
  // defer's timeout_decision to deny.
  //
  // `resolution_timeout_ms` is milliseconds and 300_000 of them will not elapse
  // during a subprocess run, so this defer really is inside its window; a bare
  // `defer` would be denied by `resolveDefer` for unreadable details and would
  // pin nothing about the entry under test, exactly as a bare ask would.
  it("withholds the output on a defer inside its window, having nowhere to hold it", async () => {
    const out = await answering(
      {
        decision: "defer",
        reasoning: "waiting on an out-of-band approval",
        defer_details: {
          reason: "awaiting change ticket",
          resolution_method: "external",
          resolution_timeout_ms: 300_000,
        },
      },
      (url) => runHook(postToolUsePayload("TOKEN=ghp_ABCDEF123456"), url),
    );

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
    expect(JSON.parse(out.stdout)).toEqual({
      decision: "block",
      reason: "waiting on an out-of-band approval",
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        updatedToolOutput: {
          stdout: "[OUTPUT WITHHELD BY POLICY]",
          stderr: "",
          interrupted: false,
          isImage: false,
          noOutputExpected: false,
        },
      },
    });
    expect(out.stdout).not.toContain("ghp_ABCDEF123456");
  });

  // The two halves composed, which is where a result-gate deny stops being
  // hypothetical: a `modify` whose redaction addresses a field the result
  // payload does not have cannot be applied, so validateDecision substitutes
  // `deny(modifications_invalid)` -- and that deny has to withhold the output
  // too, or a rewrite the host refused becomes an unredacted delivery with a
  // block reason attached. Fail-closed all the way to the bytes on stdout.
  it("refuses a redaction it cannot apply, and the refusal still withholds the output", async () => {
    const out = await answering(
      {
        decision: "modify",
        reasoning: "redaction_applied",
        modifications: { redactions: [{ path: "/outputs/9/value", replacement: "TOKEN=[REDACTED]" }] },
      },
      (url) => runHook(postToolUsePayload("TOKEN=ghp_ABCDEF123456"), url),
    );

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
    const parsed = JSON.parse(out.stdout) as { decision: string; reason: string; hookSpecificOutput: Record<string, unknown> };
    expect(parsed.decision).toBe("block");

    // The stated reason, not merely that there is one. `reason` is what Claude
    // Code shows in the transcript and what the audit trail records. Asserting
    // merely that the reason mentions "modifications" would pass even while the
    // sentence talked about arguments this tool call sent -- and there are no
    // arguments at a gate where the step has already run. A deny is only as
    // useful as its stated reason, so the reason itself is pinned.
    expect(parsed.reason).toContain('redaction path "/outputs/9/value" addresses "/outputs/9"');
    expect(parsed.reason).toContain("this step's own request or result payload");
    // Nothing in this sentence may name a thing this gate does not have; the
    // negative assertion is what would catch a reason that wrongly did.
    expect(parsed.reason).not.toContain("arguments this tool call sent");
    // And no raw JS error text: `Error:` in a rendered reason is a stringified
    // exception leaking into the transcript.
    expect(parsed.reason).not.toContain("Error:");
    expect(parsed.hookSpecificOutput.updatedToolOutput).toEqual({
      stdout: "[OUTPUT WITHHELD BY POLICY]",
      stderr: "",
      interrupted: false,
      isImage: false,
      noOutputExpected: false,
    });
    expect(out.stdout).not.toContain("ghp_ABCDEF123456");
  });

  // This host has no target for a modification at either gate -- the
  // statement is about the host, not about §6.3 or this adapter's apply
  // step. `modified_content` is a legal §6.3 shape: one opaque body
  // replacing the whole payload, exclusive of the structured edits. A host
  // whose gate accepted an opaque body could apply it as it arrives.
  //
  // This host accepts a structured object at both of its gates -- the
  // arguments a step is to run with, where it decides whether the step
  // runs, and the tool's own output object, where it sees what the step
  // produced -- and an opaque replacement string is a field of neither. So
  // there is no target for it here.
  //
  // Handing this gate one anyway hits the same hazard the whole-object
  // assertions above guard against: a plain string where the tool's output
  // shape is expected is discarded, and the original output is delivered
  // with a warning line. So the only honest answer is a withholding deny --
  // never a `modify` reported as applied while the token reaches the model.
  //
  // Measured: with `assertValidModifications`'s `modified_content` refusal
  // made a silent pass-through, this gate still fails closed -- the apply
  // step returns the document untouched, so the projection's landing check
  // (the test below) catches it and withholds. 483 pass / 3 fail, and this
  // test fails on its `reason` assertion rather than on a delivered token.
  // At the request gate there is no such backstop: the same mutation
  // renders an applied rewrite carrying `{command: "cat .env"}`, the
  // original, which is what runs. With both refusals passed through
  // together: 478 pass / 8 fail, and this gate hands the model
  // `stdout: "TOKEN=ghp_ABCDEF123456"` beside
  // `additionalContext: "redaction_applied"` -- the real secret, with an
  // explanation saying it was redacted.
  it("refuses a modified_content result modification as a withholding deny", async () => {
    const out = await answering(
      {
        decision: "modify",
        reasoning: "redaction_applied",
        modifications: { modified_content: "wholesale replacement" },
      },
      (url) => runHook(postToolUsePayload("TOKEN=ghp_ABCDEF123456"), url),
    );

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
    const parsed = JSON.parse(out.stdout) as {
      decision: string;
      reason: string;
      hookSpecificOutput: Record<string, unknown>;
    };
    expect(parsed.decision).toBe("block");
    // The stated reason has to be true at this gate. There are no arguments
    // where the step has already run, so a refusal naming only them would send
    // an incident reviewer to a document this exchange never carried.
    expect(parsed.reason).toContain("modified_content asks for a wholesale content replacement");
    expect(parsed.reason).toContain("the outputs it produced");
    expect(parsed.reason).not.toContain("arguments this tool call sent");
    expect(parsed.reason).not.toContain("Error:");
    expect(parsed.hookSpecificOutput.updatedToolOutput).toEqual({
      stdout: "[OUTPUT WITHHELD BY POLICY]",
      stderr: "",
      interrupted: false,
      isImage: false,
      noOutputExpected: false,
    });
    // The assertion that fails the moment the refusal becomes a
    // pass-through: a reported-as-applied `modified_content` renders no
    // replacement at all, so the host delivers the output the tool produced.
    expect(out.stdout).not.toContain("ghp_");
  });

  // The hazard in its purest form. A redaction path that resolves in the ACS
  // payload and names a field this host has no way to read back: `/exit_status`
  // is really there in the result payload (a hookmap literal put it there), so
  // §6.3's apply step honours it exactly as written and nothing is malformed.
  // But the ACS payload carries one leaf of the host's output object, and the
  // rewrite did not touch it -- so the replacement projected from the applied
  // document is the output the host already holds, byte for byte.
  //
  // Reporting `modify` there is the worst outcome this deployment can
  // produce: the audit trail records a redaction, the transcript says the
  // output was rewritten, and the model reads the real token. Refused as a
  // withholding deny instead.
  //
  // Measured, on the tree before the refusal existed and again by mutating it
  // away (delete the landing check in `result-output.ts`'s `projectAppliedOutput` and
  // return the projection unconditionally): 481 pass / 5 fail, and this gate
  // writes
  //
  //   {"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":
  //     {"stdout":"TOKEN=ghp_ABCDEF123456","stderr":"","interrupted":false,
  //      "isImage":false,"noOutputExpected":false},
  //     "additionalContext":"redaction_applied"}}
  //
  // -- a perfectly well-formed replacement in the tool's own output shape, so
  // nothing is discarded and nothing warns: the model reads the real token and
  // is told in the same breath that it was redacted. Four of the five failures
  // are validate-decision.test.ts's, which assert the same thing one seam
  // earlier; nothing else in 487 tests notices.
  it("refuses a redaction whose path has no host-side target", async () => {
    const out = await answering(
      {
        decision: "modify",
        reasoning: "redaction_applied",
        modifications: { redactions: [{ path: "/exit_status" }] },
      },
      (url) => runHook(postToolUsePayload("TOKEN=ghp_ABCDEF123456"), url),
    );

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
    const parsed = JSON.parse(out.stdout) as {
      decision: string;
      reason: string;
      hookSpecificOutput: Record<string, unknown>;
    };
    expect(parsed.decision).toBe("block");
    expect(parsed.reason).toContain("exactly as the step produced it");
    expect(parsed.reason).not.toContain("Error:");
    expect(parsed.hookSpecificOutput.updatedToolOutput).toEqual({
      stdout: "[OUTPUT WITHHELD BY POLICY]",
      stderr: "",
      interrupted: false,
      isImage: false,
      noOutputExpected: false,
    });
    // The load-bearing assertion: everything above it would already be true
    // of a `modify` whose projected replacement was identical to the
    // original, because a decision that changes nothing renders perfectly
    // well. This line is what actually depends on the refusal existing.
    expect(out.stdout).not.toContain("ghp_");
  });

  // Covered end to end through the real shim as a subprocess, not only at
  // packages/host-adapter/test/result-output.test.ts's call into
  // `replacingOutput` -- the layer this guards against only shows up at the
  // layer it would actually recur at. `postToolUsePayload("")` is precisely
  // the silent-command shape: `stdout` is empty and `toolResponse` above
  // hardcodes `stderr: ""` too, so both fields independently hold "". This
  // matters because `replacingOutput`'s post-condition walks the whole
  // replacement (leaf excluded) asking whether the withheld value survives
  // anywhere in it -- an empty withheld value could otherwise match
  // `stderr`'s own empty string and refuse every command that legitimately
  // prints nothing, e.g. `touch`, `mkdir`, `git add`, `export`, or a
  // successful `grep -q`. A stub Guardian answering a plain `allow` isolates
  // the claim to the preflight itself: this must not block regardless of
  // what decision would eventually arrive.
  it("does not block a silent command -- empty stdout, empty stderr -- at the result gate", async () => {
    const out = await answering({ decision: "allow" }, (url) => runHook(postToolUsePayload(""), url));

    expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
    // No `reasoning` on this decision, so no `additionalContext` field --
    // same shape the first test's own note explains.
    expect(JSON.parse(out.stdout)).toEqual({ hookSpecificOutput: { hookEventName: "PostToolUse" } });
  });
});
