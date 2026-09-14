import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The regression pin for what this deployment actually puts on stdout.
 *
 * Every other test in this directory asserts one field at a time ("the
 * decision is deny", "the reason is a non-empty string"), which is exactly the
 * shape of assertion that survives an output quietly gaining, losing or moving
 * a field. This file asserts the whole JSON object, as a literal, for every
 * decision the shipped hookmap declares -- allow, deny, ask, defer and modify
 * -- so that any change to the rendered wire shape has to be a deliberate edit
 * to the literals below rather than something a refactor can do by accident.
 *
 * It is written against the shim as a subprocess, the way Claude Code invokes
 * it, and against the real hosts/claude-code/claude-code.hookmap.yaml. That is
 * deliberate: it makes this pin independent of how the rendering is factored
 * internally -- which module names the host's fields, which layer assembles
 * the wrapper -- and dependent only on what a host process reads back. It is
 * the contract; the factoring behind it is not.
 *
 * The Guardian here is a stub rather than the real one. The five decisions
 * below are the five the hookmap knows how to render, and the shipped policy
 * bundle only ever produces two of them; a pin that could only cover `allow`
 * and `deny` would leave the three rarest renderings -- the ones nobody looks
 * at, and the ones a careless change breaks first -- unpinned.
 *
 * The shim negotiates a session before the step call, so the stub answers a
 * `handshake/hello` request and each run negotiates a real `proceed` posture.
 * That branch is why the two ACS `*_details` fixtures below are well-formed
 * rather than bare: they are what they claim to be, an ask and a defer that
 * arrived intact. Every case here is a decision that arrives, so no posture
 * is ever consulted, and this suite never reads or writes `.acs/` under the
 * repo's own cwd.
 */
const SHIM = fileURLToPath(new URL("../acs-hook.ts", import.meta.url));

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-wire-shape-"));
  dirs.push(dir);
  return dir;
}

/**
 * Removes exactly what a run of this suite can leave behind -- by name, never
 * recursively, matching the cleanup posture of posture.test.ts next door.
 * Every test here uses session id "sess-1" and every test here exercises a
 * decision that actually arrives, so `sessions/sess-1.json` is the only file
 * expected; `audit.jsonl` is removed if present, because an audit write in
 * this suite would mean a delivery failure happened and the test that saw it
 * should fail on its assertions rather than on a leftover file.
 */
function cleanupScratch(dir: string): void {
  const sessionsDir = join(dir, "sessions");
  for (const file of [join(dir, "audit.jsonl"), join(sessionsDir, "sess-1.json")]) {
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

/**
 * Runs the real shim as a subprocess against a stub Guardian that answers the
 * step call with `decision`, and returns the parsed JSON it wrote to stdout.
 *
 * Asserts exit 0 and a silent stderr first: a decision that renders correctly
 * while the process also prints a stack trace, or exits non-zero, is not a
 * pass -- and a failure there prints what was actually on stderr rather than
 * an opaque JSON.parse error.
 */
async function renderedBy(decision: Record<string, unknown>, command: string): Promise<unknown> {
  const dir = scratch();
  const stub = Bun.serve({
    port: 0,
    async fetch(req) {
      const body = (await req.json()) as { id: string | number; method: string };
      if (body.method === "handshake/hello") {
        return Response.json({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            negotiated_version: "0.1.0",
            methods_evaluated: ["steps/toolCallRequest"],
            selected_transport: "http",
            timeout_config: { default_ms: 5000 },
            on_decision_failure: "proceed",
          },
        });
      }
      return Response.json({ jsonrpc: "2.0", id: body.id, result: decision });
    },
  });
  try {
    const proc = Bun.spawn(["bun", "run", SHIM], {
      stdin: new TextEncoder().encode(
        JSON.stringify({
          session_id: "sess-1",
          hook_event_name: "PreToolUse",
          tool_name: "Bash",
          tool_input: { command },
        }),
      ),
      env: {
        ...process.env,
        ACS_GUARDIAN_URL: `http://localhost:${stub.port}/acs`,
        ACS_SESSION_DIR: join(dir, "sessions"),
        ACS_AUDIT_LOG: join(dir, "audit.jsonl"),
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    expect({ exitCode: await proc.exited, stderr }).toEqual({ exitCode: 0, stderr: "" });
    return JSON.parse(stdout);
  } finally {
    stub.stop(true);
  }
}

describe("the wire shape this host writes to stdout, pinned decision by decision", () => {
  it("renders an allow that carries no reasoning with no reason field at all", async () => {
    expect(await renderedBy({ decision: "allow", reason_codes: [], policy_references: [] }, "ls -la")).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
      },
    });
  });

  it("renders an allow that carries reasoning with that reasoning attached", async () => {
    // The shape an observe-only upstream signal produces: an ACS allow with a
    // synthesized explanation and non-empty policy_references. The
    // explanation travels to the host; the references do not, and the
    // explanation is the only thing distinguishing this from a plain allow
    // in the transcript a human reads. The case that actually pays for this
    // is a fail-open proceed, whose reason is written by applyFailurePosture
    // and needs somewhere to go.
    expect(
      await renderedBy(
        {
          decision: "allow",
          reasoning: "drift_score 0.9 reached threshold 0.5",
          reason_codes: ["drift_detected"],
          policy_references: [{ policy_id: "agt_stock", rule_id: "drift_detected" }],
        },
        "ls -la",
      ),
    ).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
        permissionDecisionReason: "drift_score 0.9 reached threshold 0.5",
      },
    });
  });

  it("renders a deny with the policy's own reasoning -- the demo's entire payoff", async () => {
    expect(
      await renderedBy({ decision: "deny", reasoning: "blocked by policy", reason_codes: ["destructive"] }, "rm -rf /"),
    ).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: "blocked by policy",
      },
    });
  });

  // `ask_details` is what makes this an ask that arrived intact: the decision
  // reaches renderDecision through `validateDecision`, which substitutes a
  // deny for an ask carrying no usable `ask_details` -- it cannot tell an
  // unexpired ask from an expired one without the window, and §6 makes that
  // fail closed. Pinning the substituted deny here instead would leave the
  // hookmap's `ask` entry -- one of the three rarest renderings this file
  // exists for -- with nothing pinning it at all; the substitution itself is
  // covered where it belongs, in
  // packages/host-adapter/test/validate-decision.test.ts.
  it("renders an ask that is still inside its window as an ask, carrying its reasoning", async () => {
    expect(
      await renderedBy(
        {
          decision: "ask",
          reasoning: "this needs a human",
          ask_details: { approver: "security-team", question: "run this?", timeout_seconds: 300 },
        },
        "curl example.com",
      ),
    ).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: "this needs a human",
      },
    });
  });

  // `defer_details` for the same reason as `ask_details` above, and the deny
  // below is the hookmap's own `defer` entry rendering (this host has no
  // deferral state, so §defer-details' own default is the least-wrong mapping)
  // rather than `validateDecision` substituting one for a defer it could not
  // read. The two are indistinguishable in the decision field and tell apart
  // only by the reason: the policy's own text here, a "missing valid
  // defer_details" message there.
  it("renders a defer that is still inside its window as a deny -- this host has no deferral state", async () => {
    expect(
      await renderedBy(
        {
          decision: "defer",
          reasoning: "waiting on an out-of-band approval",
          defer_details: {
            reason: "awaiting change ticket",
            resolution_method: "external",
            resolution_timeout_ms: 300_000,
          },
        },
        "curl example.com",
      ),
    ).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: "waiting on an out-of-band approval",
      },
    });
  });

  it("renders a modify as an allow carrying the rewritten arguments and the reason they changed", async () => {
    // `updatedInput` carries what `validateDecision` produces by applying
    // §6.3's modifications to the arguments that went out on the wire
    // (`applied_input`): the tool input Claude Code can run, with the secret
    // gone. The entry also carries a reason, because a policy-ordered
    // rewrite is the one decision that changes what runs while the
    // transcript would otherwise say nothing about it.
    expect(
      await renderedBy(
        {
          decision: "modify",
          reasoning: "redaction_applied",
          modifications: { parameter_overrides: { command: "echo [REDACTED]" } },
        },
        "echo ghp_SECRET123456",
      ),
    ).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
        permissionDecisionReason: "redaction_applied",
        updatedInput: { command: "echo [REDACTED]" },
      },
    });
  });
});
