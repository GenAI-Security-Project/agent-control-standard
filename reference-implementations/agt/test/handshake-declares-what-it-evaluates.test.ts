import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { fileURLToPath } from "node:url";
import { buildServerHello, loadMapping, startGuardian, type StartedGuardian } from "guardian";
import {
  createGuardianClient,
  createMemorySessionConfigStore,
  loadHookmap,
  negotiateSessionConfig,
} from "host-adapter";

/**
 * The handshake has to describe the Guardian that sent it.
 *
 * `methods_evaluated` is not documentation. handshake.json defines it as the
 * "Subset of the client's methods_implemented that this Guardian will actually
 * evaluate", and then says what a client must do with the difference: "Methods
 * listed by the client but absent here are NOT evaluated; the Guardian's
 * enforcement does not cover them. Clients MAY still emit them for audit but
 * MUST treat them as ALLOW-by-default."
 *
 * So the two failure directions are not symmetric in kind, only in badness:
 *
 *   - Under-declaring tells a conformant host to ignore a gate that is
 *     really enforcing -- the more dangerous direction, and the harder one
 *     to notice, since a host that never reads the field has no way to see
 *     the gap.
 *   - Over-declaring claims enforcement that does not exist, which a host is
 *     entitled to rely on. It is the direction a "just add the method to the
 *     list" fix invites.
 *
 * This is a test rather than a derived constant because what must hold is a
 * property of the running Guardian: it declares exactly what it dispatches.
 * Dispatch is two predicate-gated branches in server.ts, deliberately not a
 * table -- that module argues at length that a table keyed on the resolved
 * intervention point would hand one method's envelope to another method's
 * assembler and answer with a well-formed verdict for the wrong policy. There
 * is no expression `buildServerHello` could evaluate to learn "what server.ts
 * branches on". Deriving the list from, say, validate-envelope's method
 * constants would pin something narrower -- that a predicate exists -- and
 * leave both failures above reachable: a predicate with no branch would
 * over-declare, and a branch is what makes a method evaluated. So the
 * declaration stays a literal and the relationship is measured, by asking a
 * live Guardian which methods it answers for.
 */

const MANIFEST = fileURLToPath(new URL("../policy/manifest.yaml", import.meta.url));
const MAPPING = fileURLToPath(new URL("../mapping.yaml", import.meta.url));
const HOOKMAP = fileURLToPath(new URL("../hosts/claude-code/claude-code.hookmap.yaml", import.meta.url));

/** server.ts's own code for "well-formed envelope, no handler here". */
const METHOD_NOT_DISPATCHED = -32011;

let guardian: StartedGuardian;

beforeAll(async () => {
  guardian = await startGuardian({ port: 0, manifestPath: MANIFEST });
});

afterAll(async () => {
  await guardian.close();
});

/**
 * A payload that satisfies whatever schema `validateEnvelope` applies to this
 * method, so the probe below measures dispatch rather than validation. Only the
 * two dispatched methods have a hook payload schema today; every other method
 * is checked against the generic request-envelope shape alone, which an empty
 * object satisfies. If that stops being true the probe says so by name rather
 * than quietly reclassifying the method (see `dispatches`).
 */
function payloadFor(method: string): Record<string, unknown> {
  if (method === "steps/toolCallRequest") {
    return { tool: { name: "Bash" }, arguments: { command: { value: "ls -la" } } };
  }
  if (method === "steps/toolCallResult") {
    return { tool: { name: "Bash" }, exit_status: "success", outputs: [{ value: "nothing to redact" }] };
  }
  return {};
}

type RpcAnswer = {
  result?: { decision?: string; reason_codes?: string[] };
  error?: { code?: number; message?: string };
};

/** Posts one well-formed envelope for `method` and says whether this Guardian
 * answered for it at all. */
async function dispatches(method: string): Promise<boolean> {
  const id = crypto.randomUUID();
  const res = await fetch(guardian.url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method,
      id,
      params: {
        acs_version: "0.1.0",
        request_id: id,
        timestamp: new Date().toISOString(),
        metadata: { agent_id: "conformance", session_id: crypto.randomUUID() },
        payload: payloadFor(method),
      },
    }),
  });
  const answer = (await res.json()) as RpcAnswer;

  if (answer.error?.code === METHOD_NOT_DISPATCHED) {
    return false;
  }
  if (typeof answer.result?.decision === "string") {
    // The Guardian turns a schema failure into an honoured `deny` for any steps/*
    // method, dispatched or not -- so an envelope_invalid here means this
    // probe's payload no longer satisfies that method's schema, and the
    // measurement would be of validation rather than of dispatch. Fail loudly
    // instead of guessing: the fix is a real payload in `payloadFor`.
    if (answer.result.reason_codes?.includes("envelope_invalid") === true) {
      throw new Error(
        `probe payload for ${method} is no longer schema-valid, so dispatch cannot be measured for it: ` +
          `add a real payload to payloadFor()`,
      );
    }
    return true;
  }
  throw new Error(`unclassifiable answer for ${method}: ${JSON.stringify(answer)}`);
}

describe("the ServerHello declares exactly the methods this Guardian dispatches", () => {
  it("names every dispatched method and no undispatched one", async () => {
    const declared = buildServerHello({}).methods_evaluated;

    // The candidate set: every ACS method this deployment maps to an AGT
    // intervention point, plus whatever the hello claims. The first half is
    // sound as a universe because a dispatched method must resolve a point out
    // of this same table -- `resolveInterventionPoint` throws otherwise and the
    // step comes back as an honoured deny, never as enforcement. The second
    // half is what catches a hello naming a method the mapping does not even
    // have.
    const mapping = loadMapping(MAPPING);
    const candidates = new Set<string>(declared);
    for (const point of Object.values(mapping.intervention_points)) {
      if (typeof point.acs_method === "string") {
        candidates.add(point.acs_method);
      }
    }
    // The probe is only meaningful over a candidate set wider than the answer.
    expect(candidates.size).toBeGreaterThan(declared.length);

    const dispatched: string[] = [];
    for (const method of [...candidates].sort()) {
      if (await dispatches(method)) {
        dispatched.push(method);
      }
    }

    // Equality, in both directions, deliberately: `toEqual` on sorted arrays
    // rather than a subset check, because over-declaring is the worse failure
    // and a subset assertion would pass through it.
    expect(dispatched).toEqual([...declared].sort());
  });

  it("declares only methods the client said it implements, per handshake.json", async () => {
    const implemented = await capturedClientHello();
    // handshake.json: methods_evaluated is a "Subset of the client's
    // methods_implemented". Under-declaring on the client side is therefore not
    // a cosmetic omission -- it makes the Guardian's own answer unstateable.
    for (const method of buildServerHello({}).methods_evaluated) {
      expect(implemented).toContain(method);
    }
  });

  it("implements every ACS method the shipped hookmap can fire", async () => {
    // The other end of the same claim, one layer down: a hook mapped to a
    // method the ClientHello omits would have this host emitting envelopes for
    // a method it declared it does not implement -- and the ClientHello is
    // where a Guardian learns what it is allowed to say it evaluates, so the
    // omission travels. Read off the shipped hookmap and off the wire, neither
    // restated, so wiring a third hook without touching the adapter fails here.
    const hookmap = loadHookmap(HOOKMAP);
    const mapped = Object.values(hookmap.hooks).map((entry) => entry.acs_method);
    expect(mapped.length).toBeGreaterThan(0);

    const implemented = await capturedClientHello();
    for (const method of mapped) {
      expect(implemented).toContain(method);
    }
  });
});

/**
 * The real ClientHello's `methods_implemented`, captured off the wire from
 * `negotiateSessionConfig` rather than restated here: a recording endpoint that
 * answers with the Guardian's own ServerHello, so the adapter's handshake
 * completes exactly as it does against a real one.
 */
async function capturedClientHello(): Promise<string[]> {
  let methods: string[] | undefined;
  const recorder = Bun.serve({
    port: 0,
    async fetch(req) {
      const rpc = (await req.json()) as { id: string; params?: { payload?: { methods_implemented?: string[] } } };
      methods = rpc.params?.payload?.methods_implemented;
      return Response.json({ jsonrpc: "2.0", id: rpc.id, result: buildServerHello({}) });
    },
  });

  try {
    await negotiateSessionConfig(
      {
        guardian: createGuardianClient(`http://localhost:${recorder.port}/acs`),
        agentId: "conformance",
        sessionId: crypto.randomUUID(),
        timeoutMs: 5000,
      },
      createMemorySessionConfigStore(),
    );
  } finally {
    recorder.stop(true);
  }

  if (methods === undefined) {
    throw new Error("the adapter's ClientHello carried no methods_implemented at all");
  }
  return methods;
}
