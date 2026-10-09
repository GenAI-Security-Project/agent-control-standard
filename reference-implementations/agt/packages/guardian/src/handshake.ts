/**
 * buildServerHello builds the Guardian's answer to `handshake/hello`, per
 * handshake.json's ServerHello $def
 * (specification/v0.1.0/handshake.json at the repository root).
 *
 * The server owns version/method/profile intersection because it has the
 * ClientHello. This builder owns the deployment capabilities that are stable
 * across sessions; dispatch supplies the negotiated profile set.
 *
 * `methods_evaluated` is exactly the set this Guardian policy-evaluates.
 * Dispatched allow-by-default lifecycle hooks are deliberately absent.
 *
 * `on_decision_failure` ships the spec default, "proceed" (fail-open). This
 * responder's posture is deployment-configurable, so one binary can
 * demonstrate both fail-open and fail-closed behaviour without a rebuild.
 * This function only declares the posture on the wire; applying it happens
 * in host-adapter. A value that is neither posture throws rather than
 * falling back -- guessing which posture a typo meant would be a silent
 * bypass.
 */

export type ServerHello = {
  negotiated_version: string;
  methods_evaluated: string[];
  selected_transport: "http" | "https" | "stdio";
  signature_algorithms_supported: string[];
  timeout_config: { default_ms: number; per_method_ms?: Record<string, number> };
  on_decision_failure: "proceed" | "deny";
  skew_window_ms: number;
  profiles_accepted: string[];
};

/** The ACS spec version every schema and mapping in this repo is pinned to. */
const NEGOTIATED_VERSION = "0.1.0";

/**
 * The methods this Guardian policy-evaluates: the two native tool gates and
 * the wrapped MCP tool-call gate.
 *
 * This list has to agree exactly with what server.ts evaluates, in both
 * directions, and handshake.json's text for this field is not advisory:
 * "Methods listed by the client but absent here are NOT evaluated; the
 * Guardian's enforcement does not cover them. Clients MAY still emit them
 * for audit but MUST treat them as ALLOW-by-default." Naming a method here
 * that no branch dispatches claims enforcement that does not exist, which a
 * host is entitled to rely on. Omitting a method the dispatch does handle is
 * just as dangerous the other way: a conformant host would read this
 * ServerHello and treat that gate's decisions as advisory, ignoring them by
 * default, while the Guardian is actually enforcing them.
 *
 * So the relationship is checked rather than trusted --
 * test/handshake-declares-what-it-evaluates.test.ts pins the evaluated set and
 * separately proves allow-by-default lifecycle hooks remain dispatchable.
 *
 * It stays a literal on purpose. The dispatch it must agree with uses
 * predicate-gated branches, deliberately not a table (server.ts says why: a
 * point-driven dispatch would hand one method's envelope to another method's
 * assembler and return a well-formed verdict for the wrong policy). Nothing
 * in this module can read "what server.ts branches on", so deriving this
 * list from, say, validate-envelope's method constants would only pin that a
 * predicate exists, not that dispatch actually reaches it. The test verifies
 * what the code cannot.
 */
const METHODS_EVALUATED = [
  "steps/toolCallRequest",
  "steps/toolCallResult",
  "protocols/MCP/tools/call",
];

/**
 * Deployment-chosen default; handshake.json's timeout_config.default_ms
 * carries no spec-mandated number. 5s bounds worst-case added latency on a
 * synchronous pre-tool-call decision without being so tight that a
 * momentarily slow Guardian trips it.
 */
const DEFAULT_TIMEOUT_MS = 5000;

/** The two postures §6.4 defines. Anything else is a broken deployment. */
const POSTURES = ["proceed", "deny"] as const;
type Posture = (typeof POSTURES)[number];

/**
 * The deployment's declared posture, read from `ACS_ON_DECISION_FAILURE` and
 * defaulting to the spec's default of `proceed` (handshake.json's own
 * `default`). Making it configurable lets one binary demonstrate both
 * fail-open and fail-closed behaviour without a rebuild.
 *
 * A value that is neither posture THROWS rather than falling back. Falling
 * back to fail-open on a typo would be exactly the silent bypass this
 * project exists to prevent: the deployment asked for something, and
 * guessing which posture it meant is not available to us.
 */
// The parameter type is deliberately WIDER than buildServerHello's own
// (`{ ACS_ON_DECISION_FAILURE?: string }`), and the asymmetry is forced
// rather than accidental: the zero-argument call site passes `process.env`,
// whose index signature is `Record<string, string | undefined>` and which
// does not satisfy the narrower shape. Widening the public parameter to
// match would let any environment-like bag in where the intent is "the one
// variable this reads"; narrowing this one would need a cast at the only
// call site that matters. This is the cheaper of the two.
function readPosture(env: Record<string, string | undefined>): Posture {
  const raw = env.ACS_ON_DECISION_FAILURE;
  if (raw === undefined) {
    return "proceed";
  }
  if ((POSTURES as readonly string[]).includes(raw)) {
    return raw as Posture;
  }
  throw new Error(
    `ACS_ON_DECISION_FAILURE must be "proceed" or "deny", got ${JSON.stringify(raw)}`,
  );
}

/** §10.3: the window this Guardian enforces, declared in the ServerHello so
 * the client knows the bound. Matches SKEW_WINDOW_MS in server.ts. */
const SKEW_WINDOW_MS = 300_000;

export type ServerHelloCapabilities = {
  hmacEnabled?: boolean;
  profilesAccepted?: string[];
};

export function buildServerHello(
  env?: { ACS_ON_DECISION_FAILURE?: string },
  capabilities: ServerHelloCapabilities = {},
): ServerHello {
  const actualEnv = env ?? process.env;
  return {
    negotiated_version: NEGOTIATED_VERSION,
    methods_evaluated: METHODS_EVALUATED,
    selected_transport: "http",
    signature_algorithms_supported: capabilities.hmacEnabled ? ["HMAC-SHA256"] : [],
    timeout_config: { default_ms: DEFAULT_TIMEOUT_MS },
    on_decision_failure: readPosture(actualEnv),
    skew_window_ms: SKEW_WINDOW_MS,
    profiles_accepted: capabilities.profilesAccepted ?? [],
  };
}
