/**
 * buildServerHello builds the Guardian's answer to `handshake/hello`, per
 * handshake.json's ServerHello $def
 * (specification/v0.1.0/handshake.json at the repository root).
 *
 * `build`, not `negotiate`: this function never reads the incoming
 * ClientHello. The client (host-adapter's `negotiateSessionConfig`) genuinely
 * sends one, but every field below is a constant, returned unconditionally.
 * So `negotiated_version` and `selected_transport` are declared by this
 * Guardian rather than agreed against what the client proposed. Real
 * negotiation -- reading the ClientHello, picking a mutually supported
 * version and transport, rejecting what isn't -- is future work; see the
 * matching note in the v1 runbook of the standalone repository
 * (github.com/afogel/ACS_reference_implementation, docs/demos/v1-runbook.md).
 *
 * `methods_evaluated` is exactly the set this Guardian actually dispatches,
 * pinned against the dispatch by
 * test/handshake-declares-what-it-evaluates.test.ts rather than by this
 * sentence. See METHODS_EVALUATED below for why it is checked and not
 * derived.
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
  timeout_config: { default_ms: number; per_method_ms?: Record<string, number> };
  on_decision_failure: "proceed" | "deny";
};

export const UNSUPPORTED_VERSION_CODE = -32001;
export const CAPABILITY_NOT_NEGOTIATED_CODE = -32003;

/** The ACS spec version every schema and mapping in this repo is pinned to. */
export const NEGOTIATED_VERSION = "0.1.0";
const SUPPORTED_TRANSPORT = "http" as const;

function parseSemver(version: unknown): { major: number; minor: number; patch: number } | undefined {
  if (typeof version !== "string") return undefined;
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) return undefined;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

/**
 * Under 0.x a breaking change is a minor bump, so a peer accepts the same
 * minor with any patch and refuses a different minor; from 1.0 on, the rule is
 * the same major (#196). Derived from the Guardian's own version rather than a
 * hard-coded minor so a spec bump (e.g. 0.2.0) updates the check in one place.
 */
export function isSupportedAcsVersion(version: unknown, guardianVersion: string = NEGOTIATED_VERSION): version is string {
  const candidate = parseSemver(version);
  const own = parseSemver(guardianVersion);
  if (candidate === undefined || own === undefined) return false;
  return own.major === 0
    ? candidate.major === 0 && candidate.minor === own.minor
    : candidate.major === own.major;
}

export type HandshakeNegotiationResult =
  | { ok: true; serverHello: ServerHello }
  | { ok: false; code: number; message: string };

export function negotiateHandshake(
  envelopeParams: { acs_version: string; payload?: Record<string, unknown> },
  env?: { ACS_ON_DECISION_FAILURE?: string },
  guardianVersion: string = NEGOTIATED_VERSION,
): HandshakeNegotiationResult {
  if (!isSupportedAcsVersion(envelopeParams.acs_version, guardianVersion)) {
    return {
      ok: false,
      code: UNSUPPORTED_VERSION_CODE,
      message: `UNSUPPORTED_VERSION: unsupported acs_version ${JSON.stringify(envelopeParams.acs_version)}`,
    };
  }
  const payload = envelopeParams.payload ?? {};
  if ("acs_version" in payload && !isSupportedAcsVersion(payload.acs_version, guardianVersion)) {
    return {
      ok: false,
      code: UNSUPPORTED_VERSION_CODE,
      message: `UNSUPPORTED_VERSION: unsupported client acs_version ${JSON.stringify(payload.acs_version)}`,
    };
  }
  let selectedVersion =
    typeof payload.acs_version === "string" ? payload.acs_version : envelopeParams.acs_version;
  if ("acs_versions_supported" in payload) {
    const versions = payload.acs_versions_supported;
    const match = Array.isArray(versions)
      ? versions.find((v): v is string => isSupportedAcsVersion(v, guardianVersion))
      : undefined;
    if (match === undefined) {
      return {
        ok: false,
        code: UNSUPPORTED_VERSION_CODE,
        message: `UNSUPPORTED_VERSION: no compatible version in acs_versions_supported ${JSON.stringify(versions)}`,
      };
    }
    selectedVersion = match;
  }
  if ("transports_supported" in payload) {
    const transports = payload.transports_supported;
    if (!Array.isArray(transports) || !transports.includes(SUPPORTED_TRANSPORT)) {
      return {
        ok: false,
        code: CAPABILITY_NOT_NEGOTIATED_CODE,
        message: `CAPABILITY_NOT_NEGOTIATED: Guardian supports transport "${SUPPORTED_TRANSPORT}", client advertised ${JSON.stringify(transports)}`,
      };
    }
  }
  return {
    ok: true,
    serverHello: {
      ...buildServerHello(env),
      negotiated_version: selectedVersion,
    },
  };
}

/**
 * The methods this Guardian actually dispatches -- exactly the two gated
 * branches in server.ts (`isToolCallRequest` -> `assemblePreToolCallSnapshot`,
 * `isToolCallResult` -> `assemblePostToolCallSnapshot`). Anything else falls
 * to `method_not_dispatched`.
 *
 * This list has to agree exactly with what server.ts dispatches, in both
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
 * test/handshake-declares-what-it-evaluates.test.ts drives a candidate
 * envelope for every method mapping.yaml maps through a live Guardian and
 * asserts that the set it does not answer `method_not_dispatched` for is
 * exactly this list.
 *
 * It stays a literal on purpose. The dispatch it must agree with is two
 * predicate-gated branches, deliberately not a table (server.ts says why: a
 * point-driven dispatch would hand one method's envelope to another method's
 * assembler and return a well-formed verdict for the wrong policy). Nothing
 * in this module can read "what server.ts branches on", so deriving this
 * list from, say, validate-envelope's method constants would only pin that a
 * predicate exists, not that dispatch actually reaches it. The test verifies
 * what the code cannot.
 */
const METHODS_EVALUATED = ["steps/toolCallRequest", "steps/toolCallResult"];

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

export function buildServerHello(env?: { ACS_ON_DECISION_FAILURE?: string }): ServerHello {
  const actualEnv = env ?? process.env;
  return {
    negotiated_version: NEGOTIATED_VERSION,
    methods_evaluated: METHODS_EVALUATED,
    selected_transport: "http",
    timeout_config: { default_ms: DEFAULT_TIMEOUT_MS },
    on_decision_failure: readPosture(actualEnv),
  };
}
