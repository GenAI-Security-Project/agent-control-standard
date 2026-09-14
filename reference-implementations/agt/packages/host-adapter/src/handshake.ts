/**
 * The host half of `handshake/hello`: send a ClientHello, keep what comes back
 * as this session's config.
 *
 * Two entry points, with a real difference between them:
 *
 *   - `negotiateSessionConfig` does the exchange and THROWS. One request, one
 *     stored config, or an error naming which part failed.
 *   - `resolveSessionConfig` is what a host shim collaborates with: it is told
 *     "get me this session's config" and answers with a message -- the config
 *     to apply to this step, and whatever went wrong getting it. It never
 *     throws, and it never makes the caller ask an error object what it holds.
 *
 * The second one exists because the alternative -- catching a negotiation
 * failure, testing `error instanceof SessionConfigNotStoredError`, and reading
 * `error.config` off it to find out whether a posture had been negotiated
 * after all -- is exactly the kind of thing every host shim would otherwise
 * have to repeat, and getting it wrong is a fail-open (see
 * `SessionConfigNotStoredError`'s own doc comment below).
 *
 * The stored message is a `SessionConfig`, never a `ServerHello`.
 * `isSessionConfig` requires the two fields this host actually needs, not the
 * five handshake.json's ServerHello $def requires, so naming the stored type
 * after the wire message would over-claim what this host validates.
 * `ServerHello` stays scoped to one thing: what the Guardian sent, before
 * this host has confirmed it can use it (the Guardian's own noun for what it
 * emits -- packages/guardian/src/handshake.ts's `buildServerHello`).
 * `ServerHelloInvalidError` is named for the wire for the same reason -- the
 * fault it reports IS the arrival ("the Guardian emitted the wrong shape"),
 * not the store. No stored value, field, or type is called a ServerHello
 * anywhere.
 *
 * `negotiateSessionConfig`, not `handshake`: a bare wire verb says nothing
 * about what the caller gets, so this names the message it produces,
 * matching the `<verb><Message>` shape of the Guardian's own half
 * (`buildServerHello`).
 *
 * Stores only. Applying the negotiated posture -- falling back to
 * `timeout_config` when the Guardian is slow or silent, recording a
 * fail-open audit event per `on_decision_failure: "proceed"` -- happens
 * elsewhere. That boundary is deliberate: this project keeps a policy
 * runtime's own evaluation-layer fail-closed behaviour distinct from
 * wire-delivery failure. This module does not retry and does not write to
 * an audit sink -- it sends one request, stores one response, and returns
 * or throws.
 *
 * This call CAN time out (`HandshakeOptions.timeoutMs`, optional). It has
 * to -- there is no negotiated `timeout_config` yet at the point this runs,
 * so a caller with nothing else to bound it would otherwise hang on a
 * Guardian that accepts the connection and never answers, for exactly as
 * long as it takes Claude Code's own hook timeout to kill the process:
 * unaudited, and with nothing on stdout. What happens on a timeout (or any
 * other delivery failure) is still the caller's decision, not this
 * module's -- it only throws `GuardianTimeoutError`, same as
 * `guardianClient.post` always has; applying a posture to that throw
 * happens one layer up, in `applyFailurePosture`.
 *
 * This module knows ACS handshake vocabulary and JSON-RPC, nothing else. It
 * has no runtime dependency on the Guardian package -- it talks to the
 * Guardian only through the client role it is given, over the wire.
 */
import { randomUUID } from "node:crypto";
import type { GuardianClient, JsonRpcRequest } from "./guardian-client.ts";
import { isSessionConfig, type SessionConfig, type SessionConfigStore } from "./session-config.ts";

const HANDSHAKE_METHOD = "handshake/hello";
const ACS_VERSION = "0.1.0";

export type HandshakeOptions = {
  /** The Guardian to negotiate with -- `createGuardianClient(url)` for the
   * endpoint startGuardian returned (test-only) or the one this deployment is
   * configured for. A client rather than a URL because that is the seam: this
   * module knows the handshake, not how to reach a Guardian. */
  guardian: GuardianClient;
  /** This Observed Agent's identity on the wire (ACS metadata.agent_id). */
  agentId: string;
  /** This session's identity on the wire (ACS metadata.session_id, a uuid). */
  sessionId: string;
  /** Bounds this handshake round trip (§6.4). There is no negotiated
   * `timeout_config` yet -- negotiating it is what this call is for -- so a
   * caller with nothing better should pass the ACS default
   * (`DEFAULT_TIMEOUT_MS`, failure-posture.ts). Omitted means no timeout at
   * all, matching how `guardianClient.post` itself treats an absent
   * `timeoutMs`; a caller that omits this accepts a Guardian that accepts
   * the connection and never answers hanging indefinitely. */
  timeoutMs?: number;
};

/**
 * Thrown when the Guardian answered and this session still ended up with no
 * STORED config -- as opposed to a handshake that never got an answer at all.
 * The two are materially different incidents and must not be squashed into one:
 *
 *   - A handshake that never reached the Guardian negotiated nothing. There
 *     is no posture to apply, and `posture_source: "default"` already says
 *     so.
 *   - A ServerHello that arrived and could not be *persisted* DID negotiate
 *     a posture. Persisting it is an optimisation for the hooks that come
 *     after this one (the shipped host runs each hook in a fresh
 *     subprocess, so the file is how a later process finds it); the value in
 *     hand is authoritative for the step that negotiated it. Discarding it
 *     because the write failed is how a deployment that declared
 *     `on_decision_failure: deny` fails *open* on the very step it just
 *     negotiated -- the fail-open shape this project keeps finding.
 *
 * `config` carries the negotiated config whenever there is one to carry, so a
 * caller can apply it to the current step and still report the persistence
 * failure. It is undefined only when there was never a usable config to begin
 * with, which is one of the two members below.
 *
 * Abstract, so the family name can never be instantiated as if it were one
 * specific member: each concrete subclass names its own `kind`, and the two
 * names say which remedy applies -- fix this host's disk
 * (`SessionConfigStoreFailedError`), or fix the Guardian's output
 * (`ServerHelloInvalidError`).
 *
 * What stays true of every member, and is why they share a root at all: the
 * Guardian answered, and nothing was stored. `classifySessionFailure` reads
 * the family's `kind` and is unaffected by which member it is handed, and a
 * caller that only wants the config to apply reads `.config` without a
 * second branch.
 */
export abstract class SessionConfigNotStoredError extends Error {
  /** Which member of the family this is -- see classifySessionFailure. */
  readonly kind: "session_config_unstored" | "server_hello_invalid";
  /** The negotiated config, when one was negotiated. Undefined for
   * `server_hello_invalid`, where what arrived was not a usable config and
   * so there is genuinely nothing to apply. */
  readonly config: SessionConfig | undefined;

  protected constructor(
    message: string,
    {
      kind,
      cause,
      config,
    }: { kind: "session_config_unstored" | "server_hello_invalid"; cause?: unknown; config?: SessionConfig },
  ) {
    super(message, { cause });
    this.kind = kind;
    this.config = config;
  }
}

/**
 * The member where a usable config DID arrive and this host could not persist
 * it. The value in hand is authoritative for the step that negotiated it --
 * see the family's own doc comment above -- so it travels on `config`, and
 * discarding it because the write failed is the fail-open this class exists
 * to prevent.
 *
 * Named for the store rather than for the state, so it does not read as a
 * near-duplicate of the family it belongs to: its sibling reports a bad
 * arrival, this one reports a bad disk. Its `kind` stays
 * `session_config_unstored`, which is a durable value in the audit log and
 * so is spelled the way already-written entries spell it.
 */
export class SessionConfigStoreFailedError extends SessionConfigNotStoredError {
  declare readonly kind: "session_config_unstored";

  constructor(message: string, options: { cause?: unknown; config?: SessionConfig } = {}) {
    super(message, { ...options, kind: "session_config_unstored" });
    this.name = "SessionConfigStoreFailedError";
  }
}

/**
 * The member where what arrived was never a usable config at all: the Guardian
 * answered, and its answer carries neither of the two fields this host reads.
 * Nothing was stored, and -- unlike a hello that could not be persisted --
 * there is nothing to apply to the current step either, so `config` is
 * `undefined` by construction rather than by convention.
 *
 * Its own class because the remedy is entirely different: this one is a
 * Guardian emitting the wrong shape, not a host that cannot write to its own
 * disk. It is the one class here named for the wire, deliberately -- the fault
 * it reports is the arrival itself (see this module's header on the one noun for
 * the stored message).
 */
export class ServerHelloInvalidError extends SessionConfigNotStoredError {
  declare readonly kind: "server_hello_invalid";
  declare readonly config: undefined;

  constructor(message: string) {
    super(message, { kind: "server_hello_invalid" });
    this.name = "ServerHelloInvalidError";
  }
}

/**
 * Sends `handshake/hello`, waits for the Guardian's ServerHello, stores the
 * session config it validates out of that arrival, and returns that config.
 * Throws if the Guardian responds with a JSON-RPC error rather than a result,
 * throws `ServerHelloInvalidError` if what arrived is not a usable config, and
 * throws `SessionConfigStoreFailedError` -- carrying the config -- if the store
 * refuses to persist what did arrive.
 */
export async function negotiateSessionConfig(
  options: HandshakeOptions,
  store: SessionConfigStore,
): Promise<SessionConfig> {
  const requestId = randomUUID();

  const envelope: JsonRpcRequest = {
    jsonrpc: "2.0",
    method: HANDSHAKE_METHOD,
    id: requestId,
    params: {
      acs_version: ACS_VERSION,
      request_id: requestId,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: options.agentId, session_id: options.sessionId },
      // ClientHello shape (handshake.json's $defs.ClientHello). Not
      // schema-enforced on this method by the Guardian's own validateEnvelope
      // today, but supplied honestly rather than left empty.
      //
      // "Honestly" is the whole point of the field: this adapter builds both
      // step envelopes -- `buildEnvelope` has a request-shaped and a
      // result-shaped hookmap entry, and the shipped Claude Code hookmap maps
      // a hook to each -- so this list has to name both methods.
      // Under-declaring here is the direction that breaks the exchange rather
      // than merely misdescribing it: handshake.json defines the Guardian's
      // `methods_evaluated` as a "Subset of the client's methods_implemented",
      // so a Guardian that does evaluate result envelopes could not say so
      // without answering with a method this hello never offered.
      //
      // Deliberately a property of the adapter, not of one deployment's
      // hookmap: it says what this client can produce envelopes for, which is
      // what the field asks. A hookmap that maps fewer hooks emits fewer
      // methods and declares no less -- the Guardian narrows, per the sentence
      // above. What must never happen is a hookmap mapping a method this list
      // omits, which is what
      // test/handshake-declares-what-it-evaluates.test.ts checks against the
      // shipped hookmap.
      payload: {
        acs_versions_supported: [ACS_VERSION],
        methods_implemented: ["steps/toolCallRequest", "steps/toolCallResult"],
        transports_supported: ["http"],
        provenance_producer: "none",
      },
    },
  };

  // `post`, not `requestDecision`: this method's result is a ServerHello, not
  // a decision, and a handshake failure is a different incident from a step
  // that got no decision. It travels as a throw, separately.
  const response = await options.guardian.post(envelope, { timeoutMs: options.timeoutMs });
  if (response.error) {
    throw new Error(`handshake: Guardian rejected handshake/hello: ${response.error.message}`);
  }

  // Validated BEFORE storing, not cast and hoped for. This is the single point
  // where the Guardian's ServerHello becomes this host's SessionConfig, and it
  // becomes one by being checked -- named for the wire while it is still only
  // an arrival, and for the store once it is one.
  //
  // `get()` re-validates, so an unusable hello on disk is harmless to READ --
  // but writing one has a consequence nothing else surfaces: every `get()`
  // afterwards returns undefined, so every hook re-handshakes, forever, and
  // the deployment silently pays a round trip per hook while running on the
  // ACS default posture rather than the one its Guardian keeps declaring.
  // Rejecting it here turns that into a reported failure that travels as
  // `session_failure` on the audit entry (same route as an unstorable one),
  // instead of nothing at all.
  const serverHello = response.result as unknown;
  if (!isSessionConfig(serverHello)) {
    throw new ServerHelloInvalidError(
      `handshake: the Guardian's ServerHello is not a usable session config -- expected an object with ` +
        `on_decision_failure "proceed" or "deny" and a numeric timeout_config.default_ms, got ` +
        `${JSON.stringify(serverHello)}`,
    );
  }

  const sessionConfig: SessionConfig = serverHello;
  try {
    store.set(sessionConfig);
  } catch (error) {
    // The store is documented to throw here rather than swallow (an
    // unwritable `.acs/sessions` is a real deployment fault and hiding it
    // would be the silent half of the bug this error class exists for), so
    // this rethrows -- but with the negotiated config attached, so the
    // caller can still apply it to the step that negotiated it.
    throw new SessionConfigStoreFailedError(
      `handshake: the Guardian's ServerHello could not be stored ` +
        `(${error instanceof Error ? error.message : String(error)})`,
      { cause: error, config: sessionConfig },
    );
  }
  return sessionConfig;
}

/**
 * What a host is told when it asks for this session's config: the config that
 * governs the step about to run, and whatever went wrong establishing it.
 */
export type ResolvedSessionConfig = {
  /**
   * The config to apply to this step -- the stored one when a handshake has
   * already completed for this session, otherwise the one this process just
   * negotiated (including one it negotiated but could not persist).
   * `undefined` means nothing was negotiated and the ACS default governs,
   * which is what `posture_source: "default"` records.
   */
  config: SessionConfig | undefined;
  /**
   * Whatever went wrong negotiating or storing it, or `undefined` if nothing
   * did. Travels to the audit entry as `session_failure` and never becomes the
   * step's own failure: they are different requests that can fail for
   * unrelated reasons, and an audit entry has to classify the failure of the
   * request it is filed against.
   */
  failure: unknown;
};

/**
 * Negotiates this session's config once per session, and answers with a
 * message rather than a throw.
 *
 * A handshake failure decides nothing by itself, and it does not become the
 * step call's failure. It is not *discarded* either: it travels beside that
 * failure as `session_failure`, because the case that matters is a session
 * store this deployment cannot write to -- `set()` throws by design there,
 * every hook then re-negotiates and `store.get()` stays undefined, so a
 * deployment that declared `deny` silently fails open on every delivery
 * failure. `posture_source: "default"` records that no negotiated config was
 * found; `session_failure` records why. The step call may still succeed even
 * after this fails: the posture must never touch an arriving decision.
 *
 * Why `config` is not simply `store.get()`: the config `negotiateSessionConfig`
 * returns is not lost when `store.set` throws. Persisting it is an
 * optimisation for LATER hooks -- a host whose hooks run as fresh subprocesses
 * finds the posture through the file -- while the value in hand is
 * authoritative for the step that just negotiated it. Throwing it away
 * because the write failed would mean a deployment declaring
 * `on_decision_failure: deny` fails *open* on that very step: the posture
 * would be known in-process and unused.
 *
 * Without this function, every host shim would have to ask an error object
 * what it was carrying. `SessionConfigNotStoredError` is this module's own
 * type, so reading it here is a module reading itself; the `.config` on it is
 * `undefined` for `ServerHelloInvalidError` by construction, which is why one
 * branch covers both members of the family.
 */
export async function resolveSessionConfig(
  options: HandshakeOptions,
  store: SessionConfigStore,
): Promise<ResolvedSessionConfig> {
  let failure: unknown;
  let negotiated: SessionConfig | undefined;

  if (store.get() === undefined) {
    try {
      negotiated = await negotiateSessionConfig(options, store);
    } catch (error) {
      failure = error;
      if (error instanceof SessionConfigNotStoredError) {
        negotiated = error.config;
      }
    }
  }

  // The stored config when there is one; otherwise whatever was negotiated and
  // could not be stored. `failure` still travels either way, so a persistence
  // failure stays visible rather than being papered over by the value being
  // usable anyway.
  return { config: store.get() ?? negotiated, failure };
}
