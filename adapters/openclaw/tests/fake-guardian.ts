/**
 * Scripted Guardian for adapter tests. It verifies signed requests, tracks
 * negotiated sessions, and signs answers with the TypeScript Guardian's
 * signing functions. The test script supplies each decision.
 */
import {
  deriveSessionKey,
  signResponseHmacSha256,
  verifyHmacSha256,
} from "../../../reference-implementations/agt/packages/guardian/src/verify-signature.ts";
import { specificationFailure } from "./emitted-envelope.ts";
import type { HmacKey } from "../host-adapter.ts";

type Json = Record<string, unknown>;

export type ReceivedStep = {
  method: string;
  requestId: unknown;
  sessionId: string;
  userContext: unknown;
  turnId: unknown;
  agentName: unknown;
  payload: Json;
};

export type Reply =
  | { decision: Json }
  | { error: { code: number; message: string } }
  | { unsignedDecision: Json }
  /** Signs this exact result, even when the response schema rejects it. */
  | { signedResult: Json }
  /** Supplies exact `result` and `error` members for a signed, invalid response. */
  | { signedResponse: Json }
  /** Signs a decision, then changes it without the key, as an on-path attacker could. */
  | { tamperedDecision: Json; becomes: Json }
  | { body: string }
  | { hang: true };

export type FakeGuardian = {
  url: string;
  steps: ReceivedStep[];
  handshakes: number;
  /** `methods_implemented` from the last ClientHello. */
  methodsImplemented: unknown;
  /** `methods_evaluated` in the next ServerHello. */
  methodsEvaluated: string[] | null | undefined;
  /** Error returned without a signature for every later `handshake/hello`. */
  handshakeError: { code: number; message: string } | undefined;
  /** Fields that replace the usual fields in later ServerHellos. */
  serverHello: Json;
  /** When true, the Guardian never answers later `handshake/hello` calls. */
  handshakeHangs: boolean;
  /** Delay before each step answer. */
  delayMs: number;
  badSignatures: number;
  /** Invalid specification requests and their reasons; the Guardian refuses each with -32600. */
  invalidEnvelopes: Array<{ method: unknown; reason: string }>;
  forgetSessions(): void;
  stop(): void;
};

export type StartOptions = {
  key: HmacKey;
  reply?: (step: ReceivedStep) => Reply | Promise<Reply>;
  onDecisionFailure?: "proceed" | "deny";
  /** Methods evaluated. Omission means all client methods; `null` means no list. */
  methodsEvaluated?: string[] | null;
};

function verifies(request: Json, key: HmacKey): boolean {
  const params = request.params as Json;
  const sig = params.signature as { value?: unknown; key_id?: unknown } | undefined;
  const sessionId = (params.metadata as Json | undefined)?.session_id;
  if (typeof sig?.value !== "string" || sig.key_id !== key.keyId || typeof sessionId !== "string") {
    return false;
  }
  return verifyHmacSha256(request, sig.value, deriveSessionKey(key.secret, sessionId)).valid;
}

function signed(response: Json, key: HmacKey, sessionId: string, holder = response.error === undefined ? "result" : "error"): Json {
  const value = signResponseHmacSha256(response, deriveSessionKey(key.secret, sessionId));
  return { ...response, [holder]: { ...(response[holder] as Json), signature: { algorithm: "HMAC-SHA256", value, key_id: key.keyId } } };
}

export function startFakeGuardian({
  key,
  reply = () => ({ decision: { decision: "allow" } }),
  onDecisionFailure = "deny",
  methodsEvaluated,
}: StartOptions): FakeGuardian {
  const sessions = new Set<string>();
  const ended = new Set<string>();
  const state: FakeGuardian = {
    url: "",
    steps: [],
    handshakes: 0,
    methodsImplemented: undefined,
    methodsEvaluated,
    delayMs: 0,
    badSignatures: 0,
    handshakeError: undefined,
    handshakeHangs: false,
    serverHello: {},
    invalidEnvelopes: [],
    forgetSessions: () => sessions.clear(),
    stop: () => server.stop(true),
  };
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const request = (await req.json()) as Json;
      const invalid = specificationFailure(request);
      if (invalid !== undefined) {
        state.invalidEnvelopes.push({ method: request.method, reason: invalid });
        return Response.json({ jsonrpc: "2.0", id: request.id, error: { code: -32600, message: "invalid envelope" } });
      }
      const params = request.params as Json;
      const sessionId = (params.metadata as Json).session_id as string;
      if (!verifies(request, key)) {
        state.badSignatures += 1;
        return Response.json({ jsonrpc: "2.0", id: request.id, error: { code: -32004, message: "signature_invalid" } });
      }
      // JSON removes keys with undefined values before signing.
      const answer = (response: Json, holder?: string): Response =>
        Response.json(signed(JSON.parse(JSON.stringify({ jsonrpc: "2.0", id: request.id, ...response })) as Json, key, sessionId, holder));

      if (request.method === "handshake/hello") {
        state.handshakes += 1;
        if (state.handshakeHangs) {
          return new Promise<Response>(() => {});
        }
        if (state.handshakeError !== undefined) {
          return Response.json({ jsonrpc: "2.0", id: request.id, error: state.handshakeError });
        }
        sessions.add(sessionId);
        const hello = params.payload as Json;
        state.methodsImplemented = hello.methods_implemented;
        return answer({
          result: {
            negotiated_version: "0.1.0",
            ...(state.methodsEvaluated === null ? {} : { methods_evaluated: state.methodsEvaluated ?? hello.methods_implemented }),
            selected_transport: "http",
            signature_algorithms_supported: ["HMAC-SHA256"],
            timeout_config: { default_ms: 5000 },
            skew_window_ms: 300000,
            on_decision_failure: onDecisionFailure,
            policy_requires_provenance: false,
            profiles_accepted: ["acs-core"],
            ...state.serverHello,
          },
        });
      }
      if (!sessions.has(sessionId)) {
        return answer({ error: { code: -32003, message: "the session has not completed handshake/hello" } });
      }
      const step: ReceivedStep = {
        method: request.method as string,
        requestId: params.request_id,
        sessionId,
        userContext: (params.metadata as Json).user_context,
        turnId: (params.metadata as Json).turn_id,
        agentName: (params.metadata as Json).agent_name,
        payload: params.payload as Json,
      };
      state.steps.push(step);
      // As a Guardian does (§8): no step enters an ended session.
      if (ended.has(sessionId)) {
        return answer({ result: { type: "final", acs_version: "0.1.0", request_id: params.request_id, decision: "deny", reasoning: "session ended" } });
      }
      if (step.method === "steps/sessionEnd") {
        ended.add(sessionId);
      }
      if (state.delayMs > 0) {
        await Bun.sleep(state.delayMs);
      }
      const scripted = await reply(step);
      if ("hang" in scripted) {
        return new Promise<Response>(() => {});
      }
      if ("body" in scripted) {
        return new Response(scripted.body, { headers: { "content-type": "application/json" } });
      }
      if ("unsignedDecision" in scripted) {
        return Response.json({ jsonrpc: "2.0", id: request.id, result: { request_id: params.request_id, ...scripted.unsignedDecision } });
      }
      if ("signedResult" in scripted) {
        return answer({ result: scripted.signedResult });
      }
      if ("signedResponse" in scripted) {
        return answer(scripted.signedResponse, "result");
      }
      if ("tamperedDecision" in scripted) {
        const sent = signed({ jsonrpc: "2.0", id: request.id, result: { type: "final", acs_version: "0.1.0", request_id: params.request_id, ...scripted.tamperedDecision } }, key, sessionId);
        return Response.json({ ...sent, result: { ...(sent.result as Json), ...scripted.becomes } });
      }
      if ("error" in scripted) {
        return answer({ error: scripted.error });
      }
      return answer({ result: { type: "final", acs_version: "0.1.0", request_id: params.request_id, ...scripted.decision } });
    },
  });
  state.url = `http://127.0.0.1:${server.port}/acs`;
  return state;
}
