/**
 * §4: a Guardian answers hook traffic only after `handshake/hello` declares the
 * method for that session. Tests that post steps straight to a Guardian call
 * this first. It handshakes on every call rather than caching per session,
 * because a port freed by one test's Guardian can be reused by the next one's.
 *
 * The hello declares exactly the method of the envelope about to be sent, so
 * it never widens what a test exercises. `sign` signs the hello when the
 * Guardian under test requires signatures.
 */
export async function handshakeFor(
  url: string,
  envelope: unknown,
  sign: (hello: Record<string, unknown>) => Record<string, unknown> = hello => hello,
): Promise<void> {
  const step = envelope as { method?: unknown; params?: { metadata?: { session_id?: unknown } } } | null | undefined;
  const sessionId = step?.params?.metadata?.session_id;
  if (typeof sessionId !== "string" || typeof step?.method !== "string") return;
  if (step.method === "handshake/hello" || step.method === "system/ping") return;
  const hello = {
    jsonrpc: "2.0",
    id: "handshake",
    method: "handshake/hello",
    params: {
      acs_version: "0.1.0",
      request_id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "agent-1", session_id: sessionId },
      payload: {
        acs_versions_supported: ["0.1.0"],
        methods_implemented: [step.method],
        transports_supported: ["http"],
        provenance_producer: "none",
        profiles_supported: ["acs-core"],
      },
    },
  };
  await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(sign(hello)),
  });
}

/** `fetch` for a test that writes its step inline: handshakes for the body's session first. */
export async function fetchWithHandshake(url: string, init: RequestInit & { body: string }): Promise<Response> {
  let envelope: unknown;
  try {
    envelope = JSON.parse(init.body);
  } catch {
    // An unparseable body names no session to handshake for.
  }
  await handshakeFor(url, envelope);
  return fetch(url, init);
}
