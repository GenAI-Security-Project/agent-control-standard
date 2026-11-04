/** Forwards requests to a Guardian, records envelopes, and can tamper with its next answer. */
type Json = Record<string, unknown>;

export type RecordingProxy = {
  url: string;
  envelopes: Json[];
  /** Replaces fields in the next `result` for `method` after the Guardian signs it. */
  tamperNext(method: string, changes: Json): void;
  forwardTo(url: string): void;
  stop(): void;
};

export function recordEnvelopes(firstGuardianUrl: string): RecordingProxy {
  let guardianUrl = firstGuardianUrl;
  const envelopes: Json[] = [];
  const tampering = new Map<string, Json>();
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const body = await request.text();
      const envelope = JSON.parse(body) as Json;
      envelopes.push(envelope);
      let answer: Response;
      try {
        answer = await fetch(guardianUrl, { method: "POST", headers: { "content-type": "application/json" }, body });
      } catch {
        // Return HTTP 503 when the Guardian cannot be reached.
        return new Response(null, { status: 503 });
      }
      const changes = tampering.get(envelope.method as string);
      if (changes === undefined) {
        return new Response(await answer.text(), { status: answer.status, headers: { "content-type": "application/json" } });
      }
      tampering.delete(envelope.method as string);
      const response = (await answer.json()) as Json;
      return Response.json({ ...response, result: { ...(response.result as Json), ...changes } });
    },
  });
  return {
    url: `http://127.0.0.1:${server.port}/acs`,
    envelopes,
    tamperNext: (method, changes) => tampering.set(method, changes),
    forwardTo: (url) => {
      guardianUrl = url;
    },
    stop: () => server.stop(true),
  };
}
