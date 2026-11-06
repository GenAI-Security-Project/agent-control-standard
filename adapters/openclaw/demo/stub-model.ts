/**
 * Local OpenAI-compatible model for the demo and live test. A user message
 * with a `run: <command>` line makes the model call OpenClaw's `exec` tool.
 * The next turn replies with the returned text, so the run ends and the user
 * sees what the Guardian allowed. OpenClaw's tool loop, hooks and this adapter
 * run for real; only model judgment is stubbed.
 *
 * `bun demo/stub-model.ts` listens on STUB_PORT (8899).
 */
type ChatMessage = { role: string; content?: unknown };

export const STUB_MODEL_ID = "stub-1";

function textOf(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }
  return Array.isArray(content) ? content.map((part) => (part as { text?: unknown }).text ?? "").join("") : "";
}

/**
 * Returns the newest user command with a `run:` line. Returns `undefined`
 * after a tool result because the model must answer with text. OpenClaw can
 * append runtime context as a user message after the person's message.
 */
function commandFor(messages: ChatMessage[]): string | undefined {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i]!;
    if (message.role === "tool") {
      return undefined;
    }
    const command = message.role === "user" ? /^run: (.+)$/m.exec(textOf(message.content))?.[1]?.trim() : undefined;
    if (command !== undefined) {
      return command;
    }
  }
  return undefined;
}

function chunk(delta: Record<string, unknown>, finish: string | null): string {
  const body = { id: "chatcmpl-stub", object: "chat.completion.chunk", created: 1700000000, model: STUB_MODEL_ID, choices: [{ index: 0, delta, finish_reason: finish }] };
  return `data: ${JSON.stringify(body)}\n\n`;
}

export function startStubModel(port: number): { url: string; stop(): void } {
  const server = Bun.serve({
    port,
    hostname: "127.0.0.1",
    async fetch(request) {
      const path = new URL(request.url).pathname;
      if (path.endsWith("/models")) {
        return Response.json({ object: "list", data: [{ id: STUB_MODEL_ID, object: "model" }] });
      }
      const { messages } = (await request.json()) as { messages: ChatMessage[] };
      const command = commandFor(messages);
      const toolResult = messages.findLast((message) => message.role === "tool");
      console.log(command === undefined ? "stub model: answers with text" : `stub model: calls exec ${JSON.stringify(command)}`);
      const events = command === undefined
        ? [chunk({ role: "assistant", content: toolResult === undefined ? "No command to run." : `The tool returned: ${textOf(toolResult.content)}` }, null), chunk({}, "stop")]
        : [
            chunk({ role: "assistant", tool_calls: [{ index: 0, id: `call_${crypto.randomUUID().slice(0, 8)}`, type: "function", function: { name: "exec", arguments: JSON.stringify({ command }) } }] }, null),
            chunk({}, "tool_calls"),
          ];
      return new Response(`${events.join("")}data: [DONE]\n\n`, { headers: { "content-type": "text/event-stream" } });
    },
  });
  return { url: `http://127.0.0.1:${server.port}/v1`, stop: () => server.stop(true) };
}

if (import.meta.main) {
  const { url } = startStubModel(Number(process.env.STUB_PORT ?? 8899));
  console.log(`stub model listening at ${url}`);
}
