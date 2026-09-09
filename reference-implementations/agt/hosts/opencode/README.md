# OpenCode host shim

`acs-plugin.ts` is OpenCode's ACS plugin. OpenCode loads it once per session and calls its hook methods with live, mutable objects. The plugin builds an ACS envelope with the [host adapter](../../packages/host-adapter/README.md), posts it to the same Guardian the Claude Code shim uses, and applies the decision by changing what OpenCode handed it or by throwing. It contains no AGT code.

## Get started

1. Start the Guardian from `reference-implementations/agt`. The [tree README](../../README.md#start-the-guardian) shows the command.

2. Point OpenCode at the plugin. The `opencode.json` at the root of this tree already does, with a relative path, so an `opencode` started from `reference-implementations/agt` needs no edit. From any other project, add the plugin to that project's `opencode.json` by absolute path.

```json
{
  "plugin": ["/absolute/path/to/agent-control-standard/reference-implementations/agt/hosts/opencode/acs-plugin.ts"]
}
```

3. Start `opencode` and ask it to run `echo rm -rf /`. The plugin sends the call to the Guardian, AGT's stock pattern rule denies it, and OpenCode shows the thrown error, which carries the Guardian's reason.

The plugin hooks `tool.execute.before` for the `bash` and `webfetch` tools and `tool.execute.after` for the `bash` tool. OpenCode names its shell tool `bash` where Claude Code names it `Bash`, and both names are registered in `policy/manifest.yaml`, because AGT fails closed on a tool name it does not know.

## How each decision lands

OpenCode's hooks return nothing. The only channels back to OpenCode are the objects it hands the plugin, and a throw.

| Gate | Decision | What the plugin does |
|---|---|---|
| Before the tool runs | `deny`, `ask`, `defer` | Throws. The error carries the Guardian's reason, and the tool never runs |
| Before the tool runs | `modify` | Rewrites the argument in place |
| After the tool has run | `deny`, `ask`, `defer` | Replaces the result object. A throw here would stop the model from seeing the output, but OpenCode discards a throwing hook's changes and keeps the tool's real output in its own session record |
| After the tool has run | `modify` | Patches the output leaf and its `metadata` mirror together, so no plaintext stays in OpenCode's session record |

Because OpenCode has no field that reads a reason back after the tool has run, the plugin can print the reason on stderr. Set `ACS_DEBUG` to any value other than empty or `0`.

## What it reads

| Variable | Default | What it does |
|---|---|---|
| `ACS_GUARDIAN_URL` | `http://localhost:8787/acs` | Where the plugin sends envelopes |
| `ACS_AUDIT_LOG` | `.acs/audit.jsonl` | Where fail-open proceeds, posture-driven blocks and ungoverned skips are written |
| `ACS_HOOKMAP_PATH` | `opencode.hookmap.yaml`, beside the plugin | Which hookmap to load. Leave it unset in a deployment |
| `ACS_DEBUG` | unset | Prints each decision's reason on stderr |

There is no session directory. The plugin lives for the whole session and keeps the negotiated ServerHello in memory, so only the first hook of a session sends `handshake/hello`.

## Checks at load time

OpenCode dispatches to a plugin by reading hook names as object keys, and skips any key it does not find. A key that stops matching the name OpenCode fires disables that gate in silence. So the plugin refuses at load unless the keys it registered are exactly the hooks it expects, refuses a hookmap whose `deny` or `modify` cannot land at a gate, and exports exactly one symbol, so OpenCode's loader has no second export to mistake for a factory. OpenCode catches a throwing plugin factory and continues with the plugin unloaded, which would leave every later tool call ungoverned, so these checks refuse only what cannot work.

## Run it with no paid model account

OpenCode needs a model to decide which tool to call. A local stub that always answers with one canned `bash` call makes every run reproducible offline, and it exercises OpenCode's real tool loop and plugin dispatch. Only the model's judgement is stubbed.

Create a scratch project directory with two files. First, `opencode.json`, pointing the plugin at this tree and the model at the stub:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "stub/model-1",
  "plugin": ["/absolute/path/to/agent-control-standard/reference-implementations/agt/hosts/opencode/acs-plugin.ts"],
  "permission": { "bash": "allow" },
  "provider": {
    "stub": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Stub",
      "options": { "baseURL": "http://127.0.0.1:8899/v1", "apiKey": "unused" },
      "models": { "model-1": { "id": "model-1", "tool_call": true, "limit": { "context": 32768, "output": 4096 } } }
    }
  }
}
```

`permission.bash` is OpenCode's own permission system, separate from ACS. It is set so OpenCode does not stop to ask a human before the call reaches the plugin. The Guardian decides downstream of it.

Second, `stub-model.ts`, a minimal OpenAI-compatible endpoint. Turn one answers with a `bash` tool call whose command comes from `STUB_COMMAND`. Turn two answers with plain text so the session ends.

```ts
// A minimal OpenAI-compatible /v1/chat/completions endpoint. Turn 1 emits a
// tool call to "bash" with a command taken from STUB_COMMAND; turn 2 emits a
// plain-text reply so the session ends. Nothing here decides anything -- the
// question under test is what OpenCode's own plugin hooks do to a real tool
// call, not what a model would choose to run.
const PORT = Number(process.env.STUB_PORT ?? 8899);
const sse = (obj: unknown) => `data: ${JSON.stringify(obj)}\n\n`;

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/v1/models") {
      return Response.json({ object: "list", data: [{ id: "stub-1", object: "model" }] });
    }
    if (!url.pathname.endsWith("/chat/completions")) return new Response("not found", { status: 404 });

    const body = (await req.json()) as { messages: Array<{ role: string }> };
    const alreadyCalled = body.messages.some((m) => m.role === "tool");
    const id = "chatcmpl-stub", created = 1700000000, model = "stub-1";

    const chunks: unknown[] = alreadyCalled
      ? [
          { id, created, model, object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "STUB_DONE" }, finish_reason: null }] },
          { id, created, model, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] },
        ]
      : [
          {
            id, created, model, object: "chat.completion.chunk",
            choices: [{
              index: 0,
              delta: {
                role: "assistant",
                tool_calls: [{
                  index: 0, id: "call_stub_1", type: "function",
                  function: { name: "bash", arguments: JSON.stringify({ command: process.env.STUB_COMMAND ?? "echo hi", description: "demo" }) },
                }],
              },
              finish_reason: null,
            }],
          },
          { id, created, model, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] },
        ];

    const stream = new ReadableStream({
      start(controller) {
        const enc = new TextEncoder();
        for (const c of chunks) controller.enqueue(enc.encode(sse(c)));
        controller.enqueue(enc.encode("data: [DONE]\n\n"));
        controller.close();
      },
    });
    return new Response(stream, { headers: { "content-type": "text/event-stream" } });
  },
});
console.log(`stub model listening on :${PORT}`);
```

Then, with the Guardian running, start the stub with the command you want the model to call, and run OpenCode once from the scratch directory:

```bash
STUB_COMMAND='echo rm -rf /' bun run stub-model.ts
```

```bash
opencode run --format json "run the command"
```

The Guardian denies the call, the plugin throws, and the Inspector shows the envelope pair. Change `STUB_COMMAND` to `ls -la` and the same run is allowed.

## Files

| File | What it holds |
|---|---|
| `acs-plugin.ts` | The plugin, and the load-time checks |
| `apply-opencode-output.ts` | Applying a rendered decision to OpenCode's live objects |
| `opencode.hookmap.yaml` | The hookmap. Its header records what was measured about OpenCode's hook semantics |

## Tests

```bash
bun test hosts/opencode
```

Six files. `request-gate.test.ts` and `result-gate.test.ts` drive both gates against a live Guardian. `acs-plugin.test.ts` and `hookmap.test.ts` cover the load-time refusals. `apply-opencode-output.test.ts` covers each way a decision lands. `gate-ordering.test.ts` pins the order the checks run in.
