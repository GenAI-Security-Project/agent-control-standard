import { spawn } from "node:child_process"
import { fileURLToPath } from "node:url"

type Reply = {
  decision: "allow" | "deny" | "modify" | "ask" | "defer"
  reasoning?: string
  updated_input?: unknown
  updated_result?: unknown
}

type BeforeEvent = {
  readonly sessionID: string
  readonly messageID: string
  readonly id: string
  readonly tool: string
  input: unknown
}

type ToolResult = {
  content?: string | ReadonlyArray<{ type: string; [key: string]: unknown }>
  metadata?: Readonly<Record<string, unknown>>
  output?: unknown
}

const isToolResult = (value: unknown): value is ToolResult => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false
  const candidate = value as { content?: unknown; metadata?: unknown }
  if (candidate.content !== undefined && typeof candidate.content !== "string") {
    if (!Array.isArray(candidate.content) || candidate.content.some((block) => block === null || typeof block !== "object" || typeof (block as { type?: unknown }).type !== "string")) return false
  }
  return candidate.metadata === undefined || (candidate.metadata !== null && typeof candidate.metadata === "object" && !Array.isArray(candidate.metadata))
}

type AfterEvent = {
  readonly sessionID: string
  readonly messageID: string
  readonly id: string
  readonly tool: string
  readonly input: unknown
} & (
  | { readonly status: "completed"; result: ToolResult }
  | { readonly status: "error"; error: { message: string; error?: unknown; metadata?: Record<string, unknown> } }
)

interface PluginContext {
  tool: {
    hook(name: "execute.before", callback: (event: BeforeEvent) => Promise<void>): Promise<unknown>
    hook(name: "execute.after", callback: (event: AfterEvent) => Promise<void>): Promise<unknown>
  }
}

const projectRoot = fileURLToPath(new URL("../../", import.meta.url))
const executable = fileURLToPath(new URL("../../.acs/bin/acs-opencode-hook", import.meta.url))
const hookArguments = [
  "--guardian-url",
  process.env.ACS_GUARDIAN_URL || "http://127.0.0.1:8787/acs",
  "--hmac-secret-file",
  process.env.ACS_OPENCODE_HMAC_SECRET_FILE || ".acs/hmac-secret",
  "--state-dir",
  ".acs/opencode",
  "--audit-log",
  ".acs/opencode-audit.jsonl",
]

const invoke = (event: unknown): Promise<Reply> =>
  new Promise((resolve, reject) => {
    const child = spawn(executable, hookArguments, {
      cwd: projectRoot,
      stdio: ["pipe", "pipe", "pipe"],
    })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    let size = 0
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length
      if (size > 1 << 20) {
        child.kill("SIGKILL")
        reject(new Error("ACS policy adapter returned too much data"))
        return
      }
      stdout.push(chunk)
    })
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk))
    child.on("error", reject)
    child.on("close", (status) => {
      if (status !== 0) {
        reject(new Error(Buffer.concat(stderr).toString("utf8").trim() || `ACS policy adapter exited ${status}`))
        return
      }
      try {
        resolve(JSON.parse(Buffer.concat(stdout).toString("utf8")) as Reply)
      } catch {
        reject(new Error("ACS policy adapter returned invalid JSON"))
      }
    })
    child.stdin.end(JSON.stringify(event))
  })

const blocks = (reply: Reply) => reply.decision !== "allow" && reply.decision !== "modify"

const blockedResult = (reply: Reply) => ({
  content: reply.reasoning || `Guardian returned ${reply.decision}`,
  metadata: { acs: { decision: reply.decision } },
})

const blockedError = (reply: Reply) => ({
  message: reply.reasoning || `Guardian returned ${reply.decision}`,
  metadata: { acs: { decision: reply.decision } },
})

const modifiedError = (value: unknown): { message: string; error?: unknown; metadata?: Record<string, unknown> } | undefined => {
  if (value === null || typeof value !== "object") return undefined
  const candidate = value as { message?: unknown; error?: unknown; metadata?: unknown }
  if (typeof candidate.message !== "string") return undefined
  if (candidate.metadata !== undefined && (candidate.metadata === null || typeof candidate.metadata !== "object" || Array.isArray(candidate.metadata))) return undefined
  return {
    message: candidate.message,
    ...(candidate.error === undefined ? {} : { error: candidate.error }),
    ...(candidate.metadata === undefined ? {} : { metadata: candidate.metadata as Record<string, unknown> }),
  }
}

export const applyAfterReply = (event: AfterEvent, reply: Reply): void => {
  if (event.status === "completed") {
    if (blocks(reply)) {
      event.result = blockedResult(reply)
    } else if (reply.decision === "modify") {
      event.result = !isToolResult(reply.updated_result)
        ? blockedResult({ decision: "deny", reasoning: "The Guardian modification could not be applied" })
        : reply.updated_result
    }
    return
  }
  if (blocks(reply)) {
    event.error = blockedError(reply)
    return
  }
  if (reply.decision === "modify") {
    event.error = modifiedError(reply.updated_result) ?? blockedError({
      decision: "deny",
      reasoning: "The Guardian modification could not be applied",
    })
  }
}

export default {
  id: "acs",
  setup: async (ctx: PluginContext) => {
    await ctx.tool.hook("execute.before", async (event) => {
      const reply = await invoke({
        event: "execute.before",
        session_id: event.sessionID,
        message_id: event.messageID,
        call_id: event.id,
        tool: event.tool,
        input: event.input,
      })
      if (blocks(reply)) throw new Error(reply.reasoning || `Guardian returned ${reply.decision}`)
      if (reply.decision === "modify") event.input = reply.updated_input
    })

    await ctx.tool.hook("execute.after", async (event) => {
      const reply = await invoke({
        event: "execute.after",
        session_id: event.sessionID,
        message_id: event.messageID,
        call_id: event.id,
        tool: event.tool,
        input: event.input,
        status: event.status,
        result: event.status === "completed" ? event.result : undefined,
        error: event.status === "error" ? { message: event.error.message, error: event.error.error, metadata: event.error.metadata } : undefined,
      })
      applyAfterReply(event, reply)
    })
  },
}
