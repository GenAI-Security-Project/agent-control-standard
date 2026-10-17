import assert from "node:assert/strict"
import test from "node:test"

import plugin, { applyAfterReply } from "../../.opencode/plugins/acs.ts"

test("the shipped plugin governs real callbacks through the running Guardian", async () => {
  const callbacks = {}
  await plugin.setup({
    tool: {
      hook: async (name, callback) => {
        callbacks[name] = callback
      },
    },
  })

  const allowed = {
    sessionID: "opencode-plugin-test",
    messageID: "message-1",
    id: "call-allow",
    tool: "shell",
    input: { command: "printf ACS_OPENCODE_OK" },
  }
  await callbacks["execute.before"](allowed)
  assert.deepEqual(allowed.input, { command: "printf ACS_OPENCODE_OK" })

  await assert.rejects(
    callbacks["execute.before"]({
      sessionID: "opencode-plugin-test",
      messageID: "message-1",
      id: "call-deny",
      tool: "shell",
      input: { command: "echo rm -rf /" },
    }),
    /destructive|denied|deny/i,
  )

  const completed = {
    sessionID: "opencode-plugin-test",
    messageID: "message-1",
    id: "call-allow",
    tool: "shell",
    input: allowed.input,
    status: "completed",
    result: { content: "ACS_OPENCODE_OK", metadata: { exit: 0 } },
  }
  await callbacks["execute.after"](completed)
  assert.deepEqual(completed.result, { content: "ACS_OPENCODE_OK", metadata: { exit: 0 } })
})

test("completed results honor allow, modify, and blocking decisions", () => {
  const allowed = { status: "completed", result: { content: "original" } }
  applyAfterReply(allowed, { decision: "allow" })
  assert.deepEqual(allowed.result, { content: "original" })

  const modified = { status: "completed", result: { content: "original" } }
  applyAfterReply(modified, { decision: "modify", updated_result: { content: "redacted" } })
  assert.deepEqual(modified.result, { content: "redacted" })

  const invalid = { status: "completed", result: { content: "original" } }
  applyAfterReply(invalid, { decision: "modify", updated_result: "not an OpenCode result" })
  assert.deepEqual(invalid.result, {
    content: "The Guardian modification could not be applied",
    metadata: { acs: { decision: "deny" } },
  })

  const denied = { status: "completed", result: { content: "secret" } }
  applyAfterReply(denied, { decision: "deny", reasoning: "blocked" })
  assert.deepEqual(denied.result, { content: "blocked", metadata: { acs: { decision: "deny" } } })
})

test("failed results honor allow, modify, and blocking decisions", () => {
  const allowed = { status: "error", error: { message: "original", metadata: { code: 1 } } }
  applyAfterReply(allowed, { decision: "allow" })
  assert.deepEqual(allowed.error, { message: "original", metadata: { code: 1 } })

  const modified = { status: "error", error: { message: "secret", error: { token: "secret" }, metadata: { code: 1 } } }
  applyAfterReply(modified, { decision: "modify", updated_result: { message: "[REDACTED]", error: { token: "[REDACTED]" }, metadata: { code: 1 } } })
  assert.deepEqual(modified.error, { message: "[REDACTED]", error: { token: "[REDACTED]" }, metadata: { code: 1 } })

  const denied = { status: "error", error: { message: "secret", metadata: { code: 1 } } }
  applyAfterReply(denied, { decision: "deny", reasoning: "blocked" })
  assert.deepEqual(denied.error, { message: "blocked", metadata: { acs: { decision: "deny" } } })
})

test("an unusable modification fails closed", () => {
  const completed = { status: "completed", result: { content: "secret" } }
  applyAfterReply(completed, { decision: "modify" })
  assert.deepEqual(completed.result, {
    content: "The Guardian modification could not be applied",
    metadata: { acs: { decision: "deny" } },
  })

  const failed = { status: "error", error: { message: "secret" } }
  applyAfterReply(failed, { decision: "modify", updated_result: { content: "not an OpenCode error" } })
  assert.deepEqual(failed.error, {
    message: "The Guardian modification could not be applied",
    metadata: { acs: { decision: "deny" } },
  })
})
