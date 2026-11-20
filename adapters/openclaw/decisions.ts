/** Maps Guardian decisions and adapter refusals to hook answers. A block sends no replacement for blocked content (§6.4). */
import { type AcsDecision, WITHHELD_OUTPUT } from "./host-adapter.ts";
import type { BeforeAgentRunResult, ReplyDispatchContext, ReplyDispatchResult, ToolResultAnswer } from "./openclaw-types.ts";

export function blockedRun(reason: string): BeforeAgentRunResult {
  return { outcome: "block", reason };
}

/**
 * Claims the `reply_dispatch` takeover, so OpenClaw starts no run, as with its
 * `before_dispatch` takeover. The plugin must not throw: OpenClaw dispatches
 * messages whose hooks throw.
 */
export function droppedMessage(ctx: ReplyDispatchContext, reason: string): ReplyDispatchResult {
  let counts = { tool: 0, block: 0, final: 0 };
  try {
    counts = ctx.dispatcher.getQueuedCounts();
    ctx.recordProcessed("skipped", { reason });
    ctx.markIdle("message_completed");
  } catch {
    // The message stays dropped; only OpenClaw's bookkeeping failed.
  }
  return { handled: true, queuedFinal: false, counts };
}

export function mediaUrlsOf(metadata: Record<string, unknown> | undefined): string[] {
  const urls = metadata?.mediaUrls;
  return Array.isArray(urls) ? urls.filter((url): url is string => typeof url === "string") : [];
}

/** The replacement has no `details`, which may hold the output being withheld. */
export const WITHHELD_RESULT: ToolResultAnswer = { result: { content: [{ type: "text", text: WITHHELD_OUTPUT }], details: undefined } };

export function reasoningOf(decision: AcsDecision): string {
  return typeof decision.reasoning === "string" && decision.reasoning.length > 0
    ? decision.reasoning
    : `the Guardian answered ${decision.decision}`;
}

export function textContent(value: string): Record<string, unknown> {
  return { content: [{ type: "text", value }] };
}
