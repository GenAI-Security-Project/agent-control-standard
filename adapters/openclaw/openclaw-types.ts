/**
 * Hook and middleware types from the stock OpenClaw SDK. The type check catches
 * releases that rename or remove a field this adapter uses. Narrow types let
 * tests build only the fields they need.
 */
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";

declare const api: OpenClawPluginApi;
type BeforeAgentRun = Parameters<typeof api.on<"before_agent_run">>[1];
type ReplyDispatch = Parameters<typeof api.on<"reply_dispatch">>[1];
type BeforeToolCall = Parameters<typeof api.on<"before_tool_call">>[1];
type AfterToolCall = Parameters<typeof api.on<"after_tool_call">>[1];
type MessageSending = Parameters<typeof api.on<"message_sending">>[1];
type ReplyPayloadSending = Parameters<typeof api.on<"reply_payload_sending">>[1];
type AgentEnd = Parameters<typeof api.on<"agent_end">>[1];
type SessionEnd = Parameters<typeof api.on<"session_end">>[1];
type ToolResultMiddleware = Parameters<OpenClawPluginApi["registerAgentToolResultMiddleware"]>[0];

export type AgentContext = Pick<
  Parameters<BeforeAgentRun>[1],
  "runId" | "agentId" | "sessionKey" | "sessionId" | "senderId" | "channel" | "trigger"
>;
export type BeforeAgentRunEvent = Pick<Parameters<BeforeAgentRun>[0], "prompt" | "senderId">;
export type BeforeAgentRunResult = Awaited<ReturnType<BeforeAgentRun>>;

export type InboundMessage = Pick<
  Parameters<ReplyDispatch>[0]["ctx"],
  | "SessionKey" | "SenderId" | "OriginatingChannel" | "Surface" | "Provider" | "BodyForAgent" | "Body" | "ReplyToBody" | "ReplyToQuoteText" | "media"
>;
export type ReplyDispatchEvent = Pick<Parameters<ReplyDispatch>[0], "images"> & { ctx: InboundMessage };
export type MediaFact = NonNullable<InboundMessage["media"]>[number];
type ReplyDispatchHookContext = Parameters<ReplyDispatch>[1];
export type ReplyDispatchContext = Pick<ReplyDispatchHookContext, "recordProcessed" | "markIdle"> & {
  dispatcher: Pick<ReplyDispatchHookContext["dispatcher"], "sendFinalReply" | "getQueuedCounts">;
};
export type ReplyDispatchResult = Awaited<ReturnType<ReplyDispatch>>;

export type BeforeToolCallEvent = Pick<Parameters<BeforeToolCall>[0], "toolName" | "params" | "runId" | "toolCallId">;
export type ToolContext = Pick<Parameters<BeforeToolCall>[1], "runId" | "sessionKey" | "sessionId" | "toolCallId">;
export type BeforeToolCallResult = Awaited<ReturnType<BeforeToolCall>>;
export type RequireApproval = NonNullable<Exclude<BeforeToolCallResult, void | undefined>["requireApproval"]>;
export type ApprovalResolution = Parameters<NonNullable<RequireApproval["onResolution"]>>[0];

export type AfterToolCallEvent = Pick<Parameters<AfterToolCall>[0], "toolName" | "runId" | "toolCallId"> & Partial<Pick<Parameters<AfterToolCall>[0], "result">>;
export type AfterToolCallContext = Pick<Parameters<AfterToolCall>[1], "runId" | "toolCallId">;

export type MessageSendingEvent = Pick<Parameters<MessageSending>[0], "to" | "content" | "metadata">;
export type MessageContext = Pick<Parameters<MessageSending>[1], "channelId" | "sessionKey" | "runId">;
export type MessageSendingResult = Awaited<ReturnType<MessageSending>>;

export type ReplyPayloadSendingEvent = Pick<Parameters<ReplyPayloadSending>[0], "payload" | "channel" | "sessionKey" | "runId">;
export type ReplyPayloadContext = Pick<Parameters<ReplyPayloadSending>[1], "channelId" | "sessionKey" | "runId">;
export type ReplyPayload = ReplyPayloadSendingEvent["payload"];
export type ReplyPayloadSendingResult = Awaited<ReturnType<ReplyPayloadSending>>;

export type AgentEndEvent = Pick<Parameters<AgentEnd>[0], "runId" | "success">;
export type SessionEndEvent = Pick<Parameters<SessionEnd>[0], "sessionKey" | "sessionId" | "reason" | "nextSessionId">;
export type SessionContext = Pick<Parameters<SessionEnd>[1], "sessionKey" | "sessionId">;

export type ToolResultEvent = Pick<Parameters<ToolResultMiddleware>[0], "toolCallId" | "toolName" | "args" | "isError" | "result">;
export type ToolResultContext = Pick<Parameters<ToolResultMiddleware>[1], "runtime" | "sessionId" | "sessionKey" | "runId">;
export type ToolResult = ToolResultEvent["result"];
export type ToolResultBlock = ToolResult["content"][number];
export type ToolResultAnswer = { result: ToolResult } | undefined;

