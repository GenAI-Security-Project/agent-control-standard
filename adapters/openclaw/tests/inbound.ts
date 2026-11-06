/** OpenClaw's `reply_dispatch` arguments for a test's inbound message. */
import type { MediaFact, ReplyDispatchContext, ReplyDispatchEvent } from "../openclaw-types.ts";

export type Inbound = {
  content: string;
  /** `null` names no session. */
  sessionKey: string | null;
  senderId: string;
  channel?: string;
  quote?: string;
  media?: MediaFact[];
  images?: Array<{ data: string; mimeType: string }>;
};

export function inboundEvent(message: Inbound): ReplyDispatchEvent {
  return {
    ctx: {
      ...(message.sessionKey === null ? {} : { SessionKey: message.sessionKey }),
      SenderId: message.senderId,
      OriginatingChannel: message.channel ?? "signal",
      BodyForAgent: message.content,
      ...(message.quote === undefined ? {} : { ReplyToBody: message.quote }),
      ...(message.media === undefined ? {} : { media: message.media }),
    },
    ...(message.images === undefined ? {} : { images: message.images }),
  };
}

export function dispatchContext(notices: string[] = []): ReplyDispatchContext {
  return {
    dispatcher: {
      sendFinalReply: (payload) => {
        notices.push(payload.text ?? "");
        return true;
      },
      getQueuedCounts: () => ({ tool: 0, block: 0, final: notices.length }),
    },
    recordProcessed: () => {},
    markIdle: () => {},
  };
}
