/**
 * Builds `steps/userMessage` content from the `reply_dispatch` message:
 * quote, text, then attachments. File bytes are read from OpenClaw's paths
 * because the Guardian cannot access this host. URL attachments keep their
 * URLs. `mapping.md` defines the item order.
 */
import { readFile, stat } from "node:fs/promises";
import type { InboundMessage, MediaFact, ReplyDispatchEvent } from "./openclaw-types.ts";

export type ContentItem = { type: "text" | "image" | "audio" | "file"; value: unknown };

export type InboundContent = { content: ContentItem[] } | { refused: string };

export function channelOf(message: InboundMessage): string {
  return (message.OriginatingChannel ?? message.Surface ?? message.Provider ?? "").trim().toLowerCase();
}

function textOf(message: InboundMessage): string {
  return message.BodyForAgent ?? message.Body ?? "";
}

function itemTypeOf(fact: Pick<MediaFact, "kind" | "contentType">): ContentItem["type"] {
  const kind = fact.kind ?? fact.contentType?.split("/")[0];
  return kind === "image" || kind === "audio" ? kind : "file";
}

/**
 * An unresolved or unreadable attachment prevents sending the whole message.
 * Measured attachment bytes above maxAttachmentBytes have the same effect.
 * The adapter then drops the message.
 * URL attachments keep their URLs, which can serve different content on each fetch.
 */
export async function inboundContent(event: ReplyDispatchEvent, maxAttachmentBytes: number): Promise<InboundContent> {
  const message = event.ctx;
  const content: ContentItem[] = [];
  const quote = message.ReplyToBody ?? message.ReplyToQuoteText;
  if (quote !== undefined && quote.trim() !== "") {
    content.push({ type: "text", value: quote });
  }
  const text = textOf(message);
  if (text.trim() !== "") {
    content.push({ type: "text", value: text });
  }
  let total = 0;
  for (const fact of message.media ?? []) {
    if (fact.unresolvedThisTurn === true) {
      return { refused: "OpenClaw could not read an attachment of the message" };
    }
    const described = {
      media_type: fact.contentType ?? "application/octet-stream",
      ...(fact.fileName === undefined ? {} : { file_name: fact.fileName }),
    };
    if (fact.path === undefined) {
      if (fact.url === undefined) {
        return { refused: "an attachment of the message has neither a path nor a URL" };
      }
      content.push({ type: itemTypeOf(fact), value: { ...described, url: fact.url } });
      continue;
    }
    let data: Buffer;
    try {
      const { size } = await stat(fact.path);
      total += size;
      if (total > maxAttachmentBytes) {
        return { refused: `the message's attachments exceed maxAttachmentBytes (${maxAttachmentBytes} bytes)` };
      }
      data = await readFile(fact.path);
      if (data.length !== size) {
        return { refused: "an attachment of the message changed while it was read" };
      }
    } catch (error) {
      return { refused: `an attachment of the message cannot be read: ${(error as Error).message}` };
    }
    content.push({ type: itemTypeOf(fact), value: { ...described, data: data.toString("base64") } });
  }
  for (const image of event.images ?? []) {
    total += Buffer.byteLength(image.data, "base64");
    if (total > maxAttachmentBytes) {
      return { refused: `the message's attachments exceed maxAttachmentBytes (${maxAttachmentBytes} bytes)` };
    }
    content.push({ type: "image", value: { media_type: image.mimeType, data: image.data } });
  }
  if (content.length === 0) {
    content.push({ type: "text", value: "" });
  }
  return { content };
}
