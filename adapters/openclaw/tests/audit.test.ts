import { afterEach, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAdapterAuditSink } from "../audit.ts";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

function logPath(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-openclaw-audit-"));
  dirs.push(dir);
  return join(dir, "audit.jsonl");
}

const entry = { session_id: "s", method: "steps/toolCallRequest", rpc_id: "r", outcome: "substituted", substituted: { decision: "defer", reason_code: "defer_unsupported" } } as const;
const seqs = (path: string) => readFileSync(path, "utf8").trim().split("\n").map((line) => (JSON.parse(line) as { seq: number }).seq);

it("counts seq across every registration that writes one file, and on from the lines already there", () => {
  const path = logPath();
  writeFileSync(path, `${JSON.stringify({ seq: 7 })}\n`);
  const first = createAdapterAuditSink({ path, onError: () => {} });
  const second = createAdapterAuditSink({ path, onError: () => {} });
  expect([first.write(entry), second.write(entry), first.write(entry)]).toEqual([true, true, true]);
  expect(seqs(path)).toEqual([7, 8, 9, 10]);
});

it("stops writing after a failed write, and says why once", () => {
  const path = join(logPath(), "audit.jsonl");
  writeFileSync(path.slice(0, -"/audit.jsonl".length), "a file where the log's folder should be");
  const errors: unknown[] = [];
  const sink = createAdapterAuditSink({ path, onError: (error) => errors.push(error) });
  expect([sink.write(entry), sink.write(entry)]).toEqual([false, false]);
  expect(errors).toHaveLength(1);
});
