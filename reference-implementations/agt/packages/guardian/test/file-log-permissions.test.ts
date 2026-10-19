// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBatchedFileLog } from "../src/batched-log-writer.ts";

describe.skipIf(process.platform === "win32")("file log creation permissions", () => {
  it("creates nested directories and a log with owner-only permissions under a permissive umask", async () => {
    const root = mkdtempSync(join(tmpdir(), "acs-log-mode-"));
    const parent = join(root, "logs");
    const dir = join(parent, "session");
    const path = join(dir, "log.jsonl");
    const previousUmask = process.umask(0);
    const errors: unknown[] = [];
    const writer = createBatchedFileLog(path, (error) => errors.push(error));
    try {
      expect(existsSync(path)).toBe(false);
      writer.write("{}\n");
      await writer.close();
      expect(errors).toEqual([]);
      expect(readFileSync(path, "utf8")).toBe("{}\n");
      expect(statSync(parent).mode & 0o777).toBe(0o700);
      expect(statSync(dir).mode & 0o777).toBe(0o700);
      expect(statSync(path).mode & 0o777).toBe(0o600);
    } finally {
      await writer.close();
      process.umask(previousUmask);
      if (existsSync(path)) unlinkSync(path);
      rmdirSync(dir);
      rmdirSync(parent);
      rmdirSync(root);
    }
  });

  it("appends without changing permissions on an existing directory or file", async () => {
    const root = mkdtempSync(join(tmpdir(), "acs-log-existing-mode-"));
    const dir = join(root, "logs");
    const path = join(dir, "log.jsonl");
    mkdirSync(dir);
    writeFileSync(path, "first\n");
    chmodSync(dir, 0o750);
    chmodSync(path, 0o640);
    const errors: unknown[] = [];
    const writer = createBatchedFileLog(path, (error) => errors.push(error));
    try {
      writer.write("second\n");
      await writer.close();
      expect(errors).toEqual([]);
      expect(readFileSync(path, "utf8")).toBe("first\nsecond\n");
      expect(statSync(dir).mode & 0o777).toBe(0o750);
      expect(statSync(path).mode & 0o777).toBe(0o640);
    } finally {
      await writer.close();
      unlinkSync(path);
      rmdirSync(dir);
      rmdirSync(root);
    }
  });
});
