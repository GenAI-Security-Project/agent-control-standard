// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "bun:test";
import { Writable } from "node:stream";
import { batchLogWrites } from "../src/batched-log-writer.ts";

function capture() {
  const batches: string[][] = [];
  const stream = new Writable({
    write(chunk, _encoding, done) {
      batches.push([chunk.toString()]);
      done();
    },
    writev(chunks, done) {
      batches.push(chunks.map(({ chunk }) => chunk.toString()));
      done();
    },
  });
  return { stream, batches };
}

describe("batched log writes", () => {
  it("writes a burst as one batch, preserving Unicode and record order", async () => {
    const { stream, batches } = capture();
    const errors: unknown[] = [];
    const writer = batchLogWrites(stream, (error) => errors.push(error));
    try {
      writer.write('{"id":1,"text":"日本語"}\n');
      writer.write('{"id":2}\n');
      expect(batches).toEqual([]);
      await writer.close();
      expect(batches).toEqual([['{"id":1,"text":"日本語"}\n', '{"id":2}\n']]);
      expect(errors).toEqual([]);
    } finally {
      await writer.close();
    }
  });

  it("flushes at the record threshold and drains the remaining batch on close", async () => {
    const { stream, batches } = capture();
    const writer = batchLogWrites(stream, () => {}, { batchSize: 2 });
    try {
      writer.write("a\n");
      writer.write("b\n");
      expect(batches).toEqual([["a\n", "b\n"]]);
      writer.write("c\n");
      await writer.close();
      expect(batches).toEqual([["a\n", "b\n"], ["c\n"]]);
    } finally {
      await writer.close();
    }
  });

  it("flushes sparse traffic on the timer without another write or shutdown", async () => {
    const wrote = Promise.withResolvers<string>();
    const stream = new Writable({
      write(chunk, _encoding, done) {
        wrote.resolve(chunk.toString());
        done();
      },
    });
    const writer = batchLogWrites(stream, wrote.reject, { flushIntervalMs: 5 });
    try {
      writer.write("one\n");
      expect(await wrote.promise).toBe("one\n");
    } finally {
      await writer.close();
    }
  });

  it("keeps later batches behind a pending write and waits for all of them on close", async () => {
    const batches: string[][] = [];
    let finishFirst: (() => void) | undefined;
    const stream = new Writable({
      writev(chunks, done) {
        batches.push(chunks.map(({ chunk }) => chunk.toString()));
        if (batches.length === 1) finishFirst = done;
        else done();
      },
    });
    const writer = batchLogWrites(stream, () => {}, { batchSize: 2 });
    try {
      for (const line of ["a\n", "b\n", "c\n", "d\n"]) writer.write(line);
      const closing = writer.close();
      let closed = false;
      void closing.then(() => { closed = true; });
      await Promise.resolve();
      expect(closed).toBe(false);
      expect(batches).toEqual([["a\n", "b\n"]]);
      finishFirst?.();
      await closing;
      expect(batches.flat()).toEqual(["a\n", "b\n", "c\n", "d\n"]);
      expect(closed).toBe(true);
      expect(writer.close()).toBe(closing);
      writer.write("after close\n");
      expect(batches.flat()).toEqual(["a\n", "b\n", "c\n", "d\n"]);
    } finally {
      await writer.close();
    }
  });

  it("bounds UTF-8 bytes, including the write already in flight", async () => {
    const errors: unknown[] = [];
    let finishWrite: (() => void) | undefined;
    const stream = new Writable({ write(_chunk, _encoding, done) { finishWrite = done; } });
    const writer = batchLogWrites(stream, (error) => errors.push(error), {
      batchSize: 1,
      maxBufferedBytes: 4,
    });
    writer.write("é\n"); // Three bytes remain in flight.
    writer.write("a\n");
    writer.write("b\n");
    expect(errors).toHaveLength(1);
    expect(String(errors[0])).toContain("buffer limit exceeded");
    expect(stream.destroyed).toBe(true);
    finishWrite?.();
    await writer.close();
    expect(errors).toHaveLength(1);
  });

  it("bounds the number of queued records even when each is tiny", async () => {
    const { stream, batches } = capture();
    const errors: unknown[] = [];
    const writer = batchLogWrites(stream, (error) => errors.push(error), { maxBufferedRecords: 2 });
    writer.write("\n");
    writer.write("\n");
    writer.write("\n");
    await writer.close();
    expect(errors).toHaveLength(1);
    expect(batches).toEqual([]);
  });

  it("reports an asynchronous disk failure once and absorbs a throwing reporter", async () => {
    const errors: unknown[] = [];
    const stream = new Writable({
      write(_chunk, _encoding, done) {
        queueMicrotask(() => done(new Error("disk full")));
      },
    });
    const writer = batchLogWrites(stream, (error) => {
      errors.push(error);
      throw new Error("reporter failed too");
    });
    expect(() => writer.write("one\n")).not.toThrow();
    await writer.close();
    expect(() => writer.write("two\n")).not.toThrow();
    expect(errors).toHaveLength(1);
    expect(String(errors[0])).toContain("disk full");
  });
});
