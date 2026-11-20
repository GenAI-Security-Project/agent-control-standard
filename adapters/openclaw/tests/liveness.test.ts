import { describe, expect, it } from "bun:test";
import { createLivenessProbe } from "../liveness.ts";

describe("system/ping on a timer (§13)", () => {
  it("warns once when the Guardian stops answering, and says once when it answers again", async () => {
    const answers = [true, false, false, true, true];
    const lines: string[] = [];
    const probe = createLivenessProbe(
      { ping: async () => { if (!(answers.shift() ?? true)) throw new Error("connection refused"); } },
      5,
      { warn: (message) => lines.push(`warn ${message}`), info: (message) => lines.push(`info ${message}`) },
    );
    probe.start();
    await Bun.sleep(60);
    probe.stop();
    expect(lines).toEqual([
      "warn ACS plugin: the Guardian did not answer system/ping: connection refused",
      "info ACS plugin: the Guardian answers system/ping again",
    ]);
  });

  it("stops probing when the gateway stops", async () => {
    let pings = 0;
    const probe = createLivenessProbe({ ping: async () => { pings += 1; } }, 5, { warn: () => {}, info: () => {} });
    probe.start();
    await Bun.sleep(20);
    probe.stop();
    const seen = pings;
    await Bun.sleep(30);
    expect(pings).toBe(seen);
  });
});
