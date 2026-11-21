import { describe, expect, it, spyOn } from "bun:test";
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  checkSessionChainLink,
  createSessionChainState,
  renderAuditEntry,
  renderDecisionBadge,
  renderEnvelopeLogEntry,
  renderRpcError,
  renderSessionChain,
  renderSessionChainRow,
} from "../src/render.ts";
import { tailAuditLog } from "../src/tail-audit-log.ts";
import { tailEnvelopeLog, type EnvelopeLogEntry } from "../src/tail-envelope-log.ts";
import { tailSessionContextLog, type SessionContextLogEntry } from "../src/tail-session-context.ts";
import { escapeControlCharacters, escapeControlCharactersKeepingNewlines } from "../src/terminal-safe.ts";

const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);

// Everything a request author could use against a terminal: CSI (clear screen,
// colour), OSC (window title, terminated by BEL), a NUL, DEL, an 8-bit CSI and
// NEL (C1), and a newline that would start a forged line.
const HOSTILE = `${ESC}[2J${ESC}[31mFORGED${ESC}[0m${ESC}]0;pwned${BEL}\u0000\u007f\u009b31m\u0085\nforged-line`;

// Control characters that must never reach a terminal. `\n` is allowed because
// the renderer itself puts newlines between its own lines.
const UNSAFE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/;

/** The Inspector's own SGR styling, which is the only escape it may emit. */
function withoutOwnStyling(text: string): string {
  return text.replace(/\u001b\[\d+m/g, "");
}

function expectNoControlCharacters(text: string): void {
  expect(UNSAFE.test(withoutOwnStyling(text))).toBe(false);
}

function envelopeEntry(overrides: Partial<EnvelopeLogEntry>): EnvelopeLogEntry {
  return {
    seq: 1,
    recorded_at: "2026-08-09T12:04:31.221Z",
    direction: "response",
    method: "steps/toolCallRequest",
    rpc_id: 1,
    envelope: {},
    ...overrides,
  };
}

function sessionEntry(overrides: Partial<SessionContextLogEntry> = {}): SessionContextLogEntry {
  return {
    session_id: "sess-1",
    seq: 1,
    prev_hash: "0".repeat(64),
    hash: "a".repeat(64),
    recorded_at: "2026-08-10T12:00:00.000Z",
    method: "steps/toolCallRequest",
    request_id: "req-1",
    tool_name: "run_shell",
    ...overrides,
  };
}

const AUDIT_BASE = {
  seq: 1,
  recorded_at: "2026-08-10T12:00:00.000Z",
  session_id: "sess-1",
  method: "steps/toolCallRequest",
  rpc_id: "req-1",
} as const;

describe("escapeControlCharacters", () => {
  it("replaces C0, DEL and C1 controls with visible \\xNN escapes", () => {
    expect(escapeControlCharacters(`a${ESC}[2Jb`)).toBe("a\\x1b[2Jb");
    expect(escapeControlCharacters(`x${BEL}y`)).toBe("x\\x07y");
    expect(escapeControlCharacters("\u0000")).toBe("\\x00");
    expect(escapeControlCharacters("\u007f")).toBe("\\x7f");
    expect(escapeControlCharacters("\u0080\u009b\u009f")).toBe("\\x80\\x9b\\x9f");
    expect(escapeControlCharacters("a\nb\rc\td")).toBe("a\\x0ab\\x0dc\\x09d");
  });

  it("covers the whole control range and nothing else", () => {
    for (let code = 0; code <= 0x9f; code += 1) {
      const out = escapeControlCharacters(String.fromCharCode(code));
      const isControl = code <= 0x1f || (code >= 0x7f && code <= 0x9f);
      expect(out === String.fromCharCode(code)).toBe(!isControl);
      expect(UNSAFE.test(out) || out === "\n").toBe(false);
    }
  });

  it("leaves printable text, including non-ASCII, exactly as it was", () => {
    for (const text of ["steps/toolCallRequest", "policy#rule-7", "señor", "日本語", "🙂", "C:\\Users\\alice", ""]) {
      expect(escapeControlCharacters(text)).toBe(text);
    }
  });

  it("accepts a non-string value", () => {
    expect(escapeControlCharacters(42)).toBe("42");
    expect(escapeControlCharacters(null)).toBe("null");
  });

  it("can keep the newlines a renderer produced while escaping everything else", () => {
    expect(escapeControlCharactersKeepingNewlines(`{\n  "a": "${ESC}\u007f\u009b"\n}`)).toBe(
      '{\n  "a": "\\x1b\\x7f\\x9b"\n}',
    );
  });
});

describe("renderEnvelopeLogEntry with hostile fields", () => {
  it("escapes method and rpc_id in the header line", () => {
    const line = renderEnvelopeLogEntry(
      envelopeEntry({ direction: "request", method: HOSTILE, rpc_id: HOSTILE, envelope: { jsonrpc: "2.0" } }),
    );
    const header = line.split("\n")[0] ?? "";

    expect(header).toContain("\\x1b[2J\\x1b[31mFORGED");
    expect(header).toContain("\\x1b]0;pwned\\x07");
    expect(header).toContain("\\x0aforged-line");
    expectNoControlCharacters(header);
    expect(line.split("\n")[1]).toBe("{");
  });

  it("escapes recorded_at when it is not a timestamp", () => {
    const line = renderEnvelopeLogEntry(envelopeEntry({ recorded_at: HOSTILE }));

    expectNoControlCharacters(line);
  });

  it("escapes the JSON-RPC error message", () => {
    const line = renderEnvelopeLogEntry(
      envelopeEntry({ envelope: { jsonrpc: "2.0", id: 1, error: { code: -32010, message: HOSTILE } } }),
    );

    expect(line).toContain("\\x1b[2J");
    expectNoControlCharacters(line);
  });

  it("escapes decision, reason_codes and policy references", () => {
    const line = renderEnvelopeLogEntry(
      envelopeEntry({
        envelope: {
          jsonrpc: "2.0",
          id: 1,
          result: {
            decision: HOSTILE,
            reason_codes: [HOSTILE, "ok"],
            policy_references: [{ policy_id: HOSTILE, rule_id: HOSTILE }, { policy_id: HOSTILE }],
          },
        },
      }),
    );

    expectNoControlCharacters(line);
  });

  it("escapes DEL and C1 controls in the body, which JSON.stringify leaves alone", () => {
    const value = `a\u007fb\u0085c\u009bd`;
    expect(JSON.stringify(value)).toContain("\u009b");

    const line = renderEnvelopeLogEntry(envelopeEntry({ envelope: { note: value, [`k${ESC}`]: 1 } }));

    expect(line).toContain("a\\x7fb\\x85c\\x9bd");
    expectNoControlCharacters(line);
    expect(line.split("\n").length).toBeGreaterThan(3);
  });

  it("does not change the rendering of an ordinary entry", () => {
    const line = renderEnvelopeLogEntry(
      envelopeEntry({ envelope: { jsonrpc: "2.0", id: 1, result: { decision: "deny", reason_codes: ["R1"] } } }),
    );

    expect(line.split("\n")[0]).toBe("── #1  12:04:31.221  ← RESPONSE  steps/toolCallRequest  id=1");
    expect(line.split("\n")[1]).toBe("● DENY  reason_codes=[R1]");
  });
});

describe("the other renderers with hostile fields", () => {
  it("escapes the JSON-RPC error line", () => {
    expectNoControlCharacters(renderRpcError({ code: -32010, message: HOSTILE }));
    expectNoControlCharacters(renderRpcError({ code: null, message: HOSTILE }, { color: true }));
  });

  it("escapes the decision badge", () => {
    const message = {
      decision: HOSTILE,
      reason_codes: [HOSTILE],
      policy_references: [{ policy_id: HOSTILE, rule_id: HOSTILE }],
    };

    expectNoControlCharacters(renderDecisionBadge(message));
    expectNoControlCharacters(renderDecisionBadge(message, { color: true }));
    expectNoControlCharacters(renderDecisionBadge({ ...message, decision: "allow" }, { color: true }));
  });

  it("escapes every field of a posture-resolved audit entry", () => {
    const entry = {
      ...AUDIT_BASE,
      method: HOSTILE,
      rpc_id: HOSTILE,
      session_id: HOSTILE,
      posture: "proceed" as const,
      posture_source: "negotiated" as const,
      outcome: "proceeded" as const,
      failure: { kind: HOSTILE, message: HOSTILE },
      session_failure: { kind: HOSTILE, message: HOSTILE },
    };

    expectNoControlCharacters(renderAuditEntry(entry));
    expectNoControlCharacters(renderAuditEntry(entry, { color: true }));
    expectNoControlCharacters(renderAuditEntry({ ...entry, outcome: "blocked" }, { color: true }));
  });

  it("escapes every field of an ungoverned audit entry", () => {
    const entry = {
      ...AUDIT_BASE,
      method: HOSTILE,
      rpc_id: HOSTILE,
      session_id: HOSTILE,
      outcome: "ungoverned" as const,
      ungoverned: { tool: HOSTILE, tools: [HOSTILE, "bash"] },
    };

    expectNoControlCharacters(renderAuditEntry(entry));
    expectNoControlCharacters(renderAuditEntry(entry, { color: true }));
  });

  it("escapes every field of a session-chain row, broken or not", () => {
    const hostile = sessionEntry({
      session_id: HOSTILE,
      tool_name: HOSTILE,
      hash: HOSTILE,
      findings: [HOSTILE],
      request_id_ref: HOSTILE,
    });

    for (const color of [false, true]) {
      expectNoControlCharacters(renderSessionChainRow(hostile, { broken: false }, { color }));
      expectNoControlCharacters(renderSessionChainRow(hostile, { broken: true }, { color }));
    }
    expectNoControlCharacters(renderSessionChain([hostile, { ...hostile, seq: 2 }]));
  });

  it("keeps a forged CHAIN BREAK or ALLOW from appearing as its own line", () => {
    const row = renderSessionChainRow(
      sessionEntry({ tool_name: "x\n✖ CHAIN BREAK  #9  forged" }),
      { broken: false },
    );

    expect(row.split("\n")).toHaveLength(1);
  });
});

describe("the Inspector's own styling", () => {
  it("is still emitted when color is on, around the escaped field", () => {
    const badge = renderDecisionBadge(
      { decision: "deny", reason_codes: [`${ESC}[2J`], policy_references: [] },
      { color: true },
    );

    expect(badge).toContain(`${ESC}[31m● DENY${ESC}[0m`);
    expect(badge).toContain(`${ESC}[2m`);
    expect(badge).toContain("reason_codes=[\\x1b[2J]");
    expect(withoutOwnStyling(badge)).not.toContain(ESC);
  });

  it("paints the header and error line of a hostile entry without letting the field through", () => {
    const line = renderEnvelopeLogEntry(
      envelopeEntry({ method: HOSTILE, envelope: { jsonrpc: "2.0", id: 1, error: { code: -1, message: HOSTILE } } }),
      { color: true },
    );
    const [header, error] = line.split("\n");

    expect(header?.startsWith(`${ESC}[2m── #1`)).toBe(true);
    expect(header?.endsWith(`${ESC}[0m`)).toBe(true);
    expect(error?.startsWith(`${ESC}[31m✖ ERROR -1`)).toBe(true);
    expectNoControlCharacters(line);
  });
});

function withTempDir(name: string, run: (path: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "acs-ctl-"));
  const path = join(dir, name);
  return run(path).finally(() => {
    try {
      unlinkSync(path);
    } catch {
      // the test may not have created it
    }
    rmdirSync(dir);
  });
}

async function firstOf<T>(iterable: AsyncGenerator<T, void, void>, controller: AbortController): Promise<T> {
  const deadline = setTimeout(() => controller.abort(), 3000);
  try {
    for await (const entry of iterable) {
      return entry;
    }
    throw new Error("the tail ended without yielding an entry");
  } finally {
    clearTimeout(deadline);
    controller.abort();
  }
}

describe("logged hostile fields, tailed and rendered end to end", () => {
  it("renders an envelope-log request line whose method and id carry escape sequences", async () => {
    await withTempDir("envelopes.jsonl", async (path) => {
      const logged = envelopeEntry({
        direction: "request",
        method: `${ESC}]0;pwned${BEL}steps/toolCallRequest`,
        rpc_id: `${ESC}[2J${ESC}[31mFORGED${ESC}[0m`,
        envelope: { jsonrpc: "2.0", id: `${ESC}[2J`, method: "x" },
      });
      writeFileSync(path, `${JSON.stringify(logged)}\n`);
      expect(readFileSync(path, "latin1")).not.toContain(ESC);

      const controller = new AbortController();
      const entry = await firstOf(
        tailEnvelopeLog({ path, fromStart: true, pollMs: 10, signal: controller.signal }),
        controller,
      );
      const header = renderEnvelopeLogEntry(entry, { color: false }).split("\n")[0] ?? "";

      expect(header).toContain("\\x1b]0;pwned\\x07steps/toolCallRequest");
      expect(header).toContain("id=\\x1b[2J\\x1b[31mFORGED\\x1b[0m");
      expect([...header].filter((character) => character === ESC)).toHaveLength(0);
    });
  });

  it("renders an audit-log entry whose failure message carries escape sequences", async () => {
    await withTempDir("audit.jsonl", async (path) => {
      const logged = {
        ...AUDIT_BASE,
        posture: "proceed",
        posture_source: "negotiated",
        outcome: "proceeded",
        failure: { kind: "transport", message: `${ESC}[2J${ESC}[H` },
      };
      writeFileSync(path, `${JSON.stringify(logged)}\n`);

      const controller = new AbortController();
      const entry = await firstOf(
        tailAuditLog({ path, fromStart: true, pollMs: 10, signal: controller.signal }),
        controller,
      );
      const text = renderAuditEntry(entry, { color: false });

      expect(text).toContain("failure=transport: \\x1b[2J\\x1b[H");
      expectNoControlCharacters(text);
    });
  });

  it("renders a session-context entry whose tool_name carries escape sequences", async () => {
    await withTempDir("session-context.jsonl", async (path) => {
      writeFileSync(path, `${JSON.stringify(sessionEntry({ tool_name: `${ESC}[2Jrun` }))}\n`);

      const controller = new AbortController();
      const entry = await firstOf(
        tailSessionContextLog({ path, fromStart: true, pollMs: 10, signal: controller.signal }),
        controller,
      );
      const state = createSessionChainState();
      const row = renderSessionChainRow(entry, checkSessionChainLink(entry, state), { color: false });

      expect(row).toContain("\\x1b[2Jrun");
      expectNoControlCharacters(row);
    });
  });
});

describe("the malformed-line warnings", () => {
  const cases = [
    ["tailEnvelopeLog", "envelopes.jsonl", tailEnvelopeLog],
    ["tailAuditLog", "audit.jsonl", tailAuditLog],
    ["tailSessionContextLog", "session-context.jsonl", tailSessionContextLog],
  ] as const;

  for (const [name, file, tail] of cases) {
    it(`${name} does not print a raw control byte from an unparseable line to stderr`, async () => {
      await withTempDir(file, async (path) => {
        writeFileSync(path, `${HOSTILE.replaceAll("\n", " ")} {not json\n`);
        const errorSpy = spyOn(console, "error").mockImplementation(() => {});
        const controller = new AbortController();
        const deadline = setTimeout(() => controller.abort(), 400);
        try {
          for await (const _entry of tail({ path, fromStart: true, pollMs: 10, signal: controller.signal })) {
            // no entry is expected: the only line is malformed
          }
        } finally {
          clearTimeout(deadline);
          const printed = errorSpy.mock.calls.map((call) => String(call[0]));
          errorSpy.mockRestore();

          expect(printed.length).toBeGreaterThan(0);
          for (const text of printed) {
            expect(UNSAFE.test(text)).toBe(false);
          }
          expect(printed.some((text) => text.includes("\\x1b[2J"))).toBe(true);
        }
      });
    });
  }
});
