/**
 * The gate that reads a document and asserts it against the program.
 *
 * Every other check in this tree reads code, config, or a log. Nothing read a
 * doc -- and README.md's quickstart is the first thing anyone runs, so its
 * fenced blocks are the most-read output this project produces and the least
 * checked. V6 gave the Guardian a fourth startup line and rewrote the
 * Inspector's banner entirely, re-transcribed neither, and the suite stayed
 * green through the whole slice. That is the failure this file closes: not the
 * stale lines themselves, which are a morning's work, but the absence of
 * anything that would have said so.
 *
 * The repo's convention, which this enforces rather than introduces, is that a
 * fenced block following a command is a CAPTURE of that command -- pasted from
 * a run, not composed from reading the source. `hosts/claude-code/test/posture.test.ts`
 * already asserts one string is byte-for-byte what a runbook captures, but
 * against a hardcoded literal, so the doc and the test could
 * drift together and still agree. `test/path-dialects.test.ts` machine-checks
 * two config artifacts against each other. This is the same rail carried over
 * the last boundary: the document is the expected value, and the program's real
 * stdout is the actual one.
 *
 * WHAT THIS DOES NOT COVER, stated because a reader is entitled to the edge.
 * Only the two startup banners. The envelope and decision-badge captures
 * further down the quickstart need a governed step to produce, and the package
 * READMEs are not read here at all. A doc claim outside those two
 * fences is still only as true as whoever last measured it.
 */
import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const README = fileURLToPath(new URL("../README.md", import.meta.url));
const GUARDIAN = fileURLToPath(new URL("../packages/guardian/src/main.ts", import.meta.url));
const INSPECTOR = fileURLToPath(new URL("../packages/inspector/src/main.ts", import.meta.url));
/** Absolute, because each process below runs from a scratch cwd rather than
 * from the repo root, and an absolute manifest path never reaches stdout. */
const MANIFEST = fileURLToPath(new URL("../policy/manifest.yaml", import.meta.url));

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-readme-"));
  dirs.push(dir);
  return dir;
}

/**
 * Removes exactly what a run here can leave behind, by name, never
 * recursively -- the same discipline hosts/claude-code/test/posture.test.ts
 * uses on its own scratch dirs.
 *
 * The Guardian mkdirs its log directory at startup (envelope-log-sink.ts, and
 * server.ts's session-context appender) and writes nothing into it until an
 * envelope crosses the wire. Nothing posts to the Guardian here, so an empty
 * `.acs/` is the only artifact either process can produce, and `rmdirSync`
 * fails loudly on anything else rather than swallowing a real leak the way a
 * recursive delete would.
 */
afterEach(() => {
  while (dirs.length > 0) {
    const dir = dirs.pop() as string;
    const acs = join(dir, ".acs");
    if (existsSync(acs)) {
      rmdirSync(acs);
    }
    rmdirSync(dir);
  }
});

type Fence = { info: string; body: string };

/** Every fenced block in `markdown`, in source order, with its info string
 * and its body verbatim -- blank lines inside a block included, because one
 * of the two banners has one and a parser that trimmed it would be asserting
 * something the reader does not see. */
function fences(markdown: string): Fence[] {
  const found: Fence[] = [];
  let open: { info: string; body: string[] } | null = null;
  for (const line of markdown.split("\n")) {
    if (open === null) {
      if (line.startsWith("```")) {
        open = { info: line.slice(3).trim(), body: [] };
      }
      continue;
    }
    if (line.startsWith("```")) {
      found.push({ info: open.info, body: open.body.join("\n") });
      open = null;
      continue;
    }
    open.body.push(line);
  }
  if (open !== null) {
    throw new Error("README.md has an unclosed fenced block, so no capture in it can be located");
  }
  return found;
}

/**
 * The capture belonging to `command`: the next fence after the ```bash fence
 * whose only line is that command, and it has to be unlabelled, because an
 * info string would mean the quickstart had grown a second command block
 * where its output used to be. Both failures throw with a sentence rather
 * than returning something empty that would make the comparison below pass
 * for the wrong reason.
 */
function captureAfter(all: Fence[], command: string): string {
  const index = all.findIndex((fence) => fence.info === "bash" && fence.body.trim() === command);
  if (index === -1) {
    throw new Error(`README.md has no \`\`\`bash block whose only command is \`${command}\``);
  }
  const capture = all[index + 1];
  if (capture === undefined || capture.info !== "") {
    throw new Error(`the fence after \`${command}\` in README.md is not an unlabelled capture block`);
  }
  return capture.body;
}

/**
 * Runs one of the two long-lived processes from a scratch cwd and returns what
 * it printed.
 *
 * `lines` is the number of lines the document claims, and the process is
 * killed as soon as that many are in hand -- but the loop then keeps draining
 * to the end of the stream instead of returning, and that is what catches a
 * line the doc does NOT have. Both entrypoints print their whole banner in one
 * synchronous run of `console.log` calls before doing anything else, so an
 * extra line is already in the pipe by the time the kill lands and shows up
 * as a mismatch. The edge: a banner line emitted after a later tick would be
 * missed. Neither file has one, and a new one would belong with its siblings.
 *
 * `timeout` is the runtime's own watchdog rather than a test-side timer, and
 * it is deliberately shorter than bun test's own five-second per-test cap: a
 * banner MISSING a documented line never reaches that line count, so the
 * drain has to be ended by something, and it should be this rather than the
 * harness. The wait is paid only when the document is already wrong -- a
 * healthy run returns as soon as the documented number of lines arrives, in
 * well under a tenth of a second. So a process that never prints its banner
 * fails on the comparison, with a diff naming the line it did not print,
 * instead of dying of a bun-test timeout whose message points nowhere near
 * the cause -- the same reasoning that bounds the tailer in
 * test/session-context-roundtrip.test.ts.
 *
 * The environment is built up rather than inherited: `ACS_ON_DECISION_FAILURE=deny`
 * or a stray `ACS_ENVELOPE_LOG` in the developer's shell would otherwise
 * change the banner and fail this test for a reason that has nothing to do
 * with the document.
 */
async function bannerOf(script: string, env: Record<string, string>, lines: number): Promise<string> {
  const proc = Bun.spawn(["bun", "run", script], {
    cwd: scratch(),
    env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", NO_COLOR: "1", ...env },
    stdout: "pipe",
    stderr: "pipe",
    timeout: 3_000,
  });
  const decoder = new TextDecoder();
  let captured = "";
  let killed = false;
  for await (const chunk of proc.stdout) {
    captured += decoder.decode(chunk, { stream: true });
    if (!killed && captured.split("\n").length > lines) {
      killed = true;
      proc.kill();
    }
  }
  proc.kill();
  await proc.exited;
  // Trailing newlines only. A fenced block cannot express whether it ends in
  // a blank line, so comparing them would be asserting something no reader
  // can see; every line the reader does see is compared exactly.
  return captured.replace(/\n+$/, "");
}

/**
 * The port, and nothing but the port.
 *
 * `ACS_GUARDIAN_PORT` is a documented variable, and this suite cannot bind the
 * documented default: README.md's own step 2 tells the developer to leave a
 * Guardian listening on 8787, so a test that bound it would fail on precisely
 * the machine that followed the quickstart. The subprocess is given port 0
 * instead, and the OS's choice is rewritten to the number the document names.
 *
 * Which number that is comes out of the document, not out of a literal here --
 * a hardcoded 8787 would be a second place to update and therefore a second
 * thing to go stale. One run of digits after `localhost:` is rewritten and
 * nothing else is, so an added, removed, reworded or relabelled line still
 * fails, and so does a changed scheme, host or path.
 */
function normalisePort(observed: string, documented: string): string {
  const port = /\blocalhost:(\d+)\b/.exec(documented)?.[1];
  if (port === undefined) {
    throw new Error("README.md's Guardian capture names no localhost port, so there is nothing to normalise it to");
  }
  return observed.replaceAll(/\blocalhost:\d+/g, `localhost:${port}`);
}

const FENCES = fences(readFileSync(README, "utf8"));

describe("README.md's quickstart captures are what the processes actually print", () => {
  it("matches `bun run guardian`'s banner line for line", async () => {
    const documented = captureAfter(FENCES, "bun run guardian");
    const observed = await bannerOf(
      GUARDIAN,
      { ACS_GUARDIAN_PORT: "0", ACS_MANIFEST_PATH: MANIFEST },
      documented.split("\n").length,
    );
    expect(normalisePort(observed, documented)).toBe(documented);
  });

  it("matches `bun run inspector`'s banner line for line", async () => {
    const documented = captureAfter(FENCES, "bun run inspector");
    // No environment of its own: every path in this banner is one of the
    // three defaults, relative to the scratch cwd, which is exactly what the
    // document shows. Nothing here needs normalising.
    const observed = await bannerOf(INSPECTOR, {}, documented.split("\n").length);
    expect(observed).toBe(documented);
  });
});

describe("the capture reader itself", () => {
  // The gate above is only as good as its ability to FIND the blocks. A
  // parser that quietly returned "" for a moved block would make both tests
  // above pass against a program that printed nothing.
  it("locates a command's capture as the unlabelled fence after it", () => {
    const doc = ["prose", "```bash", "run me", "```", "more prose", "```", "output line", "```"].join("\n");
    expect(captureAfter(fences(doc), "run me")).toBe("output line");
  });

  it("keeps a blank line inside a capture, because one banner has one", () => {
    const doc = ["```bash", "run me", "```", "```", "first", "", "third", "```"].join("\n");
    expect(captureAfter(fences(doc), "run me")).toBe("first\n\nthird");
  });

  it("refuses a command it cannot find rather than returning nothing", () => {
    const doc = ["```bash", "run me", "```", "```", "output", "```"].join("\n");
    expect(() => captureAfter(fences(doc), "run something else")).toThrow(/no ```bash block/);
  });

  it("refuses a labelled block where the capture should be", () => {
    const doc = ["```bash", "run me", "```", "```json", "{}", "```"].join("\n");
    expect(() => captureAfter(fences(doc), "run me")).toThrow(/not an unlabelled capture block/);
  });

  it("refuses an unclosed fence rather than silently losing the rest of the file", () => {
    expect(() => fences(["```bash", "run me"].join("\n"))).toThrow(/unclosed fenced block/);
  });
});
