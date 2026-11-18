// Runs the viewer page's real app.js against a stub DOM and a scripted /api/rows (final review R11).
//
//   bun --no-install page_harness.mjs <app.js> [--without-reset]
//
// Server A shows rm deny verified. The viewer then restarts as server B, which judged an in-place edit while A was
// down: rm DENY failed. The page must drop A's rows and show B's. --without-reset removes the page's instance check,
// so the test can show that the harness catches the stale view. Prints one JSON object. Only node: builtins, so
// nothing is fetched or installed.
import fs from "node:fs";
import vm from "node:vm";

let src = fs.readFileSync(process.argv[2], "utf8");
if (process.argv.includes("--without-reset")) {
  src = src.replace("if (instance !== data.instance) {", "if (false) {");
}

class El {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.parent = null;
    this.dataset = {};
    this.hidden = false;
    this.className = "";
    this.colSpan = 1;
    this.own = "";
    this.classList = { toggle() {}, add() {}, remove() {} };
  }
  set textContent(value) { this.own = String(value); this.children = []; }
  get textContent() { return this.own + this.children.map((c) => c.textContent).join(""); }
  appendChild(child) { child.parent = this; this.children.push(child); return child; }
  insertBefore(child, before) {
    child.parent = this;
    const at = before ? this.children.indexOf(before) : -1;
    if (at < 0) this.children.push(child); else this.children.splice(at, 0, child);
    return child;
  }
  replaceChildren(...children) { this.children = []; children.forEach((c) => this.appendChild(c)); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((c) => c !== this); }
  scrollIntoView() {}
}

const ids = {};
for (const id of ["log", "beat", "detail", "empty", "status", "dropped", "paused"]) ids[id] = new El("div");
ids.beat.own = "Waiting for the first decision";
const document = {
  getElementById: (id) => ids[id],
  createElement: (tag) => new El(tag),
  createTextNode: (text) => { const node = new El("#text"); node.own = String(text); return node; },
};

const row = (id, seq, tool, decision, verify) => ({
  id, seq, t: "2026-12-09T10:00:00.000Z", session_id: "11111111-1111-4111-8111-111111111111",
  method: "steps/toolCallRequest", tool, decision, applied: null, conflict: false, reason_codes: [],
  algorithm: "ML-DSA-65", verify, note: null, beat: null,
});

// B reuses A's ids and seqs, as a restarted viewer does, which is what hid the new marks before R5.
const servers = {
  A: { instance: "a".repeat(32), rows: [row(1, 3, "echo", "allow", "verified"), row(2, 4, "rm", "deny", "verified")] },
  B: { instance: "b".repeat(32),
       rows: [row(1, 3, "echo", "allow", "not_checked"), row(2, 4, "rm", "DENY", "failed")] },
};
let current = "A";

async function fetch(url) {
  const after = Number(new URL(url, "http://127.0.0.1").searchParams.get("after"));
  const server = servers[current];
  const rows = server.rows.filter((r) => r.seq > after);
  return {
    ok: true,
    status: 200,
    json: async () => ({
      rows, next: 4, more: false, no_record: false, no_record_text: "no ACS record", paint: false,
      dropped: [], dropped_total: 0, paused: null, instance: server.instance,
    }),
  };
}

const timers = [];
const context = { document, fetch, setTimeout: (fn) => timers.push(fn), console, URL, Number, Array, Object };
vm.createContext(context);
vm.runInContext(src, context);

const settle = async () => { for (let i = 0; i < 8; i += 1) await new Promise((r) => setImmediate(r)); };
const tick = async () => { await settle(); const next = timers.shift(); if (next) next(); await settle(); };
const view = () => ids.log.children.map((group) => {
  const cells = group.children[0].children.map((c) => c.textContent);
  return [cells[2], cells[3], cells[6]];
});

await tick();
await tick();
const onA = view();
current = "B";
for (let i = 0; i < 4; i += 1) await tick();
process.stdout.write(JSON.stringify({ onA, onB: view() }) + "\n");
