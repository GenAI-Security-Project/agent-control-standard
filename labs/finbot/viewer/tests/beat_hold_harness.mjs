// Runs the viewer page's real app.js against a stub DOM, a scripted /api/rows and a fake clock, to check the
// headline hold. Owner: Rock Lambros.
//
//   bun --no-install beat_hold_harness.mjs <app.js> [--without-hold]
//
// One poll carries an ask, then a handshake and a first allow from a new session, the burst a paced-out replay or a
// busy FinBot sends. The headline must stay on the ask. After the hold, a later first allow takes the headline.
// --without-hold removes the hold check, so the test shows the harness catches a page that lets routine beats bury
// the ask. Prints one JSON object. Only node: builtins, so nothing is fetched or installed.
import fs from "node:fs";
import vm from "node:vm";

let src = fs.readFileSync(process.argv[2], "utf8");
if (process.argv.includes("--without-hold")) {
  src = src.replace("if (routine && Date.now() < heldUntil) return;", "");
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

const row = (id, seq, session, method, tool, decision, beat) => ({
  id, seq, t: "2026-12-09T10:00:00.000Z", session_id: session, method, tool, decision, applied: null,
  conflict: false, reason_codes: [], algorithm: "ML-DSA-65", verify: "verified", note: null, beat,
});
const S1 = "11111111-1111-4111-8111-111111111111";
const S2 = "22222222-2222-4222-8222-222222222222";
const S3 = "33333333-3333-4333-8333-333333333333";
const rows = [
  row(1, 1, S1, "steps/askPending", "finstripe__create_transfer", "ask", "ask_pending"),
  row(2, 2, S2, "handshake", null, null, "handshake"),
  row(3, 3, S2, "steps/toolCallRequest", "get_vendor_details", "allow", "first_allow"),
  row(4, 4, S3, "steps/toolCallRequest", "get_invoice_details", "allow", "first_allow"),
];
let served = 3;

async function fetch(url) {
  const after = Number(new URL(url, "http://127.0.0.1").searchParams.get("after"));
  const ready = rows.filter((r) => r.seq > after && r.seq <= served);
  return {
    ok: true,
    status: 200,
    json: async () => ({
      rows: ready, next: served, more: false, no_record: false, no_record_text: "no ACS record", paint: false,
      dropped: [], dropped_total: 0, paused: null, instance: "a".repeat(32),
    }),
  };
}

let clock = 1_000_000;
const FakeDate = { now: () => clock };
const timers = [];
const context = { document, fetch, setTimeout: (fn) => timers.push(fn), console, URL, Number, Array, Object,
  Set, Date: FakeDate };
vm.createContext(context);
vm.runInContext(src, context);

const settle = async () => { for (let i = 0; i < 8; i += 1) await new Promise((r) => setImmediate(r)); };
const tick = async () => { await settle(); const next = timers.shift(); if (next) next(); await settle(); };

await tick();
const afterBurst = ids.beat.textContent;
clock += 9000;
served = 4;
await tick();
process.stdout.write(JSON.stringify({ afterBurst, afterHold: ids.beat.textContent }) + "\n");
