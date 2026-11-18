// The FinBot lab's decision viewer page (issue #586). Owner: Rock Lambros.
//
// It polls /api/rows every 500 ms and draws what changed. Every value it shows came from a log an attacker can
// shape, so text reaches the page through textContent only, never as markup (issue #468). The server has already
// escaped control and bidi characters.
"use strict";

// A.12's beats, in the order the paint log numbers them.
const BEATS = ["handshake", "first_allow", "shadow_decision", "deny", "allow_after_fix", "ask_pending",
  "ask_resolved", "modify", "digest_mismatch", "forge_passes_hmac", "forge_fails_mldsa", "keys_only_verify",
  "downgrade_refused"];

const BEAT_LABELS = {
  handshake: "Handshake: the ACS session opens",
  first_allow: "Allow: the Guardian lets the call through",
  shadow_decision: "Shadow: the Guardian would deny, and the call still runs",
  deny: "Deny: the call never runs",
  allow_after_fix: "Allow after the fix",
  ask_pending: "Ask: the call waits for a human approver",
  ask_resolved: "Ask resolved",
  modify: "Modify: the Guardian redacts the tool output",
  digest_mismatch: "Tool changed: digest mismatch, denied",
  forge_passes_hmac: "A forged decision passes HMAC",
  forge_fails_mldsa: "A forged decision fails ML-DSA-65",
  keys_only_verify: "Verified with the public key alone",
  downgrade_refused: "Downgrade refused",
};

const VERIFY_WORDS = {
  verified: "verified",
  failed: "failed",
  not_checked: "not checked",
  unsigned: "unsigned",
  no_answer: "no answer",
};

const POLL_MS = 500;

const table = document.getElementById("log");
const beatEl = document.getElementById("beat");
const detailEl = document.getElementById("detail");
const emptyEl = document.getElementById("empty");
const statusEl = document.getElementById("status");

const groups = new Map();
const paintedBeat = new Map();
let next = 0;
// The rows already in the logs when the page loads are drawn but not logged as paints, so a reload during a shoot
// doesn't log every earlier beat a second time.
let caughtUp = false;
let paintOn = false;
let lastPainted = null;

function shortMethod(method) {
  if (method === "handshake/hello") return "handshake";
  return method.startsWith("steps/") ? method.slice("steps/".length) : method;
}

function shortTime(t) {
  return /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}/.test(t) ? t.slice(11, 23) : t;
}

function cell(tr, text, className) {
  const td = document.createElement("td");
  td.textContent = text === null || text === undefined ? "" : String(text);
  if (className) td.className = className;
  tr.appendChild(td);
  return td;
}

// Tool names and reason codes are long snake_case words. A line break may fall after each underscore, so a word
// wraps at a readable point instead of mid-letter. The pieces go in as text nodes and wbr elements, never markup.
function breakableCell(tr, text) {
  const td = document.createElement("td");
  const value = text === null || text === undefined ? "" : String(text);
  value.split(/(?<=_)/).forEach((part, index) => {
    if (index > 0) td.appendChild(document.createElement("wbr"));
    td.appendChild(document.createTextNode(part));
  });
  tr.appendChild(td);
  return td;
}

function draw(row) {
  let group = groups.get(row.id);
  const fresh = group === undefined;
  if (fresh) {
    group = document.createElement("tbody");
    group.dataset.id = String(row.id);
    // Rows keep the order they were first read in. A row that changed in the same poll can come before a newer
    // row in the answer, so a fresh row goes in front of the first row with a larger id.
    let before = null;
    for (const [id, other] of groups) {
      if (id > row.id && (before === null || Number(before.dataset.id) > id)) before = other;
    }
    groups.set(row.id, group);
    table.insertBefore(group, before);
  }
  const tr = document.createElement("tr");
  cell(tr, shortTime(row.t));
  cell(tr, shortMethod(row.method));
  breakableCell(tr, row.tool);
  cell(tr, row.decision, row.decision ? "d-" + row.decision : "");
  breakableCell(tr, row.reason_codes.join(", "));
  cell(tr, row.algorithm);
  const verify = row.verify in VERIFY_WORDS ? row.verify : "not_checked";
  cell(tr, VERIFY_WORDS[verify], "v-" + verify);
  const rows = [tr];
  if (row.note) {
    const noteRow = document.createElement("tr");
    const td = cell(noteRow, row.note, "note");
    td.colSpan = 7;
    rows.push(noteRow);
  }
  group.replaceChildren(...rows);
  return fresh;
}

function summary(row) {
  const parts = [shortMethod(row.method), row.tool, row.decision, row.reason_codes.join(", "),
    row.algorithm, VERIFY_WORDS[row.verify]];
  if (row.note) parts.push(row.note);
  return parts.filter((p) => p).join(" | ");
}

function postPaint(body) {
  fetch("/api/paint", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).catch(() => {});
}

function paint(row) {
  const label = BEAT_LABELS[row.beat];
  if (!label) return;
  beatEl.textContent = label;
  detailEl.textContent = summary(row);
  lastPainted = groups.get(row.id) || null;
  if (caughtUp && paintOn) {
    postPaint({ step: BEATS.indexOf(row.beat), text: label + " | " + detailEl.textContent });
    if (row.beat === "downgrade_refused") postPaint({ step: "end", text: "" });
  }
}

function apply(data) {
  paintOn = data.paint === true;
  let newest = null;
  for (const row of data.rows) {
    if (draw(row)) newest = groups.get(row.id);
    if (row.beat && paintedBeat.get(row.id) !== row.beat) {
      paintedBeat.set(row.id, row.beat);
      paint(row);
    }
  }
  // Only the row behind the current beat is highlighted. A redraw replaces its cells, so the mark is set again.
  for (const group of groups.values()) {
    for (const tr of group.children) tr.classList.toggle("painted", group === lastPainted);
  }
  if (newest) newest.scrollIntoView({ block: "end" });
  next = data.next;
  emptyEl.hidden = !data.no_record;
  emptyEl.textContent = data.no_record ? data.no_record_text : "";
  caughtUp = true;
}

async function poll() {
  try {
    const response = await fetch("/api/rows?after=" + next, { cache: "no-store" });
    if (response.ok) {
      apply(await response.json());
      statusEl.textContent = "";
    } else {
      statusEl.textContent = "The viewer answered " + response.status + ". Retrying.";
    }
  } catch (err) {
    statusEl.textContent = "The viewer server can't be reached. Retrying.";
  } finally {
    setTimeout(poll, POLL_MS);
  }
}

poll();
