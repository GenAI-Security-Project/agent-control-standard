#!/usr/bin/env python3
"""Post the ACS-Core conformance vectors to a running reference Guardian and report.

    python3 scripts/run-acs-core-vectors.py --guardian http://127.0.0.1:8787/acs \
        --out acs-core-results.jsonl --summary acs-core-summary.md

The vectors come from the `agent-evidence-vectors` package, pinned by version and hash in
`conformance/acs-core-vectors.txt`. Each vector quotes the MUST it tests and names the error
code a conformant Guardian returns, so a score here is a statement about one sentence of the
specification rather than about the harness.

Every member is posted twice. `raw` sends the vector's own tool name. `adapted` rewrites the
tool to the registered `Bash` tool with the arguments joined into one command, so a member
whose property lives in the envelope (replay, clock skew, version, signature) reaches the
policy path instead of being refused as an unknown tool. The summary scores the `adapted`
column; the `raw` column is kept because it is what the vector literally sends.

This is a report, not a gate. A FAIL row exits 0. The script exits 2 only when it could not
measure: the corpus is missing, or the Guardian answered no request at all.

Standard library only, so the job needs nothing beyond the pinned package.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import urllib.request
import uuid
from importlib import resources

METHODS = {
    "hooks/toolCallRequest": "steps/toolCallRequest",
    "handshake/hello": "handshake/hello",
}
SESSION_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
CORPUS = "vectors-acs-core"


def corpus_dir(override: str | None) -> str:
    """The vectors directory: an explicit path, or the one the installed package ships."""
    if override:
        return override
    root = resources.files("agent_evidence_vectors").joinpath("corpora", CORPUS)
    return str(root)


def wire(req: dict, adapted: bool, session_salt: str) -> tuple[dict | None, str | None]:
    """Translate a vector's request into the JSON-RPC envelope the Guardian validates."""
    method = METHODS.get(req["method"])
    if method is None:
        return None, "method %s has no wire form in this driver" % req["method"]
    acs = req.get("acs_version") or (req.get("acs", "0.1") + ".0")
    meta = req.get("metadata", {})
    params: dict = {
        "acs_version": acs,
        "request_id": req["request_id"],
        "timestamp": req["timestamp"],
        "metadata": {
            "agent_id": "vector-driver",
            "session_id": str(
                uuid.uuid5(SESSION_NS, session_salt + ":" + meta.get("session_id", "s"))
            ),
        },
    }
    if "turn_id" in meta and method.startswith("steps/"):
        params["metadata"]["turn_id"] = meta["turn_id"]
    for key in ("signature", "nonce"):
        if key in req:
            params[key] = req[key]
    p = req.get("params", {})
    if method == "handshake/hello":
        params["payload"] = dict(p)
    else:
        tool = p.get("tool", {})
        name, args = tool.get("name", ""), tool.get("arguments", {})
        if adapted:
            cmd = name + "".join(" --%s %s" % (k, v) for k, v in sorted(args.items()))
            params["payload"] = {
                "tool": {"name": "Bash"},
                "arguments": {"command": {"value": cmd}},
                "raw_command": cmd,
            }
        else:
            params["payload"] = {
                "tool": {"name": name},
                "arguments": {k: {"value": v} for k, v in args.items()},
            }
    return {"jsonrpc": "2.0", "id": req["request_id"], "method": method, "params": params}, None


def post(url: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    rq = urllib.request.Request(url, data=data, headers={"content-type": "application/json"})
    with urllib.request.urlopen(rq, timeout=20) as r:
        return json.loads(r.read().decode())


def observe(resp: dict) -> dict:
    if "error" in resp:
        e = resp["error"]
        return {"kind": "error", "code": e.get("code"), "message": e.get("message")}
    r = resp.get("result", {})
    if "negotiated_version" in r:
        return {"kind": "hello", "negotiated_version": r["negotiated_version"]}
    return {
        "kind": "decision",
        "decision": r.get("decision"),
        "reason_codes": r.get("reason_codes"),
    }


def drive(member: dict, url: str, adapted: bool) -> dict:
    p = member["payload"]
    salt = "%s:%s" % (member["id"], "adapted" if adapted else "raw")
    steps = p.get("steps") or ([{"request": p["request"]}] if "request" in p else None)
    if steps is None:
        return {"status": "not-on-the-wire",
                "reason": "no request envelope; the subject is %s" % sorted(p.keys())}
    obs = []
    for st in steps:
        w, err = wire(st["request"], adapted, salt)
        if err:
            return {"status": "not-on-the-wire", "reason": err}
        try:
            obs.append(observe(post(url, w)))
        except Exception as ex:  # recorded as a transport failure, never scored
            return {"status": "transport-failure", "reason": repr(ex)}
    return {"status": "ran", "observations": obs}


def score(expected: dict, run: dict) -> str:
    if run["status"] != "ran":
        return "NOT RUN"
    if expected["verdict"] == "unmeasurable":
        return "UNMEASURABLE"
    obs = run["observations"]
    if expected["verdict"] == "allow":
        ok = all(o["kind"] == "hello" or (o["kind"] == "decision" and o["decision"] == "allow")
                 for o in obs)
        return "PASS" if ok else "FAIL"
    last = obs[-1]
    refused = last["kind"] == "error" or (
        last["kind"] == "decision" and last["decision"] in ("deny", "defer"))
    if not refused:
        return "FAIL"
    if expected.get("codeValue") is not None:
        matched = last["kind"] == "error" and last["code"] == expected["codeValue"]
        return "PASS" if matched else "FAIL-CODE"
    return "PASS"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--guardian", required=True, help="the Guardian's JSON-RPC URL")
    ap.add_argument("--vectors", help="a vectors-acs-core directory; default: the installed package")
    ap.add_argument("--out", required=True, help="JSONL, one line per member")
    ap.add_argument("--summary", help="Markdown summary, appended to (e.g. $GITHUB_STEP_SUMMARY)")
    a = ap.parse_args()

    root = corpus_dir(a.vectors)
    manifest_path = os.path.join(root, "MANIFEST.json")
    if not os.path.isfile(manifest_path):
        print("run-acs-core-vectors: no MANIFEST.json under %s; nothing was measured" % root,
              file=sys.stderr)
        return 2
    with open(manifest_path) as fh:
        manifest = json.load(fh)

    counts: collections.Counter = collections.Counter()
    rows = []
    answered = 0
    with open(a.out, "w") as out:
        for entry in manifest["vectors"]:
            with open(os.path.join(root, entry["file"])) as fh:
                member = json.load(fh)
            rec = {"id": member["id"], "kind": member["kind"], "family": member["family"],
                   "requirements": member["requirements"], "expected": member["expected"]}
            for col in ("raw", "adapted"):
                run = drive(member, a.guardian, col == "adapted")
                rec[col] = run
                rec[col + "_score"] = score(member["expected"], run)
                if run["status"] == "ran":
                    answered += 1
            counts[rec["adapted_score"]] += 1
            rows.append(rec)
            out.write(json.dumps(rec) + "\n")
            print(rec["id"], member["expected"]["verdict"], member["expected"]["code"],
                  "raw=" + rec["raw_score"], "adapted=" + rec["adapted_score"])

    if answered == 0:
        print("run-acs-core-vectors: the Guardian answered no request; nothing was measured",
              file=sys.stderr)
        return 2

    lines = [
        "## ACS-Core conformance vectors against the reference Guardian",
        "",
        "Corpus `%s`, %d members, spec pinned at `%s`. Informational: FAIL rows do not fail "
        "this job." % (manifest.get("suite", CORPUS), len(rows),
                       manifest.get("specUpstreamCommit", "?")),
        "",
        "| score | members |",
        "|---|---|",
    ]
    lines += ["| %s | %d |" % (k, v) for k, v in sorted(counts.items())]
    lines += ["", "| member | requirement | expected | adapted |", "|---|---|---|---|"]
    for r in rows:
        exp = r["expected"]["verdict"] + (
            " %s" % r["expected"]["code"] if r["expected"].get("code") else "")
        lines.append("| `%s` | %s | %s | %s |" % (
            r["id"], ", ".join(r["requirements"]), exp, r["adapted_score"]))
    text = "\n".join(lines) + "\n"
    print(text)
    if a.summary:
        with open(a.summary, "a") as fh:
            fh.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
