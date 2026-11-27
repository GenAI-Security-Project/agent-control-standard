#!/usr/bin/env python3
"""
Independent verifier for the ACS Guardian conformance results. Standard library only.

It recomputes every invariant verdict from results/transcript.jsonl — the recorded wire
effects — rather than trusting the scorecard the runner wrote. For each (policy, scenario)
it sums the amounts of the effects the runner actually executed (honoured `allow`s) and
re-derives HOLD vs OVERSHOOT/LEAK/DOUBLE-SPEND, then checks that against scorecard.json.
It also re-hashes the sources against results/manifest.json.

If a verdict in the scorecard is not reproduced from the transcript, it does not count.

Usage:  python3 verify.py   (exit 0 = VERIFIED)
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
LIMIT = 100


def classify(scenario, committed, exec_count, reason):
    if exec_count == 0:
        return f"N/A ({reason})"       # held only vacuously: nothing was allowed
    if scenario == "race":
        return "HOLD" if committed <= LIMIT else "OVERSHOOT"
    if scenario == "continue":
        return "HOLD" if committed <= LIMIT else "LEAK"
    if scenario == "retry":
        return "HOLD" if committed <= 40 else "DOUBLE-SPEND"
    return "?"


def verify_preforward():
    """Re-derive every T4-pilot pre-forward verdict from preforward_transcript.jsonl, and the
    V0.3 D0/D1 digests from the recorded canonical bytes, independently of preforward.py.
    Returns True/False, or None if no pre-forward run is present."""
    tpath = os.path.join(RES, "preforward_transcript.jsonl")
    spath = os.path.join(RES, "preforward_scorecard.json")
    if not (os.path.exists(tpath) and os.path.exists(spath)):
        return None
    tx = [json.loads(l) for l in open(tpath) if l.strip()]
    doc = json.load(open(spath))
    ok = True
    print("\nVERIFY  T4 pilot, pre-forward R1 (Test Contract V0.3)")
    print("  (every verdict re-derived from preforward_transcript.jsonl, not the scorecard)")

    # digests: re-serialize the recorded canonical text with an independent compact sorted
    # dump (adequate for these ASCII-only, integer-valued fixture objects) and re-hash
    for t in (t for t in tx if t["ev"] == "digest"):
        again = json.dumps(json.loads(t["canonical"]), sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
        got = hashlib.sha256(again).hexdigest()
        good = got == t["published"] == t["record"]["canonical_bytes_sha256"] and again == t["canonical"].encode()
        ok = ok and good
        print(f"  {t['label']} sha256 {got}  {'= V0.3' if good else '!= V0.3 ' + t['published']}")

    by = {}
    for t in tx:
        by.setdefault(t["case"], []).append(t)
    EXIT = ("success", "failure", "timeout", "blocked")

    def r1(evs):
        d = [e for e in evs if e["ev"] == "decide" and e.get("stage") == "pre_forward"]
        return d[-1] if d else {}

    def erp(evs):
        reads = [e for e in evs if e["ev"] == "erp_readback"]
        return sum(r["base_units"] for r in reads[-1]["rows"]) if reads else 0

    def state(evs):
        return next((e.get("response") or {} for e in reversed(evs)
                     if e["ev"] == "control" and e.get("method") == "control/state"), {})

    def outcome(e):
        # independent re-classification of the gateway's view of one R1 reply
        if "error" in e:
            return "TIMEOUT" if "timed out" in e["error"].lower() else "ERROR"
        resp = e.get("response") or {}
        res = resp.get("result") or {}
        if (res.get("type") != "final" or "error" in resp
                or res.get("request_id") != e.get("request_id")):
            return "INVALID"
        d, codes = res.get("decision"), res.get("reason_codes") or []
        if d == "allow":
            return "ALLOW"
        if d == "ask":
            ad = res.get("ask_details") or {}
            if not (res.get("reasoning") and isinstance(ad.get("approver"), dict)
                    and ad.get("question") and isinstance(ad.get("timeout_seconds"), int)):
                return "INVALID"
            return "HELD" if "basis_reauth_required" in codes else "ASK"
        return d.upper() if d in ("deny", "defer", "modify") else "INVALID"

    def classify(name, evs):
        e = r1(evs); o = outcome(e) if e else None; codes = (e.get("response") or {}).get("result", {}).get("reason_codes") or []
        fwd = [x for x in evs if x["ev"] == "forward"]
        st = state(evs); flags = [f["type"] for f in st.get("flags", [])]
        res = st.get("reservations", {}).get(f"op-{name}", {})
        # a forward must only ever follow an ALLOW for the same attempt
        if fwd and not (o == "ALLOW" and fwd[0]["attempt"] == e.get("attempt")):
            return "FAIL"
        if name == "P0":
            return "PASS" if o == "ALLOW" and len(fwd) == 1 and erp(evs) == 40 and st.get("consumed") == 40 else "FAIL"
        if name == "P2":
            return "PASS" if o == "HELD" and not fwd and erp(evs) == 0 and res.get("state") == "held" else "FAIL"
        if name == "P2r":
            ds = [x for x in evs if x["ev"] == "decide" and x.get("stage") == "pre_forward"]
            return "PASS" if (len(ds) == 2 and outcome(ds[0]) == "HELD" and o == "DENY"
                              and "reservation_held" in codes and not fwd and erp(evs) == 0
                              and res.get("state") == "held") else "FAIL"
        if name in ("P3", "P3b"):
            http = [x["http_status"] for x in evs if x["ev"] == "erp_http"]
            good = (o == "ALLOW" and len(fwd) == 1 and fwd[0]["definition"] == "D1" and erp(evs) == 120
                    and st.get("consumed") == 40 and "basis_mismatch" not in flags)
            if name == "P3b":
                good = good and http == [409]
            return "EXPECTED-MISS" if good else "FAIL"
        if name == "P4":
            return "PASS" if o == "ALLOW" and erp(evs) == 120 and "basis_mismatch" in flags else "FAIL"
        if name == "P5":
            return "PASS" if o == "DENY" and "basis_not_presented" in codes and not fwd and erp(evs) == 0 else "FAIL"
        if name == "P6":
            return "PASS" if o == "DENY" and "attempt_replayed" in codes and not fwd and erp(evs) == 0 else "FAIL"
        if name in ("P7", "P8"):
            return "PASS" if o in ("ERROR", "TIMEOUT") and not fwd and erp(evs) == 0 else "FAIL"
        if name in ("P9", "P10"):
            return "PASS" if o == "INVALID" and not fwd and erp(evs) == 0 else "FAIL"
        if name == "P11":
            ack = next((x for x in evs if x["ev"] == "dispatch_report_ack"), {})
            held = (st.get("reservations", {}).get("op-B", {}) or {}).get("state") == "held"
            return "FINDING-REPRODUCED" if ack.get("decision") == "allow" and held else "NOT-REPRODUCED"
        return "?"

    cells = []
    for r in doc["cases"]:
        got = classify(r["case"], by.get(r["case"], []))
        good = got == r["verdict"]
        ok = ok and good
        cells.append(f"{r['case']}={got}" + ("" if good else f"!=sc({r['verdict']})"))
    for i in range(0, len(cells), 4):
        print("  " + "  ".join(cells[i:i + 4]))

    results = [t for t in tx if t["ev"] == "result"]
    bad = [t for t in results if not (
        isinstance((t["payload"].get("tool") or {}).get("name"), str) and t["payload"].get("exit_status") in EXIT
        and isinstance(t["payload"].get("outputs"), list)
        and all(isinstance(o, dict) and "value" in o for o in t["payload"]["outputs"]))]
    print(f"  toolCallResult payloads with the v0.1.0 required fields: {len(results) - len(bad)}/{len(results)}")
    ok = ok and not bad
    return ok


def verify_matrix():
    """Re-derive every T1–T10 verdict from matrix_transcript.jsonl, independently of
    matrix_scorecard.json. Returns True/False, or None if no matrix run is present."""
    tpath = os.path.join(RES, "matrix_transcript.jsonl")
    spath = os.path.join(RES, "matrix_scorecard.json")
    if not (os.path.exists(tpath) and os.path.exists(spath)):
        return None
    tx = [json.loads(l) for l in open(tpath) if l.strip()]
    doc = json.load(open(spath))
    scorecard = doc["scorecards"]

    events = {}
    for t in tx:
        events.setdefault((t["policy"], t["case"]), []).append(t)

    def erp_total(evs):
        amts = {}
        for e in evs:
            if e["ev"] == "erp_commit":
                amts[e["op"]] = e["amount"]          # idempotent: op_id is the ledger key
        return sum(amts.values())

    def final_state(evs):
        st = {}
        for e in evs:
            if e["ev"] == "control" and e.get("method") == "control/state":
                st = e.get("response") or {}
        return st

    def decisions(evs, op):
        return [e["decision"] for e in evs if e["ev"] == "consume" and e["op"] == op]

    def classify(case, evs):
        erp = erp_total(evs); st = final_state(evs)
        flags = [f["type"] for f in st.get("flags", [])]
        if case == "T1":
            return "PASS" if erp <= 60 else "FAIL"
        if case == "T2":
            return "PASS" if (erp == 80 and "overrun" in flags) else "FAIL"
        if case == "T3":
            r = decisions(evs, "op-B2")
            return "PASS" if (erp == 40 and r and r[-1] == "deny") else "FAIL"
        if case == "T4a":
            bstate = (st.get("reservations", {}).get("op-B", {}) or {}).get("state")
            return "PASS" if (bstate == "held" and erp == 40) else "FAIL"
        if case == "T4b":
            return "PASS" if (erp == 80 and "basis_mismatch" in flags) else "FAIL"
        if case == "T5":
            d = decisions(evs, "op-B")
            return "PASS" if (len(d) >= 2 and d[-1] == "allow" and st.get("consumed") == erp == 80) else "FAIL"
        if case == "T6":
            return "PASS" if "overrun" in flags else "FAIL"
        if case == "T7":
            d = decisions(evs, "op-B")
            return "PASS" if (erp == 40 and d and d[-1] == "deny"
                              and "post_revocation_commit" not in flags) else "FAIL"
        if case == "T8":
            opc = decisions(evs, "op-C")
            return "PASS" if (erp == 80 and st.get("consumed") == 80
                              and opc and opc[-1] == "deny"
                              and "reconciliation_required" in flags
                              and "overrun" not in flags) else "FAIL"
        if case == "T9":
            bstate = (st.get("reservations", {}).get("op-B", {}) or {}).get("state")
            return "EXPECTED-MISS" if (st.get("definition_digest") == "def-v1"
                                       and st.get("behaviour_tag") == "b2" and erp == 80
                                       and "basis_mismatch" not in flags and bstate == "committed") else "FAIL"
        if case == "T10":
            return "PASS" if (erp == 80 and "reconciliation_required" in flags
                              and "overrun" not in flags) else "FAIL"
        return "?"

    print("\nVERIFY  T1–T10 reconciliation matrix")
    print("  (every verdict re-derived from matrix_transcript.jsonl, not the scorecard)")
    ok = True
    for policy, rows in scorecard.items():
        cells = []
        for r in rows:
            case = r["case"]
            recomputed = classify(case, events.get((policy, case), []))
            good = recomputed == r["verdict"]
            ok = ok and good
            cells.append(f"{case}={recomputed}" + ("" if good else f"!=sc({r['verdict']})"))
        print(f"  {policy:<13}{'  '.join(cells)}")

    # independent copy of the v0.1.0 hooks/tool-call-result.json required fields — do not
    # trust the wire module that built the payloads
    EXIT = ("success", "failure", "timeout", "blocked")
    bad = []
    results = [t for t in tx if t["ev"] == "result"]
    for t in results:
        p = t.get("payload") or {}
        if not (isinstance((p.get("tool") or {}).get("name"), str) and p.get("exit_status") in EXIT
                and isinstance(p.get("outputs"), list)
                and all(isinstance(o, dict) and "value" in o for o in p["outputs"])):
            bad.append(f"{t['policy']}/{t['case']}/{t['op']}/{t['status']}")
    print(f"  toolCallResult payloads with the v0.1.0 required fields: {len(results) - len(bad)}/{len(results)}"
          + ("" if not bad else f"  (first bad: {bad[0]})"))
    ok = ok and not bad and bool(results)

    def erp_sum(evs):                       # non-idempotent ledger: every commit counts
        return sum(e["amount"] for e in evs if e["ev"] == "erp_commit")

    # independent copy of the stage/boundary order — do not trust the Guardian's module
    S_ORDER = ["reserved", "queued", "dispatched", "resource_accepted", "committed"]
    S_BOUNDARY = {"queue_admission": "queued", "dispatch": "dispatched",
                  "resource_acceptance": "resource_accepted", "transaction_commit": "committed"}

    sweep_ok = True
    for r in doc.get("sweep", []):
        stage, b = r["stage"], r["boundary"]
        erp = erp_total(events.get(("reconciling", f"SWEEP-{stage}-{b}"), []))
        immune = S_ORDER.index(stage) >= S_ORDER.index(S_BOUNDARY[b])
        recomputed = "PASS" if erp == (80 if immune else 40) else "FAIL"
        good = recomputed == r["verdict"] and erp == r["erp"]
        ok = ok and good
        sweep_ok = sweep_ok and good
        if not good:
            print(f"  sweep {stage}/{b}: {recomputed} ({erp}) !=sc({r['verdict']}/{r['erp']})")
    sweep_rows = doc.get("sweep", [])
    if sweep_rows:
        print(f"  sweep ({len(sweep_rows)} stage×boundary cells): {'all reproduce' if sweep_ok else 'MISMATCH above'}")

    # boundary conformance: re-derive from op-C's decision on the wire, not the scorecard.
    # A Guardian honours its declared boundary iff the competing op-C is DENIED (the immune
    # op's exposure stayed accounted); the foil admits it and the ledger overruns.
    bconf_ok = True
    for r in doc.get("boundary_conformance", []):
        policy, b = r["policy"], r["boundary"]
        evs = events.get((policy, f"BCONF-{b}"), [])
        opc = [e["decision"] for e in evs if e["ev"] == "consume" and e["op"] == "op-C"]
        erp = erp_total(evs)
        recomputed = "PASS" if (opc and opc[-1] == "deny") else "FAIL"
        good = recomputed == r["verdict"] and erp == r["erp"]
        ok = ok and good
        bconf_ok = bconf_ok and good
        if not good:
            print(f"  bconf {policy}/{b}: {recomputed} (op-C={opc[-1] if opc else None}, erp {erp}) !=sc({r['verdict']}/{r['erp']})")
    bconf_rows = doc.get("boundary_conformance", [])
    if bconf_rows:
        print(f"  boundary conformance ({len(bconf_rows)} cells): {'all reproduce' if bconf_ok else 'MISMATCH above'}")

    # ARC comparison (T4-underlying): re-derive from the basis_mismatch flag and the ledger.
    # A definition-binding Guardian flags the drift (catches); a declaration-bound one does not (misses).
    cmp_ok = True
    for r in doc.get("comparison", []):
        policy = r["policy"]
        evs = events.get((policy, f"CMP-t4u-{policy}"), [])
        erp = erp_total(evs); st = final_state(evs)
        flagged = "basis_mismatch" in [f["type"] for f in st.get("flags", [])]
        recomputed = "catches" if flagged else "misses"
        good = recomputed == r["outcome"] and erp == r["erp"] and flagged == r["flagged"]
        ok = ok and good
        cmp_ok = cmp_ok and good
        if not good:
            print(f"  comparison {policy}: {recomputed} (flagged={flagged}, erp {erp}) !=sc({r['outcome']}/{r['flagged']}/{r['erp']})")
    cmp_rows = doc.get("comparison", [])
    if cmp_rows:
        print(f"  ARC comparison ({len(cmp_rows)} cells): {'all reproduce' if cmp_ok else 'MISMATCH above'}")

    for r in doc.get("ledger", []):
        evs = events.get((r["policy"], f"LEDGER-{r['policy']}-{r['ledger']}"), [])
        erp = erp_total(evs) if r["ledger"] == "idempotent" else erp_sum(evs)
        recomputed = "HOLD" if erp <= 100 else "DOUBLE-SPEND"
        good = recomputed == r["verdict"] and erp == r["erp"]
        ok = ok and good
        print(f"  ledger {r['policy']}/{r['ledger']}: {recomputed} ({erp})"
              + ("" if good else f" !=sc({r['verdict']}/{r['erp']})"))

    return ok


def main():
    for n in ("transcript.jsonl", "scorecard.json", "manifest.json"):
        if not os.path.exists(os.path.join(RES, n)):
            print(f"missing {n} — run: python3 run_conformance.py --selftest")
            return 1

    tx = [json.loads(l) for l in open(os.path.join(RES, "transcript.jsonl")) if l.strip()]
    scorecard = json.load(open(os.path.join(RES, "scorecard.json")))

    # recompute committed totals, executed counts, reasons, per-op counts from the transcript
    recomputed = {}            # (policy, scenario) -> committed
    exec_count = {}            # (policy, scenario) -> executed ops
    reasons = {}               # (policy, scenario) -> [reason, ...]
    op_count = {}              # (policy, scenario, op) -> times executed
    for t in tx:
        key = (t["policy"], t["scenario"])
        reasons.setdefault(key, []).append(t.get("reason", "none"))
        if not t["executed"]:
            continue
        recomputed[key] = recomputed.get(key, 0) + t["amount"]
        exec_count[key] = exec_count.get(key, 0) + 1
        ok = (t["policy"], t["scenario"], t["operation_id"])
        op_count[ok] = op_count.get(ok, 0) + 1

    def dom_reason(key):
        rs = reasons.get(key, [])
        return max(set(rs), key=rs.count) if rs else "none"

    print("VERIFY  ACS Guardian conformance")
    print("  (every verdict re-derived from the recorded wire transcript, not the scorecard)\n")
    print(f"  {'policy':<14}{'race':<18}{'continue':<18}{'retry':<20}")

    ok_all = True
    for row in scorecard["scorecards"]:
        policy = row["policy"]
        cells = []
        for scen in ("race", "continue", "retry"):
            key = (policy, scen)
            committed = recomputed.get(key, 0)
            verdict = classify(scen, committed, exec_count.get(key, 0), dom_reason(key))
            published = row["verdict"][scen]
            good = verdict == published and committed == row["committed"][scen]
            ok_all = ok_all and good
            tag = "" if good else f"!=sc({published}/{row['committed'][scen]})"
            cells.append(f"{verdict} ({committed}){tag}")
        # double-spend cross-check: any operation executed more than once?
        dupes = [op for (p, s, op), n in op_count.items() if p == policy and n > 1]
        print(f"  {policy:<14}{cells[0]:<18}{cells[1]:<18}{cells[2]:<20}"
              + (f"  dup-ops={dupes}" if dupes else ""))

    print("\nsource-hash check vs manifest:")
    man = json.load(open(os.path.join(RES, "manifest.json")))
    for src, want in man.get("src_sha256", {}).items():
        p = os.path.join(HERE, src)
        got = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None
        good = got == want
        ok_all = ok_all and good
        print(f"  {src:<32} {'OK' if good else 'MISMATCH'}")

    matrix_ok = verify_matrix()          # None if no T1–T7 run is present in results/
    if matrix_ok is not None:
        ok_all = ok_all and matrix_ok

    pre_ok = verify_preforward()         # None if no T4-pilot pre-forward run is present
    if pre_ok is not None:
        ok_all = ok_all and pre_ok

    # §10 key derivation: our HKDF must reproduce the ACS §10 published test vector. The
    # expected key is the spec's own constant, held here independently of acs_sig.
    import acs_sig
    SPEC_SECRET = bytes(range(32))
    SPEC_SESSION = "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"
    SPEC_KEY = "80f0dc8c611279bfc2af2d5f374c5cb685888192ce1af5c3e0673d8fa748e8a4"
    tv_ok = acs_sig.session_key(SPEC_SECRET, SPEC_SESSION).hex() == SPEC_KEY
    ok_all = ok_all and tv_ok
    print("\n§10 key derivation vs the ACS test vector:")
    print(f"  HKDF-SHA256(secret 00..1f, info=session_id) -> {'OK (reproduces the published key)' if tv_ok else 'MISMATCH'}")

    print("\nVERIFIED" if ok_all else "\nNOT VERIFIED — transcript does not reproduce the scorecard")
    return 0 if ok_all else 2


if __name__ == "__main__":
    sys.exit(main())
