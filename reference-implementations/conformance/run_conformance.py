"""
ACS Guardian conformance runner.

Two layers, pointed at any Guardian over its HTTP endpoint (--guardian-url), or at a
launched mock (--policy):

  Layer A — PROTOCOL conformance: does the Guardian speak ACS correctly? Handshake
    returns a schema-valid ServerHello (the v0.1.0 handshake.json $def requires
    negotiated_version, methods_evaluated, selected_transport, timeout_config); a
    toolCallRequest returns an AcsResult that validates against response-envelope.json;
    deny carries reasoning; an undeclared method is refused; system/ping answers (§13
    SHOULD); and §10 message authentication is exercised — a valid HMAC-SHA256 signature is
    accepted, while a tampered request, an out-of-window timestamp, and a replayed request_id
    are rejected (SIGNATURE_INVALID / TIMESTAMP_OUT_OF_WINDOW / REPLAY_DETECTED). The §10
    checks run when the Guardian advertises the HMAC-SHA256 baseline and the suite holds the
    matching key material (the bundled mocks do); see acs_sig.py.

  Layer B — INVARIANT conformance: a protocol-perfect Guardian can still fail a security
    property. We drive adversarial steps/toolCallRequest sequences for a shared 100-unit
    grant and measure, from an independent world ledger (not the Guardian's own books),
    whether the committed total ever exceeded the grant. Three scenarios, straight from
    the delegated-authority cumulative-limit case (OWASP Agentic ASI03):
       race       - three concurrent consume(40) against a limit of 100
       continue   - one consume(40), its ack lost, then a later consume(70)
       retry      - one consume(40), its ack lost, then the same operation retried

The runner honours verdicts literally: on `allow` it executes (appends to the world
ledger); on `deny`/`ask`/`defer` it does not. The world ledger is a faithful append-only
record (no idempotency backstop), so preventing a double-spend is forced onto the
Guardian — this isolates the control plane, which is the point of a conformance test.

Writes results/transcript.jsonl and results/scorecard.json. Verify with verify.py.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone, timedelta

import acs_wire as w
import acs_sig

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
os.makedirs(RES, exist_ok=True)

LIMIT = 100
GRANT = "COMP-17"

# A single transcript collects every executed effect across scenarios, for the verifier.
_tx_lock = threading.Lock()
TRANSCRIPT: list[dict] = []


def record(policy, scenario, operation_id, amount, decision, executed, reason):
    with _tx_lock:
        TRANSCRIPT.append({"policy": policy, "scenario": scenario,
                           "operation_id": operation_id, "amount": amount,
                           "decision": decision, "executed": bool(executed),
                           "reason": reason})


def consume(client: w.GuardianClient, session, operation_id, amount, policy, scenario):
    """Send one budget.consume, honour the verdict against the world ledger."""
    env = w.tool_call_request("budget.consume",
                              {"grant_id": GRANT, "operation_id": operation_id, "amount": amount},
                              session_id=session)
    resp = client.call(env)
    decision = w.decision_of(resp)
    executed = decision in ("allow", "modify")
    result = resp.get("result") or {}
    if decision is None and "error" in resp:
        reason = f"jsonrpc_error:{resp['error'].get('code')}"
    else:
        rc = result.get("reason_codes") or []
        reason = ",".join(rc) if rc else (decision or "none")
    record(policy, scenario, operation_id, amount, decision, executed, reason)
    return decision, executed, env


def send_result(client: w.GuardianClient, session, operation_id, status):
    env = w.build_request("steps/toolCallResult",
                          w.tool_call_result_payload("budget.consume", GRANT, operation_id, status),
                          session_id=session)
    client.call(env)


# ---------------------------------------------------------------- Layer A: protocol -----
SERVERHELLO_REQUIRED = ("negotiated_version", "methods_evaluated", "selected_transport", "timeout_config")


def sig10_checks(client, session, sig_algs, skew, secret, key_id) -> list[dict]:
    """§10 message authentication and §10.3 replay, measured against the Guardian. Run only
    when the Guardian advertises the HMAC-SHA256 baseline and the suite holds the matching
    key material; otherwise reported as an observation, because an HMAC Guardian cannot be
    signature-tested without its shared secret. Each case isolates one failure so it draws
    one error code (SIGNATURE_INVALID -32004, TIMESTAMP_OUT_OF_WINDOW -32006, REPLAY_DETECTED
    -32005). The signing input is the RFC 8785 (JCS) canonicalization of the envelope minus
    the signature field; the key is HKDF-SHA256(secret, info=session_id) — see acs_sig.py,
    whose HKDF reproduces the ACS §10 test vector."""
    skew = skew if isinstance(skew, int) else 300000

    def consume_env(**kw):
        return w.tool_call_request("budget.consume",
                                   {"grant_id": GRANT, "operation_id": w.new_uuid(), "amount": 10},
                                   session_id=session, **kw)

    if "HMAC-SHA256" not in (sig_algs or []):
        return [{"check": "§10 signature verification", "ok": None,
                 "detail": f"PENDING: ServerHello signature_algorithms_supported={sig_algs} has no HMAC-SHA256 "
                           "baseline, so §10 signing is not exercised"},
                {"check": "§10.3 replay/timestamp rejection", "ok": None,
                 "detail": f"PENDING: no HMAC-SHA256 baseline advertised (skew_window_ms={skew})"}]
    if secret is None:
        return [{"check": "§10 signature verification", "ok": None,
                 "detail": "PENDING: Guardian advertises HMAC-SHA256 but the suite has no shared secret for it; "
                           "provide the deployment's key material to run the §10 signing checks"},
                {"check": "§10.3 replay/timestamp rejection", "ok": None,
                 "detail": "PENDING: needs the deployment's key material to produce a valid signature"}]

    checks = []
    # (a) a validly-signed request is accepted (not rejected with a §10 error)
    r = client.call(acs_sig.sign_envelope(consume_env(), secret, key_id))
    accepted = isinstance(r.get("result"), dict) and "decision" in r["result"]
    checks.append({"check": "§10 valid HMAC-SHA256 signature is accepted", "ok": accepted,
                   "detail": "" if accepted else f"a validly-signed request was not accepted: {r.get('error')}"})

    # (b) a request tampered after signing is rejected SIGNATURE_INVALID
    tampered = acs_sig.sign_envelope(consume_env(), secret, key_id)
    tampered["params"]["payload"]["arguments"]["amount"]["value"] = 999   # mutate after signing
    code_t = (client.call(tampered).get("error") or {}).get("code")
    checks.append({"check": "§10 tampered request is rejected (SIGNATURE_INVALID -32004)",
                   "ok": code_t == acs_sig.SIGNATURE_INVALID,
                   "detail": "" if code_t == acs_sig.SIGNATURE_INVALID else f"got {code_t!r}, expected -32004"})

    # (c) a stale timestamp is rejected TIMESTAMP_OUT_OF_WINDOW
    stale_ts = (datetime.now(timezone.utc) - timedelta(milliseconds=skew + 600000)).isoformat()
    code_s = (client.call(acs_sig.sign_envelope(consume_env(timestamp=stale_ts), secret, key_id)).get("error") or {}).get("code")
    checks.append({"check": "§10.3 out-of-window timestamp is rejected (TIMESTAMP_OUT_OF_WINDOW -32006)",
                   "ok": code_s == acs_sig.TIMESTAMP_OUT_OF_WINDOW,
                   "detail": "" if code_s == acs_sig.TIMESTAMP_OUT_OF_WINDOW else f"got {code_s!r}, expected -32006"})

    # (d) a replayed request (identical, same request_id) is rejected REPLAY_DETECTED on the second send
    replay = acs_sig.sign_envelope(consume_env(), secret, key_id)
    client.call(replay)                                      # first: accepted and remembered
    code_r = (client.call(replay).get("error") or {}).get("code")   # second: identical -> replay
    checks.append({"check": "§10.3 replayed request_id is rejected (REPLAY_DETECTED -32005)",
                   "ok": code_r == acs_sig.REPLAY_DETECTED,
                   "detail": "" if code_r == acs_sig.REPLAY_DETECTED else f"got {code_r!r}, expected -32005"})
    return checks


def protocol_checks(client: w.GuardianClient, policy: str,
                    sig_secret: bytes | None = None, sig_key_id: str | None = None) -> list[dict]:
    out = []
    session = w.new_uuid()

    # A schema-valid ClientHello (handshake.json's $def requires these four). The reference
    # Guardian does not read it, but a conformance client should still send a valid one.
    client_hello = {"acs_versions_supported": [w.ACS_VERSION],
                    "methods_implemented": ["steps/toolCallRequest", "steps/toolCallResult"],
                    "transports_supported": ["http"],
                    "provenance_producer": "noctis-acs-conformance"}
    hello = client.call(w.build_request("handshake/hello", client_hello, session_id=session))
    sh = hello["result"] if isinstance(hello.get("result"), dict) else {}
    missing = [f for f in SERVERHELLO_REQUIRED if f not in sh]
    out.append({"check": "handshake returns a schema-valid ServerHello (v0.1.0 $def required fields)",
                "ok": not missing,
                "detail": f"missing required field(s): {missing}" if missing else ""})
    # Capabilities the ServerHello advertises; the §10 / §10.3 checks read these.
    sig_algs = sh.get("signature_algorithms_supported") or []
    skew = sh.get("skew_window_ms")

    ping = client.call(w.build_request("system/ping", {}, session_id=session))
    if "error" not in ping:
        out.append({"check": "system/ping answers (liveness probe)", "ok": True, "detail": ""})
    else:
        # Normativity is unsettled: handshake.json says clients SHOULD include system/ping,
        # while hooks/system-ping.json says a Guardian MUST return allow for it. We report the
        # absence as an open observation (PENDING), not a pass/fail, pending clarification.
        out.append({"check": "system/ping answers (liveness probe)", "ok": None,
                    "detail": f"no system/ping (error {ping.get('error', {}).get('code')}); normativity unsettled "
                              "(handshake.json: clients SHOULD include it; hooks/system-ping.json: a Guardian MUST "
                              "return allow) — reported as an open observation, not a failure"})

    env = w.tool_call_request("budget.consume",
                              {"grant_id": GRANT, "operation_id": w.new_uuid(), "amount": 10},
                              session_id=session)
    resp = client.call(env)
    violations = w.validate_response(resp, env)
    out.append({"check": "toolCallRequest returns schema-valid AcsResult",
                "ok": not violations, "detail": violations})

    bogus = client.call(w.build_request("steps/doesNotExist", {}, session_id=session))
    out.append({"check": "undeclared method is refused (JSON-RPC error)",
                "ok": "error" in bogus})

    out.extend(sig10_checks(client, session, sig_algs, skew, sig_secret, sig_key_id))
    return out


# ---------------------------------------------------------------- Layer B: invariant ----
def scenario_race(client, policy):
    session = w.new_uuid()
    barrier = threading.Barrier(3)

    def worker(i):
        barrier.wait()                       # three concurrent arrivals
        consume(client, session, f"op-{i}", 40, policy, "race")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # confirm whatever was allowed
    for e in [t for t in TRANSCRIPT if t["policy"] == policy and t["scenario"] == "race" and t["executed"]]:
        send_result(client, session, e["operation_id"], "committed")


def scenario_continue(client, policy):
    session = w.new_uuid()
    consume(client, session, "L1", 40, policy, "continue")      # commits
    send_result(client, session, "L1", "unresolved")            # ack lost
    consume(client, session, "L2", 70, policy, "continue")      # a later, unrelated op


def scenario_retry(client, policy):
    session = w.new_uuid()
    consume(client, session, "L1", 40, policy, "retry")         # commits
    send_result(client, session, "L1", "unresolved")            # ack lost
    consume(client, session, "L1", 40, policy, "retry")         # retry the SAME operation


def committed_for(policy, scenario) -> int:
    return sum(t["amount"] for t in TRANSCRIPT
               if t["policy"] == policy and t["scenario"] == scenario and t["executed"])


def executed_count(policy, scenario) -> int:
    return sum(1 for t in TRANSCRIPT
               if t["policy"] == policy and t["scenario"] == scenario and t["executed"])


def dominant_reason(policy, scenario) -> str:
    reasons = [t["reason"] for t in TRANSCRIPT
               if t["policy"] == policy and t["scenario"] == scenario]
    return max(set(reasons), key=reasons.count) if reasons else "none"


def scenario_verdict(policy, scenario, committed) -> str:
    # A scenario is only meaningful if the Guardian actually allowed the legitimate
    # baseline. If it executed nothing (denied/errored everything), the invariant held
    # only vacuously — report N/A with the reason, never a misleading HOLD.
    if executed_count(policy, scenario) == 0:
        return f"N/A ({dominant_reason(policy, scenario)})"
    if scenario == "race":
        return "HOLD" if committed <= LIMIT else "OVERSHOOT"
    if scenario == "continue":
        return "HOLD" if committed <= LIMIT else "LEAK"
    return "HOLD" if committed <= 40 else "DOUBLE-SPEND"


def run_against(client: w.GuardianClient, policy: str,
                sig_secret: bytes | None = None, sig_key_id: str | None = None) -> dict:
    protocol = protocol_checks(client, policy, sig_secret, sig_key_id)
    scenario_race(client, policy)
    scenario_continue(client, policy)
    scenario_retry(client, policy)
    sc = {s: committed_for(policy, s) for s in ("race", "continue", "retry")}
    verdict = {s: scenario_verdict(policy, s, sc[s]) for s in ("race", "continue", "retry")}
    return {"policy": policy, "limit": LIMIT, "protocol": protocol,
            "committed": sc, "verdict": verdict}


def selftest() -> list[dict]:
    """Launch each mock policy in-process and run the full suite against it."""
    import mock_guardians.guardian as g
    scorecards = []
    port = 8830
    for policy in ("stateless", "reserve-only", "holding"):
        srv = g.make_server(policy, port, LIMIT)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        time.sleep(0.2)
        client = w.GuardianClient(f"http://127.0.0.1:{port}/acs")
        scorecards.append(run_against(client, policy, acs_sig.TEST_SECRET, acs_sig.TEST_KEY_ID))
        srv.shutdown()
        port += 1
    return scorecards


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--guardian-url", help="run against an external Guardian at this URL")
    ap.add_argument("--policy", choices=["stateless", "reserve-only", "holding"],
                    help="launch a mock Guardian of this policy and run against it")
    ap.add_argument("--selftest", action="store_true", help="run all mock policies")
    args = ap.parse_args()

    if args.selftest or (not args.guardian_url and not args.policy):
        scorecards = selftest()
        label = "selftest (all mock policies)"
    elif args.guardian_url:
        scorecards = [run_against(w.GuardianClient(args.guardian_url), "external")]
        label = args.guardian_url
    else:
        import mock_guardians.guardian as g
        srv = g.make_server(args.policy, 8829, LIMIT)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        scorecards = [run_against(w.GuardianClient("http://127.0.0.1:8829/acs"), args.policy,
                                  acs_sig.TEST_SECRET, acs_sig.TEST_KEY_ID)]
        srv.shutdown()
        label = f"mock:{args.policy}"

    with open(os.path.join(RES, "transcript.jsonl"), "w") as f:
        for t in TRANSCRIPT:
            f.write(json.dumps(t) + "\n")
    with open(os.path.join(RES, "scorecard.json"), "w") as f:
        json.dump({"target": label, "limit": LIMIT, "scorecards": scorecards}, f, indent=2)

    # manifest for the verifier
    import hashlib
    man = {"limit": LIMIT, "src_sha256": {}}
    for src in ("acs_wire.py", "acs_sig.py", "run_conformance.py", os.path.join("mock_guardians", "guardian.py"),
                os.path.join("mock_guardians", "reconciling.py"), "matrix.py", "comparison.py",
                "preforward.py", "verify.py"):
        p = os.path.join(HERE, src)
        if os.path.exists(p):
            man["src_sha256"][src] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    with open(os.path.join(RES, "manifest.json"), "w") as f:
        json.dump(man, f, indent=2)

    print(f"ACS Guardian conformance — target: {label}\n")
    print("Layer A — protocol conformance"
          + ("  (representative; all mock policies are protocol-conformant by design)"
             if len(scorecards) > 1 else ""))
    for c in scorecards[0]["protocol"]:
        mark = {True: "PASS", False: "FAIL", None: "PENDING"}[c["ok"]]
        extra = f"  ({c['detail']})" if c.get("detail") and mark != "PASS" else ""
        print(f"  [{mark:<7}] {c['check']}{extra}")
    def short(v):  # keep the table aligned; N/A reasons go to a footnote
        return "N/A" if v.startswith("N/A") else v

    print("\nLayer B — invariant conformance (does the Guardian hold the limit of 100?)")
    print(f"  {'policy':<14}{'race 3x40':<18}{'lost-ack continue':<20}{'lost-ack retry':<20}")
    notes = []
    for row in scorecards:
        v, c = row["verdict"], row["committed"]
        race = f"{short(v['race'])} ({c['race']})"
        cont = f"{short(v['continue'])} ({c['continue']})"
        retry = f"{short(v['retry'])} ({c['retry']})"
        print(f"  {row['policy']:<14}{race:<18}{cont:<20}{retry:<20}")
        for scen in ("race", "continue", "retry"):
            if v[scen].startswith("N/A"):
                notes.append(f"  {row['policy']}/{scen}: {v[scen]} — nothing was allowed, so the invariant held only vacuously")
    for n in dict.fromkeys(notes):
        print(n)
    print(f"\nFrozen evidence in {RES}/  —  verify with: python3 verify.py")

    # CI gate: a hard Layer A protocol failure (ok is False) fails the process. A PENDING
    # check (ok is None: system/ping, or §10 when no signature algorithm is advertised) is
    # an open observation, not a failure, so it does not gate.
    hard_fail = [c["check"] for c in scorecards[0]["protocol"] if c["ok"] is False]
    if hard_fail:
        print(f"\nFAIL: {len(hard_fail)} Layer A protocol check(s) failed: {hard_fail}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
