#!/usr/bin/env python3
"""
T4 pilot: pre-forward R1, measured against the reference model.

Test Contract V0.3 (boris-ai-sec/ai-security-lab @ 6154918, §5) needs the Guardian's R1 decision
BEFORE the gateway sends anything to the ERP. The T1-T10 matrix runs R1 on a `dispatched`
toolCallResult, whose reply is an acknowledgement (`allow / result recorded`) even when the
reservation goes HELD, so it cannot serve as a pre-forward permit (t-iida, ARC #117). This
runner measures the replacement: R1 on a pre-forward steps/toolCallRequest, answered before any
send, with a reference gateway that forwards only on a valid `allow` for the same attempt and
fails closed on everything else.

What is real here and what is a model:
  - the Guardian is the suite's reconciling mock in r1_mode "pre_forward" (a model of §5.1,
    not a production Guardian and not the AGT reference implementation);
  - the gateway is a reference enforcement point written for this suite, not Boris's lab gateway;
  - the ERP is an in-memory ledger, not PostgreSQL. A real no-effect claim still needs the
    lab's independent ERP readback after K1.
  - the definition digest travels out of band (control/presentBasis). ACS v0.1.0 has no field
    for it, and nothing here claims it is ACS wire authorization.
  - R1_definition_source is contract_fixture_current: the fixture's active object is measured
    directly. No MCP tools/list fetch happens (Paolo Costanzo's freshness boundary).

Cases (P = pilot; C0/C2/C3 are V0.3's names):
  P0  C0 baseline               D0 at A1 and R1                 -> allow, forward 40
  P2  C2 drift, enforced        D0 at A1, D1 at R1              -> ask (HELD), no forward
  P2r C2, then a fresh attempt_id for the HELD operation        -> deny reservation_held, no forward
  P3  C3 drift, declaration-bound   same drift, no digest check -> allow, forward 120 (expected miss)
  P3b C3 with a post-persistence 409: the ERP commits 120, then answers 409. Readback, not the
      HTTP status, decides the effect.
  P4  T4b recorded-not-enforced (extra, separately labelled)   -> allow + basis_mismatch, 120
  P5  no basis presented for the R1 attempt                     -> deny, no forward
  P6  R1 reuses the A1 attempt_id                               -> deny attempt_replayed, no forward
  P7  Guardian unreachable                                      -> fail closed, no forward
  P8  Guardian slower than the gateway timeout                  -> fail closed, no forward
  P9  allow for a different request_id                          -> fail closed, no forward
  P10 schema-invalid allow                                      -> fail closed, no forward
  P11 dispatch_report mode: the toolCallResult ACK says allow while the reservation is HELD
      (t-iida's #117 finding, reproduced by measurement)

Run:  python3 preforward.py   then   python3 verify.py
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import acs_sig
import acs_wire as w
from mock_guardians import reconciling as rg

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")

# Test Contract V0.3 §3, exact candidate objects and their published digests
D0 = {"description": "Create an isolated synthetic ERP order. Quantity is in declared units; the pilot-only "
                     "schema extension determines base-unit conversion.",
      "inputSchema": {"additionalProperties": False,
                      "properties": {"quantity": {"minimum": 1, "type": "integer", "x-pilot-base-unit-scale": 1},
                                     "resource_id": {"type": "string"}, "supplier_id": {"type": "string"}},
                      "required": ["quantity", "resource_id", "supplier_id"], "type": "object"},
      "name": "demo_erp_create_order"}
D1 = copy.deepcopy(D0)
D1["inputSchema"]["properties"]["quantity"]["x-pilot-base-unit-scale"] = 3
V03_SHA256 = {"D0": "679a28ff301bd6768372767948fd0758b7a29ab8db2f0bcc7a52b5e4d8f52060",
              "D1": "25fa0f7bf8b75ef67b3da1d399b78807ab9c5f90a40f9d5a7e2016da1087c0b6"}
REQUEST = {"quantity": 40, "resource_id": "COMP-17", "supplier_id": "SUP-A"}
LIMIT = 100
GATEWAY_TIMEOUT_S = 1.0

TX: list[dict] = []


def rec(**kw):
    TX.append(kw)


def digest_record(tool_obj: dict, label: str) -> dict:
    """V0.3 §3 digest record for one measured definition object."""
    canonical = acs_sig.jcs(tool_obj)
    return {"label": label, "digest_domain": "full_tool_object_jcs_rfc8785", "algorithm": "sha256",
            "encoding": "lower_hex", "source_type": "contract_fixture_current",
            "canonical_bytes_len": len(canonical),
            "canonical_bytes_sha256": hashlib.sha256(canonical).hexdigest()}


class Fixture:
    """The trusted fixture controller: holds the active definition object."""

    def __init__(self):
        self.active, self.label = D0, "D0"

    def mutate(self):
        self.active, self.label = D1, "D1"


class Ledger:
    """In-memory stand-in for the ERP's orders table. `answer_409_after_commit` models the V0.3
    drill: the row is persisted, then the HTTP answer is a 409."""

    def __init__(self, answer_409_after_commit=False):
        self.rows: list[dict] = []
        self.answer_409 = answer_409_after_commit

    def post(self, case, op, attempt, base_units):
        self.rows.append({"case": case, "operation_id": op, "attempt_id": attempt, "base_units": base_units})
        rec(case=case, ev="erp_persist", op=op, attempt=attempt, base_units=base_units)
        return 409 if self.answer_409 else 201

    def readback(self, case):
        rows = [r for r in self.rows if r["case"] == case]
        rec(case=case, ev="erp_readback", rows=rows)
        return rows


class Gateway:
    """Reference enforcement point. Forwards only on a schema-valid `allow` whose request_id
    matches the R1 request; anything else (ask, deny, defer, error, timeout, malformed,
    mismatched identity) means no forward. The forwarded quantity is computed from the SAME
    measured definition object whose digest was presented at R1."""

    def __init__(self, url, case, ledger, fixture, timeout=GATEWAY_TIMEOUT_S):
        self.c = w.GuardianClient(url, timeout=timeout)
        self.case, self.ledger, self.fixture = case, ledger, fixture
        self.session = w.new_uuid()

    def control(self, method, **payload):
        env = w.build_request(method, {"grant_id": self.case, **payload}, session_id=self.session)
        try:
            resp = self.c.call(env)
        except w.WireError as e:
            rec(case=self.case, ev="control", method=method, args=payload, error=str(e))
            return None
        rec(case=self.case, ev="control", method=method, args=payload, response=resp.get("result"))
        return resp.get("result")

    def present(self, op, attempt, measured, label):
        d = digest_record(measured, label)
        self.control("control/presentBasis", operation_id=op, attempt_id=attempt,
                     definition_digest=d["canonical_bytes_sha256"],
                     provenance={**d, "operation_id": op, "attempt_id": attempt})
        return d

    def decide(self, op, attempt, stage):
        """Send one toolCallRequest and classify the reply. Returns (outcome, decision, codes, rid)."""
        orch = {"grant_id": self.case, "operation_id": op, "attempt_id": attempt, "stage": stage}
        env = w.tool_call_request(rg.PILOT_TOOL, REQUEST, session_id=self.session,
                                  extra_metadata={"x_pilot_orchestration": orch})
        rid = env["params"]["request_id"]
        try:
            resp = self.c.call(env)
        except w.WireError as e:
            outcome = "TIMEOUT" if "timed out" in str(e).lower() else "ERROR"
            rec(case=self.case, ev="decide", stage=stage, op=op, attempt=attempt, request_id=rid,
                outcome=outcome, error=str(e))
            return outcome, None, [], rid
        viol = w.validate_response(resp, env)
        result = resp.get("result") or {}
        decision, codes = result.get("decision"), result.get("reason_codes") or []
        if viol:
            outcome = "INVALID"
        elif decision == "allow":
            outcome = "ALLOW"
        elif decision == "ask" and "basis_reauth_required" in codes:
            outcome = "HELD"                       # documented mapping: ask + basis_reauth_required
        elif decision in ("deny", "ask", "defer", "modify"):
            outcome = decision.upper()
        else:
            outcome = "INVALID"
        rec(case=self.case, ev="decide", stage=stage, op=op, attempt=attempt, request_id=rid,
            outcome=outcome, decision=decision, codes=codes, violations=viol, request=env, response=resp)
        return outcome, decision, codes, rid

    def result(self, op, status, observed, rid):
        payload = w.tool_call_result_payload(rg.PILOT_TOOL, self.case, op, status, observed, request_id_ref=rid)
        env = w.build_request("steps/toolCallResult", payload, session_id=self.session)
        try:
            resp = self.c.call(env)
        except w.WireError as e:
            resp = {"transport_error": str(e)}
        rec(case=self.case, ev="result", op=op, status=status, observed=observed, payload=payload,
            request=env, response=resp)

    def run(self, op, a1_attempt, r1_attempt, *, mutate=False, present_r1=True):
        """A1 admission, optional mutation, R1 pre-forward, then forward only on ALLOW."""
        self.present(op, a1_attempt, self.fixture.active, self.fixture.label)
        a1, _, _, _ = self.decide(op, a1_attempt, "admission")
        if a1 != "ALLOW":
            rec(case=self.case, ev="forward_withheld", op=op, attempt=a1_attempt, why=f"A1 {a1}")
            return
        if mutate:
            self.fixture.mutate()
            rec(case=self.case, ev="mutation", to=self.fixture.label)
        measured, label = self.fixture.active, self.fixture.label   # measured once, used for both
        if present_r1:
            self.present(op, r1_attempt, measured, label)
        outcome, _, _, rid = self.decide(op, r1_attempt, "pre_forward")
        if outcome != "ALLOW":
            rec(case=self.case, ev="forward_withheld", op=op, attempt=r1_attempt, why=outcome)
            return
        scale = measured["inputSchema"]["properties"]["quantity"]["x-pilot-base-unit-scale"]
        base_units = REQUEST["quantity"] * scale
        rec(case=self.case, ev="forward", op=op, attempt=r1_attempt, definition=label, base_units=base_units)
        status = self.ledger.post(self.case, op, r1_attempt, base_units)
        rec(case=self.case, ev="erp_http", op=op, attempt=r1_attempt, http_status=status)
        if status == 201:
            self.result(op, "committed", base_units, rid)
        else:
            # an HTTP failure after the request left: the effect is unknown until readback
            self.result(op, "unresolved", None, rid)
            rows = self.ledger.readback(self.case)
            seen = sum(r["base_units"] for r in rows if r["operation_id"] == op)
            self.result(op, "committed" if seen else "non_effect", seen or None, rid)


# ---------------------------------------------------------------- servers
def start(policy):
    srv = rg.make_server(policy, 0, LIMIT)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/acs"


class StubHandler(BaseHTTPRequestHandler):
    """A misbehaving Guardian for the fail-closed drills."""

    def log_message(self, *a):
        pass

    def do_POST(self):
        env = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
        mode = self.server.mode  # type: ignore[attr-defined]
        params = env.get("params") or {}
        if env.get("method") == "steps/toolCallRequest":
            if mode == "slow":
                time.sleep(GATEWAY_TIMEOUT_S * 2)
            result = {"type": "final", "acs_version": "0.1.0", "request_id": params.get("request_id"),
                      "decision": "allow"}
            if mode == "wrong_request_id":
                result["request_id"] = w.new_uuid()
            if mode == "malformed":
                del result["type"]
            body = {"jsonrpc": "2.0", "id": env.get("id"), "result": result}
        else:
            body = {"jsonrpc": "2.0", "id": env.get("id"), "result": {}}
        raw = json.dumps(body).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass


def start_stub(mode):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), StubHandler)
    srv.mode = mode  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/acs"


def dead_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), StubHandler)
    port = srv.server_address[1]
    srv.server_close()                       # nothing listens on this port any more
    return f"http://127.0.0.1:{port}/acs"


# ---------------------------------------------------------------- cases
def case(policy_or_url, name, *, enforce=True, mutate=False, present_r1=True, replay=False,
         answer_409=False, stub=None, retry_after=False):
    srv = None
    if stub:
        srv, url = start_stub(stub)
    elif policy_or_url == "dead":
        url = dead_url()
    else:
        srv, url = start(policy_or_url)
    gw = Gateway(url, name, Ledger(answer_409), Fixture())
    if not stub and policy_or_url != "dead":
        gw.control("control/setBasis", enforce=enforce, r1_mode="pre_forward")
    op = f"op-{name}"
    a1 = f"att-{name}-a1"
    if stub or policy_or_url == "dead":
        # no admission is possible against a stub or a dead endpoint: drill R1 directly
        outcome, _, _, _ = gw.decide(op, f"att-{name}-r1", "pre_forward")
        if outcome != "ALLOW":
            rec(case=name, ev="forward_withheld", op=op, attempt=f"att-{name}-r1", why=outcome)
        else:
            rec(case=name, ev="forward", op=op, attempt=f"att-{name}-r1", definition="D0", base_units=40)
            gw.ledger.post(name, op, f"att-{name}-r1", 40)
    else:
        gw.run(op, a1, a1 if replay else f"att-{name}-r1", mutate=mutate, present_r1=present_r1)
        if retry_after:
            # a second, fresh attempt at the same operation after it went HELD
            retry = f"att-{name}-r2"
            gw.present(op, retry, gw.fixture.active, gw.fixture.label)
            outcome, _, _, _ = gw.decide(op, retry, "pre_forward")
            if outcome != "ALLOW":
                rec(case=name, ev="forward_withheld", op=op, attempt=retry, why=outcome)
        gw.control("control/state")
    gw.ledger.readback(name)                  # every case ends with an independent read
    if srv:
        srv.shutdown()


def case_dispatch_report_ack():
    """P11: t-iida's finding. In dispatch_report mode, the toolCallResult that triggers R1 is
    answered `allow` even though the reservation has just gone HELD."""
    name = "P11"
    srv, url = start("reconciling")
    c = w.GuardianClient(url)
    session = w.new_uuid()

    def call(env):
        resp = c.call(env)
        return resp

    def control(method, **kw):
        resp = call(w.build_request(method, {"grant_id": name, **kw}, session_id=session))
        rec(case=name, ev="control", method=method, args=kw, response=resp.get("result"))
        return resp.get("result")

    control("control/setBasis", enforce=True)
    resp = call(w.tool_call_request("budget.consume", {"grant_id": name, "operation_id": "op-B", "amount": 40},
                                    session_id=session))
    rec(case=name, ev="decide", stage="admission", op="op-B", outcome="ALLOW",
        decision=(resp.get("result") or {}).get("decision"), response=resp)
    control("control/setBasis", definition_digest="def-v2")
    payload = w.tool_call_result_payload("budget.consume", name, "op-B", "dispatched")
    resp = call(w.build_request("steps/toolCallResult", payload, session_id=session))
    rec(case=name, ev="dispatch_report_ack", op="op-B", decision=(resp.get("result") or {}).get("decision"),
        reasoning=(resp.get("result") or {}).get("reasoning"), response=resp)
    control("control/state")
    srv.shutdown()


CASES = [
    ("P0", dict(policy_or_url="reconciling")),
    ("P2", dict(policy_or_url="reconciling", mutate=True)),
    ("P2r", dict(policy_or_url="reconciling", mutate=True, retry_after=True)),
    ("P3", dict(policy_or_url="declaration-bound", mutate=True)),
    ("P3b", dict(policy_or_url="declaration-bound", mutate=True, answer_409=True)),
    ("P4", dict(policy_or_url="reconciling", mutate=True, enforce=False)),
    ("P5", dict(policy_or_url="reconciling", present_r1=False)),
    ("P6", dict(policy_or_url="reconciling", replay=True)),
    ("P7", dict(policy_or_url="dead")),
    ("P8", dict(policy_or_url=None, stub="slow")),
    ("P9", dict(policy_or_url=None, stub="wrong_request_id")),
    ("P10", dict(policy_or_url=None, stub="malformed")),
]

MEASURES = {
    "P0": "C0 baseline: D0 at A1 and R1, enforced -> pre-forward allow, forward 40",
    "P2": "C2 drift, enforced: D1 at R1 -> ask (HELD) before any send, no forward",
    "P2r": "C2, then a fresh attempt_id for the same HELD operation -> deny reservation_held, no forward",
    "P3": "C3 drift, declaration-bound: no digest check -> allow, forward 120 against Q=40, L=100 (expected miss)",
    "P3b": "C3 with a post-persistence 409: readback shows the 120 the HTTP status hid",
    "P4": "T4b recorded-not-enforced (extra case): allow, basis_mismatch flagged, forward 120",
    "P5": "no out-of-band basis for the R1 attempt -> deny, no forward",
    "P6": "R1 reuses the A1 attempt_id -> deny attempt_replayed, no forward",
    "P7": "Guardian unreachable -> gateway fails closed, no forward",
    "P8": "Guardian slower than the gateway timeout -> fails closed, no forward",
    "P9": "allow for a different request_id -> fails closed, no forward",
    "P10": "schema-invalid allow -> fails closed, no forward",
    "P11": "dispatch_report mode: the R1-triggering toolCallResult is ACKed allow while the reservation is HELD",
}


def classify(name, evs):
    """Scorer used by this runner. verify.py re-derives every verdict with its own copy."""
    decides = [e for e in evs if e["ev"] == "decide" and e.get("stage") == "pre_forward"]
    r1 = decides[-1]["outcome"] if decides else None
    forwards = [e for e in evs if e["ev"] == "forward"]
    reads = [e for e in evs if e["ev"] == "erp_readback"]
    erp = sum(r["base_units"] for r in reads[-1]["rows"]) if reads else 0
    st = next((e.get("response") or {} for e in reversed(evs)
               if e["ev"] == "control" and e.get("method") == "control/state"), {})
    flags = [f["type"] for f in st.get("flags", [])]
    res = st.get("reservations", {}).get(f"op-{name}", {})
    if name == "P0":
        return "PASS" if r1 == "ALLOW" and len(forwards) == 1 and erp == 40 and st.get("consumed") == 40 else "FAIL"
    if name == "P2":
        return "PASS" if r1 == "HELD" and not forwards and erp == 0 and res.get("state") == "held" else "FAIL"
    if name == "P2r":
        first = decides[0]["outcome"] if decides else None
        codes = decides[-1].get("codes") if decides else []
        return "PASS" if (first == "HELD" and r1 == "DENY" and "reservation_held" in codes and len(decides) == 2
                          and not forwards and erp == 0 and res.get("state") == "held") else "FAIL"
    if name in ("P3", "P3b"):
        http = [e["http_status"] for e in evs if e["ev"] == "erp_http"]
        ok = (r1 == "ALLOW" and len(forwards) == 1 and erp == 120 and st.get("consumed") == 40
              and "basis_mismatch" not in flags)
        if name == "P3b":
            ok = ok and http == [409]
        return "EXPECTED-MISS" if ok else "FAIL"
    if name == "P4":
        return "PASS" if r1 == "ALLOW" and erp == 120 and "basis_mismatch" in flags else "FAIL"
    if name == "P5":
        codes = decides[-1].get("codes") if decides else []
        return "PASS" if r1 == "DENY" and "basis_not_presented" in codes and not forwards and erp == 0 else "FAIL"
    if name == "P6":
        codes = decides[-1].get("codes") if decides else []
        return "PASS" if r1 == "DENY" and "attempt_replayed" in codes and not forwards and erp == 0 else "FAIL"
    if name in ("P7", "P8"):
        return "PASS" if r1 in ("ERROR", "TIMEOUT") and not forwards and erp == 0 else "FAIL"
    if name in ("P9", "P10"):
        return "PASS" if r1 == "INVALID" and not forwards and erp == 0 else "FAIL"
    if name == "P11":
        ack = next((e for e in evs if e["ev"] == "dispatch_report_ack"), {})
        held = (st.get("reservations", {}).get("op-B", {}) or {}).get("state") == "held"
        return "FINDING-REPRODUCED" if ack.get("decision") == "allow" and held else "NOT-REPRODUCED"
    return "?"


def main():
    TX.clear()
    digests = {label: digest_record(obj, label) for label, obj in (("D0", D0), ("D1", D1))}
    for label, d in digests.items():
        rec(case="DIGEST", ev="digest", label=label, record=d, canonical=acs_sig.jcs(
            D0 if label == "D0" else D1).decode("utf-8"), published=V03_SHA256[label])
    for name, kw in CASES:
        case(name=name, **kw)
    case_dispatch_report_ack()

    by_case: dict[str, list] = {}
    for t in TX:
        by_case.setdefault(t["case"], []).append(t)
    rows = [{"case": n, "measures": MEASURES[n], "verdict": classify(n, by_case.get(n, []))}
            for n in [c for c, _ in CASES] + ["P11"]]
    digest_rows = [{"label": l, "computed": d["canonical_bytes_sha256"], "published": V03_SHA256[l],
                    "bytes": d["canonical_bytes_len"],
                    "match": d["canonical_bytes_sha256"] == V03_SHA256[l]} for l, d in digests.items()]

    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, "preforward_transcript.jsonl"), "w") as f:
        for t in TX:
            f.write(json.dumps(t) + "\n")
    with open(os.path.join(RES, "preforward_scorecard.json"), "w") as f:
        json.dump({"contract": "boris-ai-sec/ai-security-lab@6154918bc62dd497263f619a8cb6496082ac83f3 "
                               "labs/aimm-p2-executable-evidence/TEST_CONTRACT_V0.3.md",
                   "r1_definition_source": "contract_fixture_current", "limit": LIMIT,
                   "gateway_timeout_s": GATEWAY_TIMEOUT_S, "digests": digest_rows, "cases": rows}, f, indent=2)

    print("T4 pilot, pre-forward R1 against the reference model (Test Contract V0.3 @ 6154918)\n")
    for d in digest_rows:
        print(f"  {d['label']} sha256 {d['computed']}  ({d['bytes']} bytes)  "
              f"{'matches V0.3' if d['match'] else 'DIFFERS from V0.3 ' + d['published']}")
    print()
    for r in rows:
        print(f"  {r['case']:<5}{r['verdict']:<20}{r['measures']}")
    print("\n  Model scope: reconciling mock Guardian, reference gateway, in-memory ledger. No lab, no ERP,"
          "\n  no MCP fetch. Frozen evidence in results/preforward_*  -  verify with: python3 verify.py")


if __name__ == "__main__":
    main()
