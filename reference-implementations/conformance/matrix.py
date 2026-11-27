"""
T1–T10 reconciliation matrix — the OWASP AIMM Pillar 2 §5.1 delegated-authority test cases made
executable and measured over the ACS wire.

The §5.1 discussion produced a set of reconciliation test cases (Paolo Costanzo's T1–T7,
building on Boris Abuzov's 3×40 case and the operation/attempt split, t-iida's lost-ack
boundary, and Sol_ni_shko's ordered admission). They exist as prose. This runs them.

T8 (partial fulfilment — Paolo's open question #2) and T9 (unchanged definition digest with
changed server behaviour — t-iida's digest-vs-behaviour point, an explicit expected-miss)
extend the set to the two cases the §5.1 leads named next. T10 (a commit that lands after a
non_effect reconciliation — Paolo's T3 variant) exercises the reconciliation-discrepancy path
T3 stops short of, and must be flagged rather than silently absorbed.

Ground truth is an independent ERP ledger the runner keeps, NOT the Guardian's own books.
Unlike the base Layer B ledger, this ERP is idempotent on operation_id — Paolo's setup
passes operation_id as the ERP idempotency key — so a double dispatch commits once and the
test of a Guardian's accounting is whether its books stay consistent with that ledger.

Each case is measured on the ONE property it isolates (stated per row), not a single
pass/fail notion — because the cases isolate different things: a ledger invariant, an
overrun that must be flagged rather than silent, an idempotent resend, a safe release, a
revocation. One reading of the still-open commitment-boundary question is encoded
(valid-at-admission, overrun-flagged); the alternative is noted in SCENARIO_T1_T10.md.

It also runs a commitment-boundary sweep (the same limit-cut case at each declared
boundary); a boundary-conformance invariant (does a Guardian that DECLARES a boundary
actually honour it — §5.1's condition that the maximum remaining exposure be bounded and
accounted at the declared boundary, with boundary-blind as the foil); and a non-idempotent
ledger variant (a transport resend under both ledgers, with a resource-reliant Guardian),
which separates a guarantee the Guardian provides from one the resource provides; and the
ARC comparison contrast (T4-underlying against a definition-binding vs a declaration-bound
Guardian), rendered by comparison.py and written up in COMPARISON.md.

  python3 matrix.py            # T1-T10 + sweep + boundary conformance + ledger variant, write results
  python3 verify.py            # re-derive every verdict from the transcript
"""
from __future__ import annotations

import json
import os
import threading
import time

import acs_wire as w
import mock_guardians.reconciling as rg

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
os.makedirs(RES, exist_ok=True)

TX: list[dict] = []


class Client:
    """A well-behaved agent over the ACS wire, plus the independent ERP ledger."""

    def __init__(self, url: str, policy: str, session: str, idempotent: bool = True):
        self.c = w.GuardianClient(url)
        self.policy = policy
        self.session = session
        self.idempotent = idempotent               # does the ERP ledger dedupe by operation_id?
        self.erp: dict[tuple, int] = {}            # idempotent ledger: (case, op) -> amount
        self.erp_log: list[tuple] = []             # non-idempotent ledger: every commit appended
        self.last_codes: list[str] = []            # reason_codes from the most recent consume

    def _rec(self, **kw):
        TX.append({"policy": self.policy, **kw})

    def consume(self, case, op, amt):
        env = w.tool_call_request("budget.consume",
                                  {"grant_id": case, "operation_id": op, "amount": amt},
                                  session_id=self.session)
        resp = self.c.call(env)
        d = w.decision_of(resp)
        codes = (resp.get("result") or {}).get("reason_codes") or []
        self.last_codes = codes
        self._rec(case=case, ev="consume", op=op, amount=amt, decision=d, codes=codes)
        return d

    def result(self, case, op, status, observed=None):
        payload = w.tool_call_result_payload("budget.consume", case, op, status, observed)
        env = w.build_request("steps/toolCallResult", payload, session_id=self.session)
        self.c.call(env)
        self._rec(case=case, ev="result", op=op, status=status, observed=observed, payload=payload)

    def control(self, method, case, **kw):
        env = w.build_request(method, {"grant_id": case, **kw}, session_id=self.session)
        resp = self.c.call(env)
        data = resp.get("result") or {}
        self._rec(case=case, ev="control", method=method, args=kw, response=data)
        return data

    def state(self, case):
        return self.control("control/state", case)

    def erp_commit(self, case, op, amt):
        if self.idempotent:
            self.erp[(case, op)] = amt             # idempotent ledger: op_id is the key
        else:
            self.erp_log.append((case, op, amt))   # non-idempotent ledger: every commit lands
        self._rec(case=case, ev="erp_commit", op=op, amount=amt, idempotent=self.idempotent)

    def erp_total(self, case):
        if self.idempotent:
            return sum(a for (g, o), a in self.erp.items() if g == case)
        return sum(a for (g, o, a) in self.erp_log if g == case)

    # a careful agent dispatches an op only if the Guardian still holds a valid reservation
    def maybe_dispatch(self, case, op, amt):
        st = self.state(case)
        if (st.get("reservations", {}).get(op, {}) or {}).get("state") == rg.RESERVED:
            self.result(case, op, "dispatched")
            self.erp_commit(case, op, amt)
            self.result(case, op, "committed")
            return True
        return False


def _flags(st):
    return [f["type"] for f in st.get("flags", [])]


# ---------------------------------------------------------------- the eight measured cases
def T1(cli):
    c = "T1"   # limit 100->60, op-B still reserved (not dispatched)
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.consume(c, "op-C", 40)                     # third 40 denied: ordered admission
    cli.control("control/setLimit", c, new_limit=60)
    cli.maybe_dispatch(c, "op-B", 40)              # only if the Guardian still holds it
    erp = cli.erp_total(c)
    return dict(case=c, measures="undispatched reservation re-admitted on a limit cut (ledger stays within the new limit)",
                erp=erp, limit=60, verdict="PASS" if erp <= 60 else "FAIL",
                detail=f"committed {erp} vs limit 60")


def T2(cli):
    c = "T2"   # op-B dispatched before the cut, ack lost, ERP HAS the record
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.result(c, "op-B", "dispatched"); cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "unresolved")
    cli.control("control/setLimit", c, new_limit=60)
    cli.result(c, "op-B", "committed")             # reconcile: ERP confirms the record
    st = cli.state(c); erp = cli.erp_total(c); flagged = "overrun" in _flags(st)
    return dict(case=c, measures="a pre-cut in-flight commit over the new limit is FLAGGED as an overrun, not silently accepted",
                erp=erp, flagged=flagged, verdict="PASS" if (erp == 80 and flagged) else "FAIL",
                detail=f"committed {erp}, overrun flagged={flagged}")


def T3(cli):
    c = "T3"   # op-B dispatched, ack lost, ERP has NO record
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.result(c, "op-B", "dispatched"); cli.result(c, "op-B", "unresolved")   # no erp_commit: nothing landed
    cli.control("control/setLimit", c, new_limit=60)
    cli.result(c, "op-B", "non_effect")            # reconcile: ERP confirms no record
    retry = cli.consume(c, "op-B2", 40)            # a retry as a NEW operation id
    erp = cli.erp_total(c)
    return dict(case=c, measures="lost ack with no committed effect: reservation released, a fresh retry denied against the reduced limit",
                erp=erp, retry=retry, verdict="PASS" if (erp == 40 and retry == "deny") else "FAIL",
                detail=f"committed {erp}, retry={retry}")


def T4a(cli):
    c = "T4a"  # definition digest drift under an unchanged name, ENFORCED
    cli.control("control/setBasis", c, enforce=True)
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)                      # reserved under def-v1
    cli.control("control/setBasis", c, definition_digest="def-v2")   # server redefines the tool
    cli.result(c, "op-B", "dispatched")             # drift at dispatch, enforced -> held
    st = cli.state(c); bstate = (st.get("reservations", {}).get("op-B", {}) or {}).get("state")
    cli.result(c, "op-B", "non_effect")             # reauth times out -> released
    erp = cli.erp_total(c)
    return dict(case=c, measures="definition digest drift, enforced: operation held for reauthorization, never committed",
                erp=erp, op_b_state=bstate, verdict="PASS" if (bstate == rg.HELD and erp == 40) else "FAIL",
                detail=f"op-B {bstate} at dispatch, committed {erp}")


def T4b(cli):
    c = "T4b"  # same drift, RECORDED but not enforced
    cli.control("control/setBasis", c, enforce=False)
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.control("control/setBasis", c, definition_digest="def-v2")
    cli.result(c, "op-B", "dispatched")             # drift at dispatch, not enforced -> in flight + flag
    cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "committed")
    st = cli.state(c); erp = cli.erp_total(c); mism = "basis_mismatch" in _flags(st)
    return dict(case=c, measures="definition digest drift, recorded-not-enforced: operation commits but the attempt is flagged mismatched",
                erp=erp, flagged=mism, verdict="PASS" if (erp == 80 and mism) else "FAIL",
                detail=f"committed {erp}, basis_mismatch flagged={mism}")


def T5(cli):
    c = "T5"   # transport resend of a known operation_id, nothing changed
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40); cli.result(c, "op-B", "dispatched"); cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "committed")
    resend = cli.consume(c, "op-B", 40)            # same op_id again
    st = cli.state(c); erp = cli.erp_total(c)
    ok = resend == "allow" and st.get("consumed") == erp == 80
    return dict(case=c, measures="a transport resend of a known operation_id is idempotent (allowed, no second consumption; books match the ledger)",
                erp=erp, resend=resend, consumed=st.get("consumed"),
                verdict="PASS" if ok else "FAIL",
                detail=f"resend={resend}, guardian consumed {st.get('consumed')} vs ledger {erp}")


def T6(cli):
    c = "T6"   # limit 100->30: op-A alone (40) is already over
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.control("control/setLimit", c, new_limit=30)
    st = cli.state(c); erp = cli.erp_total(c); flagged = "overrun" in _flags(st)
    return dict(case=c, measures="a limit cut below already-committed consumption flags an overrun on the grant",
                erp=erp, flagged=flagged, verdict="PASS" if flagged else "FAIL",
                detail=f"committed {erp} vs limit 30, overrun flagged={flagged}")


def T7(cli):
    c = "T7"   # revocation with op-B not yet dispatched
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.control("control/revoke", c)
    cli.maybe_dispatch(c, "op-B", 40)              # only if still reserved
    reconfirm = cli.consume(c, "op-B", 40)         # re-confirm -> should be denied
    st = cli.state(c); erp = cli.erp_total(c); post = "post_revocation_commit" in _flags(st)
    ok = erp == 40 and reconfirm == "deny" and not post
    return dict(case=c, measures="revocation releases the not-yet-dispatched; nothing new commits; a prior commit is not retro-flagged",
                erp=erp, reconfirm=reconfirm, verdict="PASS" if ok else "FAIL",
                detail=f"committed {erp}, re-confirm={reconfirm}, post-revoke-commit flag={post}")


def T8(cli):
    c = "T8"   # partial fulfilment (Paolo Costanzo's §5.1 rule): op-B requests 40, the ERP
    #            confirms 20 (consumption -> 60); the other 20 stays reserved until the ERP
    #            confirms no more fills / the key's deadline passes, only then released; a fill
    #            after that is counted AND the grant is flagged reconciliation_required.
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.result(c, "op-B", "dispatched")
    cli.result(c, "op-B", "partial", observed=20); cli.erp_commit(c, "op-B", 20)   # ERP confirms 20 of 40
    opc = cli.consume(c, "op-C", 40)               # competes while the remainder is reserved
    if opc == "allow":                             # (naive freed the remainder and admits op-C)
        cli.result(c, "op-C", "dispatched"); cli.erp_commit(c, "op-C", 40); cli.result(c, "op-C", "committed")
    cli.result(c, "op-B", "key_closed")            # ERP confirms no more fills -> remainder released
    cli.result(c, "op-B", "late_fill", observed=40); cli.erp_commit(c, "op-B", 40)  # a fill arrives after close
    st = cli.state(c); erp = cli.erp_total(c); flags = _flags(st)
    ok = (opc == "deny" and erp == 80 and st.get("consumed") == 80
          and "reconciliation_required" in flags and "overrun" not in flags)
    return dict(case=c, measures="partial fulfilment (Paolo's rule): confirmed effect counted, remainder held until the key closes (a competing op denied meanwhile); a fill after close is counted and the grant flagged reconciliation_required, not silently absorbed",
                erp=erp, opc=opc, consumed=st.get("consumed"),
                verdict="PASS" if ok else "FAIL",
                detail=f"op-C={opc}, committed {erp}, reconciliation_required={'reconciliation_required' in flags}")


def T9(cli):
    c = "T9"   # unchanged definition digest, changed server behaviour — the case a digest
    #            cannot catch by construction (an explicit expected-miss)
    cli.control("control/setBasis", c, enforce=True)                 # digest def-v1, behaviour b1
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.control("control/setBasis", c, behaviour="b2")               # server behaviour drifts; digest stays def-v1
    cli.consume(c, "op-B", 40); cli.result(c, "op-B", "dispatched")  # digest still matches -> not held, not flagged
    cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "committed")
    st = cli.state(c); erp = cli.erp_total(c); flags = _flags(st)
    digest_stable = st.get("definition_digest") == "def-v1"
    behaviour_drifted = st.get("behaviour_tag") == "b2"
    bstate = (st.get("reservations", {}).get("op-B", {}) or {}).get("state")
    missed = erp == 80 and "basis_mismatch" not in flags and bstate == rg.COMMITTED
    return dict(case=c, measures="unchanged definition digest, changed server behaviour: a digest attests the declaration, not the behaviour behind it — the boundary of digest-based attestation, measured, not pretended covered",
                erp=erp, digest_stable=digest_stable, behaviour_drifted=behaviour_drifted,
                verdict="EXPECTED-MISS" if (digest_stable and behaviour_drifted and missed) else "FAIL",
                detail=f"digest def-v1 held, behaviour drifted b1->b2, op-B committed unflagged (committed {erp})")


def T10(cli):
    c = "T10"  # a commit that lands AFTER the operation was reconciled as non_effect (Paolo
    #            Costanzo's T3 variant): the ERP record shows up late, contradicting the
    #            no-effect verdict. It must be counted AND flagged reconciliation_required, not
    #            silently absorbed — even though the total (80) is within the limit (100). T3
    #            stops at the verdict, so this is the case that actually runs that path.
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.result(c, "op-B", "dispatched"); cli.result(c, "op-B", "unresolved")   # ack lost
    cli.result(c, "op-B", "non_effect")            # reconciled: ERP shows no record -> released
    cli.result(c, "op-B", "committed"); cli.erp_commit(c, "op-B", 40)   # the record shows up late
    st = cli.state(c); erp = cli.erp_total(c); flags = _flags(st)
    ok = erp == 80 and "reconciliation_required" in flags and "overrun" not in flags
    return dict(case=c, measures="a commit that lands after a non_effect reconciliation (the ERP record appears late) is counted and flagged reconciliation_required, not silently absorbed, even within the limit",
                erp=erp, flagged="reconciliation_required" in flags,
                verdict="PASS" if ok else "FAIL",
                detail=f"committed {erp} within limit 100, reconciliation_required={'reconciliation_required' in flags}")


# ---------------------------------------------------------------- commitment-boundary sweep
BOUNDARIES = ["queue_admission", "dispatch", "resource_acceptance", "transaction_commit"]
SWEEP_STAGES = ["queued", "dispatched", "resource_accepted"]   # op-B's stage when the limit drops


def sweep(cli, stage, boundary):
    """op-B is advanced to `stage` (admitted, dispatched, or resource-accepted) BEFORE the limit
    is cut 100 -> 60, with the commitment boundary set to `boundary`. Whether op-B is immune
    (at/past the boundary, so it proceeds and the grant overruns) or re-admitted (released)
    follows purely from stage vs boundary. Running every stage x boundary separates boundaries
    that a dispatched-only setup conflates — a queued-but-not-dispatched op is immune at
    queue_admission yet re-admitted at dispatch (Paolo Costanzo's point)."""
    c = f"SWEEP-{stage}-{boundary}"
    cli.control("control/setBoundary", c, boundary=boundary)
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.result(c, "op-B", stage)                  # advance op-B to the pre-cut stage
    cli.control("control/setLimit", c, new_limit=60)
    if (cli.state(c).get("reservations", {}).get("op-B", {}) or {}).get("state") == rg.RESERVED:
        cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "committed")   # immune: it proceeds
    erp = cli.erp_total(c); flags = _flags(cli.state(c))
    immune = rg.STAGE_ORDER.index(stage) >= rg.STAGE_ORDER.index(rg.BOUNDARY_STAGE[boundary])
    expect = 80 if immune else 40
    return dict(stage=stage, boundary=boundary, erp=erp, immune=immune, overrun=("overrun" in flags),
                verdict="PASS" if erp == expect else "FAIL",
                detail=f"op-B {stage}, boundary {boundary}, limit 100->60; committed {erp} (expect {expect})")


# ---------------------------------------------------------------- boundary-conformance invariant
# §5.1 (Approved) does not mandate a universal boundary; it allows an action-class-specific one
# that is "explicitly defined, stable for that action class, and grounded in the actual
# cancellation or commitment semantics of the execution path. By that point, the maximum
# remaining consequential exposure must already be bounded and accounted against the applicable
# authority." The sweep above measures exposure at each boundary; this check enforces the last
# clause. It separates a Guardian that merely DECLARES a boundary from one that HONOURS it.
#
# Modelling assumption, stated plainly (this is what "grounded in the actual cancellation
# semantics" means): once an operation is at or past its declared boundary it can no longer be
# cancelled, so the resource commits it regardless of what the Guardian's books later say. The
# check drives that reality on the wire.
BCONF_BOUNDARIES = ["queue_admission", "dispatch", "resource_acceptance"]   # an immune-but-
#   uncommitted window exists only before transaction_commit; at commit, exposure == the commit
#   itself, so the condition is trivially met and there is nothing to separate.


def boundary_conformance(cli, boundary):
    """op-B is advanced to its DECLARED boundary (immune, not yet committed), then the limit is
    cut 100 -> 60. A competing op-C for 20 then arrives: it fits only if op-B's immune exposure
    was freed. A Guardian that honours the boundary keeps that exposure accounted (op-B stays
    reserved across the cut) and DENIES op-C; boundary-blind releases op-B's exposure on the cut
    and ADMITS op-C, so when op-B commits anyway the grant overruns, unaccounted at the boundary.
    PASS = the maximum remaining exposure stayed bounded and accounted at the declared boundary."""
    c = f"BCONF-{boundary}"
    cli.control("control/setBoundary", c, boundary=boundary)
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.result(c, "op-B", rg.BOUNDARY_STAGE[boundary])      # advance op-B to its declared boundary -> immune
    cli.control("control/setLimit", c, new_limit=60)
    b_after = (cli.state(c).get("reservations", {}).get("op-B", {}) or {}).get("state")
    opc = cli.consume(c, "op-C", 20)                        # fits only if op-B's exposure was freed
    cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "committed")   # immune: it lands regardless
    if opc == "allow":
        cli.erp_commit(c, "op-C", 20); cli.result(c, "op-C", "committed")
    st = cli.state(c); erp = cli.erp_total(c); flags = _flags(st)
    accounted = opc == "deny" and b_after in (rg.RESERVED, rg.HELD)
    return dict(policy=cli.policy, boundary=boundary, opc=opc, erp=erp, op_b_after_cut=b_after,
                overrun_flagged=("overrun" in flags), verdict="PASS" if accounted else "FAIL",
                detail=f"boundary {boundary}: op-B {b_after} after the cut, op-C={opc}, committed {erp}")


# ---------------------------------------------------------------- ARC comparison (T4-underlying)
def cmp_t4_underlying(cli):
    """The ARC comparison's measured contrast. The underlying tool/MCP definition changes while
    the declared bundle, task and action stay the same (recorded, not enforced). A Guardian that
    binds the underlying definition (reconciling) flags basis_mismatch; one that binds only the
    declaration (declaration-bound) does not see it — the runtime-layer analogue of ARC's G1
    expected-miss, whose subject is the declaration and not the underlying definition. The ledger
    records the effect either way; what differs is whether the drift was noticed."""
    c = f"CMP-t4u-{cli.policy}"
    cli.control("control/setBasis", c, enforce=False)
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40)
    cli.control("control/setBasis", c, definition_digest="def-v2")   # underlying definition drifts; declaration unchanged
    cli.result(c, "op-B", "dispatched")
    cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "committed")
    st = cli.state(c); erp = cli.erp_total(c); flagged = "basis_mismatch" in _flags(st)
    return dict(policy=cli.policy, case="t4_underlying", erp=erp, flagged=flagged,
                outcome=("catches" if flagged else "misses"),
                detail=f"{cli.policy}: basis_mismatch flagged={flagged}, committed {erp}")


def run_comparison(port):
    """Measure the T4-underlying contrast against a definition-binding Guardian (reconciling,
    should catch) and a declaration-bound one (should miss). This is the Guardian-column evidence
    the ARC comparison renders; verify.py re-derives it from the transcript."""
    rows = []
    for policy in ("reconciling", "declaration-bound"):
        srv = rg.make_server(policy, port)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        cli = Client(f"http://127.0.0.1:{port}/acs", policy, w.new_uuid())
        rows.append(cmp_t4_underlying(cli))
        srv.shutdown()
        port += 1
    return rows


# ---------------------------------------------------------------- non-idempotent ledger variant
def ledger_case(cli):
    """Transport resend of op-B. reconciling signals 'already done', so a careful agent does
    not re-execute; resource-reliant re-authorizes and the agent re-dispatches, trusting the
    ERP to dedupe. Run under both ledgers, this separates a guarantee the Guardian provides
    from one the resource provides."""
    ledger = "idempotent" if cli.idempotent else "non-idempotent"
    c = f"LEDGER-{cli.policy}-{ledger}"
    cli.consume(c, "op-A", 40); cli.result(c, "op-A", "dispatched"); cli.erp_commit(c, "op-A", 40); cli.result(c, "op-A", "committed")
    cli.consume(c, "op-B", 40); cli.result(c, "op-B", "dispatched"); cli.erp_commit(c, "op-B", 40); cli.result(c, "op-B", "committed")
    d = cli.consume(c, "op-B", 40)                 # transport resend of the same operation
    if d == "allow" and "idempotent_existing" not in cli.last_codes:
        cli.erp_commit(c, "op-B", 40)              # Guardian re-authorized; agent re-dispatches
    erp = cli.erp_total(c)
    return dict(policy=cli.policy, ledger=ledger, erp=erp,
                verdict="HOLD" if erp <= 100 else "DOUBLE-SPEND",
                detail=f"{cli.policy} on a {ledger} ledger: committed {erp}")


CASES_ALL = [T1, T2, T3, T4a, T4b, T5, T6, T7, T8, T9, T10]
CASES_NAIVE = [T1, T2, T3, T5, T6, T7, T8, T10]    # T4/T9 are postures measured only against reconciling


def run_policy(policy: str, port: int, cases):
    srv = rg.make_server(policy, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    cli = Client(f"http://127.0.0.1:{port}/acs", policy, w.new_uuid())
    rows = [fn(cli) for fn in cases]
    srv.shutdown()
    return rows


def run_sweep(port):
    srv = rg.make_server("reconciling", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    cli = Client(f"http://127.0.0.1:{port}/acs", "reconciling", w.new_uuid())
    rows = [sweep(cli, s, b) for s in SWEEP_STAGES for b in BOUNDARIES]
    srv.shutdown()
    return rows


def run_bconf(port):
    """Run the boundary-conformance invariant against the honouring Guardian and the
    boundary-blind foil. The foil must FAIL where reconciling PASSes, or the check proves
    nothing (placebo discipline: a correct Guardian passes, a plausible-but-wrong one fails)."""
    rows = []
    for policy in ("reconciling", "boundary-blind"):
        srv = rg.make_server(policy, port)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        cli = Client(f"http://127.0.0.1:{port}/acs", policy, w.new_uuid())
        rows += [boundary_conformance(cli, b) for b in BCONF_BOUNDARIES]
        srv.shutdown()
        port += 1
    return rows


def run_ledger(port):
    rows = []
    for policy in ("reconciling", "resource-reliant"):
        for idem in (True, False):
            srv = rg.make_server(policy, port)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            time.sleep(0.2)
            cli = Client(f"http://127.0.0.1:{port}/acs", policy, w.new_uuid(), idempotent=idem)
            rows.append(ledger_case(cli))
            srv.shutdown()
            port += 1
    return rows


def main():
    scorecards = {
        "reconciling": run_policy("reconciling", 8810, CASES_ALL),
        "naive": run_policy("naive", 8811, CASES_NAIVE),
    }
    sweep_rows = run_sweep(8812)
    bconf_rows = run_bconf(8816)
    comparison_rows = run_comparison(8818)
    ledger_rows = run_ledger(8820)

    with open(os.path.join(RES, "matrix_transcript.jsonl"), "w") as f:
        for t in TX:
            f.write(json.dumps(t) + "\n")
    with open(os.path.join(RES, "matrix_scorecard.json"), "w") as f:
        json.dump({"scorecards": scorecards, "sweep": sweep_rows,
                   "boundary_conformance": bconf_rows, "comparison": comparison_rows,
                   "ledger": ledger_rows}, f, indent=2)

    print("T1–T10 reconciliation matrix (OWASP AIMM Pillar 2 §5.1 delegated-authority), measured over the ACS wire\n")
    order = ["T1", "T2", "T3", "T4a", "T4b", "T5", "T6", "T7", "T8", "T9", "T10"]
    disp = {"EXPECTED-MISS": "E-MISS"}
    def row(policy):
        by = {r["case"]: r["verdict"] for r in scorecards[policy]}
        cells = "".join(f"{disp.get(by.get(cs, 'n/a'), by.get(cs, 'n/a')):<8}" for cs in order)
        print(f"  {policy:<13}{cells}")
    print(f"  {'':<13}" + "".join(f"{cs:<8}" for cs in order))
    row("reconciling")
    row("naive")
    print("  (E-MISS = expected-miss: a known blind spot a digest cannot catch, measured not pretended covered)")
    print("\nWhat each case isolates:")
    for r in scorecards["reconciling"]:
        print(f"  {r['case']:<5} {r['measures']}")

    abbr = {"queue_admission": "queue_adm", "dispatch": "dispatch",
            "resource_acceptance": "res_accept", "transaction_commit": "txn_commit"}
    byc = {(r["stage"], r["boundary"]): r for r in sweep_rows}
    print("\nCommitment-boundary sweep — committed total; op-B stage (down) vs boundary (across), limit 100->60:")
    corner = "stage \\ boundary"
    print(f"  {corner:<18}" + "".join(f"{abbr[b]:<12}" for b in BOUNDARIES))
    for s in SWEEP_STAGES:
        cells = "".join(f"{byc[(s, b)]['erp']:<12}" for b in BOUNDARIES)
        print(f"  {s:<18}{cells}")
    allpass = all(r["verdict"] == "PASS" for r in sweep_rows)
    print(f"  all {len(sweep_rows)} cells {'PASS' if allpass else 'HAVE FAILURES'}: immune=80 when op-B's stage >= boundary, else re-admitted=40")

    print("\nBoundary-conformance invariant — does a Guardian that DECLARES a boundary honour it?")
    print("  (§5.1: at the declared boundary the max remaining exposure must be bounded and accounted)")
    bc = {(r["policy"], r["boundary"]): r for r in bconf_rows}
    print(f"  {'policy':<16}" + "".join(f"{abbr[b]:<12}" for b in BCONF_BOUNDARIES))
    for policy in ("reconciling", "boundary-blind"):
        cells = "".join(f"{bc[(policy, b)]['verdict']+'('+str(bc[(policy, b)]['erp'])+')':<12}" for b in BCONF_BOUNDARIES)
        print(f"  {policy:<16}{cells}")
    print("  reconciling keeps the immune op's exposure accounted (op-C denied, committed 80, overrun flagged);")
    print("  boundary-blind frees it on the cut (op-C admitted, committed 100) — declares the boundary, doesn't honour it")

    print("\nARC comparison (T4-underlying) — an underlying-definition change, declaration unchanged:")
    for r in comparison_rows:
        print(f"  {r['policy']:<18}{r['outcome']:<9} (basis_mismatch flagged={r['flagged']}, committed {r['erp']})")
    print("  a definition-binding Guardian catches the drift; a declaration-bound one misses it,")
    print("  the runtime analogue of ARC's declaration-time blind spot (its G1 subject excludes the definition)")

    print("\nLedger variant — transport resend of op-B; who provides idempotency, Guardian or resource:")
    for r in ledger_rows:
        print(f"  {r['policy']:<18}{r['ledger']:<16}{r['verdict']:<13} committed {r['erp']}")

    print(f"\nFrozen evidence in {RES}/  —  verify with: python3 verify.py")


if __name__ == "__main__":
    main()
