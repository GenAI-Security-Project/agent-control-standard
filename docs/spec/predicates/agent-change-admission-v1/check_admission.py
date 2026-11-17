#!/usr/bin/env python3
"""Conformance checker for the agent-change-admission v1 predicate family (rev v1.1).

v1.1 closes defects found by the external AI review (09-外部实现实测/):
  - role binding: only the role block implied by predicateType may carry the signing key
  - non-empty, algorithm-tagged digests only
  - witness key must be registry-pinned, not self-declared
  - outcome must be a record whose digest is recomputed
  - one ledger schema; fail closed when verifier context is incomplete
  - replay on any reuse of (session_id, request_id)

Usage: python3 check_admission.py [--emit-examples]
"""
import json, hashlib, os, sys, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROLE = {
    "https://lgd.dev/attestation/agent-change-admission/v1": ("admission", "guardian", "self"),
    "https://lgd.dev/attestation/agent-change-witness/v1": ("witness", "witness", "peer"),
    "https://lgd.dev/attestation/agent-change-anchor/v1": ("anchor", "anchor", "external"),
}
ROLES = ("guardian", "witness", "anchor")


def jcs(o):
    if o is None or isinstance(o, bool):
        return json.dumps(o)
    if isinstance(o, int):
        return str(o)
    if isinstance(o, str):
        return json.dumps(o, ensure_ascii=False)
    if isinstance(o, list):
        return "[" + ",".join(jcs(x) for x in o) + "]"
    if isinstance(o, dict):
        return "{" + ",".join(jcs(k) + ":" + jcs(v) for k, v in sorted(o.items())) + "}"


def digest(o):
    d = o if isinstance(o, bytes) else jcs(o).encode("utf-8")
    return {"sha256": hashlib.sha256(d).hexdigest()}


def stmt_digest(s):
    """Normative statement digest: JCS over the statement with the detached signature removed."""
    return digest(jcs({k: v for k, v in s.items() if k != "_sig"}))


def good_digest(d):
    return isinstance(d, dict) and isinstance(d.get("sha256"), str) and len(d["sha256"]) == 64 \
        and all(c in "0123456789abcdef" for c in d["sha256"])


def verify(s, ctx):
    codes = []
    pt = s.get("predicateType")
    if pt not in ROLE:
        return {"ok": False, "scope": None, "codes": ["unknown_predicate"], "kind": None}
    kind, role, implied_scope = ROLE[pt]
    p = s.get("predicate") or {}

    # AC-0a role binding
    for r in ROLES:
        if r != role and p.get(r):
            codes.append("foreign_role_block")
    rb = p.get(role)
    if not isinstance(rb, dict) or not rb.get("key_id"):
        codes.append("role_missing")
        key_id = None
    else:
        key_id = rb["key_id"]

    # AC-0b signature scope
    sig = s.get("_sig")
    if not sig:
        codes.append("unsigned")
    elif key_id:
        pub = (ctx.get("keys") or {}).get(key_id)
        if pub is None:
            codes.append("unknown_key")
        else:
            try:
                pub.verify(base64.b64decode(sig), stmt_digest(s)["sha256"].encode())
            except Exception:
                codes.append("bad_signature")

    # AC-0c scope must equal the type-implied scope
    if p.get("witness_scope") != implied_scope:
        codes.append("scope_mismatch")

    change = p.get("change") or {}
    payload = change.get("payload_digest")
    if kind in ("admission", "witness"):
        if not good_digest(payload):
            codes.append("invalid_digest")
        subs = s.get("subject") or []
        if not (isinstance(subs, list) and len(subs) >= 1 and any(x.get("digest") == payload for x in subs)):
            codes.append("subject_mismatch")
        if change.get("canonicalization") != "jcs-rfc8785":
            codes.append("non_canonical_payload")
        # AC-2 outcome record
        out_rec = p.get("outcome")
        out_d = p.get("outcome_digest")
        if not isinstance(out_rec, dict) or not good_digest(out_d):
            codes.append("outcome_mismatch")
        elif digest(out_rec) != out_d or out_d == payload:
            codes.append("outcome_mismatch")

    # AC-3 witness binding
    if kind == "witness":
        adm_d = ctx.get("admission_statement_digest")
        adm_ctx = ctx.get("admission_context")
        if not adm_d:
            codes.append("verifier_context_incomplete")
        obs = (p.get("observed_admission") or {}).get("sha256")
        if not obs or obs != adm_d:
            codes.append("witness_not_bound")
        wc = p.get("context") or {}
        if not isinstance(adm_ctx, dict):
            codes.append("verifier_context_incomplete")
        elif (wc.get("session_id"), wc.get("request_id")) != (adm_ctx.get("session_id"), adm_ctx.get("request_id")):
            codes.append("witness_not_bound")
        led = ctx.get("ledger") or {}
        key = (wc.get("session_id"), wc.get("request_id"))
        if key in led and led[key] != stmt_digest(s)["sha256"]:
            codes.append("duplicate_vector")

    # AC-4 lift
    if kind == "witness":
        w = rb
        obs_agent = (ctx.get("observed") or {})
        if w.get("key_id") == obs_agent.get("key_id"):
            codes.append("witness_control_overlap")
        if not w.get("control_domain"):
            codes.append("witness_control_overlap")
        elif w.get("control_domain") == obs_agent.get("control_domain"):
            codes.append("witness_control_overlap")
        pin = w.get("key_pin") or {}
        reg = (ctx.get("registry") or {}).get(w.get("key_id"))
        if not (pin.get("registry_uri") and pin.get("key_fingerprint") and reg):
            codes.append("witness_key_unpinned")
        elif reg.get("fingerprint") != pin["key_fingerprint"] or reg.get("writable_by_observed"):
            codes.append("witness_key_unpinned")

    if kind == "anchor":
        a = rb
        pin = a.get("pin") or {}
        reg = (ctx.get("registry") or {}).get(a.get("key_id"))
        anchored_at = p.get("anchored_at")
        if not (pin.get("registry_uri") and pin.get("key_fingerprint") and pin.get("pinned_at") and reg):
            codes.append("anchor_key_unpinned")
        elif reg.get("fingerprint") != pin["key_fingerprint"]:
            codes.append("anchor_key_unpinned")
        elif reg.get("writable_by_observed"):
            codes.append("anchor_not_independent")
        elif anchored_at and pin["pinned_at"] > anchored_at:
            codes.append("anchor_key_unpinned")
        if p.get("timestamp_only"):
            codes.append("timestamp_not_lift")
        indep = p.get("independent_of") or []
        obs_agent = (ctx.get("observed") or {})
        if obs_agent.get("agent_id") not in indep and obs_agent.get("org") not in indep:
            codes.append("anchor_not_independent")

    # AC-5 replay
    if kind == "admission":
        c = p.get("context") or {}
        if not c.get("session_id") or not c.get("request_id"):
            codes.append("invalid_context")
        if (c.get("session_id"), c.get("request_id")) in (ctx.get("ledger") or {}):
            codes.append("replay_detected")

    # AC-6 policy binding
    if kind == "admission":
        if (p.get("policy") or {}).get("version") not in (ctx.get("active_policy_versions") or set()):
            codes.append("policy_stale")

    codes = sorted(set(codes))
    return {"ok": not codes, "scope": None if codes else implied_scope, "codes": codes, "kind": kind}


def keypair():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, sk.public_key(), "sha256:" + hashlib.sha256(pub).hexdigest()


def sign(s, sk):
    s = {k: v for k, v in s.items() if k != "_sig"}
    s["_sig"] = base64.b64encode(sk.sign(stmt_digest(s)["sha256"].encode())).decode()
    return s


def build():
    g_sk, g_pub, g_fp = keypair()
    p_sk, p_pub, p_fp = keypair()
    a_sk, a_pub, a_fp = keypair()

    payload = {"tool": "read_file", "scope": "/etc/hosts"}
    outcome = {"applied": True, "effect": "read_file:/etc/hosts", "audit_id": "a-77"}
    policy = {"name": "tool-admission", "version": "2026.11.1"}
    ctx0 = {"acs_version": "0.1.4", "session_id": "6f1c2a9e-1d40-4d3e-9c3a-77ab01e2c9de",
            "request_id": "b0a2f7c4-2e21-4a10-9d55-0e6b8c2f4a13", "chain_hash": "0" * 63 + "1",
            "agent_id": "agent:researcher-01"}

    def adm(disp="ALLOW", pol=policy, ses=None, req=None):
        c = dict(ctx0)
        if ses: c["session_id"] = ses
        if req: c["request_id"] = req
        return {"_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "change-payload", "digest": digest(payload)}],
                "predicateType": "https://lgd.dev/attestation/agent-change-admission/v1",
                "predicate": {"change": {"kind": "tool_register", "payload_digest": digest(payload),
                                         "canonicalization": "jcs-rfc8785", "payload_media_type": "application/json"},
                              "context": c,
                              "guardian": {"id": "guardian:gw-1", "key_id": "guardian-key-1", "control_domain": "org:guardian"},
                              "policy": {"digest": digest(policy), "version": pol["version"]},
                              "disposition": disp, "reason_codes": [], "decided_at": "2026-11-17T01:50:00Z",
                              "outcome": outcome, "outcome_digest": digest(outcome), "witness_scope": "self"}}

    def wit(adm_d, key_id="peer-key-1", dom="org:peer-lab", pin=True):
        w = {"key_id": key_id, "org": "org:peer-lab", "control_domain": dom, "role": "peer"}
        if pin:
            w["key_pin"] = {"registry_uri": "https://registry.example.org/keys/peer-key-1",
                            "key_fingerprint": p_fp, "pinned_at": "2026-10-30T00:00:00Z"}
        return {"_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "change-payload", "digest": digest(payload)}],
                "predicateType": "https://lgd.dev/attestation/agent-change-witness/v1",
                "predicate": {"change": {"kind": "tool_register", "payload_digest": digest(payload),
                                         "canonicalization": "jcs-rfc8785"},
                              "context": ctx0, "witness": w,
                              "observed_admission": {"sha256": adm_d},
                              "outcome": outcome, "outcome_digest": digest(outcome),
                              "witnessed_at": "2026-11-17T01:52:00Z", "witness_scope": "peer"}}

    def anc(adm_d, pin_at="2026-10-30T00:00:00Z", ts_only=False):
        return {"_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "change-payload", "digest": digest(payload)}],
                "predicateType": "https://lgd.dev/attestation/agent-change-anchor/v1",
                "predicate": {"anchor": {"key_id": "anchor-key-1", "org": "org:independent-notary",
                                         "pin": {"registry_uri": "https://registry.example.org/keys/anchor-key-1",
                                                 "pinned_at": pin_at, "key_fingerprint": a_fp}},
                              "independent_of": ["agent:researcher-01", "org:guardian"],
                              "binds": {"statement_digest": {"sha256": adm_d}},
                              "anchored_at": "2026-11-17T02:00:00Z", "witness_scope": "external",
                              **({"timestamp_only": True} if ts_only else {})}}

    a = sign(adm(), g_sk)
    ad = stmt_digest(a)["sha256"]
    w = sign(wit(ad), p_sk)
    x = sign(anc(ad), a_sk)

    base = {"keys": {"guardian-key-1": g_pub, "peer-key-1": p_pub, "anchor-key-1": a_pub},
            "observed": {"key_id": "guardian-key-1", "control_domain": "org:guardian",
                         "agent_id": "agent:researcher-01", "org": "org:guardian"},
            "active_policy_versions": {"2026.11.1"},
            "ledger": {},
            "registry": {"peer-key-1": {"fingerprint": p_fp, "pinned_at": "2026-10-30T00:00:00Z", "writable_by_observed": False},
                         "anchor-key-1": {"fingerprint": a_fp, "pinned_at": "2026-10-30T00:00:00Z", "writable_by_observed": False}},
            "admission_statement_digest": ad,
            "admission_context": {"session_id": ctx0["session_id"], "request_id": ctx0["request_id"]}}

    cases = []
    def case(name, st, over=None, ok=True, codes=()):
        c = dict(base)
        if over: c.update(over)
        cases.append({"name": name, "statement": st, "ctx": c, "expect_ok": ok, "expect_codes": list(codes)})

    case("P1 admission / self", a)
    case("P2 witness / peer (pinned key)", w)
    case("P3 anchor / external", x)

    n1 = adm(); n1["subject"] = [{"name": "p", "digest": {"sha256": "9" * 64}}]
    case("N1 subject swapped", sign(n1, g_sk), ok=False, codes=["subject_mismatch"])

    n2 = adm(); n2["predicate"]["outcome_digest"] = digest(payload)
    case("N2 outcome restates payload", sign(n2, g_sk), ok=False, codes=["outcome_mismatch"])

    case("N3 witness binds another statement", sign(wit(digest({"x": 1})["sha256"]), p_sk), ok=False, codes=["witness_not_bound"])

    case("N4 witness signed by observed party", sign(wit(ad, key_id="guardian-key-1", dom="org:guardian"), g_sk),
         ok=False, codes=["witness_control_overlap", "witness_key_unpinned"])

    case("N5 witness key has no pin", sign(wit(ad, pin=False), p_sk), ok=False, codes=["witness_key_unpinned"])

    case("N6 anchor key unpinned", x,
         over={"registry": {"peer-key-1": base["registry"]["peer-key-1"]}}, ok=False, codes=["anchor_key_unpinned"])

    case("N7 timestamp only", sign(anc(ad, ts_only=True), a_sk), ok=False, codes=["timestamp_not_lift"])

    case("N8 anchor pinned after anchoring", sign(anc(ad, pin_at="2026-11-17T02:30:00Z"), a_sk),
         ok=False, codes=["anchor_key_unpinned"])

    case("N9 policy stale", a, over={"active_policy_versions": {"2026.12.1"}}, ok=False, codes=["policy_stale"])

    case("N10 replay: same request_id reused", a,
         over={"ledger": {(ctx0["session_id"], ctx0["request_id"]): "0" * 64}}, ok=False, codes=["replay_detected"])

    case("N11 unsigned", {k: v for k, v in a.items() if k != "_sig"}, ok=False, codes=["unsigned"])

    up = adm(); up["predicate"]["witness_scope"] = "external"
    case("N12 scope claim upgraded", sign(up, g_sk), ok=False, codes=["scope_mismatch"])

    n13 = wit(ad); n13["predicate"]["guardian"] = {"key_id": "guardian-key-1"}
    case("N13 foreign role block in witness", sign(n13, g_sk), ok=False, codes=["foreign_role_block"])

    n14 = adm(); del n14["predicate"]["change"]["payload_digest"]; n14["subject"] = [{"name": "p", "digest": {}}]
    case("N14 payload digest omitted", sign(n14, g_sk), ok=False, codes=["invalid_digest"])

    n15 = wit(ad); n15["predicate"]["witness"]["control_domain"] = None
    case("N15 witness domain omitted", sign(n15, p_sk), ok=False, codes=["witness_control_overlap"])

    case("N16 verifier context incomplete", w, over={"admission_statement_digest": None},
         ok=False, codes=["verifier_context_incomplete"])

    n17 = adm(); del n17["predicate"]["context"]["request_id"]
    case("N17 request_id omitted", sign(n17, g_sk), ok=False, codes=["invalid_context"])

    n18 = wit(ad); n18["predicate"]["context"] = {**ctx0, "request_id": "1111"}
    case("N18 witness recycled onto another request_id", sign(n18, p_sk), ok=False, codes=["witness_not_bound"])

    tam = sign(adm(), g_sk); tam["predicate"]["disposition"] = "DENY"
    case("N19 payload tampered after signing", tam, ok=False, codes=["bad_signature"])

    case("N20 peer key in a registry the observed party writes", w,
         over={"registry": {**base["registry"], "peer-key-1": {"fingerprint": p_fp, "pinned_at": "2026-10-30T00:00:00Z",
                                                              "writable_by_observed": True}}},
         ok=False, codes=["witness_key_unpinned"])

    return cases, {"adm": a, "witness": w, "anchor": x, "payload": payload, "outcome": outcome,
                   "adm_dig": ad, "sk": {"guardian": g_sk, "peer": p_sk, "anchor": a_sk},
                   "fps": {"guardian": g_fp, "peer": p_fp, "anchor": a_fp}}


def run(verbose=True):
    cases, art = build()
    rows = []
    for c in cases:
        r = verify(c["statement"], c["ctx"])
        ok = ((not r["codes"]) == c["expect_ok"]) and all(x in r["codes"] for x in c["expect_codes"])
        rows.append({"name": c["name"], "expect_ok": c["expect_ok"], "got_ok": r["ok"],
                     "codes": r["codes"], "scope": r["scope"], "pass": ok})
    if verbose:
        print(f"{'vector':48} {'expect':6} {'got':5} {'verdict':6} codes")
        for r in rows:
            print(f"{r['name']:48} {str(r['expect_ok']):6} {str(r['got_ok']):5} {'PASS' if r['pass'] else 'FAIL':6} {','.join(r['codes']) or '-'}")
        print(f"\n{sum(r['pass'] for r in rows)}/{len(rows)} vectors behaved as specified")
    return rows, art


def emit(outdir):
    cases, art = build()
    os.makedirs(os.path.join(outdir, "negative"), exist_ok=True)
    def w(name, obj):
        with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True); f.write("\n")
    w("admission-self.json", art["adm"])
    w("witness-peer.json", art["witness"])
    w("anchor-external.json", art["anchor"])
    w("change-payload.json", art["payload"])
    w("outcome-record.json", art["outcome"])
    for c in cases:
        if not c["expect_ok"]:
            slug = c["name"].split()[0].lower() + "-" + "-".join(c["name"].split()[1:]).replace(",", "").replace(":", "")
            w(os.path.join("negative", slug + ".json"), c["statement"])
    return outdir


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    if "--emit-examples" in sys.argv:
        print("wrote", emit(os.path.join(here, "examples")))
    else:
        rows, _ = run()
        json.dump(rows, open(os.path.join(here, "vector_results.json"), "w"), indent=2)
        sys.exit(0 if all(r["pass"] for r in rows) else 1)
