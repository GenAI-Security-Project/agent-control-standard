"""Post ACS-Core envelope vectors to a Guardian over HTTP and score them by error code.

    python3 -I tests/negative_controls_runner.py --guardian http://127.0.0.1:8787/acs

This is the runner that `tests/test_negative_controls.py` holds to the requirements in
issue #53. It is standard library only and runs as its own process, one child per run, so
nothing it measures can reach its exit status (#53 requirement 4).

Output is one line per vector, `PASS <id>`, `FAIL <id> ...` or `NOT-RUN <id> ...`, then a
closing `RESULT pass=<n> fail=<n> not_run=<n>` line. Exit 0 means every vector was scored
and passed, 1 means at least one failed, and 2 means nothing could be measured: the suite
is structurally invalid, or no vector was scored (#53 requirement 9).

A vector names the section it tests and the spec version it was written against, and its
expectation is either an ALLOW decision or a JSON-RPC error code from section 17.1. Prose
in a message is never compared (#53 requirement 7).

The signature is HMAC-SHA256, the ACS-Core baseline in section 10, over the RFC 8785 form
of the JSON-RPC request with `params.signature` removed. The per-session key is HKDF-SHA256
with the pre-shared secret as input keying material, an empty salt, and the session_id as
info. Section 10 leaves the HKDF salt and info to the deployment, so this runner fixes them
and a Guardian under test is configured the same way. The canonical form here is
`json.dumps` with sorted keys and no whitespace, which equals RFC 8785 for the ASCII
strings and integers these vectors carry.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request
import uuid

SPEC_VERSION = "0.1.4"
SPEC = "docs/spec/instrument/specification.md"
DEFAULT_PSK = "acs-negative-controls-test-key"

# Each vector is data: the runner has no per-vector code. A step's fields say how its
# envelope differs from a fresh, signed, current request in the vector's session.
VECTORS = [
    {
        "id": "signature-valid",
        "group": "signature",
        "kind": "positive",
        "requirement": {"spec_version": SPEC_VERSION, "anchor": SPEC + "#10-cryptographic-signatures",
                        "quote": "A signature over the \u00a710 canonical input is REQUIRED in ACS-Core."},
        "steps": [{"signature": "valid"}],
        "expect": {"decision": "allow"},
    },
    {
        "id": "signature-invalid",
        "group": "signature",
        "kind": "negative",
        "requirement": {"spec_version": SPEC_VERSION, "anchor": SPEC + "#10-cryptographic-signatures",
                        "quote": "A verifier MUST recompute this canonical form and MUST reject a "
                                 "signature that does not cover it (`SIGNATURE_INVALID`, \u00a717.1)."},
        "steps": [{"signature": "invalid"}],
        "expect": {"error": -32004},
    },
    {
        "id": "signature-missing",
        "group": "signature",
        "kind": "negative",
        "requirement": {"spec_version": SPEC_VERSION, "anchor": SPEC + "#171-acs-error-code-registry",
                        "quote": "A required signature is missing, malformed, or fails verification (\u00a710)."},
        "steps": [{"signature": "absent"}],
        "expect": {"error": -32004},
    },
    {
        "id": "request-id-fresh",
        "group": "replay",
        "kind": "positive",
        "requirement": {"spec_version": SPEC_VERSION, "anchor": SPEC + "#103-replay-protection",
                        "quote": "MUST reject duplicate `request_id` values within the session"},
        "steps": [{}, {}],
        "expect": {"decision": "allow"},
    },
    {
        "id": "request-id-repeated",
        "group": "replay",
        "kind": "negative",
        "requirement": {"spec_version": SPEC_VERSION, "anchor": SPEC + "#103-replay-protection",
                        "quote": "MUST reject duplicate `request_id` values within the session with "
                                 "`REPLAY_DETECTED` (`-32005`, \u00a717.1)"},
        "steps": [{}, {"request_id": "repeat"}],
        "expect": {"error": -32005},
    },
    {
        "id": "timestamp-inside-window",
        "group": "window",
        "kind": "positive",
        "requirement": {"spec_version": SPEC_VERSION, "anchor": SPEC + "#103-replay-protection",
                        "quote": "Guardians MUST reject requests whose `timestamp` is more than the "
                                 "negotiated skew window"},
        "steps": [{"timestamp_offset_s": -60}],
        "expect": {"decision": "allow"},
    },
    {
        "id": "timestamp-outside-window",
        "group": "window",
        "kind": "negative",
        "requirement": {"spec_version": SPEC_VERSION, "anchor": SPEC + "#103-replay-protection",
                        "quote": "returning `TIMESTAMP_OUT_OF_WINDOW` (`-32006`, \u00a717.1)"},
        "steps": [{"timestamp_offset_s": -86400}],
        "expect": {"error": -32006},
    },
]

# Envelope properties a vector can vary, with the values that count as a change from a
# conformant request. A suite that never changes one of them cannot tell a Guardian that
# checks it from one that ignores it (#53 requirement 5).
VARIED = {
    "signature": ("invalid", "absent"),
    "request_id": ("repeat",),
}


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def session_key(psk: str, session_id: str) -> bytes:
    """HKDF-SHA256 (RFC 5869), one 32-byte block, empty salt, session_id as info."""
    prk = hmac.new(b"\x00" * 32, psk.encode(), hashlib.sha256).digest()
    return hmac.new(prk, session_id.encode() + b"\x01", hashlib.sha256).digest()


def sign(body: dict, psk: str) -> dict:
    """Return the signature object for a request whose params carry no signature yet."""
    key = session_key(psk, body["params"]["metadata"]["session_id"])
    mac = hmac.new(key, canonical(body), hashlib.sha256).digest()
    return {"algorithm": "HMAC-SHA256", "value": base64.b64encode(mac).decode(), "key_id": "test"}


def now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def envelope(step: dict, session_id: str, last_request_id: str | None, psk: str) -> dict:
    request_id = last_request_id if step.get("request_id") == "repeat" else str(uuid.uuid4())
    when = now() + datetime.timedelta(seconds=step.get("timestamp_offset_s", 0))
    params = {
        "acs_version": SPEC_VERSION,
        "request_id": request_id,
        "timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "metadata": {"agent_id": "negative-controls", "session_id": session_id},
        "payload": {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}},
    }
    body = {"jsonrpc": "2.0", "id": request_id, "method": "steps/toolCallRequest", "params": params}
    mode = step.get("signature", "valid")
    if mode == "valid":
        params["signature"] = sign(body, psk)
    elif mode == "invalid":
        good = sign(body, psk)
        mac = base64.b64decode(good["value"])
        flipped = bytes([mac[0] ^ 1]) + mac[1:]
        params["signature"] = dict(good, value=base64.b64encode(flipped).decode())
    return body


def post(url: str, body: dict) -> dict:
    request = urllib.request.Request(url, data=canonical(body), headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode())


def observe(response: dict) -> dict:
    """Reduce a response to what is scored: an error code, or a decision."""
    if "error" in response:
        return {"error": response["error"].get("code")}
    return {"decision": (response.get("result") or {}).get("decision")}


def structural_errors(vectors: list) -> list:
    """Rules the suite must meet before any vector is posted."""
    errors = []
    groups: dict = {}
    for vector in vectors:
        req = vector.get("requirement") or {}
        if not req.get("spec_version") or not req.get("anchor"):
            errors.append("%s names no requirement and spec version" % vector.get("id"))
        groups.setdefault(vector.get("group"), set()).add(vector.get("kind"))
    for group, kinds in sorted(groups.items(), key=lambda item: str(item[0])):
        # A positive control with no negative beside it certifies an allow-everything
        # Guardian, and a negative with no positive certifies a deny-everything one.
        if kinds != {"positive", "negative"}:
            errors.append("group %s needs a positive and a negative control, has %s" % (group, sorted(kinds)))
    steps = [step for vector in vectors for step in vector.get("steps", [])]
    for field, changed in VARIED.items():
        if steps and not any(step.get(field) in changed for step in steps):
            errors.append("no vector changes %s, so a Guardian that ignores it passes" % field)
    return errors


def score(vector: dict, observations: list) -> tuple[str, str]:
    expect, last = vector["expect"], observations[-1]
    if "decision" in expect:
        ok = all(o.get("decision") == expect["decision"] for o in observations)
        return ("PASS" if ok else "FAIL"), "expected %s observed %s" % (expect, observations)
    ok = last.get("error") == expect["error"]
    return ("PASS" if ok else "FAIL"), "expected %s observed %s" % (expect, last)


def run(url: str, vectors: list, psk: str) -> int:
    errors = structural_errors(vectors)
    if errors:
        for error in errors:
            print("SUITE-INVALID " + error)
        print("RESULT pass=0 fail=0 not_run=%d" % len(vectors))
        return 2
    counts = {"PASS": 0, "FAIL": 0, "NOT-RUN": 0}
    for vector in vectors:
        session_id, last, observations = str(uuid.uuid4()), None, []
        try:
            for step in vector["steps"]:
                body = envelope(step, session_id, last, psk)
                last = body["params"]["request_id"]
                observations.append(observe(post(url, body)))
        except (OSError, ValueError, urllib.error.URLError) as exc:
            # A transport failure measured nothing, so it is never scored as a pass.
            counts["NOT-RUN"] += 1
            print("NOT-RUN %s %s" % (vector["id"], type(exc).__name__))
            continue
        verdict, detail = score(vector, observations)
        counts[verdict] += 1
        print("FAIL %s %s" % (vector["id"], detail) if verdict == "FAIL" else "PASS " + vector["id"])
    print("RESULT pass=%d fail=%d not_run=%d" % (counts["PASS"], counts["FAIL"], counts["NOT-RUN"]))
    if counts["PASS"] + counts["FAIL"] == 0:
        return 2
    return 1 if counts["FAIL"] or counts["NOT-RUN"] else 0


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--guardian", required=True, help="the Guardian's JSON-RPC URL")
    parser.add_argument("--vectors", help="a JSON file holding a vector list; default: VECTORS")
    parser.add_argument("--psk", default=DEFAULT_PSK, help="pre-shared secret for the HMAC key")
    args = parser.parse_args(argv)
    vectors = VECTORS
    if args.vectors:
        with open(args.vectors) as handle:
            vectors = json.load(handle)
    return run(args.guardian, vectors, args.psk)


if __name__ == "__main__":
    sys.exit(main())
