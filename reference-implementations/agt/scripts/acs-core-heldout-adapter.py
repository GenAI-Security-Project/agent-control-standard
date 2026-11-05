#!/usr/bin/env python3
"""Answer the held-out runner's questions by asking the reference Guardian.

    python3 conformance/heldout-runner/agent_evidence_vectors/heldout.py run -- \
        python3 scripts/acs-core-heldout-adapter.py --guardian http://127.0.0.1:8787/acs

The runner (conformance/heldout-runner/, retained byte for byte from agent-evidence-vectors
0.17.7 and checked by scripts/check-acs-core-vendor.py) writes one JSON line per member, `{"question": <payload>}`, and reads one answer line,
`{"verdict": "allow" | "deny" | "unmeasurable", "code": <section 17.1 name> | null}`. The
adapter never sees a member's id, family or expected verdict, so it cannot look one up,
and the runner mixes in members the Spec workstream sealed from a seed nobody else holds.

Each step is translated to the wire exactly as scripts/run-acs-core-vectors.py does in its
`adapted` column, and the Guardian's answer becomes the verdict. A payload with no request
envelope has no wire form here and is answered `unmeasurable`, and so is a decision-failure
fixture: an ordinary decision on the wire cannot show that no decision was rendered or that
an audit event exists.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "run_acs_core_vectors", os.path.join(HERE, "run-acs-core-vectors.py")
)
assert _spec is not None and _spec.loader is not None
driver = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(driver)

# Section 17.1 of the specification, by value. The vectors assert a name, the wire carries
# the number.
REGISTRY = {
    -32000: "SESSION_REFUSED",
    -32001: "UNSUPPORTED_VERSION",
    -32002: "PROVENANCE_REQUIRED",
    -32003: "CAPABILITY_NOT_NEGOTIATED",
    -32004: "SIGNATURE_INVALID",
    -32005: "REPLAY_DETECTED",
    -32006: "TIMESTAMP_OUT_OF_WINDOW",
    -32007: "CHAIN_MISMATCH",
}


def answer(question: dict, url: str) -> dict:
    member = {"id": str(uuid.uuid4()), "payload": question}
    run = driver.drive(member, url, adapted=True)
    if run["status"] != "ran":
        return {"verdict": "unmeasurable", "code": None, "why": run.get("reason")}
    last = run["observations"][-1]
    if last["kind"] == "error":
        return {"verdict": "deny", "code": REGISTRY.get(last["code"])}
    if last["kind"] == "decision" and last["decision"] in ("deny", "defer"):
        return {"verdict": "deny", "code": None}
    return {"verdict": "allow", "code": None}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--guardian", required=True, help="the Guardian's JSON-RPC URL")
    a = ap.parse_args()
    for line in sys.stdin:
        reply = answer(json.loads(line)["question"], a.guardian)
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
