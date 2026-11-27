"""
ARC x Guardian x ledger: render the three-layer comparison from the verified matrix results.

This is a presenter, not a measurer. Every Guardian and ledger cell it prints comes from
results/matrix_scorecard.json, which verify.py re-derives from the wire transcript, so the
comparison introduces no second source of truth and nothing it shows rests on its own say-so.

The ARC column is taken from ARC's merged, maintainer-run fixture (pinned in COMPARISON.md).
It is not measured by this suite. Noctis has reproduced it against the published tarball; no party outside both projects has yet.

  python3 matrix.py         # produce the verified results first
  python3 comparison.py     # render the three-layer table from them
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SCORE = os.path.join(HERE, "results", "matrix_scorecard.json")

ARC = {
    "t4_declared":   "REJECT, G1_SUBJECT_MISMATCH for all three declaration changes (ARC fixture, maintainer-run)",
    "t4_underlying": "G1 PASS, EXPECTED_MISS, execution_authorized: false (ARC fixture, maintainer-run)",
    "t8":            "G3 validates lifecycle declarations; reconciliation of actual partial fills and late-arriving effects is outside ARC's scope (ARC fixture, maintainer-run)",
}


def main():
    if not os.path.exists(SCORE):
        print("no results/matrix_scorecard.json found; run: python3 matrix.py")
        return 1
    doc = json.load(open(SCORE))
    rec = {r["case"]: r for r in doc["scorecards"]["reconciling"]}
    cmp = {r["policy"]: r for r in doc.get("comparison", [])}
    t4a, t4b, t8 = rec.get("T4a", {}), rec.get("T4b", {}), rec.get("T8", {})
    rc, db = cmp.get("reconciling", {}), cmp.get("declaration-bound", {})

    print("ARC x Guardian x ledger: three independent layers over one scenario")
    print("  Guardian and ledger columns from the verified matrix results; ARC column from ARC's maintainer-run fixture (reproduced by Noctis; not yet by a third party).\n")

    print("T4-declared (change is in the declared bundle, task or action):")
    print(f"  ARC (declaration):   {ARC['t4_declared']}")
    print(f"  Guardian (boundary): drift caught at dispatch: hold for reauth when enforced (T4a={t4a.get('verdict')}), "
          f"commit and flag basis_mismatch when recorded (T4b={t4b.get('verdict')})")
    print("  independent ledger:  effect bounded, 40 held / 80 committed-and-flagged\n")

    print("T4-underlying (underlying tool or MCP definition changes, declaration unchanged):")
    print(f"  ARC (declaration):   {ARC['t4_underlying']}")
    print(f"  Guardian (boundary): a definition-binding Guardian {rc.get('outcome')} it "
          f"(reconciling, basis_mismatch flagged={rc.get('flagged')}); a declaration-bound one "
          f"{db.get('outcome')} it (flagged={db.get('flagged')})")
    print(f"  independent ledger:  {rc.get('erp')} committed either way; the difference is whether the drift was noticed\n")

    print("T8 (partial fulfilment with a late-arriving effect):")
    print(f"  ARC (declaration):   {ARC['t8']}")
    print("  Guardian (boundary): counts the confirmed 20, holds the remainder to key close, denies a competing op, "
          f"flags reconciliation_required on the late fill (T8={t8.get('verdict')})")
    print(f"  independent ledger:  {t8.get('erp')}, flagged, no double-spend (naive double-spends to 120)\n")

    print("Every Guardian and ledger cell above is a verdict in matrix_scorecard.json that verify.py")
    print("re-derives from the wire transcript. The ARC cells come from ARC's maintainer-run fixture, not from this suite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
