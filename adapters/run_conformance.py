#!/usr/bin/env python3
"""
The one authoritative command for this suite's checks — ACS v0.1.0
EMISSION conformance plus the summary-level Guardian checks. NOT a full
ACS-Core conformance gate (that spans the Guardian, framework wiring,
and deployment config, and is tracked separately — see the README's
scope note and milestone #33).

Runs, in order, and reports passed / skipped / failed SEPARATELY:
  1. Guardian conformance suite (test_acs_core_conformance).
  2. Shared-library tests (_common) — signing, protocol invariants,
     the capture-oracle self-checks.
  3. The selected adapter suites — including the emission matrix that
     captures real adapter bytes against the canonical schemas.

Every skip is printed by NAME + REASON and classified expected vs
unexpected against the EXACT EXPECTED_SKIPS allowlist (below).

Exit status:
  - non-zero if ANY suite has a failure/error.
  - non-zero if ANY UNEXPECTED skip occurred — a skip not on the
    allowlist. A dependency-gated test (e.g. NAT when nvidia-nat IS
    installed) that silently skips is therefore a build failure, never
    banked as green.
  - the allowlist tolerates only real-framework smoke tests that need an
    interactive product no runner has (Cursor GUI, authenticated
    `claude` CLI).
  - with --strict: non-zero on ANY skip at all, including the allowlisted
    ones — for a fully-provisioned gate that demands every test run.

Usage:
  python3 run_conformance.py cursor
  python3 run_conformance.py claude cursor
  python3 run_conformance.py claude cursor nat
  python3 run_conformance.py cursor --strict

At least one platform is required; there is no implicit "run all"
default. `claude-code` is accepted as an alias for `claude`. Shared
Guardian and _common checks run for every selection. When selecting NAT,
run under an interpreter that has nvidia-nat-core (e.g. the NAT
adapter's venv) or the NAT suite's skips count as unexpected and fail.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (label, cwd, discover-or-module)
SHARED_SUITES = (
    ("guardian-conformance", HERE, ("module", "test_acs_core_conformance")),
    ("_common",              HERE / "_common", ("discover", "tests")),
)

PLATFORM_SUITES = {
    "claude": ("claude-code", HERE / "claude-code", ("discover", "tests")),
    "cursor": ("cursor", HERE / "cursor", ("discover", "tests")),
    "nat": ("nat", HERE / "nat", ("discover", "tests")),
}

PLATFORM_ALIASES = {
    "claude": "claude",
    "claude-code": "claude",
    "cursor": "cursor",
    "nat": "nat",
}


class _CountingResult(unittest.TextTestRunner.resultclass):
    """Counts successes via addSuccess(): `testsRun - failures - skips`
    underflows when a setUpClass error never increments testsRun."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.successes = 0

    def addSuccess(self, test):  # noqa: N802
        super().addSuccess(test)
        self.successes += 1


# Skips tolerated in headless CI (tests needing the Cursor GUI or an
# authenticated `claude` CLI). Full (suite, test id, reason) triples
# compared for exact equality; any other skip fails the build.
EXPECTED_SKIPS = frozenset({
    ("cursor",
     "tests.test_live.LiveCursorPlaceholder.test_run_manual_procedure",
     "Cursor live verification is a manual procedure; see live_verification.md"),
    ("claude-code",
     "tests.test_live.LiveClaudeCodeRoundTrip.test_benign_bash_runs",
     "`claude` CLI not on PATH"),
    ("claude-code",
     "tests.test_live.LiveClaudeCodeRoundTrip.test_destructive_bash_blocked",
     "`claude` CLI not on PATH"),
})


def _is_expected_skip(suite: str, test_id: str, reason: str) -> bool:
    """Exact-triple membership — no substring leniency."""
    return (suite, test_id, reason) in EXPECTED_SKIPS


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run shared ACS checks and the selected adapter emission suites."
        )
    )
    parser.add_argument(
        "platforms",
        metavar="PLATFORM",
        nargs="+",
        choices=tuple(PLATFORM_ALIASES),
        help="one or more of: claude, cursor, nat",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail on expected skips as well as unexpected skips",
    )
    return parser.parse_args(argv)


def _select_suites(platforms: list[str]) -> list[tuple[str, Path, tuple[str, str]]]:
    """Return shared suites plus each selected platform once."""
    suites = list(SHARED_SUITES)
    selected: set[str] = set()
    for platform in platforms:
        canonical = PLATFORM_ALIASES[platform]
        if canonical not in selected:
            suites.append(PLATFORM_SUITES[canonical])
            selected.add(canonical)
    return suites


def _run_suite(cwd: Path, kind: tuple[str, str]) -> tuple[int, list[tuple[str, str]], int]:
    """Return (passed, skipped[(id, reason)], failed) for one suite.

    `failed` counts failures + errors INCLUDING setUpClass/module errors
    (which land in result.errors even though they never ran a test), so
    a broken suite can never masquerade as green."""
    loader = unittest.TestLoader()
    sys.path.insert(0, str(cwd))
    if kind[0] == "module":
        suite = loader.loadTestsFromName(kind[1])
    else:
        suite = loader.discover(str(cwd / kind[1]), top_level_dir=str(cwd))
    runner = unittest.TextTestRunner(verbosity=1, stream=sys.stderr,
                                     resultclass=_CountingResult)
    result = runner.run(suite)
    failed = len(result.failures) + len(result.errors)
    # t.id() is the stable "module.Class.method" form the allowlist keys
    # on — NOT str(t), which on 3.11+ is "method (module.Class.method)"
    # and would never match the exact triple (caught by running it).
    skipped = [(t.id(), reason) for t, reason in result.skipped]
    return result.successes, skipped, failed


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    suites = _select_suites(args.platforms)
    rows: list[tuple[str, int, int, int]] = []
    all_skips: list[tuple[str, str, str]] = []  # (suite, test id, reason)
    # Run each suite in a fresh subprocess so sys.path / module-cache
    # bleed between adapters can't mask or cause failures. Results come
    # back as one JSON line so skip names + reasons survive.
    for label, cwd, kind in suites:
        cmd = [sys.executable, "-c",
               "import sys, json; sys.argv=['x'];"
               "from run_conformance import _run_suite; from pathlib import Path;"
               f"p,s,f=_run_suite(Path({str(cwd)!r}), {kind!r});"
               "print('__RESULT__' + json.dumps([p, s, f]))"]
        proc = subprocess.run(cmd, cwd=str(HERE), capture_output=True, text=True)
        sys.stderr.write(proc.stderr)
        line = [ln for ln in proc.stdout.splitlines() if ln.startswith("__RESULT__")]
        if not line:
            sys.stderr.write(proc.stdout)
            rows.append((label, 0, 0, 1))
            continue
        import json
        p, skips, f = json.loads(line[0][len("__RESULT__"):])
        rows.append((label, p, len(skips), f))
        for test_id, reason in skips:
            all_skips.append((label, test_id, reason))

    print("\n" + "=" * 60)
    print("ACS emission/reference-stack summary")
    print("=" * 60)
    print(f"{'suite':22s} {'pass':>5} {'skip':>5} {'fail':>5}")
    tp = ts = tf = 0
    for label, p, s, f in rows:
        print(f"{label:22s} {p:5d} {s:5d} {f:5d}")
        tp += p; ts += s; tf += f
    print("-" * 60)
    print(f"{'TOTAL':22s} {tp:5d} {ts:5d} {tf:5d}")
    print("=" * 60)

    # Report every skip by NAME + REASON, split expected vs unexpected.
    unexpected = []
    if all_skips:
        print("Skipped tests:")
        for suite, test_id, reason in all_skips:
            expected = _is_expected_skip(suite, test_id, reason)
            if not expected:
                unexpected.append((suite, test_id, reason))
            tag = "  (expected)" if expected else "  (UNEXPECTED)"
            print(f"  - [{suite}] {test_id}\n      reason: {reason}{tag}")
        print("=" * 60)

    if tf:
        print(f"FAILED — {tf} test(s) failed/errored.")
        return 1
    if unexpected:
        print(f"FAILED — {len(unexpected)} UNEXPECTED skip(s). A skipped "
              "test is not a passing test; a dependency-gated test that "
              "silently skips must not bank as green. Install the missing "
              "dependency (e.g. nvidia-nat-core) so it runs, or add it to "
              "EXPECTED_SKIPS only if it genuinely cannot be automated.")
        return 1
    if args.strict and ts:
        # Under --strict, even allowlisted (expected) skips fail — for a
        # fully-provisioned gate that demands EVERY test actually run.
        print(f"FAILED (--strict) — {ts} skipped; --strict requires zero "
              "skips of any kind (including the manual Cursor procedure).")
        return 1
    print(f"OK — {tp} passed, {ts} skipped "
          f"({len(all_skips) - len(unexpected)} expected).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
