"""
Tests for the authoritative runner's selection and skip classification.

The allowlist must be exact on the (suite, test id, reason) triple —
a substring match would tolerate an unrelated test carrying an
allowlisted reason string.
"""
from __future__ import annotations

import sys
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

# run_conformance.py lives at adapters/ (two levels up from _common/tests/).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import run_conformance as rc  # noqa: E402


class PlatformSelection(unittest.TestCase):
    def test_one_platform_runs_shared_checks_and_that_platform(self):
        labels = [suite[0] for suite in rc._select_suites(["cursor"])]
        self.assertEqual(
            labels, ["guardian-conformance", "_common", "cursor"])

    def test_multiple_platforms_follow_requested_order(self):
        labels = [
            suite[0]
            for suite in rc._select_suites(["nat", "claude", "cursor"])
        ]
        self.assertEqual(
            labels,
            ["guardian-conformance", "_common", "nat", "claude-code", "cursor"],
        )

    def test_claude_code_alias_and_duplicates_run_once(self):
        labels = [
            suite[0]
            for suite in rc._select_suites(
                ["claude-code", "claude", "cursor", "cursor"]
            )
        ]
        self.assertEqual(
            labels, ["guardian-conformance", "_common", "claude-code", "cursor"])

    def test_platform_is_required(self):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            rc._parse_args([])
        self.assertEqual(raised.exception.code, 2)

    def test_unknown_platform_is_rejected(self):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            rc._parse_args(["windsurf"])
        self.assertEqual(raised.exception.code, 2)

    def test_strict_flag_can_follow_platforms(self):
        args = rc._parse_args(["claude", "cursor", "--strict"])
        self.assertEqual(args.platforms, ["claude", "cursor"])
        self.assertTrue(args.strict)


class SkipClassifierIsExact(unittest.TestCase):
    CURSOR = ("cursor",
              "tests.test_live.LiveCursorPlaceholder.test_run_manual_procedure",
              "Cursor live verification is a manual procedure; see live_verification.md")

    def test_real_allowlisted_skips_are_expected(self):
        for entry in rc.EXPECTED_SKIPS:
            self.assertTrue(rc._is_expected_skip(*entry),
                f"allowlisted triple not recognized: {entry}")

    def test_fake_test_borrowing_cursor_reason_is_unexpected(self):
        """The exact hole: a NAT test that borrows the Cursor reason must
        NOT be classified expected."""
        self.assertFalse(rc._is_expected_skip(
            "nat",
            "tests.test_emission.NatEmission.test_pre_invoke_emits_tool_call_request",
            self.CURSOR[2]),
            "a test borrowing an allowlisted REASON must still be "
            "unexpected — match is on the full triple, not the reason")

    def test_right_test_wrong_reason_is_unexpected(self):
        """Same test id, byte-different reason → unexpected (a real skip
        for a new reason must not be silently tolerated)."""
        self.assertFalse(rc._is_expected_skip(
            self.CURSOR[0], self.CURSOR[1],
            "Cursor live verification is a manual procedure"),  # missing tail
            "reason must match exactly, including the whole string")

    def test_right_reason_wrong_suite_is_unexpected(self):
        self.assertFalse(rc._is_expected_skip(
            "nat", self.CURSOR[1], self.CURSOR[2]),
            "suite label is part of the exact match")

    def test_substring_does_not_leak(self):
        """A reason that CONTAINS an allowlisted reason as a substring is
        still unexpected — proves we're not doing `in`."""
        self.assertFalse(rc._is_expected_skip(
            self.CURSOR[0], self.CURSOR[1],
            "PREFIX " + self.CURSOR[2] + " SUFFIX"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
