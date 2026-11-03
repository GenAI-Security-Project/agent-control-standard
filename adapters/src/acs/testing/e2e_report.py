"""Shared output and recording-Guardian helpers for each adapter's e2e_check.py."""
from __future__ import annotations

import json
from typing import Any, Callable

CHECK = "✓"
CROSS = "✗"
PASS_TXT = "\033[1;32mPASS\033[0m"
FAIL_TXT = "\033[1;31mFAIL\033[0m"
BOLD = "\033[1m"
RESET = "\033[0m"


class Report:
    """Scenario PASS/FAIL output and a final summary."""

    def __init__(self) -> None:
        self.entries: list[tuple[str, bool]] = []

    def print_header(self, *lines: str, width: int = 70) -> None:
        bar = "═" * width
        print(bar)
        for line in lines:
            print(f"  {line}")
        print(bar)
        print()
        print("─" * width)
        print()

    def case(self, num: int, total: int, title: str) -> None:
        print(f"[{num}/{total}] {BOLD}{title}{RESET}")

    def field(self, label: str, value: str) -> None:
        print(f"      {label:12s} {value}")

    def sub(self, label: str, ok: bool, detail: str = "") -> None:
        mark = CHECK if ok else CROSS
        line = f"      {mark} {label}"
        if detail:
            line += f"  ({detail})"
        print(line)

    def json_block(self, label: str, obj: Any, *, truncate: int = 200) -> None:
        rendered = json.dumps(self._trim(obj, truncate), indent=2, sort_keys=True)
        rendered = "\n".join("        " + ln for ln in rendered.splitlines())
        print(f"      ── {label}")
        print(rendered)

    def quote_block(self, label: str, text: str, *, max_chars: int = 400) -> None:
        text = text.strip()
        if len(text) > max_chars:
            text = text[:max_chars] + f"\n[…+{len(text) - max_chars} more chars truncated]"
        wrapped = "\n".join("        " + ln for ln in text.splitlines())
        print(f"      ── {label}")
        print(wrapped)

    def operator_action(self, instructions: list[str]) -> None:
        import sys
        print(f"      {BOLD}── ACTION REQUIRED ──{RESET}")
        for i, line in enumerate(instructions, 1):
            print(f"        {i}. {line}")
        print()
        try:
            input(f"      {BOLD}Press Enter when done (or Ctrl-C to abort):{RESET} ")
        except (EOFError, KeyboardInterrupt):
            print()
            print("      Aborted.")
            sys.exit(1)
        print()

    def _trim(self, obj: Any, n: int) -> Any:
        if isinstance(obj, str):
            return obj if len(obj) <= n else obj[:n] + f"…(+{len(obj) - n} chars)"
        if isinstance(obj, dict):
            return {k: self._trim(v, n) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._trim(v, n) for v in obj]
        return obj

    def finish(self, title: str, ok: bool) -> None:
        verdict = PASS_TXT if ok else FAIL_TXT
        print(f"      Result      {verdict}")
        print()
        self.entries.append((title, ok))

    def summary(self, success_banner: str, *, width: int = 70) -> bool:
        bar = "═" * width
        passed = sum(1 for _, ok in self.entries if ok)
        total = len(self.entries)
        print(bar)
        if passed == total:
            print(f"  Summary: {passed}/{total} scenarios passed — "
                  f"\033[1;32m{success_banner}\033[0m")
            print("  (smoke test, not a conformance certification: run "
                  "adapters/run_conformance.py for the summary-level Core checks)")
        else:
            print(f"  Summary: {passed}/{total} scenarios passed — "
                  f"\033[1;31mFAILURES BELOW\033[0m")
            for title, ok in self.entries:
                if not ok:
                    print(f"   {CROSS} {title}")
        print(bar)
        return passed == total


def real_policy_handler(evaluate_step: Callable) -> Callable[[dict], dict]:
    """Wrap a policy function with evaluate_step's signature as a ProgrammableGuardian default handler."""
    def handler(req: dict) -> dict:
        method = req.get("method", "")
        params = req.get("params") or {}
        request_id = params.get("request_id", "")
        chain_hash = params.get("chain_hash", "0" * 64)
        return evaluate_step(method, params, request_id, chain_hash)
    return handler


def assert_envelopes_signed_and_valid(guardian: Any,
                                        validate_request_envelope: Callable,
                                        sub_results: list) -> None:
    """Append the signing and schema sub-checks every scenario needs to sub_results."""
    signed_envs = [r for r in guardian.received
                    if r.get("params", {}).get("signature", {}).get("algorithm") == "HMAC-SHA256"]
    all_signed = (len(signed_envs) == len(guardian.received))
    sub_results.append(("Every envelope is HMAC-SHA256 signed",
                         all_signed,
                         f"{len(signed_envs)}/{len(guardian.received)}"))
    schema_errors: list = []
    for r in guardian.received:
        if r.get("method") in ("handshake/hello", "system/ping"):
            continue
        errs = validate_request_envelope(r)
        if errs:
            schema_errors.append((r.get("method"), errs[0]))
    sub_results.append(("Every envelope validates against canonical schema",
                         not schema_errors,
                         "no errors" if not schema_errors
                         else f"{len(schema_errors)} envelopes failed: {schema_errors[0]}"))
