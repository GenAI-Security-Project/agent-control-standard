"""The example Guardian from acs-adapters with test-only policy hooks, keyed on tool names no real agent sends.

Everything else, signing, schema validation, replay checks and the chain, is the example Guardian's own code.
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any

from acs.guardian import example_guardian as eg

_evaluate_step = eg.evaluate_step
_evaluate_handshake = eg.evaluate_handshake
_handle_request = eg.handle_request
_respond = eg.GuardianHandler._respond


def _tool(params: dict[str, Any]) -> str:
    return ((params.get("payload") or {}).get("tool") or {}).get("name", "")


def evaluate_step(method: str, params: dict, request_id: str, chain_hash: str) -> dict:
    base = {"type": "final", "acs_version": eg.ACS_VERSION, "request_id": request_id, "chain_hash": chain_hash}
    tool = _tool(params)
    if method == "steps/toolCallRequest":
        if tool == "slow_tool":
            time.sleep(float(os.environ.get("HARNESS_SLOW_S", "1.5")))
        if tool == "override_tool":
            return {**base, "decision": "modify", "reasoning": "recipient rewritten",
                    "reason_codes": ["external_recipient"],
                    "modifications": {"parameter_overrides": {"to": "ops@ns1.finbot"}}}
        if tool == "ask_tool":
            return {**base, "decision": "ask", "reasoning": "needs approval", "reason_codes": ["payment_over_threshold"],
                    "ask_details": {"approver": {"type": "human", "id": "lab-approver"},
                                    "question": "Approve?", "timeout_seconds": 60}}
        if tool == "defer_tool":
            return {**base, "decision": "defer", "reasoning": "later", "reason_codes": ["deferred"],
                    "defer_details": {"reason": "low_confidence", "resolution_method": "timeout",
                                      "resolution_timeout_ms": 1000}}
    if method == "steps/toolCallResult":
        if tool == "get_vendor_details":
            return {**base, "decision": "modify", "reasoning": "bank account removed",
                    "reason_codes": ["sensitive_field_redacted"],
                    "modifications": {"redactions": [{"path": "/outputs/0/value/bank_account_number"}]}}
        if tool == "bad_path_tool":
            return {**base, "decision": "modify", "reasoning": "missing field",
                    "modifications": {"redactions": [{"path": "/outputs/0/value/missing"}]}}
        if tool == "text_tool":
            return {**base, "decision": "modify", "reasoning": "rewritten",
                    "modifications": {"modified_content": "summary withheld"}}
        if tool == "leaky_tool":
            return {**base, "decision": "deny", "reasoning": "leak", "reason_codes": ["leak_blocked"]}
    return _evaluate_step(method, params, request_id, chain_hash)


def evaluate_handshake(params: dict, request_id: str) -> dict:
    hello = _evaluate_handshake(params, request_id)
    if os.environ.get("HARNESS_OMIT_POSTURE") == "1":
        hello.pop("on_decision_failure", None)
    return hello


_failed_hellos = 0


def handle_request(request: dict) -> dict:
    global _failed_hellos
    if request.get("method") == "handshake/hello" and _failed_hellos < int(os.environ.get("HARNESS_FAIL_HELLOS", "0")):
        _failed_hellos += 1
        return {"__harness_status__": 503}
    count_file = os.environ.get("HARNESS_COUNT_FILE")
    if count_file:
        with open(count_file, "a", encoding="utf-8") as f:
            f.write(f"{request.get('method')}\n")
    tool = _tool(request.get("params") or {})
    if tool == "rate_limited_tool":
        return {"__harness_status__": 429}
    response = _handle_request(request)
    if tool == "tampered_tool" and "result" in response:
        signature = response["result"]["signature"]
        value = signature["value"]
        signature["value"] = ("A" if value[0] != "A" else "B") + value[1:]
    return response


def respond(self: Any, status: int, body: dict) -> None:
    if "__harness_status__" in body:
        return _respond(self, body["__harness_status__"], {"detail": "rate limited"})
    return _respond(self, status, body)


eg.evaluate_step = evaluate_step
eg.evaluate_handshake = evaluate_handshake
eg.handle_request = handle_request
eg.GuardianHandler._respond = respond

if __name__ == "__main__":
    sys.exit(eg.main())
