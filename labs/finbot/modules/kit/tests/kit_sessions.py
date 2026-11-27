"""Whole gateway sessions for the module 7 kit tests (issue #589, LAB-16 Task 12).

Version 1.0.0. Owner: Rock Lambros.

A session here is what the lab gateway writes for one epoch: the ClientHello and ServerHello, sessionStart, an allowed
tool call, a denied one, and sessionEnd. Each line goes through the gateway's own Transcript writer (fixtures.LabState),
and each step answer carries the chain head acs-verify recomputes, built with acs-verify's own chain_entry and
entry_hash, which mirror the example Guardian's compute_entry_hash and append_to_chain. So acs-verify passes a genuine
session in full, chain included, and any failure a test sees comes from what the kit changed.

Lab conventions: ML-DSA-65 response signing and the x_acs_lab_response_algorithm(s) handshake fields (issue #316),
the request hash in each ML-DSA-65 answer (issue #13), the key document (issue #460).
"""
from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import fixtures
from fixtures import SESSION_A, LabState, answer, request, sign_hmac, tool_request

from acs.core import ACS_VERSION, MAX_REQUEST_BODY_BYTES
from acs.testing.verify import chain_entry, entry_hash

KIT_DIR = Path(__file__).resolve().parents[1]
HMAC = "HMAC-SHA256"
MLDSA = "ML-DSA-65"
HANDSHAKE = "handshake/hello"
DENY_REASON = "vendor_domain_not_allowed"


def kit(name: str) -> ModuleType:
    """modules/kit/<name>.py loaded by path under the name lab_modules gives it, so the kit's verify never shadows the
    viewer's verify module on a shared sys.path."""
    module_name = f"lab_bundle_{name}"
    if module_name in sys.modules:
        return sys.modules[module_name]
    if str(KIT_DIR) not in sys.path:
        sys.path.insert(0, str(KIT_DIR))
    spec = importlib.util.spec_from_file_location(module_name, KIT_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def client_hello(session_id: str, mldsa: bool) -> dict[str, Any]:
    """A ClientHello shaped as acs.client's _hello shapes it, offering ML-DSA-65 responses only when mldsa is set."""
    payload: dict[str, Any] = {
        "acs_versions_supported": [ACS_VERSION], "methods_implemented": ["steps/toolCallRequest"],
        "transports_supported": ["http"], "max_payload_size_bytes": MAX_REQUEST_BODY_BYTES,
        "provenance_producer": "none", "wrapped_protocols": [], "profiles_supported": ["acs-core"],
        "signature_algorithms_supported": [HMAC],
    }
    if mldsa:
        payload["x_acs_lab_response_algorithms"] = [MLDSA]
    return request(HANDSHAKE, payload, session_id=session_id)


def server_hello(hello: dict[str, Any], mldsa: bool) -> dict[str, Any]:
    """The example Guardian's ServerHello for hello, unsigned."""
    result: dict[str, Any] = {
        "negotiated_version": ACS_VERSION, "methods_evaluated": hello["params"]["payload"]["methods_implemented"],
        "selected_transport": "http", "signature_algorithms_supported": [HMAC], "timeout_config": {"default_ms": 5000},
        "skew_window_ms": 300000, "on_decision_failure": "deny", "policy_requires_provenance": False,
        "profiles_accepted": ["acs-core"],
    }
    if mldsa:
        result["x_acs_lab_response_algorithm"] = MLDSA
    return {"jsonrpc": "2.0", "id": hello["id"], "result": result}


@dataclass
class Session:
    session_id: str
    algorithm: str
    path: Path
    # Line numbers, counted from 1 as acs-verify counts them.
    deny_line: int | None = None
    lines: dict[str, int] = field(default_factory=dict)


def write_session(lab: LabState, *, key: fixtures.DecisionKey | None = None, session_id: str = SESSION_A,
                  deny: bool = True) -> Session:
    """One session's transcript, signed with key under ML-DSA-65, or under the HMAC session key without one."""
    mldsa = key is not None

    def sign(resp: dict[str, Any], req: dict[str, Any]) -> dict[str, Any]:
        return key.sign(resp, req) if key is not None else sign_hmac(resp, session_id)

    session = Session(session_id, MLDSA if mldsa else HMAC, lab.transcript_path(session_id))
    line = 0
    head: str | None = None

    def pair(name: str, req: dict[str, Any], resp: dict[str, Any]) -> None:
        nonlocal line
        lab.pair(req, sign(resp, req))
        session.lines[name] = line + 2
        line += 2

    def step(name: str, req: dict[str, Any], decision: str, **extra: Any) -> None:
        nonlocal head
        entry = chain_entry(req)
        assert entry is not None
        head = entry_hash(entry, head)
        pair(name, req, answer(req, decision, type="final", acs_version=ACS_VERSION, chain_hash=head, **extra))

    hello = client_hello(session_id, mldsa)
    pair("hello", hello, server_hello(hello, mldsa))
    step("start", request("steps/sessionStart", {}, session_id=session_id), "allow")
    step("allow", tool_request("get_vendor", {"vendor_id": 7}, session_id=session_id), "allow")
    if deny:
        step("deny", tool_request("send_email", {"to": "drop@example.net"}, session_id=session_id), "deny",
             reasoning="send_email to a domain outside the vendor list", reason_codes=[DENY_REASON])
        session.deny_line = session.lines["deny"]
    step("end", request("steps/sessionEnd", {}, session_id=session_id), "allow")
    return session
