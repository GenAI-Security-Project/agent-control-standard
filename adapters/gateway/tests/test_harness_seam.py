"""The harness must hook the seam the Guardian's do_POST calls, whichever Guardian shape is installed.

Before the example Guardian's single-read refactor, do_POST called handle_request. After it, do_POST calls _handle and
handle_request is only a wrapper nobody on the wire path reaches. Stubs of both shapes keep this test independent of
which Guardian is on the branch, so the two pull requests can merge in either order.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from typing import Any

import pytest

HARNESS = Path(__file__).parent / "guardian_harness.py"
RATE_LIMITED = {"method": "steps/toolCallRequest",
                "params": {"payload": {"tool": {"name": "rate_limited_tool"}}}}


def _signed() -> dict:
    return {"jsonrpc": "2.0", "id": 1, "result": {"signature": {"value": "AAAA"}}}


def _stub(split_handle: bool) -> types.ModuleType:
    """A minimal example_guardian. split_handle=True is the _handle shape, False the handle_request-only shape."""
    eg = types.ModuleType("acs.guardian.example_guardian")
    eg.ACS_VERSION = "stub"
    eg.evaluate_step = lambda method, params, request_id, chain_hash: {}
    eg.evaluate_handshake = lambda params, request_id: {}
    eg.main = lambda: 0

    class GuardianHandler:
        def _respond(self, status: int, body: dict) -> None:
            self.sent = (status, body)

    eg.GuardianHandler = GuardianHandler
    if split_handle:
        eg._handle = lambda request, read: (200, _signed())
        eg.handle_request = lambda request: eg._handle(request, None)[1]
    else:
        eg.handle_request = lambda request: _signed()
    return eg


def _load_harness(monkeypatch: pytest.MonkeyPatch, eg: types.ModuleType) -> Any:
    package = types.ModuleType("acs.guardian")
    package.example_guardian = eg
    monkeypatch.setitem(sys.modules, "acs", types.ModuleType("acs"))
    monkeypatch.setitem(sys.modules, "acs.guardian", package)
    monkeypatch.setitem(sys.modules, "acs.guardian.example_guardian", eg)
    spec = importlib.util.spec_from_file_location("harness_under_test", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("split_handle", [False, True], ids=["handle_request_only", "handle_seam"])
def test_a_429_injection_reaches_the_seam_do_post_calls(monkeypatch, split_handle):
    eg = _stub(split_handle)
    _load_harness(monkeypatch, eg)
    if split_handle:
        status, body = eg._handle(RATE_LIMITED, None)
        assert status == 200
    else:
        body = eg.handle_request(RATE_LIMITED)
    assert body == {"__harness_status__": 429}


@pytest.mark.parametrize("split_handle", [False, True], ids=["handle_request_only", "handle_seam"])
def test_the_signature_tamper_reaches_the_seam_do_post_calls(monkeypatch, split_handle):
    eg = _stub(split_handle)
    _load_harness(monkeypatch, eg)
    request = {"method": "steps/toolCallRequest", "params": {"payload": {"tool": {"name": "tampered_tool"}}}}
    body = eg._handle(request, None)[1] if split_handle else eg.handle_request(request)
    assert body["result"]["signature"]["value"] == "BAAA"
