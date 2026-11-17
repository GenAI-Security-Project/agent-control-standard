"""Opt-in: the example Guardian against a real `opa` server running policy/lab_test.rego.

Skipped unless `opa` (1.x) is on PATH. run_conformance.py does not collect tests/guardian, so the skip never
counts against its expected-skip list. The policy is a lab convention until issue #531 settles the OPA binding.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from opa_process import running_opa
from round_trip_helpers import TRANSFER, VENDOR_RESULT, send_step

OPA = shutil.which("opa")
POLICY = Path(__file__).resolve().parent / "policy" / "lab_test.rego"
pytestmark = pytest.mark.skipif(OPA is None, reason="opt-in: put an opa 1.x binary on PATH to run against real OPA")


@pytest.fixture
def opa_url(tmp_path):
    with running_opa(OPA, POLICY, tmp_path) as url:
        yield url

def test_the_policy_redacts_every_output(guardian, opa_url):
    _, result = send_step(guardian(opa_url), "steps/toolCallResult", VENDOR_RESULT)
    assert result["decision"] == "modify"
    assert result["modifications"] == {"redactions": [{"path": "/outputs/0/value/bank_account_number"},
                                                      {"path": "/outputs/1/value/bank_account_number"}]}


def test_the_policy_denies_an_external_recipient(guardian, opa_url):
    mail = {"tool": {"name": "finmail__send_email"}, "arguments": {"to": {"value": ["collector@exfil.example"]}}}
    _, result = send_step(guardian(opa_url), "steps/toolCallRequest", mail)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["external_recipient"])


def test_the_policy_allows_anything_else(guardian, opa_url):
    _, result = send_step(guardian(opa_url), "steps/toolCallRequest", TRANSFER)
    assert result["decision"] == "allow"
