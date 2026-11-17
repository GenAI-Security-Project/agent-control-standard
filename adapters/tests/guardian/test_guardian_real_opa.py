"""Opt-in: the example Guardian against a real `opa` server running policy/lab_test.rego.

Skipped unless `opa` (1.x) is on PATH. run_conformance.py does not collect tests/guardian, so the skip never
counts against its expected-skip list. The policy is a lab convention until issue #531 settles the OPA binding.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from round_trip_helpers import TRANSFER, VENDOR_RESULT, send_step

OPA = shutil.which("opa")
POLICY = Path(__file__).resolve().parent / "policy" / "lab_test.rego"
pytestmark = pytest.mark.skipif(OPA is None, reason="opt-in: put an opa 1.x binary on PATH to run against real OPA")

# OPA has to answer GET /health with 200 within this many seconds of starting. A TCP accept isn't enough: a
# container runtime's port proxy accepts before OPA inside it is listening.
HEALTH_DEADLINE_S = 30.0
START_ATTEMPTS = 3


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _healthy(port: int, process: subprocess.Popen) -> bool:
    """Poll GET /health until 200. False as soon as the process exits, or when the deadline passes."""
    deadline = time.monotonic() + HEALTH_DEADLINE_S
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.1)
    return False


def _stop(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


@pytest.fixture
def opa_url(tmp_path):
    """Start OPA on a fresh port, retrying when a start fails, as when another process took the port first."""
    failures = []
    for attempt in range(START_ATTEMPTS):
        port = _free_port()
        log_path = tmp_path / f"opa-{attempt}.log"
        with open(log_path, "wb") as log:
            process = subprocess.Popen([OPA, "run", "--server", "--addr", f"127.0.0.1:{port}", str(POLICY)],
                                       stdout=subprocess.DEVNULL, stderr=log)
        if _healthy(port, process):
            try:
                yield f"http://127.0.0.1:{port}/v1/data/lab/verdict"
            finally:
                _stop(process)
            return
        _stop(process)
        failures.append(f"attempt {attempt + 1} on port {port}, exit {process.returncode}: "
                        f"{log_path.read_text(errors='replace')[-2000:]}")
    pytest.fail("OPA did not become healthy:\n" + "\n".join(failures))


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
