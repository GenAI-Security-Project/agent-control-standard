"""Fixtures shared by the example Guardian's OPA backend tests."""
from __future__ import annotations

import os

import pytest

from acs.testing.harness import launch_guardian, signing_env


@pytest.fixture
def guardian(tmp_path, monkeypatch):
    """Start the example Guardian on the OPA backend, pointed at whatever URL the test passes."""
    started = []
    for name, value in {**signing_env(), "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)

    def start(opa_url: str) -> str:
        env = {**os.environ, "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "state"),
               "ACS_POLICY_BACKEND": "opa", "ACS_OPA_URL": opa_url, "ACS_OPA_TIMEOUT_MS": "1000"}
        process, port = launch_guardian(env=env)
        started.append(process)
        return f"http://127.0.0.1:{port}/acs"

    yield start
    for process in started:
        process.terminate()
        process.wait(timeout=5)
