import os
import socket
import subprocess
import sys
import time

import httpx

from conftest import finbot_request


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(env):
    return subprocess.Popen([sys.executable, "-m", "acs_gateway"], env={**os.environ, **env},
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)


def test_the_entry_point_serves_once_the_guardian_answers(guardian, upstream, tmp_path):
    port = free_port()
    proc = start({"ACS_LAB_MODE": "enforce", "ACS_GUARDIAN_URL": guardian, "ACS_UPSTREAM_URL": upstream.url,
                  "ACS_GATEWAY_PORT": str(port), "ACS_GATEWAY_STATE_DIR": str(tmp_path / "state"),
                  "ACS_SESSION_STATE_DIR": "", "ACS_HANDSHAKE_CACHE": ""})
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                response = httpx.post(f"http://127.0.0.1:{port}/v1/responses", json=finbot_request(), timeout=5)
                break
            except httpx.ConnectError:
                assert time.monotonic() < deadline and proc.poll() is None
                time.sleep(0.2)
        assert response.status_code == 200
        assert (tmp_path / "state" / "handshakes").is_dir()
    finally:
        proc.terminate()
        proc.wait(10)


def test_the_entry_point_exits_when_the_guardian_never_answers(tmp_path):
    proc = start({"ACS_LAB_MODE": "enforce", "ACS_GUARDIAN_URL": "http://127.0.0.1:9/",
                  "ACS_GUARDIAN_READY_TIMEOUT_S": "1", "ACS_GATEWAY_PORT": str(free_port()),
                  "ACS_GATEWAY_STATE_DIR": str(tmp_path / "state")})
    _, stderr = proc.communicate(timeout=30)
    assert proc.returncode != 0
    assert "system/ping" in stderr


def test_the_entry_point_serves_the_approver_page_on_its_own_loopback_port(guardian, upstream, tmp_path):
    port, approver_port = free_port(), free_port()
    secret = "approver-secret-" + "0123456789abcdef" * 2
    token = tmp_path / "approver.token"
    token.write_text(secret)
    token.chmod(0o600)
    proc = start({"ACS_LAB_MODE": "enforce", "ACS_GUARDIAN_URL": guardian, "ACS_UPSTREAM_URL": upstream.url,
                  "ACS_GATEWAY_PORT": str(port), "ACS_GATEWAY_APPROVER_PORT": str(approver_port),
                  "ACS_GATEWAY_APPROVER_TOKEN_FILE": str(token),
                  "ACS_GATEWAY_STATE_DIR": str(tmp_path / "state"), "ACS_SESSION_STATE_DIR": "",
                  "ACS_HANDSHAKE_CACHE": ""})
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                response = httpx.get(f"http://127.0.0.1:{approver_port}/", timeout=5,
                                     headers={"Authorization": f"Bearer {secret}"})
                break
            except httpx.ConnectError:
                assert time.monotonic() < deadline and proc.poll() is None
                time.sleep(0.2)
        assert response.status_code == 200
        assert "No action is waiting for approval." in response.text
        assert httpx.get(f"http://127.0.0.1:{approver_port}/", timeout=5).status_code == 401
        # The model port never serves the page.
        assert httpx.get(f"http://127.0.0.1:{port}/", timeout=5).status_code == 404
    finally:
        proc.terminate()
        proc.wait(10)


def test_the_entry_point_refuses_an_approver_token_file_that_others_can_read(guardian, tmp_path):
    token = tmp_path / "approver.token"
    token.write_text("x" * 40)
    token.chmod(0o644)
    proc = start({"ACS_LAB_MODE": "enforce", "ACS_GUARDIAN_URL": guardian, "ACS_GATEWAY_PORT": str(free_port()),
                  "ACS_GATEWAY_APPROVER_PORT": str(free_port()), "ACS_GATEWAY_APPROVER_TOKEN_FILE": str(token),
                  "ACS_GATEWAY_STATE_DIR": str(tmp_path / "state")})
    _, stderr = proc.communicate(timeout=30)
    assert proc.returncode == 2
    assert "ACS_GATEWAY_APPROVER_TOKEN_FILE" in stderr and "0600" in stderr
