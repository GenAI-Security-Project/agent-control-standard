"""GET /keys serves the Guardian's key document when ML-DSA-65 response signing is on (issue #576).

The key document and the route are lab conventions until issue #460 settles key publication. With the mode off, GET
answers 501 on every path, as BaseHTTPRequestHandler always has.
"""
from __future__ import annotations

import datetime
import http.server
import json
import os
import threading
import urllib.error
import urllib.request

import pytest

from acs.guardian import example_guardian
from acs.testing.harness import signing_env

PING = json.dumps({"jsonrpc": "2.0", "id": "p", "method": "system/ping",
                   "params": {"request_id": "p", "metadata": {}, "payload": {}}}).encode()


@pytest.fixture
def serve(monkeypatch):
    """Serve GuardianHandler in this process on a free port and return its base URL."""
    servers = []
    monkeypatch.setattr(example_guardian, "PERSIST_ENABLED", False)

    def start() -> str:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), example_guardian.GuardianHandler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def fetch(url: str, *, data: bytes | None = None) -> tuple[int, dict, bytes]:
    """One request with no proxy, returning (status, headers, body) for any status."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"} if data else {})
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


@pytest.fixture
def signing_off(monkeypatch):
    for name, value in signing_env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    monkeypatch.setattr(example_guardian, "RESPONSE_SIGNING_NAME", "")
    monkeypatch.setattr(example_guardian, "DECISION_SIGNER", None)


@pytest.fixture
def signing_on(monkeypatch, tmp_path):
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    from decision_signing_helpers import configure_in_process
    return configure_in_process(monkeypatch, tmp_path)


@pytest.mark.parametrize("path", ["/keys", "/"])
def test_get_is_501_when_signing_is_off(signing_off, serve, path):
    status, _, _ = fetch(serve() + path)
    assert status == 501


def test_keys_returns_the_document(signing_on, serve):
    status, headers, body = fetch(serve() + "/keys")
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    document = json.loads(body)
    with open(os.environ["ACS_GUARDIAN_KEYS"], encoding="utf-8") as f:
        assert document == json.load(f)
    from acs.client import parse_key_document
    keys = parse_key_document(document, key_id="lab-guardian-1", now=datetime.datetime.now(datetime.timezone.utc))
    assert keys.fingerprint == signing_on.fingerprint


def test_a_query_string_still_reaches_keys(signing_on, serve):
    status, _, _ = fetch(serve() + "/keys?format=json")
    assert status == 200


@pytest.mark.parametrize("path", ["/", "/keys/", "/KEYS", "/keys/../keys.json", "/acs"])
def test_other_get_paths_are_404(signing_on, serve, path):
    status, _, body = fetch(serve() + path)
    assert status == 404
    assert b"lab-guardian" not in body


@pytest.mark.parametrize("path", ["/acs", "/keys", "/anything"])
def test_post_still_answers_on_any_path(signing_off, serve, path):
    status, _, body = fetch(serve() + path, data=PING)
    assert status == 200
    assert json.loads(body)["result"]["decision"] == "allow"
