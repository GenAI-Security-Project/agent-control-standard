"""The real-OPA fixture's health probe, tested without an opa binary.

A stub stands in for OPA's /health and /v1/config, so these run everywhere, unlike test_guardian_real_opa.py.
"""
from __future__ import annotations

import http.server
import json
import threading

import pytest

import opa_process


class _Alive:
    """Stands in for a running process."""
    returncode = None

    def poll(self):
        return None


@pytest.fixture
def fake_opa():
    """A stub answering /health with 200 and /v1/config with a probe label. Yields (port, set_label)."""
    state = {"label": "mine"}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                payload = b"{}"
            else:
                payload = json.dumps({"result": {"labels": {"probe": state["label"]}}}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], lambda label: state.update(label=label)
    server.shutdown()
    server.server_close()


def test_the_probe_ignores_proxy_variables(fake_opa, monkeypatch):
    port, _ = fake_opa
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    assert opa_process.healthy(port, _Alive(), "mine", deadline_s=3)


def test_the_probe_rejects_another_listener(fake_opa):
    # A 200 from /health isn't enough: the listener on the port has to be the OPA this fixture started.
    port, set_label = fake_opa
    set_label("someone-else")
    assert not opa_process.healthy(port, _Alive(), "mine", deadline_s=1)
