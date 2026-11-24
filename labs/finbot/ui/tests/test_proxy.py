"""ui/proxy.py: loopback-only forwarding to one fixed upstream, with streamed bodies (2026-11-24 lab videos)."""
import http.client
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scenarios"))

import proxy  # noqa: E402


class Upstream(BaseHTTPRequestHandler):
    seen: list = []
    fingerprints: list = []

    def do_GET(self):
        Upstream.seen.append((self.command, self.path, self.headers.get("Host"), None))
        Upstream.fingerprints.append((self.headers.get("Accept-Language"), self.headers.get("Accept-Encoding")))
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for n in range(3):
                self.wfile.write(f"data: {n}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.05)
            return
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "finbot_session=abc; HttpOnly; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        Upstream.seen.append((self.command, self.path, self.headers.get("Host"), self.rfile.read(length)))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        return


@pytest.fixture
def stack():
    Upstream.seen = []
    Upstream.fingerprints = []
    up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    proxy.Handler.upstream = ("127.0.0.1", up.server_address[1])
    front = ThreadingHTTPServer(("127.0.0.1", 0), proxy.Handler)
    front.daemon_threads = True
    threading.Thread(target=front.serve_forever, daemon=True).start()
    yield front.server_address[1]
    front.shutdown()
    up.shutdown()


def request(port, method, path, host="localhost:8097", body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest(method, path, skip_host=True)
    conn.putheader("Host", host)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    return conn.getresponse()


def test_a_request_reaches_finbot_with_its_host_and_cookie(stack):
    r = request(stack, "GET", "/vendor/assistant")
    assert (r.status, r.read()) == (200, b"hello")
    assert r.getheader("Set-Cookie") == "finbot_session=abc; HttpOnly; Path=/"
    assert Upstream.seen == [("GET", "/vendor/assistant", "localhost:8097", None)]


def test_a_post_body_goes_through(stack):
    assert request(stack, "POST", "/vendor/api/v1/chat", body=b'{"message": "hi"}').status == 204
    assert Upstream.seen[-1][3] == b'{"message": "hi"}'


def test_a_stream_arrives_whole(stack):
    r = request(stack, "GET", "/stream")
    assert r.getheader("Content-Type") == "text/event-stream"
    assert r.read() == b"data: 0\n\ndata: 1\n\ndata: 2\n\n"


@pytest.mark.parametrize("host", ["evil.example.com", "evil.example.com:8097", ""])
def test_a_non_loopback_host_is_refused(stack, host):
    assert request(stack, "GET", "/", host=host).status == 421
    assert Upstream.seen == []


def test_an_absolute_target_is_refused_and_never_followed(stack):
    assert request(stack, "GET", "http://example.com/").status == 400
    assert Upstream.seen == []


@pytest.mark.parametrize("header, name", [("localhost:8097", "localhost"), ("[::1]:8097", "[::1]"),
                                          ("LOCALHOST", "localhost"), ("127.0.0.1", "127.0.0.1")])
def test_host_name_drops_the_port(header, name):
    assert proxy.host_name(header) == name


def test_the_browser_carries_the_drivers_fingerprint(stack):
    conn = http.client.HTTPConnection("127.0.0.1", stack, timeout=5)
    conn.request("GET", "/vendor/assistant", headers={"Host": "localhost:8097", "Accept-Language": "fr-CA,fr;q=0.9",
                                                      "Accept-Encoding": "gzip, br"})
    conn.getresponse().read()
    assert Upstream.fingerprints == [("en-US", "identity")]
    import finbot_client
    assert {k: finbot_client.FINGERPRINT_HEADERS[k] for k in proxy.FINGERPRINT} == proxy.FINGERPRINT
