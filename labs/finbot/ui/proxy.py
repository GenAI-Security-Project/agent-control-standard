"""Forward a browser on the host to FinBot's own web UI, which publishes no port (C-17).

Owner: Rock Lambros. Version 0.1.0. Lab code for the FinBot lab, added 2026-11-24 for the lab videos, which type the
attack into FinBot's real chat page.

    python labs/finbot/ui/proxy.py [--host 0.0.0.0] [--port 8097] [--upstream finbot:8000]

FinBot sits on internal networks only, so Docker publishes nothing from it. This proxy joins one of them (drive-net)
and one network Docker can publish from, and forwards every request to the one fixed upstream. It never reads a
target from the request, so it gives FinBot, and anything else on drive-net, no route anywhere but back to FinBot.

A loopback bind doesn't stop a page on another site from reaching it through DNS rebinding, so a request must name a
loopback host in its Host header, as the decision viewer requires. The Host goes to FinBot unchanged, so FinBot's
same-origin and CSRF checks see the origin the browser sees. Responses stream through unbuffered, since FinBot's chat
answers as text/event-stream.
"""
from __future__ import annotations

import argparse
import http.client
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "[::1]"})
# Hop-by-hop headers (RFC 9110 7.6.1) belong to one connection, so they are not forwarded either way.
HOP_BY_HOP = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
                        "transfer-encoding", "upgrade", "proxy-connection"})
MAX_BODY = 10 * 1024 * 1024
# A chat can think for minutes on a live model (FinBot's LLM_TIMEOUT is 360 s in compose.yaml).
UPSTREAM_TIMEOUT_S = 400.0
CHUNK = 4096


def host_name(host_header: str) -> str:
    """The host name in a Host header, without its port, lowercased."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[: host.find("]") + 1] if "]" in host else host
    return host.rsplit(":", 1)[0] if ":" in host else host


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.0 with Connection: close, so a streamed body ends when the connection does and needs no re-chunking.
    protocol_version = "HTTP/1.0"
    server_version = "acs-lab-finbot-ui"
    upstream: tuple[str, int] = ("finbot", 8000)

    def _refuse(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _forward(self) -> None:
        if host_name(self.headers.get("Host", "")) not in LOOPBACK_NAMES:
            self._refuse(421, "this proxy answers only a loopback host name")
            return
        # Only origin-form targets: an absolute URI would name a host, and this proxy names its own.
        if not self.path.startswith("/"):
            self._refuse(400, "the request target must be a path")
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY or "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            self._refuse(413 if length > MAX_BODY else 400, "the request body must have a length of at most 10 MiB")
            return
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        conn = http.client.HTTPConnection(*self.upstream, timeout=UPSTREAM_TIMEOUT_S)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            response = conn.getresponse()
            self.send_response(response.status, response.reason)
            for name, value in response.getheaders():
                if name.lower() not in HOP_BY_HOP and name.lower() != "content-length":
                    self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            while chunk := response.read1(CHUNK):
                self.wfile.write(chunk)
                self.wfile.flush()
        except (OSError, http.client.HTTPException):
            # Headers may be out already, so the only safe signal left is closing the connection.
            if not self.wfile.closed:
                try:
                    self._refuse(502, "FinBot did not answer")
                except OSError:
                    pass
        finally:
            conn.close()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _forward

    def log_message(self, format: str, *args) -> None:
        # Request lines carry FinBot's paths and query strings, which can name a vendor. Nothing is logged.
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8097)
    parser.add_argument("--upstream", default="finbot:8000", help="host:port of FinBot's web app")
    args = parser.parse_args(argv)
    up_host, _, up_port = args.upstream.rpartition(":")
    if not up_host or not up_port.isdigit():
        parser.error("--upstream must be host:port")
    Handler.upstream = (up_host, int(up_port))
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(f"ACS_FINBOT_UI_LISTENING port={server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
