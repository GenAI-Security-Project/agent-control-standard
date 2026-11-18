"""Serve the FinBot lab's read-only decision viewer on localhost (issue #586).

Owner: Rock Lambros. Lab code for the FinBot lab (BUILD_PLAN A.12).

    python labs/finbot/viewer/server.py [--host 127.0.0.1] [--port 8095]

The page polls GET /api/rows?after=<seq> and draws what changed. The one write is POST /api/paint, which appends a
line to ACS_VIEWER_PAINT_LOG for the video shoot, and only when that setting is set.

The viewer binds 127.0.0.1 by default. A localhost bind doesn't stop a page on another site from reaching it through
DNS rebinding, so every request must name a loopback host in its Host header, and a paint must come from the page's
own origin. Only the host name is checked, not the port, since a published container port can differ from the port
the viewer binds inside its container.

Settings: ACS_TRANSCRIPT_DIR (required), ACS_AUDIT_FILE, ACS_GUARDIAN_KEYS with ACS_GUARDIAN_KEY_ID and
ACS_GUARDIAN_KEY_FINGERPRINT, ACS_VIEWER_PAINT_LOG, and ACS_VIEWER_VERIFY_DIR (default: the verify directory beside
the transcript directory).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from beats import BEATS, NO_RECORD_TEXT  # noqa: E402
from model import Model, escape_text, receipt_time  # noqa: E402
from verify import KeySource  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8095
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "[::1]"})
WILDCARD_HOSTS = frozenset({"", "0.0.0.0", "::"})
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8"}
_STATIC_NAME = re.compile(r"[a-z][a-z0-9_-]*\.(?:html|js|css)")
# A client that sends nothing for this long is dropped, so a silent connection can't hold a handler thread (M9).
HANDLER_TIMEOUT_S = 10.0
# A paint is a beat index and a line of text. Anything larger is not from the page.
MAX_PAINT_BYTES = 4096
MAX_PAINT_TEXT = 1000
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "Referrer-Policy": "no-referrer",
}


class ViewerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], model: Model, static_dir: Path, paint_log: Path | None) -> None:
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, ViewerHandler)
        self.model = model
        self.paint_log = paint_log
        # One lock around every read of the logs and every paint, since the model is not thread safe.
        self.lock = threading.Lock()
        # The files served are the ones there at start, looked up by exact name, so no request path reaches the disk.
        self.static_files = {path.name: path for path in Path(static_dir).iterdir()
                             if _STATIC_NAME.fullmatch(path.name) and path.is_file()}
        host = address[0]
        bracketed = f"[{host}]" if ":" in host else host
        self.allowed_names = LOOPBACK_NAMES | ({bracketed.lower()} if host not in WILDCARD_HOSTS else set())


def _host_name(header: str | None) -> str | None:
    if not header:
        return None
    header = header.strip().lower()
    if header.startswith("["):
        end = header.find("]")
        return header[:end + 1] if end > 0 else None
    return header.split(":", 1)[0]


class ViewerHandler(BaseHTTPRequestHandler):
    server: ViewerServer
    server_version = "acs-lab-viewer"
    sys_version = ""
    timeout = HANDLER_TIMEOUT_S

    def log_message(self, format: str, *args: Any) -> None:
        # Request lines carry text any client chose, so none of it reaches a terminal (issue #468).
        return

    def _reply(self, status: int, body: bytes = b"", content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        if status != HTTPStatus.NO_CONTENT:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and status != HTTPStatus.NO_CONTENT:
            self.wfile.write(body)

    def _json(self, status: int, value: Any) -> None:
        self._reply(status, json.dumps(value, ensure_ascii=True).encode("ascii"), "application/json")

    def _host_ok(self) -> bool:
        return _host_name(self.headers.get("Host")) in self.server.allowed_names

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._reply(HTTPStatus.FORBIDDEN, b"forbidden")
            return
        url = urlsplit(self.path)
        if url.path == "/":
            self._static("index.html")
        elif url.path.startswith("/static/"):
            self._static(url.path[len("/static/"):])
        elif url.path == "/api/rows":
            self._rows(url.query)
        else:
            self._reply(HTTPStatus.NOT_FOUND, b"not found")

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._reply(HTTPStatus.FORBIDDEN, b"forbidden")
            return
        if urlsplit(self.path).path != "/api/paint" or self.server.paint_log is None:
            self._reply(HTTPStatus.NOT_FOUND, b"not found")
            return
        if self.headers.get("Origin") != f"http://{self.headers.get('Host')}":
            self._reply(HTTPStatus.FORBIDDEN, b"forbidden")
            return
        self._paint()

    def _static(self, name: str) -> None:
        path = self.server.static_files.get(name)
        if path is None:
            self._reply(HTTPStatus.NOT_FOUND, b"not found")
            return
        try:
            body = path.read_bytes()
        except OSError:
            self._reply(HTTPStatus.NOT_FOUND, b"not found")
            return
        self._reply(HTTPStatus.OK, body, CONTENT_TYPES[path.suffix])

    def _rows(self, query: str) -> None:
        values = parse_qs(query, keep_blank_values=True).get("after", [])
        if len(values) != 1 or not values[0].isdigit():
            self._reply(HTTPStatus.BAD_REQUEST, b"after must be one whole number")
            return
        after = int(values[0])
        model = self.server.model
        with self.server.lock:
            try:
                model.refresh()
            except Exception as e:  # noqa: BLE001
                # A read that breaks leaves the rows already read standing. The page keeps polling.
                sys.stderr.write(f"acs-viewer: reading the logs failed: {escape_text(type(e).__name__)}\n")
            page, next_seq, more = model.page(after)
            body = {"rows": [row.public() for row in page], "next": next_seq, "more": more,
                    "no_record": model.no_record, "no_record_text": NO_RECORD_TEXT,
                    "paint": self.server.paint_log is not None, "dropped": model.drops()}
        self._json(HTTPStatus.OK, body)

    def _paint(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_PAINT_BYTES:
            self._reply(HTTPStatus.BAD_REQUEST, b"bad paint")
            return
        try:
            paint = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            paint = None
        line = _paint_line(paint)
        if line is None:
            self._reply(HTTPStatus.BAD_REQUEST, b"bad paint")
            return
        assert self.server.paint_log is not None
        data = (json.dumps(line, ensure_ascii=True) + "\n").encode("ascii")
        with self.server.lock:
            try:
                fd = os.open(self.server.paint_log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "ab") as f:
                    f.write(data)
            except OSError:
                self._reply(HTTPStatus.INTERNAL_SERVER_ERROR, b"paint log not writable")
                return
        self._reply(HTTPStatus.NO_CONTENT)


def _paint_line(paint: Any) -> dict[str, Any] | None:
    """The paint log line (A.12), stamped with the time it arrived, or None for a body the page never sends."""
    if not isinstance(paint, dict):
        return None
    step, text = paint.get("step"), paint.get("text")
    if step == "end":
        return {"step": "end", "t": receipt_time()}
    if isinstance(step, bool) or not isinstance(step, int) or not 0 <= step < len(BEATS):
        return None
    if not isinstance(text, str) or len(text) > MAX_PAINT_TEXT:
        return None
    return {"step": step, "t": receipt_time(), "text": escape_text(text)}


def make_server(host: str, port: int, model: Model, static_dir: Path, paint_log: Path | None) -> ViewerServer:
    return ViewerServer((host, port), model, static_dir, paint_log)


def serve(httpd: ViewerServer) -> None:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acs-viewer", description="The FinBot lab's read-only decision viewer.")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"address to bind (default {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port to bind (default {DEFAULT_PORT})")
    args = parser.parse_args(argv)
    env = os.environ
    transcripts = env.get("ACS_TRANSCRIPT_DIR", "").strip()
    if not transcripts:
        sys.stderr.write("acs-viewer: ACS_TRANSCRIPT_DIR is not set. It names the gateway's transcript directory\n")
        return 2
    transcript_dir = Path(transcripts)
    audit = env.get("ACS_AUDIT_FILE", "").strip()
    verify_dir = env.get("ACS_VIEWER_VERIFY_DIR", "").strip()
    paint = env.get("ACS_VIEWER_PAINT_LOG", "").strip()
    keys = KeySource(env)
    if keys.configured and keys.current() is None:
        sys.stderr.write("acs-viewer: ACS_GUARDIAN_KEYS can't be used yet, so every row reads not checked until it "
                         "can\n")
    model = Model(transcript_dir, Path(audit) if audit else None, keys,
                  verify_dir=Path(verify_dir) if verify_dir else transcript_dir.parent / "verify")
    httpd = make_server(args.host, args.port, model, STATIC_DIR, Path(paint) if paint else None)
    sys.stdout.write(f"ACS_VIEWER_LISTENING port={httpd.server_address[1]}\n")
    sys.stdout.flush()
    serve(httpd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
