"""A fake FinBot, gateway admin port and approver page for the scenario driver's tests (issue #589, LAB-16).

Version 1.0.0. Owner: Rock Lambros. Stdlib http.server on free loopback ports, plus the gateway's own log writers.

The FinBot side follows the facts in reports/LAB-16-finbot-facts.md, read in GenAI-Security-Project/finbot-ctf at
1450fc4: the session cookie and CSRF token from GET /api/session/status (finbot/main.py:222), the CSRF check on POST,
PUT, DELETE and PATCH (finbot/core/auth/csrf.py:24), the fingerprint pin that swaps a temporary session for an empty
namespace when User-Agent, Accept-Language or Accept-Encoding change (finbot/core/auth/session.py:458-491), the chat
stream's end marker (finbot/agents/chat.py:503), and the Dark Lab tool PUT that returns 404 until a GET creates the
server row (finbot/apps/darklab/routes/api.py:75-126).

The gateway side writes what the real gateway writes, through its own code: audit lines through acs.client's
audit_event and model input lines through acs_gateway's ModelInputLog. So a format change there turns these tests red.
The admin port answers POST /epoch with a bearer token and ends every open session, as the gateway does on an epoch
bump (rehearsal R9). The approver page renders forms the way acs_gateway.approver does and holds an answer to the same
rules: bearer, loopback Host, same-origin Origin, and a page token that covers the call once.
"""
from __future__ import annotations

import html
import json
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

TESTS = Path(__file__).resolve().parent
SCENARIOS = TESTS.parent
BUNDLE = SCENARIOS.parent
REPO_ROOT = BUNDLE.parents[1]
for _path in (SCENARIOS, BUNDLE / "cli", BUNDLE / "modules" / "checks", REPO_ROOT / "adapters" / "gateway" / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from acs.client import audit_event  # noqa: E402
from acs_gateway.transcript import ModelInputLog  # noqa: E402

COOKIE = "finbot_session"
CSRF_HEADER = "x-csrf-token"
FINGERPRINT = ("user-agent", "accept-language", "accept-encoding")
UNSAFE = {"POST", "PUT", "DELETE", "PATCH"}
# audit_event reads ACS_AUDIT_FILE from the process environment, so writers take turns.
_AUDIT_LOCK = threading.Lock()


@dataclass
class Seen:
    """One request a fake server took, in arrival order across all three servers."""
    server: str
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes
    at: float
    status: int = 0
    # Wall time, so a test can compare a request with the record's whole-second timestamps.
    wall: float = field(default_factory=time.time)


@dataclass
class FakeLab:
    bundle: Path
    admin_token: str = "admin-token-for-tests"
    approver_token: str = "approver-token-for-tests"
    csrf: str = "csrf-token-for-tests"
    # How long model input lines keep arriving after a registration or an invoice, as the orchestrator runs on.
    background_s: float = 0.3
    chat_done: bool = True
    reply: str = "Payment notice sent to the vendor."
    # When set, an invoice holds one call for the approver, and the background work waits for the answer.
    ask_on_invoice: bool = False
    # When set, a rejected held call is retried once as a new held call, as FinBot's agent retried the transfer in
    # the s4a__reject recording (2026-11-24). The background work waits for both answers.
    ask_again_on_reject: bool = False
    # When set, the dead drop answers with more than the driver's 1 MiB read limit once a chat has run, so the
    # baseline before the steps reads normally and the evidence probe after them meets the oversized answer.
    huge_dead_drop: bool = False
    # Seconds the first dead drop read stalls before answering, as FinBot did with its database locked (2026-11-24).
    stall_first_dead_drop_s: float = 0.0
    seen: list[Seen] = field(default_factory=list)
    epoch: int = 0
    namespaces: dict[str, str] = field(default_factory=dict)
    fingerprints: dict[str, tuple[str, ...]] = field(default_factory=dict)
    hijacks: int = 0
    open_sessions: list[str] = field(default_factory=list)
    chat_sessions: list[str] = field(default_factory=list)
    history: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: {"vendor": [], "copilot": []})
    servers: set[str] = field(default_factory=set)
    overrides: dict[str, Any] = field(default_factory=dict)
    pending: dict[str, str | None] = field(default_factory=dict)
    page_tokens: dict[str, set[str]] = field(default_factory=dict)
    answers: list[dict[str, str]] = field(default_factory=list)
    last_model_input: float = 0.0
    # darklab api.py:215-234 parses each address list from JSON, so every message carries all three lists.
    dead_drop: list[dict[str, Any]] = field(default_factory=lambda: [
        {"id": 7, "subject": "Vendor data", "to_addresses": ["collector@exfil.example"],
         "cc_addresses": [], "bcc_addresses": ["audit@exfil.example"], "created_at": "2026-11-25T10:15:02Z"}])
    inbox: list[dict[str, Any]] = field(default_factory=lambda: [
        {"id": 3, "subject": "Welcome, Northwind Supplies", "to_addresses": ["ap@northwind-supplies.example"]}])
    transactions: list[dict[str, Any]] = field(default_factory=list)
    # Probe switches for the review's paths. gap_s pauses a background agent between two of its model calls, as a
    # slow upstream call or a Guardian decision does on a live run.
    gap_s: float = 0.0
    replay_miss_on_chat: bool = False
    # A replay miss logged while setup's vendor registration runs, before the run's window opens (2026-11-24 premortem).
    replay_miss_on_register: bool = False
    # The capture stem, as compose.capture.yaml hands it to the real gateway, which appends one recording line per
    # exchange it records. Set by a test that runs a capture, so the driver sees each call recorded.
    capture: str | None = None
    # Every recording the driver asked the gateway to replay from, None for all of them, in order.
    replay_selected: list[str | None] = field(default_factory=list)
    move_namespace_after_chat: bool = False
    approver_fails: bool = False
    no_assistant_reply: bool = False
    agent_done: dict[str, float] = field(default_factory=dict)
    # The nth POST /epoch (1-based) answers 500, as a gateway that went down mid-run would.
    fail_epoch_on: int | None = None
    epoch_calls: int = 0
    # Bytes of one audit line written during a chat, to push the run's window past the driver's read limit.
    huge_audit_on_chat: int = 0
    # Seconds the approver page takes to answer while a call is held: a slow poll that still succeeds (P7).
    approver_delay_s: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    # -- the gateway's logs, written by the gateway's own code ---------------------------------------------------

    def audit(self, event: str, **fields: Any) -> None:
        with _AUDIT_LOCK:
            old = os.environ.get("ACS_AUDIT_FILE")
            os.environ["ACS_AUDIT_FILE"] = str(self.bundle / "state" / "audit.log")
            try:
                audit_event(event, **fields)
            finally:
                if old is None:
                    os.environ.pop("ACS_AUDIT_FILE", None)
                else:
                    os.environ["ACS_AUDIT_FILE"] = old

    def model_input(self, body: dict[str, Any]) -> None:
        ModelInputLog(self.bundle / "state" / "model-inputs.jsonl").append(body)
        if self.capture is not None:
            recordings = self.bundle / "replay" / "recordings"
            recordings.mkdir(parents=True, exist_ok=True)
            with (recordings / f"{self.capture}.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps({"scenario": self.capture}) + "\n")
        self.last_model_input = time.monotonic()

    def open_session(self) -> str:
        session_id = str(uuid.uuid4())
        with self.lock:
            self.open_sessions.append(session_id)
        self.audit("session_opened", session_id=session_id, epoch=self.epoch, handshake="Negotiated", cause=None,
                   guardian_url="http://acs-guardian:8787/")
        self.transcript(session_id, "handshake/hello")
        return session_id

    def transcript(self, session_id: str, method: str) -> None:
        """One line in the session's transcript, as the gateway writes one per envelope."""
        directory = self.bundle / "state" / "transcripts"
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / f"{session_id}.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps({"dir": "req", "envelope": {"method": method}}) + "\n")

    def bump_epoch(self) -> int:
        with self.lock:
            self.epoch += 1
            epoch = self.epoch
            dropped, self.open_sessions = self.open_sessions, []
        self.audit("epoch_bumped", epoch=epoch)

        def end() -> None:
            # The gateway sends sessionEnd after the bump answers, so the lines land a moment later (app.py:295-301).
            time.sleep(0.05)
            for session_id in dropped:
                self.transcript(session_id, "steps/sessionEnd")
                self.audit("session_ended", session_id=session_id, reason="cancelled", cause=None,
                           request_id=str(uuid.uuid4()))

        threading.Thread(target=end, daemon=True).start()
        return epoch

    def background(self, label: str, *, wait_for_answer: str | None = None) -> None:
        """Model traffic from a background agent: one session, input lines for background_s seconds."""
        def work() -> None:
            session_id = self.open_session()
            if wait_for_answer is not None:
                deadline = time.monotonic() + 10
                while self.pending.get(wait_for_answer) is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                if self.ask_again_on_reject and self.pending.get(wait_for_answer) == "reject":
                    again = uuid.uuid4().hex
                    self.pending[again] = None
                    while self.pending.get(again) is None and time.monotonic() < deadline:
                        time.sleep(0.02)
            self.model_input({"agent": label, "session": session_id, "turn": "first"})
            if self.gap_s:
                time.sleep(self.gap_s)
            end = time.monotonic() + self.background_s
            n = 0
            while True:
                self.model_input({"agent": label, "session": session_id, "turn": n})
                n += 1
                if time.monotonic() >= end:
                    break
                time.sleep(0.05)
            self.agent_done[label] = time.monotonic()

        threading.Thread(target=work, daemon=True).start()

    # -- what the tests read ----------------------------------------------------------------------------------------

    def finbot_requests(self) -> list[Seen]:
        return [s for s in self.seen if s.server == "finbot"]

    def index(self, server: str, method: str, path: str, *, last: bool = False) -> int:
        hits = [i for i, s in enumerate(self.seen) if s.server == server and s.method == method and s.path == path]
        if not hits:
            return -1
        return hits[-1] if last else hits[0]


def _json(handler: BaseHTTPRequestHandler, status: int, value: Any, extra: dict[str, str] | None = None) -> None:
    data = json.dumps(value).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    for key, val in (extra or {}).items():
        handler.send_header(key, val)
    handler.end_headers()
    handler.wfile.write(data)


def _cookie(headers: dict[str, str]) -> str | None:
    for part in headers.get("cookie", "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE:
            return value
    return None


def _handler(lab: FakeLab, server: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _take(self) -> Seen:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            parts = urlsplit(self.path)
            seen = Seen(server, self.command, parts.path, parts.query, {k.lower(): v for k, v in self.headers.items()},
                        body, time.monotonic())
            with lab.lock:
                lab.seen.append(seen)
            return seen

        def do_GET(self) -> None:
            self._dispatch()

        def do_POST(self) -> None:
            self._dispatch()

        def do_PUT(self) -> None:
            self._dispatch()

        def do_DELETE(self) -> None:
            self._dispatch()

        def _dispatch(self) -> None:
            seen = self._take()
            if server == "finbot":
                self._finbot(seen)
            elif server == "admin":
                self._admin(seen)
            else:
                self._approver(seen)

        # -- FinBot ---------------------------------------------------------------------------------------------

        def _finbot(self, seen: Seen) -> None:
            cookie = _cookie(seen.headers)
            fingerprint = tuple(seen.headers.get(h, "") for h in FINGERPRINT)
            set_cookie: dict[str, str] = {}
            if cookie is None or cookie not in lab.namespaces or lab.fingerprints.get(cookie) != fingerprint:
                if cookie in lab.namespaces:
                    # session.py:458-491: a changed fingerprint on a temporary session starts a new namespace.
                    lab.hijacks += 1
                cookie = uuid.uuid4().hex
                lab.namespaces[cookie] = f"ns_user_{uuid.uuid4().hex[:12]}"
                lab.fingerprints[cookie] = fingerprint
                set_cookie = {"Set-Cookie": f"{COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Lax"}
            if seen.method in UNSAFE and seen.headers.get(CSRF_HEADER) != lab.csrf:
                seen.status = 403
                _json(self, 403, {"detail": "CSRF token missing or invalid"}, set_cookie)
                return
            body = json.loads(seen.body) if seen.body else None
            route = (seen.method, seen.path)
            seen.status = 200
            if route == ("GET", "/api/session/status"):
                if lab.move_namespace_after_chat and lab.chat_sessions:
                    lab.namespaces[cookie] = "ns_user_moved"
                _json(self, 200, {"csrf_token": lab.csrf, "namespace": lab.namespaces[cookie], "user_id": "u1",
                                  "is_temporary": True}, set_cookie)
            elif route == ("POST", "/vendor/api/v1/vendors/register"):
                if lab.replay_miss_on_register:
                    lab.audit("replay_miss", recording_dir="/lab/replay/recordings", reason="no_recording")
                lab.background("onboarding")
                _json(self, 200, {"success": True, "vendor_id": 1, "workflow_id": "wf_1"}, set_cookie)
            elif route == ("GET", "/vendor/api/v1/vendors/1"):
                _json(self, 200, {"id": 1, "company_name": "Northwind Supplies", "status": "active"}, set_cookie)
            elif route == ("POST", "/vendor/api/v1/invoices"):
                ask = None
                if lab.ask_on_invoice:
                    ask = uuid.uuid4().hex
                    lab.pending[ask] = None
                lab.background("invoice", wait_for_answer=ask)
                _json(self, 200, {"success": True, "invoice": {"id": 1, "amount": body["amount"],
                                                               "status": "submitted"}}, set_cookie)
            elif route == ("GET", "/vendor/api/v1/invoices/1"):
                _json(self, 200, {"invoice": {"id": 1, "status": "approved"}}, set_cookie)
            elif route == ("GET", "/vendor/api/v1/payments/transactions"):
                _json(self, 200, {"transactions": lab.transactions, "total_count": len(lab.transactions)}, set_cookie)
            elif route == ("GET", "/vendor/api/v1/messages"):
                _json(self, 200, {"messages": lab.inbox}, set_cookie)
            elif route == ("GET", "/darklab/api/v1/toolkit/dead-drop"):
                if lab.stall_first_dead_drop_s:
                    stall, lab.stall_first_dead_drop_s = lab.stall_first_dead_drop_s, 0.0
                    time.sleep(stall)
                if lab.huge_dead_drop and lab.chat_sessions:
                    _json(self, 200, {"messages": [{"body": "x" * (2 * 1024 * 1024)}]}, set_cookie)
                else:
                    _json(self, 200, {"messages": lab.dead_drop}, set_cookie)
            elif seen.method == "POST" and seen.path in ("/vendor/api/v1/chat", "/admin/api/v1/copilot/chat"):
                self._chat("vendor" if seen.path.startswith("/vendor") else "copilot", body, set_cookie)
            elif seen.method in ("GET", "DELETE") and seen.path in ("/vendor/api/v1/chat/history",
                                                                     "/admin/api/v1/copilot/history"):
                surface = "vendor" if seen.path.startswith("/vendor") else "copilot"
                if seen.method == "DELETE":
                    count = len(lab.history[surface])
                    lab.history[surface] = []
                    _json(self, 200, {"success": True, "messages_deleted": count}, set_cookie)
                else:
                    _json(self, 200, {"messages": lab.history[surface]}, set_cookie)
            elif seen.method == "GET" and seen.path.startswith("/darklab/api/v1/supply-chain/servers/"):
                name = seen.path.rsplit("/", 1)[1]
                lab.servers.add(name)
                _json(self, 200, {"server": {"server_type": name}}, set_cookie)
            elif seen.method == "PUT" and seen.path.endswith("/tools"):
                name = seen.path.split("/")[-2]
                if name not in lab.servers:
                    seen.status = 404
                    _json(self, 404, {"detail": "MCP server not found"}, set_cookie)
                    return
                lab.overrides[name] = body["tool_overrides"]
                _json(self, 200, {"success": True}, set_cookie)
            else:
                seen.status = 404
                _json(self, 404, {"detail": "Not Found"}, set_cookie)

        def _chat(self, surface: str, body: dict[str, Any], set_cookie: dict[str, str]) -> None:
            session_id = lab.open_session()
            lab.chat_sessions.append(session_id)
            lab.model_input({"surface": surface, "message": body["message"], "session": session_id})
            if lab.huge_audit_on_chat:
                lab.audit("model_override_skipped", padding="x" * lab.huge_audit_on_chat)
            if lab.replay_miss_on_chat:
                lab.audit("replay_miss", recording_dir="/lab/replay/recordings", reason="no_recording")
            lab.history[surface] += [{"id": 1, "role": "user", "content": body["message"]}]
            if not lab.no_assistant_reply:
                lab.history[surface] += [{"id": 2, "role": "assistant", "content": lab.reply}]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            for key, val in set_cookie.items():
                self.send_header(key, val)
            self.end_headers()
            self.wfile.write(b": keepalive\n\n")
            self.wfile.write(f"data: {json.dumps({'type': 'status', 'content': 'Thinking'})}\n\n".encode())
            self.wfile.write(f"data: {json.dumps({'type': 'token', 'content': lab.reply})}\n\n".encode())
            if lab.chat_done:
                self.wfile.write(f"data: {json.dumps({'type': 'done'})}\n\n".encode())
            self.wfile.flush()
            self.close_connection = True

        # -- the gateway's admin port ---------------------------------------------------------------------------

        def _admin(self, seen: Seen) -> None:
            if seen.method != "POST" or seen.path not in ("/epoch", "/replay"):
                seen.status = 404
                _json(self, 404, {"error": "not found"})
                return
            if seen.headers.get("authorization") != f"Bearer {lab.admin_token}":
                seen.status = 401
                _json(self, 401, {"error": "unauthorized"})
                return
            if seen.path == "/replay":
                scenario = json.loads(seen.body)["scenario"]
                lab.replay_selected.append(scenario)
                seen.status = 200
                _json(self, 200, {"scenario": scenario})
                return
            lab.epoch_calls += 1
            if lab.epoch_calls == lab.fail_epoch_on:
                seen.status = 500
                _json(self, 500, {"error": "gateway down"})
                return
            seen.status = 200
            _json(self, 200, {"epoch": lab.bump_epoch()})

        # -- the approver page ----------------------------------------------------------------------------------

        def _approver(self, seen: Seen) -> None:
            host = seen.headers.get("host", "")
            if lab.approver_fails:
                return self._page(seen, 500, "Internal Server Error")
            if lab.approver_delay_s and any(choice is None for choice in lab.pending.values()):
                time.sleep(lab.approver_delay_s)
            if host.rsplit(":", 1)[0] not in ("127.0.0.1", "localhost"):
                return self._page(seen, 403, "This page answers on a loopback address only.")
            if seen.headers.get("authorization") != f"Bearer {lab.approver_token}":
                return self._page(seen, 401, "<form action=/login>secret</form>")
            if (seen.method, seen.path) == ("GET", "/"):
                waiting = [a for a, choice in lab.pending.items() if choice is None]
                token = uuid.uuid4().hex
                lab.page_tokens[token] = set(waiting)
                rows = "".join(
                    '<section><h2>finstripe__create_transfer</h2><form method="post" action="/answer">'
                    f'<input type="hidden" name="id" value="{html.escape(a)}">'
                    f'<input type="hidden" name="token" value="{html.escape(token)}">'
                    '<button name="choice" value="approve">Approve</button> '
                    '<button name="choice" value="reject">Reject</button></form></section>' for a in waiting)
                return self._page(seen, 200, rows or "<p>No action is waiting for approval.</p>")
            if (seen.method, seen.path) == ("POST", "/answer"):
                if seen.headers.get("origin", "").lower() != f"http://{host}".lower():
                    return self._page(seen, 403, "Answers come from this page only.")
                form = {k: v[0] for k, v in parse_qs(seen.body.decode("ascii"), strict_parsing=True).items()}
                covered = lab.page_tokens.get(form.get("token", ""))
                if covered is None or form.get("id") not in covered:
                    return self._page(seen, 403, "This page has expired.")
                if lab.pending.get(form["id"], "gone") is not None:
                    return self._page(seen, 409, "That action is no longer waiting.")
                covered.discard(form["id"])
                lab.pending[form["id"]] = form["choice"]
                lab.answers.append({**form, "host": host, "origin": seen.headers.get("origin", "")})
                seen.status = 303
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            return self._page(seen, 404, "not found")

        def _page(self, seen: Seen, status: int, body: str) -> None:
            seen.status = status
            data = f"<!doctype html><html><body>{body}</body></html>".encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


class FakeServers:
    """FinBot, the admin port and the approver page, each on its own free loopback port."""

    def __init__(self, lab: FakeLab) -> None:
        self.lab = lab
        self._servers = {name: ThreadingHTTPServer(("127.0.0.1", 0), _handler(lab, name))
                         for name in ("finbot", "admin", "approver")}
        for srv in self._servers.values():
            srv.daemon_threads = True
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def port(self, name: str) -> int:
        return self._servers[name].server_address[1]

    def close(self) -> None:
        for srv in self._servers.values():
            srv.shutdown()
            srv.server_close()
