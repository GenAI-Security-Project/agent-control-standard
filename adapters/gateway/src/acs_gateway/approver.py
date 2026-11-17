"""The approver page: pending ASKs held by the gateway, and the one place a person answers them (LAB-08, issue #581).

The page runs on its own port, in the gateway's process and event loop, and is off unless ACS_GATEWAY_APPROVER_PORT
is set. It shows each held call's tool, arguments and the Guardian's question, and takes one answer per call:
approve or reject. Nothing it accepts can change the call itself. The answer goes back to the Guardian, whose next
decision is the only thing that releases the call (D-043).

Tool arguments come from the model and are attacker-controllable, so everything rendered is escaped and the page
runs no script. Answers are POST only and need a token minted with the page, a same-origin Origin header, and a
loopback Host, so another site, or a rebinding name that resolves to 127.0.0.1, can't answer for the approver.
"""
from __future__ import annotations

import asyncio
import hmac
import html
import json
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

CHOICES = ("approve", "reject")
# Names a browser on this machine uses for a loopback listener. The bind host joins them when it isn't a wildcard.
_LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})
_WILDCARDS = frozenset({"", "0.0.0.0", "::"})
# The page reloads itself every few seconds, and each load mints a token, so a form stays valid for a while after
# newer loads. Bounded, so reloads can't grow memory.
_TOKEN_TTL_S = 600.0
_MAX_TOKENS = 256
_MAX_FORM_BYTES = 4096
_REFRESH_S = 3
_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'"),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    # same-origin, so a same-origin POST still carries its Origin header for the check below.
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}


@dataclass
class Pending:
    """One held call waiting for the approver."""
    ask_id: str
    session_id: str
    call_id: str
    tool: str
    arguments: Any
    question: str
    approver_id: str
    deadline: float
    _loop: asyncio.AbstractEventLoop = field(repr=False, compare=False)
    _future: asyncio.Future = field(repr=False, compare=False)
    # Set under the registry lock: the accepted answer, or closed once the wait ended without one.
    answer: str | None = None
    closed: bool = False


class Approvals:
    """The pending ASKs and the page's answer tokens. Safe to answer from any thread or loop."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, Pending] = {}
        self._tokens: OrderedDict[str, float] = OrderedDict()

    async def wait(self, *, session_id: str, call_id: str, tool: str, arguments: Any, question: str,
                   approver_id: str, deadline: float) -> str | None:
        """List the call and wait for an answer until deadline (time.monotonic()). Returns "approve", "reject", or
        None when no answer came in time. The call leaves the page however the wait ends, a cancellation included."""
        loop = asyncio.get_running_loop()
        pending = Pending(secrets.token_urlsafe(16), session_id, call_id, tool, arguments, question, approver_id,
                          deadline, loop, loop.create_future())
        with self._lock:
            self._items[pending.ask_id] = pending
        try:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                try:
                    return await asyncio.wait_for(asyncio.shield(pending._future), remaining)
                except asyncio.TimeoutError:
                    pass
            with self._lock:
                # An answer accepted before the deadline whose wake-up hadn't run yet still counts.
                pending.closed = True
                return pending.answer
        finally:
            with self._lock:
                pending.closed = True
                self._items.pop(pending.ask_id, None)

    def answer(self, ask_id: str, choice: str) -> bool:
        """Record the approver's choice. False when the call isn't pending, was already answered, or its deadline
        passed, so a late click never changes an outcome."""
        if choice not in CHOICES:
            return False
        with self._lock:
            pending = self._items.get(ask_id)
            if (pending is None or pending.closed or pending.answer is not None
                    or time.monotonic() >= pending.deadline):
                return False
            pending.answer = choice

        def settle() -> None:
            if not pending._future.done():
                pending._future.set_result(choice)

        pending._loop.call_soon_threadsafe(settle)
        return True

    def pending(self) -> list[Pending]:
        with self._lock:
            return [p for p in self._items.values() if not p.closed and p.answer is None]

    def mint_token(self) -> str:
        token = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            self._tokens[token] = now + _TOKEN_TTL_S
            while len(self._tokens) > _MAX_TOKENS:
                self._tokens.popitem(last=False)
        return token

    def token_valid(self, token: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            # Compared in constant time against each live token, so timing says nothing about any of them.
            return any(hmac.compare_digest(token.encode(), known.encode()) for known in self._tokens)

    def _expire(self, now: float) -> None:
        while self._tokens and next(iter(self._tokens.values())) <= now:
            self._tokens.popitem(last=False)


def _hostname(host_header: str) -> str:
    """The name part of a Host header, without its port or IPv6 brackets."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _render(approvals: Approvals, notice: str = "") -> str:
    token = approvals.mint_token()
    now = time.monotonic()
    rows = []
    for item in approvals.pending():
        # ensure_ascii shows bidi controls and other invisible characters as escapes, so the approver sees them.
        arguments = json.dumps(item.arguments, indent=2, sort_keys=True, ensure_ascii=True, default=str)
        rows.append(
            "<section>"
            f"<h2>{html.escape(item.tool)}</h2>"
            f"<p class=q>{html.escape(item.question)}</p>"
            f"<p class=meta>Approver {html.escape(item.approver_id)}. "
            f"{max(0, int(item.deadline - now))} seconds left, then the call is denied.</p>"
            f"<pre>{html.escape(arguments)}</pre>"
            '<form method="post" action="/answer">'
            f'<input type="hidden" name="id" value="{html.escape(item.ask_id)}">'
            f'<input type="hidden" name="token" value="{html.escape(token)}">'
            '<button name="choice" value="approve">Approve</button> '
            '<button name="choice" value="reject">Reject</button>'
            "</form></section>")
    body = "".join(rows) or "<p>No action is waiting for approval.</p>"
    # A token goes on the page even with nothing pending, so a reload always carries a fresh one.
    return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
            f'<meta http-equiv="refresh" content="{_REFRESH_S}">'
            "<title>ACS approver</title><style>"
            "body{font:15px system-ui,sans-serif;margin:2rem;max-width:48rem}"
            "section{border:1px solid #999;border-radius:6px;padding:1rem;margin:1rem 0}"
            "pre{background:#f4f4f4;padding:.5rem;overflow-x:auto;white-space:pre-wrap}"
            ".meta{color:#555}button{font-size:1rem;margin-right:.5rem}"
            "</style></head><body><h1>Actions waiting for approval</h1>"
            f"<p>{html.escape(notice)}</p>{body}"
            f'<form hidden><input name="token" value="{html.escape(token)}"></form>'
            "</body></html>")


def create_approver_app(approvals: Approvals, bind_host: str = "127.0.0.1") -> Starlette:
    """GET / lists the pending calls. POST /answer takes one choice. Lab convention until issue #175 defines how an
    approver's answer reaches the Guardian."""
    allowed_hosts = set(_LOOPBACK_NAMES)
    if bind_host.strip().lower() not in _WILDCARDS:
        allowed_hosts.add(_hostname(bind_host))

    def refuse(status: int, message: str) -> Response:
        return HTMLResponse(f"<!doctype html><title>ACS approver</title><p>{html.escape(message)}</p>",
                            status_code=status, headers=_HEADERS)

    def local(request: Request) -> bool:
        return _hostname(request.headers.get("host", "")) in allowed_hosts

    async def index(request: Request) -> Response:
        if not local(request):
            return refuse(403, "This page answers on a loopback address only.")
        return HTMLResponse(_render(approvals), headers=_HEADERS)

    async def answer(request: Request) -> Response:
        if not local(request):
            return refuse(403, "This page answers on a loopback address only.")
        if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
            return refuse(403, "Answers come from this page only.")
        # Browsers send Origin on every POST, so a missing one isn't a browser on this page.
        expected = f"{request.url.scheme}://{request.headers.get('host', '')}".lower()
        if request.headers.get("origin", "").lower() != expected:
            return refuse(403, "Answers come from this page only.")
        raw = await request.body()
        if len(raw) > _MAX_FORM_BYTES:
            return refuse(400, "The form is too large.")
        try:
            form = parse_qs(raw.decode("ascii"), keep_blank_values=True, strict_parsing=True)
        except (UnicodeDecodeError, ValueError):
            return refuse(400, "The form can't be read.")
        if set(form) - {"id", "choice", "token"} or any(len(v) != 1 for v in form.values()):
            return refuse(400, "The form carries a field this page doesn't take.")
        if not approvals.token_valid(form.get("token", [""])[0]):
            return refuse(403, "This page has expired. Reload it and answer again.")
        choice = form.get("choice", [""])[0]
        if choice not in CHOICES:
            return refuse(400, "The answer must be approve or reject.")
        if not approvals.answer(form.get("id", [""])[0], choice):
            return refuse(409, "That action is no longer waiting. It was answered, or its time ran out.")
        return RedirectResponse("/", status_code=303, headers=_HEADERS)

    return Starlette(routes=[Route("/", index, methods=["GET"]), Route("/answer", answer, methods=["POST"])])
