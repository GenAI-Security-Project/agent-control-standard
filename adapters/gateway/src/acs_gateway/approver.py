"""The approver page: pending ASKs held by the gateway, and the one place a person answers them (LAB-08, issue #581).

The page runs on its own port, in the gateway's process and event loop, and is off unless ACS_GATEWAY_APPROVER_PORT
is set. It shows each held call's tool, arguments, the Guardian's question and context, and takes one answer per
call: approve or reject. Nothing it accepts can change the call itself. An approval goes back to the Guardian, whose
next decision is the only thing that releases the call (D-043).

The page releases held tool calls, so it needs the secret in ACS_GATEWAY_APPROVER_TOKEN_FILE, sent as a bearer token
or entered once on the page and kept in a same-site cookie. A local process or a sibling container can claim any
Host and Origin, so the secret is the control. The browser checks stay as a second layer: an answer is POST only and
needs a same-origin Origin, a loopback Host, and a token minted with the page that covers only the calls that page
showed, once each.

Tool arguments come from the model and are attacker-controllable, so everything rendered is escaped, invisible and
bidirectional characters show as \\uXXXX escapes, and the page runs no script.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import secrets
import threading
import time
import unicodedata
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

CHOICES = ("approve", "reject")
# What wait() returns when no answer came in time. Any other non-choice value is the cause a stop check gave.
TIMEOUT = "timeout"
COOKIE = "acs_approver"
# Names a browser on this machine uses for a loopback listener. The bind host joins them when it isn't a wildcard.
_LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})
_WILDCARDS = frozenset({"", "0.0.0.0", "::"})
# The page reloads itself every few seconds, and each load mints a token, so a form stays valid for a while after
# newer loads. Bounded, so reloads can't grow memory.
_TOKEN_TTL_S = 600.0
_MAX_TOKENS = 256
_MAX_FORM_BYTES = 4096
_REFRESH_S = 3
# How often a held call checks whether its request still stands (a disconnect, an epoch bump, a retirement).
_STOP_POLL_S = 0.2
# Characters with no visible glyph of their own, or that reorder text, by Unicode category: controls, format
# characters (bidi overrides, zero-width joiners), private use, surrogates, unassigned, and line or paragraph breaks.
_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"})
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
    context: str | None
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
        # token -> (expiry, the ask_ids its page showed and that it hasn't answered yet)
        self._tokens: OrderedDict[str, tuple[float, set[str]]] = OrderedDict()

    async def wait(self, *, session_id: str, call_id: str, tool: str, arguments: Any, question: str,
                   approver_id: str, deadline: float, context: str | None = None,
                   stop: Callable[[], Awaitable[str | None]] | None = None) -> str:
        """List the call and wait for an answer until deadline (time.monotonic()).

        Returns "approve" or "reject", TIMEOUT when no answer came in time, or the cause stop() gave when the request
        stopped standing first. The call leaves the page however the wait ends, a cancellation included.
        """
        loop = asyncio.get_running_loop()
        pending = Pending(secrets.token_urlsafe(16), session_id, call_id, tool, arguments, question, approver_id,
                          context, deadline, loop, loop.create_future())
        with self._lock:
            self._items[pending.ask_id] = pending
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    return await asyncio.wait_for(asyncio.shield(pending._future), min(remaining, _STOP_POLL_S))
                except asyncio.TimeoutError:
                    pass
                cause = await stop() if stop is not None else None
                if cause is not None:
                    with self._lock:
                        if pending.answer is None:
                            pending.closed = True
                            return cause
                    return pending.answer
            with self._lock:
                # An answer accepted before the deadline whose wake-up hadn't run yet still counts.
                pending.closed = True
                return pending.answer or TIMEOUT
        finally:
            with self._lock:
                pending.closed = True
                self._items.pop(pending.ask_id, None)

    def answer(self, ask_id: str, choice: str) -> bool:
        """Record the approver's choice. False when the call isn't pending, was already answered, or its deadline
        passed, so a late click never changes an outcome."""
        with self._lock:
            return self._answer(ask_id, choice)

    def submit(self, token: str, ask_id: str, choice: str) -> int:
        """An answer from the page: 303 when taken, 403 when the token is unknown, expired, or doesn't cover this
        call, and 409 when the call is no longer waiting. A token answers each call its page showed once."""
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            covered = next((ids for known, (_, ids) in self._tokens.items()
                            if hmac.compare_digest(token.encode(), known.encode())), None)
            if covered is None or ask_id not in covered:
                return 403
            if not self._answer(ask_id, choice):
                return 409
            covered.discard(ask_id)
            return 303

    def _answer(self, ask_id: str, choice: str) -> bool:
        if choice not in CHOICES:
            return False
        pending = self._items.get(ask_id)
        if pending is None or pending.closed or pending.answer is not None or time.monotonic() >= pending.deadline:
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

    def mint_token(self, ask_ids: Iterable[str]) -> str:
        """A token that may answer the given calls, once each."""
        token = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            self._tokens[token] = (now + _TOKEN_TTL_S, set(ask_ids))
            while len(self._tokens) > _MAX_TOKENS:
                self._tokens.popitem(last=False)
        return token

    def _expire(self, now: float) -> None:
        while self._tokens and next(iter(self._tokens.values()))[0] <= now:
            self._tokens.popitem(last=False)


def visible(text: str) -> str:
    """text with every invisible or reordering character written as a \\uXXXX escape, then HTML-escaped, so a label
    can't hide characters or reverse what the approver reads."""
    shown = "".join(
        (f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}")
        if unicodedata.category(ch) in _HIDDEN_CATEGORIES or (unicodedata.category(ch) == "Zs" and ch != " ")
        else ch
        for ch in text)
    return html.escape(shown)


def _hostname(host_header: str) -> str:
    """The name part of a Host header, without its port or IPv6 brackets."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


_STYLE = ("body{font:15px system-ui,sans-serif;margin:2rem;max-width:48rem}"
          "section{border:1px solid #999;border-radius:6px;padding:1rem;margin:1rem 0}"
          "pre{background:#f4f4f4;padding:.5rem;overflow-x:auto;white-space:pre-wrap}"
          ".meta{color:#555}button{font-size:1rem;margin-right:.5rem}")


def _document(body: str, refresh: bool) -> str:
    meta = f'<meta http-equiv="refresh" content="{_REFRESH_S}">' if refresh else ""
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>{meta}<title>ACS approver</title>"
            f"<style>{_STYLE}</style></head><body>{body}</body></html>")


def _render(approvals: Approvals) -> str:
    items = approvals.pending()
    token = approvals.mint_token(p.ask_id for p in items)
    now = time.monotonic()
    rows = []
    for item in items:
        # ensure_ascii shows bidi controls and other invisible characters as escapes, so the approver sees them.
        arguments = json.dumps(item.arguments, indent=2, sort_keys=True, ensure_ascii=True, default=str)
        context = f"<p>{visible(item.context)}</p>" if item.context else ""
        rows.append(
            "<section>"
            f"<h2>{visible(item.tool)}</h2>"
            f"<p class=q>{visible(item.question)}</p>{context}"
            f"<p class=meta>Approver {visible(item.approver_id)}. "
            f"{max(0, int(item.deadline - now))} seconds left, then the call is denied.</p>"
            f"<pre>{html.escape(arguments)}</pre>"
            '<form method="post" action="/answer">'
            f'<input type="hidden" name="id" value="{html.escape(item.ask_id)}">'
            f'<input type="hidden" name="token" value="{html.escape(token)}">'
            '<button name="choice" value="approve">Approve</button> '
            '<button name="choice" value="reject">Reject</button>'
            "</form></section>")
    body = "".join(rows) or "<p>No action is waiting for approval.</p>"
    return _document(f"<h1>Actions waiting for approval</h1>{body}", refresh=True)


def _login_page(message: str = "") -> str:
    note = f"<p>{html.escape(message)}</p>" if message else ""
    return _document("<h1>ACS approver</h1>" + note +
                     '<form method="post" action="/login"><label>Approver secret '
                     '<input type="password" name="secret" autocomplete="current-password"></label> '
                     "<button>Open</button></form>", refresh=False)


def create_approver_app(approvals: Approvals, secret: str, bind_host: str = "127.0.0.1") -> Starlette:
    """GET / lists the pending calls, POST /answer takes one choice, POST /login trades the secret for a cookie.

    Lab convention until issue #175 defines how an approver's answer reaches the Guardian.
    """
    allowed_hosts = set(_LOOPBACK_NAMES)
    if bind_host.strip().lower() not in _WILDCARDS:
        allowed_hosts.add(_hostname(bind_host))
    bearer = f"Bearer {secret}".encode("utf-8")
    # The cookie carries a value derived from the secret, never the secret itself, and changes when the secret does.
    session_value = hmac.new(secret.encode("utf-8"), b"acs-approver-cookie", hashlib.sha256).hexdigest()

    def refuse(status: int, message: str) -> Response:
        return HTMLResponse(_document(f"<p>{html.escape(message)}</p>", refresh=False), status_code=status,
                            headers=_HEADERS)

    def local(request: Request) -> bool:
        return _hostname(request.headers.get("host", "")) in allowed_hosts

    def authenticated(request: Request) -> bool:
        given = request.headers.get("authorization", "").encode("utf-8")
        cookie = request.cookies.get(COOKIE, "").encode("utf-8")
        return hmac.compare_digest(given, bearer) or hmac.compare_digest(cookie, session_value.encode())

    def same_origin(request: Request) -> bool:
        if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
            return False
        # Browsers send Origin on every POST, so a missing one isn't a browser on this page.
        expected = f"{request.url.scheme}://{request.headers.get('host', '')}".lower()
        return request.headers.get("origin", "").lower() == expected

    async def form(request: Request, fields: set[str]) -> dict[str, str] | Response:
        raw = await request.body()
        if len(raw) > _MAX_FORM_BYTES:
            return refuse(400, "The form is too large.")
        try:
            parsed = parse_qs(raw.decode("ascii"), keep_blank_values=True, strict_parsing=True)
        except (UnicodeDecodeError, ValueError):
            return refuse(400, "The form can't be read.")
        if set(parsed) - fields or any(len(v) != 1 for v in parsed.values()):
            return refuse(400, "The form carries a field this page doesn't take.")
        return {k: v[0] for k, v in parsed.items()}

    async def index(request: Request) -> Response:
        if not local(request):
            return refuse(403, "This page answers on a loopback address only.")
        if not authenticated(request):
            return HTMLResponse(_login_page(), status_code=401, headers=_HEADERS)
        return HTMLResponse(_render(approvals), headers=_HEADERS)

    async def login(request: Request) -> Response:
        if not local(request):
            return refuse(403, "This page answers on a loopback address only.")
        if not same_origin(request):
            return refuse(403, "Sign in from this page only.")
        fields = await form(request, {"secret"})
        if isinstance(fields, Response):
            return fields
        if not hmac.compare_digest(fields.get("secret", "").encode("utf-8"), secret.encode("utf-8")):
            return HTMLResponse(_login_page("That secret is wrong."), status_code=401, headers=_HEADERS)
        response = RedirectResponse("/", status_code=303, headers=_HEADERS)
        response.set_cookie(COOKIE, session_value, httponly=True, samesite="strict", path="/")
        return response

    async def answer(request: Request) -> Response:
        if not local(request):
            return refuse(403, "This page answers on a loopback address only.")
        if not authenticated(request):
            return refuse(401, "Open the page with the approver secret first.")
        if not same_origin(request):
            return refuse(403, "Answers come from this page only.")
        fields = await form(request, {"id", "choice", "token"})
        if isinstance(fields, Response):
            return fields
        choice = fields.get("choice", "")
        if choice not in CHOICES:
            return refuse(400, "The answer must be approve or reject.")
        status = approvals.submit(fields.get("token", ""), fields.get("id", ""), choice)
        if status == 403:
            return refuse(403, "This page has expired, or didn't show that action. Reload it and answer again.")
        if status == 409:
            return refuse(409, "That action is no longer waiting. It was answered, or its time ran out.")
        return RedirectResponse("/", status_code=303, headers=_HEADERS)

    return Starlette(routes=[Route("/", index, methods=["GET"]), Route("/login", login, methods=["POST"]),
                             Route("/answer", answer, methods=["POST"])])
