"""FinBot's own API, as the scenario driver calls it (issue #589, LAB-16 Task 4). Standard library only.

Version 1.0.0. Owner: Rock Lambros.

Facts from GenAI-Security-Project/finbot-ctf at 1450fc4 (reports/LAB-16-finbot-facts.md):

- GET /api/session/status gives a temporary session, its namespace and its CSRF token (finbot/main.py:222-234). The
  cookie finbot_session can rotate, so every Set-Cookie goes into one http.cookiejar (finbot/core/auth/middleware.py).
- POST, PUT, DELETE and PATCH need X-CSRF-Token (finbot/core/auth/csrf.py:24, :120). DELETE does too.
- FinBot hashes User-Agent, Accept-Language and Accept-Encoding into the session. A temporary session whose hash
  changes is replaced by a new one in an empty namespace with no error (finbot/core/auth/session.py:458-491), so every
  request sends the same three values.
- A chat answers as text/event-stream and ends with data: {"type": "done"} (finbot/agents/chat.py:503). An exception
  ends the stream without it, so a stream with no done marker is a failed chat.

Every read is capped at MAX_READ bytes, and a larger answer is refused rather than cut short, because a cut JSON body
can't be parsed and a cut stream would read as a failed chat. Every route comes from finbot_routes, the table the
scenario tests pin, so the driver can't call a route those tests never saw. Nothing here prints. The driver escapes
every FinBot string through report.escape before it reaches the terminal.
"""
from __future__ import annotations

import http.cookiejar
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

import finbot_routes as routes

BASE_URL = "http://finbot:8000"
MAX_READ = 1024 * 1024
REQUEST_TIMEOUT_S = 30.0
# One chat may wait on several model calls, each bounded by FinBot's LLM_TIMEOUT of 360 seconds (compose.yaml), so a
# single read gets the driver's whole done bound.
STREAM_TIMEOUT_S = 420.0
# The fingerprint FinBot pins to the session. Fixed values, sent on every request. identity keeps bodies unencoded,
# so the byte cap counts what the driver parses.
FINGERPRINT_HEADERS = {"User-Agent": "acs-lab-driver/1", "Accept-Language": "en-US", "Accept-Encoding": "identity"}
# FinBot's session cookie (finbot/config.py SESSION_COOKIE_NAME).
SESSION_COOKIE = "finbot_session"
UNSAFE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})
_DETAIL_CHARS = 200


class FinBotError(Exception):
    """FinBot didn't answer as its API says it does. The message holds FinBot text, so callers escape it."""


@dataclass(frozen=True)
class ChatResult:
    done: bool
    text: str


def _read_capped(response: Any, limit: int) -> bytes:
    data = response.read(limit + 1)
    if len(data) > limit:
        raise FinBotError(f"FinBot's answer is larger than {limit} bytes")
    return data


class FinBot:
    """One FinBot session: its cookie jar, its CSRF token and its namespace."""

    def __init__(self, base_url: str = BASE_URL, *, max_read: int = MAX_READ,
                 timeout: float = REQUEST_TIMEOUT_S) -> None:
        self.base_url = base_url.rstrip("/")
        self.max_read = max_read
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        # No proxy handler entries: FinBot sits on the internal drive-net, and a proxy from the environment would
        # carry the session cookie somewhere else.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                   urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf: str | None = None
        self.namespace: str | None = None

    def open_session(self) -> str:
        """Starts the session, keeps its cookie and CSRF token, and returns its namespace."""
        status = self.call(routes.SESSION_STATUS)
        csrf, namespace = status.get("csrf_token") if isinstance(status, dict) else None, None
        if isinstance(status, dict):
            namespace = status.get("namespace")
        if not (isinstance(csrf, str) and csrf and isinstance(namespace, str) and namespace):
            raise FinBotError("FinBot's session status has no CSRF token or namespace")
        self.csrf, self.namespace = csrf, namespace
        return namespace

    def current_namespace(self) -> str:
        """The namespace the cookie maps to now. A change since open_session means FinBot swapped the session."""
        status = self.call(routes.SESSION_STATUS)
        namespace = status.get("namespace") if isinstance(status, dict) else None
        if not isinstance(namespace, str):
            raise FinBotError("FinBot's session status has no namespace")
        return namespace

    def _request(self, route: tuple[str, str], body: Any, query: dict[str, Any] | None,
                 path_values: dict[str, Any]) -> urllib.request.Request:
        method, template = route
        if route not in routes.ROUTES:
            raise FinBotError(f"{method} {template} is not a route the scenario tests pin")
        url = self.base_url + routes.fill(template, **path_values)
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = dict(FINGERPRINT_HEADERS)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif method in UNSAFE_METHODS:
            data = b""
        if method in UNSAFE_METHODS:
            if self.csrf is None:
                raise FinBotError("no FinBot session yet, so no CSRF token")
            headers["X-CSRF-Token"] = self.csrf
        return urllib.request.Request(url, data=data, method=method, headers=headers)

    def _open(self, request: urllib.request.Request, timeout: float) -> Any:
        try:
            return self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as e:
            try:
                detail = e.read(_DETAIL_CHARS * 4).decode("utf-8", errors="replace")[:_DETAIL_CHARS]
            except OSError:
                detail = ""
            finally:
                e.close()
            raise FinBotError(f"FinBot answered {request.get_method()} {urllib.parse.urlsplit(request.full_url).path} "
                              f"with HTTP {e.code}: {detail}") from None
        except (urllib.error.URLError, OSError) as e:
            raise FinBotError(f"FinBot didn't answer ({getattr(e, 'reason', e)})") from None

    def call(self, route: tuple[str, str], *, body: Any = None, query: dict[str, Any] | None = None,
             **path_values: Any) -> Any:
        """One request on a pinned route, its JSON answer parsed."""
        request = self._request(route, body, query, path_values)
        with self._open(request, self.timeout) as response:
            data = _read_capped(response, self.max_read)
        try:
            return json.loads(data) if data else None
        except ValueError:
            raise FinBotError(f"FinBot's answer to {route[0]} {route[1]} isn't JSON") from None

    def chat(self, surface: str, message: str, *, timeout: float = STREAM_TIMEOUT_S) -> ChatResult:
        """Sends one chat message and reads the stream to its done marker, within timeout and MAX_READ."""
        route = routes.step_route({"kind": "chat", "surface": surface})
        request = self._request(route, {"message": message}, None, {})
        deadline = time.monotonic() + timeout
        tokens: list[str] = []
        total = 0
        with self._open(request, timeout) as response:
            while time.monotonic() < deadline:
                line = response.readline(self.max_read + 1)
                if not line:
                    break
                total += len(line)
                if total > self.max_read:
                    raise FinBotError(f"FinBot's chat stream is larger than {self.max_read} bytes")
                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                # Lines starting with a colon are SSE comments, FinBot's keepalives (chat.py:406).
                if not text.startswith("data:"):
                    continue
                try:
                    event = json.loads(text[5:].strip())
                except ValueError:
                    continue
                if not isinstance(event, dict):
                    continue
                if event.get("type") == "done":
                    return ChatResult(True, "".join(tokens))
                if event.get("type") == "token" and isinstance(event.get("content"), str):
                    tokens.append(event["content"])
        return ChatResult(False, "".join(tokens))
