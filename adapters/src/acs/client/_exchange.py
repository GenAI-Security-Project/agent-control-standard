"""One Guardian round trip: POST a signed request and classify what came back, with no side effects."""
from __future__ import annotations

import http.client
import json
import socket
import threading
import urllib.error
import urllib.request
from dataclasses import replace
from typing import Any

from acs.client._config import FailPosture, Resolution
from acs.client._outcome import Decided, Outcome, Refused, Undecided
from acs.client._signing import sign_envelope, verify_signature
from acs.client._urls import validate_guardian_url
from acs.core import MAX_REQUEST_BODY_BYTES, guardian_error_cause, is_guardian_refusal, response_matches_request


class RequestTooLargeError(Exception):
    """The envelope exceeds the Guardian's body cap; checked before sending, since a 413 can arrive as a connection reset."""


# Statuses that refuse the request when the body carries no JSON-RPC envelope.
HTTP_REFUSAL_STATUSES = frozenset({400, 413})


class GuardianHTTPError(Exception):
    """A non-2xx answer; body is the decoded JSON, or None."""

    def __init__(self, status: int, body: Any):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}")


def is_jsonrpc_response(body: Any) -> bool:
    """True for a JSON-RPC 2.0 response: "jsonrpc": "2.0", and a result or error, each present one an object."""
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
        return False
    members = [body[k] for k in ("result", "error") if k in body]
    return bool(members) and all(isinstance(m, dict) for m in members)


def post(request: dict[str, Any], *, guardian_url: str, timeout_s: float) -> Any:
    """POST the request and return the decoded JSON body; raises on oversize, a non-2xx status, transport failure or bad JSON."""
    body = json.dumps(request).encode("utf-8")
    if len(body) > MAX_REQUEST_BODY_BYTES:
        raise RequestTooLargeError(len(body))
    req = urllib.request.Request(
        guardian_url, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    # A socket timeout bounds each read, not the exchange, so the §6.4 deadline waits on a worker and then shuts its sockets.
    done, aborter, box = threading.Event(), _Aborter(), {}

    def fetch() -> None:
        _worker.aborter = aborter
        try:
            box["value"] = _fetch(req, timeout_s, aborter)
        except BaseException as e:  # noqa: BLE001
            box["error"] = e
        finally:
            aborter.release()
            done.set()

    worker = threading.Thread(target=fetch, name="acs-exchange", daemon=True)
    worker.start()
    if not done.wait(timeout_s):
        aborter.abort()
        raise TimeoutError(f"no complete response within {timeout_s:g}s")
    if "error" in box:
        raise box["error"]
    return box["value"]


class _Aborter:
    """The exchange's sockets, held as duplicates because TLS wrapping detaches the original, shut down together at the deadline."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sockets: list[socket.socket] = []
        self.aborted = threading.Event()

    def add(self, sock: socket.socket) -> None:
        with self._lock:
            if not self.aborted.is_set():
                self._sockets.append(sock.dup())
                return
        sock.close()
        raise TimeoutError("the exchange passed its deadline")

    def abort(self) -> None:
        with self._lock:
            self.aborted.set()
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def release(self) -> None:
        with self._lock:
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            sock.close()


_worker = threading.local()


def _create_connection(*args: Any, **kwargs: Any) -> socket.socket:
    sock = socket.create_connection(*args, **kwargs)
    aborter = getattr(_worker, "aborter", None)
    if aborter is not None:
        aborter.add(sock)
    return sock


class _HTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _create_connection


class _HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _create_connection


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(_HTTPConnection, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: urllib.request.Request) -> Any:
        kwargs: dict[str, Any] = {"context": self._context}
        if hasattr(self, "_check_hostname"):
            kwargs["check_hostname"] = self._check_hostname
        return self.do_open(_HTTPSConnection, req, **kwargs)


def _open(req: urllib.request.Request, timeout: float) -> Any:
    """Send through the environment's proxies on abortable connections; a redirect is an HTTP error, not a new request."""
    opener = urllib.request.OpenerDirector()
    for handler in (urllib.request.ProxyHandler(), _HTTPHandler(), _HTTPSHandler(),
                    urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        opener.add_handler(handler)
    return opener.open(req, timeout=timeout)


def _fetch(req: urllib.request.Request, timeout_s: float, aborter: _Aborter) -> Any:
    cancelled = aborter.aborted
    try:
        with _open(req, timeout=timeout_s) as resp:
            raw = _read(resp, cancelled)
    except urllib.error.HTTPError as e:
        try:
            parsed = json.loads(_read(e, cancelled).decode("utf-8"))
        except Exception:  # noqa: BLE001
            parsed = None
        raise GuardianHTTPError(e.code, parsed) from e
    return json.loads(raw.decode("utf-8"))


def _read(resp: Any, cancelled: threading.Event) -> bytes:
    """Read the body one socket read at a time until the deadline."""
    read1 = getattr(resp, "read1", None)
    if read1 is None:
        return resp.read()
    chunks = []
    while not cancelled.is_set():
        chunk = read1(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def round_trip(request: dict[str, Any], *, guardian_url: str, posture: FailPosture,
               session_id: str | None) -> Decided | Resolution:
    """Sign the request as the last step before sending, exchange it within its method's timeout, and resolve anything but a usable decision with the posture."""
    try:
        sign_envelope(request, session_id=session_id)
    except Exception as e:  # noqa: BLE001
        return posture.resolve(Undecided("adapter_exception", {"error": str(e)}, f"adapter error: {e}"))
    outcome = exchange(request, guardian_url=guardian_url,
                       timeout_s=posture.timeout_for(request.get("method", "")), session_id=session_id)
    return outcome if isinstance(outcome, Decided) else posture.resolve(outcome)


def exchange(request: dict[str, Any], *, guardian_url: str, timeout_s: float,
             session_id: str | None) -> Outcome:
    """POST one request and classify the answer; never raises."""
    params = request.get("params") or {}
    method, request_id = request.get("method"), params.get("request_id")
    try:
        validate_guardian_url(guardian_url)
    except ValueError as e:
        return Undecided("guardian_url_rejected", {"method": method, "error": str(e)},
                         f"Guardian URL rejected: {e}")
    http_status = None
    try:
        response = post(request, guardian_url=guardian_url, timeout_s=timeout_s)
    except RequestTooLargeError as e:
        return Refused("request_exceeds_max_payload", {"body_bytes": e.args[0], "method": method},
                       f"envelope exceeds body cap: {e}")
    except GuardianHTTPError as e:
        if not is_jsonrpc_response(e.body):
            fields = {"http_status": e.status, "method": method}
            if e.status in HTTP_REFUSAL_STATUSES:
                return Refused(f"http_{e.status}_refusal", fields, f"Guardian refused at HTTP layer ({e.status})")
            return Undecided(f"http_{e.status}_error", fields, f"Guardian returned HTTP {e.status}")
        # A JSON-RPC envelope gets the same binding and signature checks under any status.
        response, http_status = e.body, e.status
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        timed_out = isinstance(e, TimeoutError) or isinstance(getattr(e, "reason", None), TimeoutError)
        fields = {"request_id": request_id, "method": method, "error": str(e)}
        if timed_out:
            return Undecided("decision_timeout", fields, f"decision timed out after {timeout_s:g}s: {e}")
        return Undecided("transport_failure", fields, f"Guardian unreachable: {e}")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return Undecided("malformed_response", {"request_id": request_id, "method": method, "error": str(e)},
                         f"Guardian response is not JSON: {e}")
    except Exception as e:  # noqa: BLE001
        return Undecided("adapter_exception", {"error": str(e)}, f"adapter error: {e}")
    try:
        outcome = classify_response(request, response, session_id=session_id)
    except Exception as e:  # noqa: BLE001
        outcome = Refused("response_unverifiable", {"request_id": request_id, "method": method, "error": str(e)},
                          f"Guardian response could not be verified: {e}")
    if http_status is None or isinstance(outcome, Decided):
        return outcome
    return replace(outcome, fields={**outcome.fields, "http_status": http_status})


def classify_response(request: dict[str, Any], response: Any, *, session_id: str | None) -> Outcome:
    """Classify a decoded Guardian answer; mis-bound or unverifiable answers and refusal codes fail closed."""
    params = request.get("params") or {}
    method, request_id = request.get("method"), params.get("request_id")
    if not is_jsonrpc_response(response):
        return Undecided("malformed_response", {"request_id": request_id, "method": method},
                         "Guardian response is not a JSON-RPC 2.0 response with an object result or error")
    if not response_matches_request(request, response):
        claimed = response["error"].get("code") if "error" in response else None
        return Refused("response_binding_mismatch",
                       {"claimed_error_code": claimed} if claimed is not None else {},
                       "response not bound to request")
    if "error" in response:
        err = response["error"]
        code = err.get("code")
        # Errors are signed too; an unverifiable error under fail-open would be an allow.
        if not verify_signature(response, session_id=session_id):
            return Refused("error_signature_invalid",
                           {"claimed_error_code": code, "claimed_cause": guardian_error_cause(code)},
                           "error response signature invalid")
        cause = guardian_error_cause(code)
        fields = {"error_code": code, "error_message": err.get("message"),
                  "request_id": request_id, "method": method}
        message = f"Guardian returned JSON-RPC error {code} ({cause}): {err.get('message', '')}"
        if is_guardian_refusal(code):
            return Refused(cause, fields, message)
        return Undecided(cause, fields, message)
    if not verify_signature(response, session_id=session_id):
        return Refused("response_signature_invalid", {}, "response signature invalid")
    return Decided(response)
