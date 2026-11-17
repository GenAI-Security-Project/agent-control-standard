from __future__ import annotations

import copy
import http.client
import json
import math
import re
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from acs.client._audit import audit_event
from acs.client._config import FailPosture, Resolution
from acs.client._outcome import Decided, Outcome, Refused, Undecided
from acs.client._signing import sign_envelope, verify_signature
from acs.client._urls import validate_guardian_url
from acs.core import (
    BINDING_REQUEST,
    BINDING_SHAPE,
    MAX_REQUEST_BODY_BYTES,
    guardian_error_cause,
    is_guardian_refusal,
    modify_composition_violation,
    normalize_decision,
    request_binding_problem,
    response_binding_problem,
    response_shape_problem,
    schemas_dir,
)

if TYPE_CHECKING:
    from acs.client._key_document import ResponseKeys

# Called with "req" and the signed request just before it is sent, and with "resp" and every decoded
# answer before it is classified (PREMORTEM P6). It gets a deep copy, so it can't change what is sent
# or judged. No "resp" call means no answer arrived, and the outcome's cause says why.
OnWire = Callable[[str, Any], None]


def report_on_wire(on_wire: OnWire | None, direction: str, envelope: Any, method: Any) -> dict[str, Any] | None:
    """Hand a copy of the envelope to on_wire. When the callback raises, audit it and return the failure's fields."""
    if on_wire is None:
        return None
    try:
        on_wire(direction, copy.deepcopy(envelope))
    except Exception as e:  # noqa: BLE001
        # A record of the exchange the caller asked for is missing, so the step must not go on as if it existed.
        fields = {"dir": direction, "method": method, "error": str(e)}
        audit_event("on_wire_failed", **fields)
        return fields
    return None


def keyring_verified(response: Any, request: Mapping[str, Any], response_keys: ResponseKeys) -> bool:
    """Whether the answer verifies under the key document's pinned key, as the answer to request.

    The key comes from the document by key_id (issue #308, RFC 8725 section 3.1). The envelope's
    algorithm never selects it, and D-026 applies per key_id: an exact match, no fallback. The
    answer must also answer request (D-029), and an HMAC signature never passes. It must also
    carry the hash of request's signed input, since one key signs every session and ids alone
    let an answer be relayed between sessions (lab convention, issue #13 is the closest issue).
    """
    # The lazy public export loads cryptography only on this path.
    import acs.core
    return acs.core.verify_with_keyring(response, response_keys.keyring, expected_key_id=response_keys.key_id,
                                        request=request, require_request_digest=True)


def _response_verified(response: dict[str, Any], request: Mapping[str, Any], session_id: str | None,
                       response_keys: ResponseKeys | None) -> bool:
    """The step exchange's one signature check: the key document's pinned key with response_keys, else HMAC."""
    if response_keys is None:
        return verify_signature(response, session_id=session_id)
    return keyring_verified(response, request, response_keys)


def _on_wire_refusal(fields: dict[str, Any]) -> Refused:
    return Refused("on_wire_failed", fields, f"on_wire callback failed on {fields['dir']}: {fields['error']}")


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


_MAX_SAFE_INTEGER = 2**53 - 1
_SURROGATE = re.compile("[\ud800-\udfff]")


class _KeyCollision(ValueError):
    pass


def _signable(value: Any, replaced: dict[str, int]) -> Any:
    if isinstance(value, str):
        value, n = _SURROGATE.subn("\ufffd", value)
        if n:
            replaced["lone_surrogates"] = replaced.get("lone_surrogates", 0) + n
        return value
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) and abs(value) > _MAX_SAFE_INTEGER:
        replaced["unsafe_integers"] = replaced.get("unsafe_integers", 0) + 1
        return str(value)
    if isinstance(value, float) and not math.isfinite(value):
        replaced["non_finite_numbers"] = replaced.get("non_finite_numbers", 0) + 1
        return str(value)
    if isinstance(value, dict):
        normalized: dict[Any, Any] = {}
        for key, item in value.items():
            signed_key = _signable(key, replaced)
            if signed_key in normalized:
                # The signed view would drop one of the two values.
                raise _KeyCollision(f"two keys normalize to {signed_key!r}")
            normalized[signed_key] = _signable(item, replaced)
        return normalized
    if isinstance(value, list):
        return [_signable(v, replaced) for v in value]
    return value


def _normalize(request: dict[str, Any]) -> str | None:
    """Replace what RFC 8785 cannot encode (lone surrogates, integers past 2**53 - 1, NaN and infinities) so the
    Guardian still sees the step; return why the request cannot be signed when two keys would become one."""
    replaced: dict[str, int] = {}
    try:
        params = _signable(request.get("params"), replaced)
    except RecursionError:
        return None
    except _KeyCollision as e:
        return str(e)
    if replaced:
        request["params"] = params
        audit_event("envelope_normalized", method=request.get("method"),
                    request_id=(params or {}).get("request_id"), **replaced)
    return None


def round_trip(request: dict[str, Any], *, guardian_url: str, posture: FailPosture,
               session_id: str | None, gate: bool = False, response_keys: ResponseKeys | None = None,
               on_wire: OnWire | None = None) -> Decided | Resolution:
    """Sign, exchange within the method's timeout, and resolve anything but a usable decision with the posture; on a gate an unsignable request fails closed.

    response_keys and on_wire go to exchange() unchanged. Both default to None, which is today's path.
    """
    collision = _normalize(request)
    try:
        if collision is not None:
            raise ValueError(collision)
        sign_envelope(request, session_id=session_id)
    except Exception as e:  # noqa: BLE001
        outcome = Undecided("envelope_not_signable", {"error": str(e)}, f"envelope not signable: {e}")
        return (posture.closed() if gate else posture).resolve(outcome)
    outcome = exchange(request, guardian_url=guardian_url,
                       timeout_s=posture.timeout_for(request.get("method", "")), session_id=session_id,
                       response_keys=response_keys, on_wire=on_wire)
    if not isinstance(outcome, Decided):
        return posture.resolve(outcome)
    result = outcome.response.get("result")
    try:
        problem = result_problem(result)
    except Exception as e:  # noqa: BLE001
        problem = f"result could not be checked: {e}"
    if problem is None:
        return outcome
    params = request.get("params") or {}
    fields = {"method": request.get("method"), "request_id": params.get("request_id"), "problem": problem}
    message = f"Guardian response fails response-envelope.json: {problem}"
    if normalize_decision(result).disposition == "allow":
        return posture.resolve(Undecided("malformed_response", fields, message))
    # A restrictive or unreadable verdict is never carried out as an allow.
    return posture.resolve(Refused("malformed_response", fields, message))


_RESULT_VALIDATOR: Any = None


def _result_validator() -> Any:
    """A validator for response-envelope.json's AcsResult, resolving its references against the bundled schemas."""
    global _RESULT_VALIDATOR
    if _RESULT_VALIDATOR is None:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource

        resources = []
        for path in schemas_dir().glob("*.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            if "$id" in schema:
                resources.append((schema["$id"], Resource.from_contents(schema)))
        registry = Registry().with_resources(resources)
        envelope = json.loads((schemas_dir() / "response-envelope.json").read_text(encoding="utf-8"))
        _RESULT_VALIDATOR = Draft202012Validator({"$ref": f"{envelope['$id']}#/$defs/AcsResult"}, registry=registry,
                                                 format_checker=Draft202012Validator.FORMAT_CHECKER)
    return _RESULT_VALIDATOR


def result_problem(result: Any) -> str | None:
    """Why a decision result fails response-envelope.json's AcsResult, or None."""
    from jsonschema.exceptions import best_match

    errors = list(_result_validator().iter_errors(result))
    if not errors:
        return None
    if (isinstance(result, dict) and result.get("decision") == "modify"
            and all(e.absolute_path and e.absolute_path[0] == "modifications" for e in errors)
            and modify_composition_violation(result.get("modifications"))):
        # §6.3 makes this a DENY the adapter applies, which trace/otel-mapping.json does not count as a decision failure.
        return None
    error = best_match(errors)
    where = "/".join(str(p) for p in error.absolute_path)
    return f"{where}: {error.message}" if where else error.message


def exchange(request: dict[str, Any], *, guardian_url: str, timeout_s: float,
             session_id: str | None, response_keys: ResponseKeys | None = None,
             on_wire: OnWire | None = None) -> Outcome:
    """POST one request and classify the answer; never raises.

    With response_keys, every answer must verify under the key document's pinned key (issue #576).
    on_wire sees the signed request before it is sent and every decoded answer before it is
    classified. A callback that raises refuses the step, and on "req" nothing is sent.
    """
    # A request no answer could bind is the adapter's own error. The rule's own request check
    # refuses it here, before any I/O and before anything below reads it, so exchange() never
    # raises on it.
    problem = request_binding_problem(request)
    if problem is not None:
        return Refused("request_envelope_invalid", {"error": problem},
                       f"request can't bind a Guardian answer: {problem}")
    params = request.get("params") or {}
    method, request_id = request.get("method"), params.get("request_id")
    try:
        validate_guardian_url(guardian_url)
    except ValueError as e:
        return Undecided("guardian_url_rejected", {"method": method, "error": str(e)},
                         f"Guardian URL rejected: {e}")
    failed = report_on_wire(on_wire, "req", request, method)
    if failed is not None:
        return _on_wire_refusal(failed)
    http_status, reported = None, False
    try:
        response = post(request, guardian_url=guardian_url, timeout_s=timeout_s)
    except RequestTooLargeError as e:
        return Refused("request_exceeds_max_payload", {"body_bytes": e.args[0], "method": method},
                       f"envelope exceeds body cap: {e}")
    except GuardianHTTPError as e:
        # Any decoded body is an answer that arrived, so on_wire sees it whatever its shape.
        if e.body is not None:
            reported = True
            failed = report_on_wire(on_wire, "resp", e.body, method)
            if failed is not None:
                return _on_wire_refusal(failed)
        # The rule's own shape check: a body that isn't a JSON-RPC answer stays an HTTP outcome.
        if response_shape_problem(e.body) is not None:
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
    if not reported:
        failed = report_on_wire(on_wire, "resp", response, method)
        if failed is not None:
            return _on_wire_refusal(failed)
    try:
        outcome = classify_response(request, response, session_id=session_id, response_keys=response_keys)
    except Exception as e:  # noqa: BLE001
        outcome = Refused("response_unverifiable", {"request_id": request_id, "method": method, "error": str(e)},
                          f"Guardian response could not be verified: {e}")
    if http_status is None or isinstance(outcome, Decided):
        return outcome
    return replace(outcome, fields={**outcome.fields, "http_status": http_status})


def key_id_rejected(error: Any) -> bool:
    """An unsigned SIGNATURE_INVALID error: how a Guardian answers a key_id it holds no secret for (§10)."""
    return isinstance(error, dict) and error.get("code") == -32004 and "signature" not in error


def claims_json_rpc_answer(body: Any) -> bool:
    """A JSON-RPC 2.0 object whose result or error, each present one, is an object: the shape accepted before the binding rule."""
    if not isinstance(body, Mapping) or body.get("jsonrpc") != "2.0":
        return False
    members = [body[k] for k in ("result", "error") if k in body]
    return bool(members) and all(isinstance(m, Mapping) for m in members)


def classify_response(request: dict[str, Any], response: Any, *, session_id: str | None,
                      response_keys: ResponseKeys | None = None) -> Outcome:
    """Classify a decoded Guardian answer; mis-bound or unverifiable answers and refusal codes fail closed.

    With response_keys, every signature is checked under the key document's pinned key instead of HMAC.
    """
    # The one binding rule decides. A request it can't accept is the caller's error, so nothing
    # here reads the request until the rule has.
    binding = response_binding_problem(request, response)
    if binding == BINDING_REQUEST:
        return Refused("request_envelope_invalid", {}, "request can't bind a Guardian answer")
    params = request.get("params")
    # An error binds by id alone, so params may still be anything here.
    params = params if isinstance(params, Mapping) else {}
    method, request_id = request.get("method"), params.get("request_id")
    # A malformed response is undecided, so the fail posture applies, as for a transport
    # failure. Any other reason refuses the step. A JSON-RPC answer the rule rejects only for a
    # method or for carrying both members is refused, since its signature is never checked and
    # altering a signed answer this way must not let an attacker choose the fail posture.
    if binding == BINDING_SHAPE:
        if claims_json_rpc_answer(response):
            return Refused("response_shape_invalid", {"request_id": request_id, "method": method},
                           "Guardian response is a JSON-RPC answer with a method or with both a result and an error")
        return Undecided("malformed_response", {"request_id": request_id, "method": method},
                         "Guardian response is not a JSON-RPC 2.0 response with exactly one object result or "
                         "error and no method")
    if binding is not None:
        error = response.get("error") if isinstance(response, Mapping) else None
        claimed = error.get("code") if isinstance(error, Mapping) else None
        return Refused("response_binding_mismatch",
                       {"claimed_error_code": claimed} if claimed is not None else {},
                       "response not bound to request")
    if "error" in response:
        err = response["error"]
        code = err.get("code")
        # Errors are signed too; an unverifiable error under fail-open would be an allow.
        if not _response_verified(response, request, session_id, response_keys):
            if key_id_rejected(err):
                return Refused("key_id_rejected", {"claimed_error_code": code},
                               "Guardian answered an unsigned SIGNATURE_INVALID, how it reports a key_id it does not "
                               "hold (§10); check ACS_HMAC_KEY_ID")
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
    if not _response_verified(response, request, session_id, response_keys):
        return Refused("response_signature_invalid", {}, "response signature invalid")
    return Decided(response)
