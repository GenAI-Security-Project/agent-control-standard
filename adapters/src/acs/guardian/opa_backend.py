"""An opt-in OPA policy backend for the example Guardian, a lab convention until issue #531 settles the OPA binding.

ACS_POLICY_BACKEND=opa sends steps/toolCallRequest and steps/toolCallResult to the OPA data API at
ACS_OPA_URL as {"input": {"method", "payload", "metadata"}}. OPA answers {"result": verdict}. The input
document and the verdict shape are not part of the specification. With ACS_POLICY_BACKEND unset the
Guardian never calls evaluate, so the reference adapters see today's decisions.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

BACKEND_ENV = "ACS_POLICY_BACKEND"
URL_ENV = "ACS_OPA_URL"
TIMEOUT_ENV = "ACS_OPA_TIMEOUT_MS"
DEFAULT_TIMEOUT_MS = 2000
# The ServerHello advertises timeout_config.default_ms 5000. OPA gets at most 4000 of it, so the Guardian keeps
# a second to validate, sign, and answer before the client gives up.
MAX_TIMEOUT_MS = 4000
# A verdict is a few hundred bytes. The cap keeps a broken or hostile policy server from filling memory.
MAX_RESPONSE_BYTES = 1024 * 1024


# The signed reasoning for each failure. It reaches the agent, so it names no host, status, or policy detail.
# The details go to the Guardian's stderr log instead.
FAILURE_REASONING = {
    "opa_unreachable": "The policy service could not be reached, so the step is denied.",
    "opa_timeout": "The policy service did not answer in time, so the step is denied.",
    "opa_http_error": "The policy service returned an error, so the step is denied.",
    "opa_response_malformed": "The policy service returned an unreadable answer, so the step is denied.",
    "opa_result_missing": "The policy returned no decision for this step, so the step is denied.",
    "opa_verdict_invalid": "The policy returned a decision the Guardian cannot accept, so the step is denied.",
    "policy_backend_misconfigured": "The Guardian's policy backend is misconfigured, so the step is denied.",
}


def redact_url(url: str) -> str:
    """The URL without its userinfo, for logs and error messages."""
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.username is None and parts.password is None:
            return url
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        netloc = f"{host}:{parts.port}" if parts.port else host
        return urllib.parse.urlunsplit(parts._replace(netloc=netloc))
    except ValueError:
        return "<unparseable URL>"


def _log(reason_code: str, detail: str) -> None:
    sys.stderr.write(f"[guardian] OPA {reason_code}: {detail}\n")
    sys.stderr.flush()


class OpaConfigError(ValueError):
    """The OPA backend is selected but its settings cannot be used."""


class OpaFailure(Exception):
    """No usable answer came from OPA. reason_code names the failure on the deny it turns into."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


@dataclass(frozen=True)
class OpaConfig:
    url: str
    timeout_s: float


def selected(env: Mapping[str, str] = os.environ) -> bool:
    return env.get(BACKEND_ENV, "").strip().lower() == "opa"


def load_config(env: Mapping[str, str] = os.environ) -> OpaConfig:
    url = env.get(URL_ENV, "").strip()
    parts = urllib.parse.urlsplit(url)
    # Only http(s) to a named host: urllib would otherwise open file: and ftp: URLs from the environment.
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise OpaConfigError(f"{URL_ENV} must be an http or https URL to the OPA data API, got {redact_url(url)!r}")
    raw_timeout = env.get(TIMEOUT_ENV, "").strip() or str(DEFAULT_TIMEOUT_MS)
    try:
        timeout_ms = int(raw_timeout)
    except ValueError:
        raise OpaConfigError(f"{TIMEOUT_ENV} must be an integer number of milliseconds, got {raw_timeout!r}") from None
    if not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
        raise OpaConfigError(f"{TIMEOUT_ENV} must be between 1 and {MAX_TIMEOUT_MS}, got {timeout_ms}")
    return OpaConfig(url=url, timeout_s=timeout_ms / 1000.0)


def backend_problem(env: Mapping[str, str] = os.environ) -> str | None:
    """Why the configured policy backend cannot run, or None when it can (or none is configured)."""
    name = env.get(BACKEND_ENV, "").strip().lower()
    if not name:
        return None
    if name != "opa":
        return f"{BACKEND_ENV}={name!r} is not a known policy backend (the only one is opa)"
    try:
        load_config(env)
    except OpaConfigError as e:
        return str(e)
    return None


def build_input(method: str, params: Mapping[str, Any]) -> dict:
    """The lab input document. The signature, nonce, and timestamp stay out: the Guardian has already checked them."""
    return {"input": {"method": method,
                      "payload": params.get("payload") or {},
                      "metadata": params.get("metadata") or {}}}


class _Exchange:
    """The sockets of one OPA query, so the caller can shut them down at the deadline and free the worker thread.

    They are held as duplicates because TLS wrapping detaches the original socket.
    """

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
        raise TimeoutError("the OPA query passed its deadline")

    def abort(self) -> None:
        with self._lock:
            self.aborted.set()
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            # shutdown, not close, is what wakes a recv blocked in another thread.
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
    exchange = getattr(_worker, "exchange", None)
    if exchange is not None:
        exchange.add(sock)
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


def _opener() -> urllib.request.OpenerDirector:
    # No proxies, so proxy variables never reroute a policy call. No redirect handler, so a 3xx is an HTTP error.
    opener = urllib.request.OpenerDirector()
    for handler in (urllib.request.ProxyHandler({}), _HTTPHandler(), _HTTPSHandler(),
                    urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        opener.add_handler(handler)
    return opener


def _post(config: OpaConfig, body: bytes, deadline: float, exchange: _Exchange) -> bytes:
    """One POST whose body read stops at the deadline, one socket read at a time."""
    _worker.exchange = exchange
    request = urllib.request.Request(config.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
    timed_out = OpaFailure("opa_timeout", f"OPA did not answer within {config.timeout_s}s")
    try:
        with _opener().open(request, timeout=config.timeout_s) as response:
            if response.status != 200:
                raise OpaFailure("opa_http_error", f"OPA answered HTTP {response.status}")
            chunks, size = [], 0
            while True:
                if time.monotonic() >= deadline or exchange.aborted.is_set():
                    raise timed_out
                chunk = response.read1(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise OpaFailure("opa_response_malformed", f"OPA response exceeds {MAX_RESPONSE_BYTES} bytes")
                chunks.append(chunk)
    except OpaFailure:
        raise
    except urllib.error.HTTPError as e:
        e.close()
        raise OpaFailure("opa_http_error", f"OPA answered HTTP {e.code}") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, TimeoutError) or exchange.aborted.is_set():
            raise timed_out from None
        raise OpaFailure("opa_unreachable", f"OPA unreachable: {e.reason}") from None
    except (TimeoutError, http.client.HTTPException, OSError) as e:
        if isinstance(e, TimeoutError) or exchange.aborted.is_set():
            raise timed_out from None
        raise OpaFailure("opa_unreachable", f"OPA unreachable: {type(e).__name__}") from None
    finally:
        _worker.exchange = None
        exchange.release()
    return b"".join(chunks)


def query(config: OpaConfig, document: Mapping[str, Any]) -> Any:
    """POST the document and return OPA's result member. Raises OpaFailure for every way that can fail."""
    body = json.dumps(document).encode("utf-8")
    deadline = time.monotonic() + config.timeout_s
    exchange = _Exchange()
    box: dict[str, Any] = {}

    def fetch() -> None:
        try:
            box["data"] = _post(config, body, deadline, exchange)
        except BaseException as e:  # noqa: BLE001
            box["error"] = e

    # A socket timeout bounds each read, not the exchange. The caller waits only until the deadline, then shuts
    # the sockets down, so the worker thread and its connection end too instead of reading on in the background.
    worker = threading.Thread(target=fetch, name="acs-opa-query", daemon=True)
    worker.start()
    worker.join(config.timeout_s)
    if worker.is_alive():
        exchange.abort()
        raise OpaFailure("opa_timeout", f"OPA did not answer within {config.timeout_s}s")
    if "error" in box:
        error = box["error"]
        if isinstance(error, OpaFailure):
            raise error
        raise OpaFailure("opa_unreachable", f"OPA query failed: {type(error).__name__}")
    try:
        answer = json.loads(box["data"].decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        # RecursionError: a body nested past the parser's limit is malformed too, never an unhandled crash.
        raise OpaFailure("opa_response_malformed", f"OPA response is not usable JSON: {type(e).__name__}") from None
    if not isinstance(answer, dict):
        raise OpaFailure("opa_response_malformed", "OPA response is not a JSON object")
    if "result" not in answer:
        # OPA leaves result out when the rule is undefined. That is never an allow.
        raise OpaFailure("opa_result_missing", "OPA returned no result (the policy rule is undefined)")
    return answer["result"]


# The fields a policy may decide. Everything else in the result (type, acs_version, request_id, chain_hash, and
# the signature) belongs to the Guardian, so a verdict that names one is rejected rather than merged.
VERDICT_KEYS = frozenset({"decision", "reasoning", "reason_codes", "modifications", "ask_details",
                          "policy_references", "policy_data"})
# DEFER is left out: the lab gateway denies it anyway (BUILD_PLAN A.4), so a policy that defers is a policy bug.
VERDICT_DECISIONS = frozenset({"allow", "deny", "modify", "ask"})
# The Guardian canonicalizes and signs the result recursively, so a verdict nests no deeper than this.
MAX_VERDICT_DEPTH = 64

def _depth_exceeds(value: Any, limit: int) -> bool:
    """Whether value nests deeper than limit, checked without recursion."""
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > limit:
                return True
            stack.extend((child, depth + 1) for child in (node.values() if isinstance(node, dict) else node))
    return False


def _resolve_pointer(document: Any, pointer: str) -> bool:
    """Whether an RFC 6901 pointer names a value inside document."""
    if not pointer.startswith("/"):
        return False
    node = document
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return False
            node = node[token]
        elif isinstance(node, list):
            if not token.isdigit() or (token != "0" and token.startswith("0")) or int(token) >= len(node):
                return False
            node = node[int(token)]
        else:
            return False
    return True


def _modification_problem(modifications: Mapping[str, Any], method: str, payload: Mapping[str, Any]) -> str | None:
    from acs.core._decision import modify_composition_violation
    violation = modify_composition_violation(dict(modifications))
    if violation:
        return violation
    if "modified_content" in modifications and method == "steps/toolCallRequest":
        # The adapters and the gateway apply parameter_overrides to a call, never an opaque replacement.
        return "modified_content has no meaning on steps/toolCallRequest (use parameter_overrides)"
    if "redactions" in modifications and not modifications["redactions"]:
        # An empty list changes nothing, so a modify that carries only it would deliver the step unchanged.
        return "redactions is empty, so the modify changes nothing"
    overrides = modifications.get("parameter_overrides")
    if overrides is not None:
        if method != "steps/toolCallRequest":
            return f"parameter_overrides has no arguments to override on {method}"
        unknown = sorted(set(overrides) - set(payload.get("arguments") or {}))
        if unknown:
            return f"parameter_overrides names arguments the call does not carry: {unknown}"
        # acs.core compares overrides as /<key>, but a redaction path is rooted at the payload, where the same
        # argument lives at /arguments/<key>. Compare them there, so two edits to one argument cannot both pass.
        for key in overrides:
            target = "/arguments/" + key.replace("~", "~0").replace("/", "~1")
            for redaction in modifications.get("redactions") or []:
                path = redaction.get("path") or ""
                if path == target or path.startswith(target + "/") or target.startswith(path + "/"):
                    return f"redaction path {path!r} overlaps parameter_override {key!r} (section 6.3)"
    paths = [redaction.get("path") for redaction in modifications.get("redactions") or []]
    for path in paths:
        # A path that misses would redact nothing and let the value through, so it is a policy error, not a no-op.
        if not path or not _resolve_pointer(payload, path):
            return f"redaction path {path!r} does not name a value in the payload"
    return _sibling_output_problem(paths, payload)


_OUTPUT_PATH = re.compile(r"/outputs/(?:0|[1-9][0-9]*)/value(/.*)?")


def _sibling_output_problem(paths: list[str], payload: Mapping[str, Any]) -> str | None:
    """A redaction inside one output must be repeated in every output that carries the same field.

    Redacting only the first output let the rest through (issue #469), so a partial redaction is invalid.
    """
    outputs = payload.get("outputs")
    if not isinstance(outputs, list):
        return None
    wanted = set(paths)
    for path in paths:
        match = _OUTPUT_PATH.fullmatch(path)
        if match is None:
            continue
        rest = match.group(1) or ""
        for index in range(len(outputs)):
            sibling = f"/outputs/{index}/value{rest}"
            if sibling not in wanted and _resolve_pointer(payload, sibling):
                return f"redaction {path!r} leaves the same field at {sibling!r} unredacted"
    return None


def verdict_problem(verdict: Any, method: str, payload: Mapping[str, Any], base: Mapping[str, Any]) -> str | None:
    """Why the verdict cannot become this step's decision, or None when it can."""
    if not isinstance(verdict, dict):
        return f"the verdict is a {type(verdict).__name__}, not an object"
    if _depth_exceeds(verdict, MAX_VERDICT_DEPTH):
        return f"the verdict nests deeper than {MAX_VERDICT_DEPTH} levels"
    extra = sorted(set(verdict) - VERDICT_KEYS)
    if extra:
        return f"the verdict carries fields a policy may not set: {extra}"
    decision = verdict.get("decision")
    if decision not in VERDICT_DECISIONS:
        return f"decision {decision!r} is not one of {sorted(VERDICT_DECISIONS)}"
    if "modifications" in verdict and decision != "modify":
        return f"decision {decision} carries modifications"
    if "ask_details" in verdict and decision != "ask":
        return f"decision {decision} carries ask_details"
    # The same AcsResult check acs.client applies to every answer it receives. It passes a section 6.3
    # composition violation, which _modification_problem below rejects.
    from acs.client._exchange import result_problem
    problem = result_problem({**base, **verdict})
    if problem:
        return f"the result fails response-envelope.json AcsResult: {problem}"
    if decision == "ask" and verdict["ask_details"].get("timeout_disposition", "deny") != "deny":
        # D-043: the Guardian owns the ASK timeout, and an unanswered ASK denies.
        return "ask_details.timeout_disposition must be deny (D-043)"
    if decision == "modify":
        return _modification_problem(verdict["modifications"], method, payload)
    return None


def _deny(base: Mapping[str, Any], reason_code: str, detail: str) -> dict:
    _log(reason_code, detail)
    return {**base, "decision": "deny", "reasoning": FAILURE_REASONING[reason_code], "reason_codes": [reason_code]}


def misconfigured(base: Mapping[str, Any]) -> dict:
    """The deny for a backend that is named but was never loaded, which main() would have refused to start with."""
    return _deny(base, "policy_backend_misconfigured",
                 f"{BACKEND_ENV} is set but no OPA settings were loaded at startup")


def evaluate(method: str, params: Mapping[str, Any], base: Mapping[str, Any], config: OpaConfig) -> dict:
    """The step's result from OPA. Every failure, and every verdict that does not validate, is a deny (D-036, D-040)."""
    try:
        verdict = query(config, build_input(method, params))
    except OpaFailure as e:
        return _deny(base, e.reason_code, f"OPA policy evaluation failed: {e.message}")
    except Exception as e:  # noqa: BLE001
        # Anything unexpected still ends in a signed deny, never in a dropped connection.
        return _deny(base, "opa_verdict_invalid", f"OPA policy evaluation failed: {type(e).__name__}")
    try:
        problem = verdict_problem(verdict, method, params.get("payload") or {}, base)
    except Exception as e:  # noqa: BLE001
        problem = f"verdict validation failed: {type(e).__name__}"
    if problem:
        return _deny(base, "opa_verdict_invalid", f"OPA verdict rejected: {problem}")
    return {**base, **verdict}
