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
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

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
    # Built once with the config. A new opener per query rebuilt its SSL context, about 12 ms of the budget.
    opener: urllib.request.OpenerDirector = field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "opener", _opener())


def load_config(env: Mapping[str, str] = os.environ) -> OpaConfig:
    url = env.get(URL_ENV, "").strip()
    unusable = OpaConfigError(f"{URL_ENV} must be an http or https URL to the OPA data API, got {redact_url(url)!r}")
    try:
        parts = urllib.parse.urlsplit(url)
        # Reading port raises on a port that is not a number or out of range, so a bad one stops startup here.
        parts.port  # noqa: B018
    except ValueError:
        raise unusable from None
    # Only http(s) to a named host: urllib would otherwise open file: and ftp: URLs from the environment.
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise unusable
    raw_timeout = env.get(TIMEOUT_ENV, "").strip() or str(DEFAULT_TIMEOUT_MS)
    try:
        timeout_ms = int(raw_timeout)
    except ValueError:
        raise OpaConfigError(f"{TIMEOUT_ENV} must be an integer number of milliseconds, got {raw_timeout!r}") from None
    if not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
        raise OpaConfigError(f"{TIMEOUT_ENV} must be between 1 and {MAX_TIMEOUT_MS}, got {timeout_ms}")
    return OpaConfig(url=url, timeout_s=timeout_ms / 1000.0)


def backend_problem(name: str, env: Mapping[str, str] = os.environ) -> str | None:
    """Why the named policy backend can't run, or None when it can or none is named.

    The example Guardian parses the name, once, and passes it in. env supplies only the OPA URL and timeout.
    """
    name = name.strip().lower()
    if not name:
        return None
    if name != "opa":
        return f"ACS_POLICY_BACKEND={name!r} is not a known policy backend (the only one is opa)"
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


def _post(config: OpaConfig, body: bytes, exchange: _Exchange) -> bytes:
    """One POST, read one socket read at a time so an abort from query() ends it between reads."""
    _worker.exchange = exchange
    request = urllib.request.Request(config.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
    timed_out = OpaFailure("opa_timeout", f"OPA did not answer within {config.timeout_s}s")
    try:
        with config.opener.open(request, timeout=config.timeout_s) as response:
            if response.status != 200:
                raise OpaFailure("opa_http_error", f"OPA answered HTTP {response.status}")
            chunks, size = [], 0
            while True:
                if exchange.aborted.is_set():
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


def _reject_constant(name: str) -> Any:
    # NaN, Infinity, and -Infinity are not JSON, and JCS cannot sign them.
    raise ValueError(f"non-finite constant {name}")


def query(config: OpaConfig, document: Mapping[str, Any]) -> Any:
    """POST the document and return OPA's result member. Raises OpaFailure for every way that can fail."""
    body = json.dumps(document).encode("utf-8")
    exchange = _Exchange()
    box: dict[str, Any] = {}

    def fetch() -> None:
        try:
            box["data"] = _post(config, body, exchange)
        except BaseException as e:  # noqa: BLE001
            box["error"] = e

    # The one timeout: the caller waits until the deadline, then shuts the sockets down, so the worker thread and its
    # connection end too instead of reading on in the background. A socket timeout alone bounds each read, not the
    # exchange, so a server that dribbles bytes would outlast it.
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
        answer = json.loads(box["data"].decode("utf-8"), parse_constant=_reject_constant)
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
# Caps on a redacting modify, checked before anything walks the redactions, so validation stays well inside
# the decision timeout.
MAX_REDACTIONS = 2000
# The one subtree of each payload a modify may change.
MODIFY_ROOTS = {"steps/toolCallRequest": "/arguments", "steps/toolCallResult": "/outputs"}
MAX_REDACTED_OUTPUTS = 1000
# Matches MAX_VERDICT_DEPTH. It bounds the per-path cost of the existence and coverage checks.
MAX_REDACTION_PATH_DEPTH = 64


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


class PointerError(ValueError):
    """A string that isn't an RFC 6901 JSON Pointer this backend accepts."""


_INVALID_ESCAPE = re.compile(r"~(?![01])")
# RFC 6901 array indexes in ASCII. str.isdigit would also accept Arabic-Indic digits and superscripts.
_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")


def decode_pointer(path: Any) -> list[str]:
    """The reference tokens of an RFC 6901 pointer. The one parser every pointer here goes through.

    It refuses a pointer that doesn't start with / or uses an escape other than ~0 and ~1, so two spellings
    can never name the same key.
    """
    if not isinstance(path, str) or not path.startswith("/"):
        raise PointerError(f"{path!r} is not a JSON Pointer")
    if _INVALID_ESCAPE.search(path):
        raise PointerError(f"{path!r} has an escape RFC 6901 does not allow (only ~0 and ~1)")
    return [token.replace("~1", "/").replace("~0", "~") for token in path[1:].split("/")]


def _step(node: Any, token: str) -> tuple[bool, Any]:
    """One pointer step: whether token names a child of node, and the child."""
    if isinstance(node, dict):
        return (True, node[token]) if token in node else (False, None)
    if isinstance(node, list):
        if _ARRAY_INDEX.fullmatch(token) and int(token) < len(node):
            return True, node[int(token)]
    return False, None


def _resolve_pointer(document: Any, pointer: Any) -> bool:
    """Whether an RFC 6901 pointer names a value inside document."""
    try:
        tokens = decode_pointer(pointer)
    except PointerError:
        return False
    node = document
    for token in tokens:
        found, node = _step(node, token)
        if not found:
            return False
    return True


def replace_at(document: Any, pointer: str, value: Any) -> None:
    """Replace the value the pointer names inside document. The caller has checked that it resolves."""
    *parents, leaf = decode_pointer(pointer)
    node = document
    for token in parents:
        found, node = _step(node, token)
        if not found:
            raise PointerError(f"{pointer!r} does not resolve")
    if isinstance(node, list):
        found, _ = _step(node, leaf)
        if not found:
            raise PointerError(f"{pointer!r} does not resolve")
        node[int(leaf)] = value
    else:
        node[leaf] = value


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
    if "parameter_overrides" in modifications and not modifications["parameter_overrides"]:
        return "parameter_overrides is empty, so the modify changes nothing"
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
    # The allowlist the gateway applies too: a modify changes a call's arguments or a result's outputs and nothing
    # else, so it can never rename the tool after the hard denies judged the original name.
    root = MODIFY_ROOTS.get(method)
    for path in paths:
        if not isinstance(path, str) or root is None or not path.startswith(root + "/"):
            return f"redaction path {path!r} is outside {root}/, the only part of {method} a modify may change"
    for path in paths:
        # A path that misses would redact nothing and let the value through, so it is a policy error, not a no-op.
        if not path or not _resolve_pointer(payload, path):
            return f"redaction path {path!r} does not name a value in the payload"
    return _overlap_problem(paths) or _coverage_problem(paths, payload)


def _overlap_problem(paths: list[str]) -> str | None:
    """Section 6.3 wants disjoint targets, so no redaction path repeats or sits inside another.

    Paths sort as token tuples, where every path that starts with P follows P directly, so comparing each path
    with the next finds every repeat and every nesting. The cost is the sort plus one pass over the tokens.
    """
    try:
        # Decoded tokens, so two spellings of one key compare equal.
        ordered = sorted((tuple(decode_pointer(path)), path) for path in paths)
    except PointerError as e:
        return f"redaction path {e}"
    for (tokens, path), (next_tokens, next_path) in zip(ordered, ordered[1:]):
        if tokens == next_tokens:
            return f"redaction path {path!r} appears more than once"
        if next_tokens[:len(tokens)] == tokens:
            return f"redaction path {next_path!r} sits inside redaction path {path!r}"
    return None


class _Shape:
    """One node of the redaction shapes: array positions are wildcards, object keys are literal."""

    __slots__ = ("keys", "items", "path")

    def __init__(self) -> None:
        self.keys: dict[str, _Shape] = {}
        self.items: _Shape | None = None
        self.path: str | None = None  # set where a redaction path ends


def _encode(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _coverage_problem(paths: list[str], payload: Mapping[str, Any]) -> str | None:
    """A redaction must also cover every other array index that holds the same field.

    Redacting /outputs/0/value/ssn but not /outputs/1/value/ssn, or rows/0/ssn but not rows/1/ssn, let the rest
    through (issue #469). Each path becomes a shape with its array indexes wildcarded. One walk of the payload
    along the merged shapes then finds every value a shape names, and each one must be redacted. Arrays hold
    only wildcards and objects only keys, so the walk visits each payload node at most once.
    """
    root = _Shape()
    redacted: set[str] = set()
    for path in paths:
        tokens = decode_pointer(path)
        node, shape = payload, root
        for token in tokens:
            is_array = isinstance(node, list)
            _, node = _step(node, token)  # every path here already resolved
            if is_array:
                shape.items = shape.items or _Shape()
                shape = shape.items
            else:
                shape = shape.keys.setdefault(token, _Shape())
        shape.path = path
        redacted.add("/" + "/".join(_encode(token) for token in tokens))
    stack: list[tuple[Any, _Shape, str]] = [(payload, root, "")]
    while stack:
        node, shape, pointer = stack.pop()
        if shape.path is not None and pointer not in redacted:
            return f"redaction {shape.path!r} leaves the same field at {pointer!r} unredacted"
        if isinstance(node, list) and shape.items is not None:
            stack.extend((item, shape.items, f"{pointer}/{index}") for index, item in enumerate(node))
        elif isinstance(node, dict) and shape.keys:
            # Walk the smaller side, so a wide object or a wide set of shapes costs no more than the other.
            if len(node) <= len(shape.keys):
                keys = [key for key in node if key in shape.keys]
            else:
                keys = [key for key in shape.keys if key in node]
            stack.extend((node[key], shape.keys[key], f"{pointer}/{_encode(key)}") for key in keys)
    return None


def _size_problem(verdict: Mapping[str, Any], payload: Mapping[str, Any]) -> str | None:
    modifications = verdict.get("modifications")
    redactions = modifications.get("redactions") if isinstance(modifications, dict) else None
    if not isinstance(redactions, list) or not redactions:
        return None
    if len(redactions) > MAX_REDACTIONS:
        return f"the modify carries {len(redactions)} redactions, more than {MAX_REDACTIONS}"
    for redaction in redactions:
        path = redaction.get("path") if isinstance(redaction, dict) else None
        # Each token of a path costs a step in the existence and coverage checks, so depth is capped too.
        if isinstance(path, str) and path.count("/") > MAX_REDACTION_PATH_DEPTH:
            return f"redaction path depth {path.count('/')} is more than {MAX_REDACTION_PATH_DEPTH}"
    outputs = payload.get("outputs")
    if isinstance(outputs, list) and len(outputs) > MAX_REDACTED_OUTPUTS:
        return f"a redacting modify on {len(outputs)} outputs, more than {MAX_REDACTED_OUTPUTS}"
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
    size = _size_problem(verdict, payload)
    if size:
        return size
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
    """The deny for a backend named when the Guardian was imported but never loaded by main()."""
    return _deny(base, "policy_backend_misconfigured",
                 "ACS_POLICY_BACKEND named a policy backend at import, but no OPA settings were loaded")


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
    # A number JCS cannot encode passes these checks. The Guardian's signing site turns it into a signed deny.
    return {**base, **verdict}
