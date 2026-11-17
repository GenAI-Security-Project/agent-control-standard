"""An opt-in OPA policy backend for the example Guardian, a lab convention until issue #531 settles the OPA binding.

ACS_POLICY_BACKEND=opa sends steps/toolCallRequest and steps/toolCallResult to the OPA data API at
ACS_OPA_URL as {"input": {"method", "payload", "metadata"}}. OPA answers {"result": verdict}. The input
document and the verdict shape are not part of the specification. With ACS_POLICY_BACKEND unset the
Guardian never calls evaluate, so the reference adapters see today's decisions.
"""
from __future__ import annotations

import json
import os
import threading
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
# The ServerHello advertises timeout_config.default_ms 5000, so OPA has to answer well inside it.
MAX_TIMEOUT_MS = 4999
# A verdict is a few hundred bytes. The cap keeps a broken or hostile policy server from filling memory.
MAX_RESPONSE_BYTES = 1024 * 1024


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


# The two methods this backend judges. Every other method keeps the example Guardian's own handling.
METHODS = frozenset({"steps/toolCallRequest", "steps/toolCallResult"})


def configured(env: Mapping[str, str] = os.environ) -> bool:
    """Whether any policy backend is named. A name other than opa is a misconfiguration, which denies."""
    return bool(env.get(BACKEND_ENV, "").strip())


def selected(env: Mapping[str, str] = os.environ) -> bool:
    return env.get(BACKEND_ENV, "").strip().lower() == "opa"


def load_config(env: Mapping[str, str] = os.environ) -> OpaConfig:
    url = env.get(URL_ENV, "").strip()
    parts = urllib.parse.urlsplit(url)
    # Only http(s) to a named host: urllib would otherwise open file: and ftp: URLs from the environment.
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise OpaConfigError(f"{URL_ENV} must be an http or https URL to the OPA data API, got {url!r}")
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect from the policy server is a misconfiguration, so it surfaces as a non-200 instead of being followed.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# No ProxyHandler entries, so proxy variables in the Guardian's environment never reroute a policy call.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _post(config: OpaConfig, body: bytes) -> bytes:
    request = urllib.request.Request(config.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
    try:
        with _OPENER.open(request, timeout=config.timeout_s) as response:
            if response.status != 200:
                raise OpaFailure("opa_http_error", f"OPA answered HTTP {response.status}")
            data = response.read(MAX_RESPONSE_BYTES + 1)
    except OpaFailure:
        raise
    except urllib.error.HTTPError as e:
        raise OpaFailure("opa_http_error", f"OPA answered HTTP {e.code}") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, TimeoutError):
            raise OpaFailure("opa_timeout", f"OPA did not answer within {config.timeout_s}s") from None
        raise OpaFailure("opa_unreachable", f"OPA unreachable: {e.reason}") from None
    except TimeoutError:
        raise OpaFailure("opa_timeout", f"OPA did not answer within {config.timeout_s}s") from None
    except OSError as e:
        raise OpaFailure("opa_unreachable", f"OPA unreachable: {e}") from None
    if len(data) > MAX_RESPONSE_BYTES:
        raise OpaFailure("opa_response_malformed", f"OPA response exceeds {MAX_RESPONSE_BYTES} bytes")
    return data


def query(config: OpaConfig, document: Mapping[str, Any]) -> Any:
    """POST the document and return OPA's result member. Raises OpaFailure for every way that can fail."""
    body = json.dumps(document).encode("utf-8")
    box: dict[str, Any] = {}

    def fetch() -> None:
        try:
            box["data"] = _post(config, body)
        except BaseException as e:  # noqa: BLE001
            box["error"] = e

    # A socket timeout bounds each read, not the exchange, so a server that dribbles bytes is cut off here.
    worker = threading.Thread(target=fetch, name="acs-opa-query", daemon=True)
    worker.start()
    worker.join(config.timeout_s)
    if worker.is_alive():
        raise OpaFailure("opa_timeout", f"OPA did not answer within {config.timeout_s}s")
    if "error" in box:
        error = box["error"]
        if isinstance(error, OpaFailure):
            raise error
        raise OpaFailure("opa_unreachable", f"OPA query failed: {error}")
    try:
        answer = json.loads(box["data"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise OpaFailure("opa_response_malformed", f"OPA response is not JSON: {e}") from None
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

_validator_lock = threading.Lock()
_validator: Any = None
_validator_error: str | None = None


def _result_validator() -> Any:
    """A validator for an AcsResult from specification/v0.1.0, or None with _validator_error set."""
    global _validator, _validator_error
    with _validator_lock:
        if _validator is None and _validator_error is None:
            try:
                from jsonschema import Draft202012Validator
                from referencing import Registry, Resource

                from acs.core import schemas_dir
                spec_dir = schemas_dir(os.environ.get("ACS_SPEC_DIR"))
                resources = []
                for path in sorted(spec_dir.glob("*.json")):
                    with open(path, encoding="utf-8") as f:
                        contents = json.load(f)
                    if isinstance(contents, dict) and isinstance(contents.get("$id"), str):
                        resources.append((contents["$id"], Resource.from_contents(contents)))
                envelope_id = next(uri for uri, _ in resources if uri.endswith("/response-envelope.json"))
                # Validating the result against AcsResult directly, not the envelope's oneOf, keeps errors specific.
                _validator = Draft202012Validator(
                    {"$ref": envelope_id + "#/$defs/AcsResult"},
                    registry=Registry().with_resources(resources),
                    format_checker=Draft202012Validator.FORMAT_CHECKER,
                )
            except Exception as e:  # noqa: BLE001
                _validator_error = f"the decision schemas could not be loaded ({e})"
        return _validator


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
    overrides = modifications.get("parameter_overrides")
    if overrides is not None:
        if method != "steps/toolCallRequest":
            return f"parameter_overrides has no arguments to override on {method}"
        unknown = sorted(set(overrides) - set(payload.get("arguments") or {}))
        if unknown:
            return f"parameter_overrides names arguments the call does not carry: {unknown}"
    for redaction in modifications.get("redactions") or []:
        path = redaction.get("path")
        # A path that misses would redact nothing and let the value through, so it is a policy error, not a no-op.
        if not path or not _resolve_pointer(payload, path):
            return f"redaction path {path!r} does not name a value in the payload"
    return None


def verdict_problem(verdict: Any, method: str, payload: Mapping[str, Any], base: Mapping[str, Any]) -> str | None:
    """Why the verdict cannot become this step's decision, or None when it can."""
    if not isinstance(verdict, dict):
        return f"the verdict is a {type(verdict).__name__}, not an object"
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
    validator = _result_validator()
    if validator is None:
        return _validator_error
    from jsonschema.exceptions import best_match
    error = best_match(validator.iter_errors({**base, **verdict}))
    if error is not None:
        where = "/".join(str(p) for p in error.absolute_path) or "the result"
        return f"{where} fails response-envelope.json AcsResult: {error.message}"
    if decision == "ask" and verdict["ask_details"].get("timeout_disposition", "deny") != "deny":
        # D-043: the Guardian owns the ASK timeout, and an unanswered ASK denies.
        return "ask_details.timeout_disposition must be deny (D-043)"
    if decision == "modify":
        return _modification_problem(verdict["modifications"], method, payload)
    return None


def _deny(base: Mapping[str, Any], reason_code: str, reasoning: str) -> dict:
    return {**base, "decision": "deny", "reasoning": reasoning, "reason_codes": [reason_code]}


def evaluate(method: str, params: Mapping[str, Any], base: Mapping[str, Any],
             env: Mapping[str, str] = os.environ) -> dict:
    """The step's result from OPA. Every failure, and every verdict that does not validate, is a deny (D-036, D-040)."""
    problem = backend_problem(env) if selected(env) else f"{BACKEND_ENV} does not select opa"
    if problem:
        return _deny(base, "policy_backend_misconfigured", f"policy backend misconfigured: {problem}")
    config = load_config(env)
    try:
        verdict = query(config, build_input(method, params))
    except OpaFailure as e:
        return _deny(base, e.reason_code, f"OPA policy evaluation failed: {e.message}")
    problem = verdict_problem(verdict, method, params.get("payload") or {}, base)
    if problem:
        return _deny(base, "opa_verdict_invalid", f"OPA verdict rejected: {problem}")
    return {**base, **verdict}
