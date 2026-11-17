"""An opt-in OPA policy backend for the example Guardian, a lab convention until issue #531 settles the OPA binding.

ACS_POLICY_BACKEND=opa sends steps/toolCallRequest and steps/toolCallResult to the OPA data API at
ACS_OPA_URL as {"input": {"method", "payload", "metadata"}}. OPA answers {"result": verdict}. The input
document and the verdict shape are not part of the specification. With ACS_POLICY_BACKEND unset the
Guardian never imports a policy decision from here, so the reference adapters see today's decisions.
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
