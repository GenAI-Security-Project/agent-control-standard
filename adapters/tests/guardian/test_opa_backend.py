"""The OPA backend's client half: configuration, the input document, and how each OPA failure is named.

The input document and the verdict shape are a lab convention until issue #531 settles the OPA binding.
"""
from __future__ import annotations

import time

import pytest

from acs.guardian import opa_backend
from acs.guardian.opa_backend import OpaConfig, OpaConfigError, OpaFailure
from opa_stub import StubOpa, closed_port_url

PARAMS = {
    "acs_version": "0.1.0",
    "request_id": "11111111-1111-4111-8111-111111111111",
    "timestamp": "2026-11-16T00:00:00Z",
    "nonce": "n",
    "metadata": {"agent_id": "finbot", "session_id": "22222222-2222-4222-8222-222222222222", "platform": "lab"},
    "payload": {"tool": {"name": "finmail__send_email", "version": "sha256:ab"},
                "arguments": {"to": {"value": ["collector@exfil.example"]}}},
    "signature": {"algorithm": "HMAC-SHA256", "value": "x", "key_id": "lab"},
}
DENY = {"decision": "deny", "reasoning": "Recipient outside the company", "reason_codes": ["external_recipient"]}


def _config(url: str, timeout_s: float = 0.5) -> OpaConfig:
    return OpaConfig(url=url, timeout_s=timeout_s)


def _failure(config: OpaConfig) -> OpaFailure:
    with pytest.raises(OpaFailure) as info:
        opa_backend.query(config, {"input": {}})
    return info.value


def test_input_document_carries_method_payload_and_metadata_only():
    document = opa_backend.build_input("steps/toolCallRequest", PARAMS)
    assert document == {"input": {"method": "steps/toolCallRequest", "payload": PARAMS["payload"],
                                  "metadata": PARAMS["metadata"]}}


def test_query_posts_the_document_and_returns_the_result_member():
    with StubOpa(DENY) as opa:
        document = opa_backend.build_input("steps/toolCallRequest", PARAMS)
        assert opa_backend.query(_config(opa.url), document) == DENY
    assert opa.inputs == [document]


def test_opa_down_is_unreachable():
    assert _failure(_config(closed_port_url())).reason_code == "opa_unreachable"


def test_opa_slower_than_the_timeout_is_a_timeout():
    with StubOpa(DENY, delay_s=2.0) as opa:
        started = time.monotonic()
        assert _failure(_config(opa.url, timeout_s=0.3)).reason_code == "opa_timeout"
        assert time.monotonic() - started < 1.5


@pytest.mark.parametrize("status", [400, 404, 500, 503])
def test_a_non_200_answer_is_an_http_error(status):
    with StubOpa(DENY, status=status) as opa:
        assert _failure(_config(opa.url)).reason_code == "opa_http_error"


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b"\xff\xfe", b"{" + b" " * (2 * 1024 * 1024) + b"}"])
def test_a_body_that_is_not_a_bounded_json_object_is_malformed(body):
    with StubOpa(body=body) as opa:
        assert _failure(_config(opa.url)).reason_code == "opa_response_malformed"


def test_a_body_nested_past_the_parser_limit_is_malformed():
    deep = b'{"result": ' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    with StubOpa(body=deep) as opa:
        assert _failure(_config(opa.url)).reason_code == "opa_response_malformed"


def test_an_undefined_rule_is_a_missing_result():
    # OPA answers {} when the rule is undefined. Reading that as allow is the issue #469 failure.
    with StubOpa(body=b"{}") as opa:
        assert _failure(_config(opa.url)).reason_code == "opa_result_missing"


def test_selected_only_for_opa():
    assert opa_backend.selected({}) is False
    assert opa_backend.selected({"ACS_POLICY_BACKEND": ""}) is False
    assert opa_backend.selected({"ACS_POLICY_BACKEND": " OPA "}) is True


def test_load_config_reads_url_and_timeout():
    config = opa_backend.load_config({"ACS_OPA_URL": "http://opa:8181/v1/data/finbot/verdict",
                                      "ACS_OPA_TIMEOUT_MS": "750"})
    assert config == OpaConfig(url="http://opa:8181/v1/data/finbot/verdict", timeout_s=0.75)
    assert opa_backend.load_config({"ACS_OPA_URL": "https://opa/x"}).timeout_s == 2.0


@pytest.mark.parametrize("env", [
    {},
    {"ACS_OPA_URL": ""},
    {"ACS_OPA_URL": "file:///etc/passwd"},
    {"ACS_OPA_URL": "http://"},
    {"ACS_OPA_URL": "http://opa/x", "ACS_OPA_TIMEOUT_MS": "0"},
    {"ACS_OPA_URL": "http://opa/x", "ACS_OPA_TIMEOUT_MS": "abc"},
    {"ACS_OPA_URL": "http://opa/x", "ACS_OPA_TIMEOUT_MS": "5000"},
])
def test_load_config_rejects_a_bad_setting(env):
    with pytest.raises(OpaConfigError):
        opa_backend.load_config(env)


def test_backend_problem_names_what_is_wrong():
    assert opa_backend.backend_problem({}) is None
    assert opa_backend.backend_problem({"ACS_POLICY_BACKEND": "opa", "ACS_OPA_URL": "http://opa/x"}) is None
    assert "ACS_OPA_URL" in opa_backend.backend_problem({"ACS_POLICY_BACKEND": "opa"})
    assert "rego" in opa_backend.backend_problem({"ACS_POLICY_BACKEND": "rego"})
