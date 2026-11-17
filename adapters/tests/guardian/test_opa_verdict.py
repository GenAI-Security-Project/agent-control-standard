"""The OPA backend's verdict half: a verdict becomes a decision only after it validates, and anything else denies.

The verdict shape is a lab convention until issue #531 settles the OPA binding. Validation uses the decision
shapes in specification/v0.1.0 (modifications.json, ask-details.json, and the AcsResult per-decision rules).
"""
from __future__ import annotations

import copy
import time

import pytest

from acs.guardian import opa_backend
from acs.guardian.opa_backend import OpaConfig
from opa_stub import StubOpa, closed_port_url

REQUEST_ID = "11111111-1111-4111-8111-111111111111"
CHAIN = "a" * 64
BASE = {"type": "final", "acs_version": "0.1.0", "request_id": REQUEST_ID, "chain_hash": CHAIN}
METADATA = {"agent_id": "finbot", "session_id": "22222222-2222-4222-8222-222222222222", "platform": "lab"}
CALL = {"tool": {"name": "finstripe__create_transfer"},
        "arguments": {"amount": {"value": 9000}, "to": {"value": "acct-1"}}}
RESULT = {"tool": {"name": "get_vendor_details"}, "exit_status": "success",
          "request_id_ref": "33333333-3333-4333-8333-333333333333",
          "outputs": [{"value": {"name": "Acme", "bank_account_number": "111"}},
                      {"value": {"name": "Beta", "bank_account_number": "222"}}]}
# Only the first output carries the field, so one redaction covers the result.
MIXED = {**RESULT, "outputs": [{"value": {"name": "Acme", "bank_account_number": "111"}},
                               {"value": {"name": "Beta"}}, {"value": "plain text"}]}
ASK_DETAILS = {"approver": {"type": "human", "id": "lab-approver"},
               "question": "Approve a transfer of 9000?", "timeout_seconds": 240}
REDACT_ALL = {"redactions": [{"path": "/outputs/0/value/bank_account_number"},
                             {"path": "/outputs/1/value/bank_account_number"}]}

VALID = [
    ("steps/toolCallRequest", CALL, {"decision": "allow"}),
    ("steps/toolCallRequest", CALL, {"decision": "deny", "reasoning": "no", "reason_codes": ["external_recipient"]}),
    ("steps/toolCallRequest", CALL, {"decision": "modify", "reasoning": "cap the amount",
                                     "modifications": {"parameter_overrides": {"amount": 5000}}}),
    ("steps/toolCallRequest", CALL, {"decision": "ask", "reasoning": "over threshold",
                                     "reason_codes": ["payment_over_threshold"], "ask_details": ASK_DETAILS}),
    ("steps/toolCallResult", RESULT, {"decision": "allow"}),
    ("steps/toolCallResult", RESULT, {"decision": "deny", "reasoning": "secret in output"}),
    ("steps/toolCallResult", RESULT, {"decision": "modify", "reasoning": "bank account redacted",
                                      "reason_codes": ["sensitive_field_redacted"], "modifications": REDACT_ALL}),
    ("steps/toolCallResult", MIXED, {"decision": "modify", "reasoning": "only one output carries it",
                                     "modifications": {"redactions": [
                                         {"path": "/outputs/0/value/bank_account_number"}]}}),
    ("steps/toolCallResult", RESULT, {"decision": "modify", "reasoning": "rewritten",
                                      "modifications": {"modified_content": "[withheld]"}}),
]

INVALID = {
    "not an object": None,
    "a list": ["allow"],
    "an empty object": {},
    "an unknown key": {"decision": "allow", "extra": 1},
    "a request_id override": {"decision": "allow", "request_id": "99999999-9999-4999-8999-999999999999"},
    "a chain_hash override": {"decision": "allow", "chain_hash": "b" * 64},
    "a signature": {"decision": "allow", "signature": {"algorithm": "HMAC-SHA256", "value": "x", "key_id": "k"}},
    "a defer": {"decision": "defer", "reasoning": "later"},
    "an upper-case decision": {"decision": "ALLOW"},
    "a non-string decision": {"decision": True},
    "a deny without reasoning": {"decision": "deny"},
    "a modify without modifications": {"decision": "modify", "reasoning": "r"},
    "modifications on an allow": {"decision": "allow", "modifications": REDACT_ALL},
    "ask_details on a deny": {"decision": "deny", "reasoning": "r", "ask_details": ASK_DETAILS},
    "an ask without ask_details": {"decision": "ask", "reasoning": "r"},
    "ask_details missing timeout_seconds": {"decision": "ask", "reasoning": "r",
                                            "ask_details": {k: v for k, v in ASK_DETAILS.items()
                                                            if k != "timeout_seconds"}},
    "an ask that allows on timeout (D-043)": {"decision": "ask", "reasoning": "r",
                                              "ask_details": {**ASK_DETAILS, "timeout_disposition": "allow"}},
    "both modification shapes": {"decision": "modify", "reasoning": "r",
                                 "modifications": {"modified_content": "x", **REDACT_ALL}},
    "a redaction path that does not resolve": {"decision": "modify", "reasoning": "r",
                                               "modifications": {"redactions": [
                                                   {"path": "/outputs/0/value/bank_acount_number"}]}},
    "a redaction past the last output": {"decision": "modify", "reasoning": "r",
                                         "modifications": {"redactions": [
                                             {"path": "/outputs/2/value/bank_account_number"}]}},
    "a redaction path that is not a pointer": {"decision": "modify", "reasoning": "r",
                                               "modifications": {"redactions": [{"path": "outputs.0"}]}},
    "a redaction that skips an output carrying the field (issue #469)": {
        "decision": "modify", "reasoning": "r",
        "modifications": {"redactions": [{"path": "/outputs/0/value/bank_account_number"}]}},
    "a whole-value redaction that skips an output": {
        "decision": "modify", "reasoning": "r", "modifications": {"redactions": [{"path": "/outputs/1/value"}]}},
    "an empty redactions list": {"decision": "modify", "reasoning": "r", "modifications": {"redactions": []}},
    "parameter_overrides on a result": {"decision": "modify", "reasoning": "r",
                                        "modifications": {"parameter_overrides": {"amount": 1}}},
    "reason_codes that are not strings": {"decision": "deny", "reasoning": "r", "reason_codes": [1]},
}


@pytest.mark.parametrize("method,payload,verdict", VALID)
def test_a_valid_verdict_has_no_problem(method, payload, verdict):
    assert opa_backend.verdict_problem(verdict, method, payload, BASE) is None


@pytest.mark.parametrize("name", sorted(INVALID))
def test_an_invalid_verdict_has_a_problem(name):
    assert opa_backend.verdict_problem(INVALID[name], "steps/toolCallResult", RESULT, BASE)


def test_parameter_overrides_must_name_an_argument_the_call_carries():
    verdict = {"decision": "modify", "reasoning": "r", "modifications": {"parameter_overrides": {"cc": "x"}}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallRequest", CALL, BASE)


def _evaluate(method: str, payload: dict, url: str) -> dict:
    params = {"request_id": REQUEST_ID, "metadata": METADATA, "payload": copy.deepcopy(payload)}
    return opa_backend.evaluate(method, params, dict(BASE), OpaConfig(url=url, timeout_s=0.3))


@pytest.mark.parametrize("method,payload,verdict", VALID)
def test_evaluate_merges_a_valid_verdict_into_the_base(method, payload, verdict):
    with StubOpa(verdict) as opa:
        result = _evaluate(method, payload, opa.url)
    assert result == {**BASE, **verdict}
    assert opa.inputs == [{"input": {"method": method, "payload": payload, "metadata": METADATA}}]


@pytest.mark.parametrize("name", sorted(INVALID))
def test_evaluate_denies_an_invalid_verdict(name):
    with StubOpa(INVALID[name]) as opa:
        result = _evaluate("steps/toolCallResult", RESULT, opa.url)
    assert result["decision"] == "deny"
    assert result["reason_codes"] == ["opa_verdict_invalid"]
    assert (result["request_id"], result["chain_hash"]) == (REQUEST_ID, CHAIN)
    assert set(result) == {"type", "acs_version", "request_id", "chain_hash", "decision", "reasoning",
                           "reason_codes"}


@pytest.mark.parametrize("stub_kwargs,code", [
    ({"delay_s": 1.5}, "opa_timeout"),
    ({"status": 500}, "opa_http_error"),
    ({"body": b"<html>"}, "opa_response_malformed"),
    ({"body": b"{}"}, "opa_result_missing"),
])
def test_evaluate_denies_each_opa_failure_with_its_code(stub_kwargs, code):
    with StubOpa({"decision": "allow"}, **stub_kwargs) as opa:
        result = _evaluate("steps/toolCallRequest", CALL, opa.url)
    assert (result["decision"], result["reason_codes"]) == ("deny", [code])
    assert result["reasoning"]


def test_evaluate_denies_when_opa_is_down():
    result = _evaluate("steps/toolCallRequest", CALL, closed_port_url())
    assert (result["decision"], result["reason_codes"]) == ("deny", ["opa_unreachable"])


def _nested(depth: int) -> dict:
    node: dict = {}
    for _ in range(depth):
        node = {"n": node}
    return node


def test_a_verdict_nested_deeper_than_the_guardian_can_sign_is_invalid():
    verdict = {"decision": "allow", "policy_data": _nested(500)}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallRequest", CALL, BASE)


def test_evaluate_denies_a_body_nested_past_the_parser_limit():
    deep = b'{"result": ' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    with StubOpa(body=deep) as opa:
        result = _evaluate("steps/toolCallRequest", CALL, opa.url)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["opa_response_malformed"])


def test_evaluate_denies_when_validation_itself_fails(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("validator exploded")
    monkeypatch.setattr(opa_backend, "verdict_problem", broken)
    with StubOpa({"decision": "allow"}) as opa:
        result = _evaluate("steps/toolCallRequest", CALL, opa.url)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["opa_verdict_invalid"])


@pytest.mark.parametrize("path", ["/arguments/to", "/arguments/to/value", "/arguments"])
def test_a_redaction_that_overlaps_a_parameter_override_is_invalid(path):
    # Section 6.3: structured targets are disjoint. Overrides address /arguments/<key> in the payload.
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": path}], "parameter_overrides": {"to": "acct-2"}}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallRequest", CALL, BASE)


def test_a_redaction_beside_a_parameter_override_is_valid():
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": "/arguments/amount/value"}],
                                 "parameter_overrides": {"to": "acct-2"}}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallRequest", CALL, BASE) is None


def test_modified_content_on_a_tool_call_is_invalid():
    # A call's arguments are structured, so a rewrite goes through parameter_overrides, as a result's goes
    # through redactions or modified_content.
    verdict = {"decision": "modify", "reasoning": "r", "modifications": {"modified_content": "rm -rf /"}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallRequest", CALL, BASE)


def _assert_generic(result: dict, code: str, leaked: list[str]) -> None:
    assert (result["decision"], result["reason_codes"]) == ("deny", [code])
    assert result["reasoning"] == opa_backend.FAILURE_REASONING[code]
    assert len(result["reasoning"]) <= 200
    for text in leaked:
        assert text not in result["reasoning"]


@pytest.mark.parametrize("stub_kwargs,code", [
    ({"status": 503}, "opa_http_error"),
    ({"body": b"<html>internal-opa-17.corp</html>"}, "opa_response_malformed"),
    ({"body": b"{}"}, "opa_result_missing"),
    ({"delay_s": 1.0}, "opa_timeout"),
])
def test_signed_reasoning_is_generic_and_the_details_go_to_the_log(capsys, stub_kwargs, code):
    with StubOpa({"decision": "allow"}, **stub_kwargs) as opa:
        result = _evaluate("steps/toolCallRequest", CALL, opa.url)
    _assert_generic(result, code, ["127.0.0.1", "503", "internal-opa-17", "Error"])
    assert code in capsys.readouterr().err


def test_an_unreachable_opa_names_no_host_in_the_signed_reasoning(capsys):
    url = closed_port_url()
    result = _evaluate("steps/toolCallRequest", CALL, url)
    _assert_generic(result, "opa_unreachable", ["127.0.0.1", "Errno", "refused"])
    assert "opa_unreachable" in capsys.readouterr().err


def test_an_invalid_verdict_keeps_the_problem_out_of_the_signed_reasoning(capsys):
    with StubOpa({"decision": "allow", "request_id": "99999999-9999-4999-8999-999999999999"}) as opa:
        result = _evaluate("steps/toolCallRequest", CALL, opa.url)
    _assert_generic(result, "opa_verdict_invalid", ["request_id", "99999999"])
    assert "request_id" in capsys.readouterr().err


def test_every_failure_message_fits_200_characters():
    assert set(opa_backend.FAILURE_REASONING) == {
        "opa_unreachable", "opa_timeout", "opa_http_error", "opa_response_malformed", "opa_result_missing",
        "opa_verdict_invalid", "policy_backend_misconfigured"}
    assert all(0 < len(text) <= 200 for text in opa_backend.FAILURE_REASONING.values())


@pytest.mark.parametrize("paths", [
    ["/outputs/0/value/bank_account_number", "/outputs/1/value/bank_account_number",
     "/outputs/0/value/bank_account_number"],
    ["/outputs/0/value", "/outputs/1/value", "/outputs/0/value/bank_account_number",
     "/outputs/1/value/bank_account_number"],
    ["/outputs/0", "/outputs/1", "/outputs/1/value"],
])
def test_redaction_paths_that_repeat_or_nest_are_invalid(paths):
    # Section 6.3: structured targets are disjoint, so no path repeats or contains another.
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": p} for p in paths]}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallResult", RESULT, BASE)


ROWS = {**RESULT, "outputs": [{"value": {"rows": [{"ssn": "1", "name": "a"}, {"ssn": "2", "name": "b"}]}},
                              {"value": {"rows": [{"name": "c"}, {"ssn": "3"}]}}]}


def _redact(*paths: str) -> dict:
    return {"decision": "modify", "reasoning": "r", "modifications": {"redactions": [{"path": p} for p in paths]}}


@pytest.mark.parametrize("payload,verdict", [
    (RESULT, _redact("/outputs/0")),
    (RESULT, _redact("/outputs/1/value")),
    (ROWS, _redact("/outputs/0/value/rows/0/ssn")),
    (ROWS, _redact("/outputs/0/value/rows/0/ssn", "/outputs/0/value/rows/1/ssn")),
    (ROWS, _redact("/outputs/1/value/rows/1/ssn")),
    (ROWS, _redact("/outputs/0/value/rows/0")),
])
def test_a_redaction_must_cover_every_index_that_holds_the_same_field(payload, verdict):
    # Issue #469 in every form: a whole output, a value, and array elements nested inside a value.
    assert opa_backend.verdict_problem(verdict, "steps/toolCallResult", payload, BASE)


@pytest.mark.parametrize("payload,verdict", [
    (RESULT, _redact("/outputs/0", "/outputs/1")),
    (ROWS, _redact("/outputs/0/value/rows/0/ssn", "/outputs/0/value/rows/1/ssn", "/outputs/1/value/rows/1/ssn")),
    (ROWS, _redact("/outputs/0/value/rows/0", "/outputs/0/value/rows/1", "/outputs/1/value/rows/0",
                   "/outputs/1/value/rows/1")),
])
def test_a_redaction_that_covers_every_index_passes(payload, verdict):
    assert opa_backend.verdict_problem(verdict, "steps/toolCallResult", payload, BASE) is None



def _outputs(*values) -> dict:
    return {**RESULT, "outputs": [{"value": value} for value in values]}


# Coverage compares field paths with every array index removed, so one field covers every occurrence at any list
# depth. Bar's case: /outputs/0/value/ssn must also reach /outputs/1/value/0/ssn.
BAR = _outputs({"ssn": "1"}, [{"ssn": "2"}])
NESTED = _outputs({"ssn": "1"}, [[{"ssn": "2"}, {"ssn": "3"}]])
RECORDS = _outputs([{"ssn": "1", "name": "a"}, {"name": "b"}], {"name": "c"}, [[{"ssn": "2"}]])
ELSEWHERE = _outputs({"ssn": "1"}, {"contact": {"ssn": "2"}}, {"ssn": "3"})


@pytest.mark.parametrize("payload,verdict", [
    (BAR, _redact("/outputs/0/value/ssn")),
    (NESTED, _redact("/outputs/0/value/ssn")),
    (NESTED, _redact("/outputs/0/value/ssn", "/outputs/1/value/0/0/ssn")),
    (RECORDS, _redact("/outputs/0/value/0/ssn")),
    (ELSEWHERE, _redact("/outputs/0/value/ssn", "/outputs/1/value/contact/ssn")),
])
def test_a_redaction_must_cover_the_same_field_at_any_list_depth(payload, verdict):
    assert opa_backend.verdict_problem(verdict, "steps/toolCallResult", payload, BASE)


@pytest.mark.parametrize("payload,verdict", [
    (BAR, _redact("/outputs/0/value/ssn", "/outputs/1/value/0/ssn")),
    (NESTED, _redact("/outputs/0/value/ssn", "/outputs/1/value/0/0/ssn", "/outputs/1/value/0/1/ssn")),
    (RECORDS, _redact("/outputs/0/value/0/ssn", "/outputs/2/value/0/0/ssn")),
    # /outputs/1/value/contact/ssn is a different field path, so redacting /value/ssn does not demand it.
    (ELSEWHERE, _redact("/outputs/0/value/ssn", "/outputs/2/value/ssn")),
])
def test_a_redaction_that_covers_the_field_at_every_list_depth_passes(payload, verdict):
    assert opa_backend.verdict_problem(verdict, "steps/toolCallResult", payload, BASE) is None


def _many(outputs: int, fields: int = 1) -> tuple[dict, dict]:
    payload = {**RESULT, "outputs": [{"value": {f"f{k}": "x" for k in range(fields)}} for _ in range(outputs)]}
    paths = [f"/outputs/{i}/value/f{k}" for i in range(outputs) for k in range(fields)]
    return payload, _redact(*paths)


def _timed_problem(payload: dict, verdict: dict) -> tuple[str | None, float]:
    started = time.monotonic()
    problem = opa_backend.verdict_problem(verdict, "steps/toolCallResult", payload, BASE)
    return problem, time.monotonic() - started


def test_a_thousand_outputs_each_redacted_passes_within_a_second():
    problem, elapsed = _timed_problem(*_many(1000))
    assert problem is None
    assert elapsed < 1.0


def test_ten_thousand_outputs_each_redacted_denies_within_a_second():
    problem, elapsed = _timed_problem(*_many(10_000))
    assert problem == "the modify carries 10000 redactions, more than 2000"
    assert elapsed < 1.0


def test_more_than_a_thousand_outputs_is_invalid_under_the_redaction_cap():
    # 1,001 redactions stays under the 2,000 redaction cap, so only the outputs cap can reject this.
    problem, elapsed = _timed_problem(*_many(1001))
    assert problem == "a redacting modify on 1001 outputs, more than 1000"
    assert elapsed < 1.0


def test_more_than_two_thousand_redactions_is_invalid():
    problem, _ = _timed_problem(*_many(700, fields=3))
    assert problem == "the modify carries 2100 redactions, more than 2000"


def test_an_empty_parameter_overrides_object_is_invalid():
    verdict = {"decision": "modify", "reasoning": "r", "modifications": {"parameter_overrides": {}}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallRequest", CALL, BASE)


@pytest.mark.parametrize("method,payload,path", [
    ("steps/toolCallRequest", CALL, "/tool/name"),
    ("steps/toolCallRequest", CALL, "/tool"),
    ("steps/toolCallRequest", CALL, "/"),
    ("steps/toolCallRequest", CALL, "/metadata/agent_id"),
    ("steps/toolCallRequest", CALL, "/arguments"),
    ("steps/toolCallRequest", CALL, "/outputs/0/value"),
    ("steps/toolCallResult", RESULT, "/tool/name"),
    ("steps/toolCallResult", RESULT, "/exit_status"),
    ("steps/toolCallResult", RESULT, "/request_id_ref"),
    ("steps/toolCallResult", RESULT, "/outputs"),
    ("steps/toolCallResult", RESULT, "/arguments/to"),
])
def test_a_modify_touches_only_arguments_on_a_call_and_outputs_on_a_result(method, payload, path):
    # Renaming /tool/name after the hard denies ran would turn a harmless tool into bash.
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": path, "replacement": "Bash"}]}}
    problem = opa_backend.verdict_problem(verdict, method, payload, BASE)
    assert problem


def _deep_paths(count: int, depth: int) -> list[str]:
    stem = "/outputs/0/value" + "/a" * (depth - 4)
    return [f"{stem}/k{i}" for i in range(count)]


def test_the_overlap_check_is_linear_in_path_depth():
    paths = _deep_paths(2000, 900)
    started = time.monotonic()
    assert opa_backend._overlap_problem(paths) is None
    assert time.monotonic() - started < 0.2


@pytest.mark.parametrize("extra", ["/outputs/0/value/a", "/outputs/0/value" + "/a" * 896 + "/k7"])
def test_the_overlap_check_still_finds_a_deep_prefix_or_duplicate(extra):
    assert opa_backend._overlap_problem(_deep_paths(2000, 900) + [extra])


@pytest.mark.parametrize("paths", [
    ["/arguments/a~", "/arguments/a~0"],
    ["/arguments/a~2"],
    ["/outputs/0/value/~x"],
])
def test_an_invalid_pointer_escape_is_an_overlap_problem(paths):
    # RFC 6901 allows only ~0 and ~1. Without that rule, /arguments/a~ and /arguments/a~0 both name key a~.
    assert opa_backend._overlap_problem(paths)


def _deep_result(depth: int) -> tuple[dict, str]:
    value: dict = {"ssn": "1"}
    for _ in range(depth - 4):
        value = {"n": value}
    path = "/outputs/0/value" + "/n" * (depth - 4) + "/ssn"
    return {**RESULT, "outputs": [{"value": value}]}, path


def test_a_redaction_path_deeper_than_64_tokens_is_invalid():
    payload, path = _deep_result(65)
    verdict = {"decision": "modify", "reasoning": "r", "modifications": {"redactions": [{"path": path}]}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallResult", payload, BASE) == (
        "redaction path depth 65 is more than 64")


def test_a_redaction_path_64_tokens_deep_passes():
    payload, path = _deep_result(64)
    verdict = {"decision": "modify", "reasoning": "r", "modifications": {"redactions": [{"path": path}]}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallResult", payload, BASE) is None


@pytest.mark.parametrize("pointer", ["/a~2", "/a~", "/~x/b", "a/b"])
def test_one_pointer_parser_rejects_an_invalid_pointer_everywhere(pointer):
    document = {"a~2": 1, "a~": 1, "~x": {"b": 1}, "a": {"b": 1}}
    with pytest.raises(opa_backend.PointerError):
        opa_backend.decode_pointer(pointer)
    assert opa_backend._resolve_pointer(document, pointer) is False
    with pytest.raises(opa_backend.PointerError):
        opa_backend.replace_at(document, pointer, "x")


def test_a_redaction_with_an_invalid_escape_is_invalid_even_when_its_raw_key_exists():
    payload = {**RESULT, "outputs": [{"value": {"a~2": "secret"}}]}
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": "/outputs/0/value/a~2"}]}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallResult", payload, BASE)


@pytest.mark.parametrize("token", ["\u0663", "\u00b2", "01", "+1", " 1", "1 "])
def test_an_array_index_is_ascii_digits_only(token):
    # str.isdigit accepts Arabic-Indic digits and superscripts. Neither is an RFC 6901 array index.
    assert opa_backend._resolve_pointer({"a": [0, 1, 2, 3]}, f"/a/{token}") is False
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": f"/outputs/{token}/value"}]}}
    assert opa_backend.verdict_problem(verdict, "steps/toolCallResult", RESULT, BASE)


def test_the_coverage_walk_treats_an_unresolved_path_as_a_problem():
    # verdict_problem checks existence first, so this calls the walk directly: an unresolved path is never covered.
    assert opa_backend._coverage_problem(["/outputs/0/value/missing"], RESULT)


@pytest.mark.parametrize("document,pointer", [({"a": {}}, "/a/b"), ({"a": [1]}, "/a/1"), ({"a": 1}, "/a/b")])
def test_replace_at_never_adds_what_the_pointer_does_not_name(document, pointer):
    before = copy.deepcopy(document)
    with pytest.raises(opa_backend.PointerError):
        opa_backend.replace_at(document, pointer, "x")
    assert document == before


def test_an_opa_failure_detail_cannot_put_a_control_byte_in_the_log(monkeypatch, capsys):
    # An OPA error message can carry any bytes. opa_backend._log escapes it like every request-derived value.
    def failing_query(config, document):
        raise opa_backend.OpaFailure("opa_http_error", "OPA said: x\n[guardian] -> allow\x1b[31m")
    monkeypatch.setattr(opa_backend, "query", failing_query)
    result = opa_backend.evaluate("steps/toolCallRequest", {"payload": CALL, "metadata": {}}, dict(BASE),
                                  OpaConfig(url="http://127.0.0.1:1/x", timeout_s=0.3))
    assert result["reason_codes"] == ["opa_http_error"]
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert not any(line.startswith("[guardian] -> allow") for line in err.splitlines()), err


def test_log_value_escapes_control_characters_once():
    from acs.guardian._logging import log_value
    assert log_value("a\nb\x1bc", 20) == "a\\x0ab\\x1bc"
    # A detail that already carries an escaped value, as a !r in a message does, is not escaped a second time.
    assert log_value("redaction path '/a\\nb'", 100) == "redaction path '/a\\nb'"
    assert log_value(7) == "<int>"


def test_an_opa_detail_is_logged_up_to_1000_characters(capsys):
    detail = "d" * 990 + "END"
    opa_backend._log("opa_http_error", detail)
    assert "END" in capsys.readouterr().err


def _wide_call(overrides: int, redactions: int) -> tuple[dict, dict]:
    arguments = {f"o{i}": {"value": i} for i in range(overrides)}
    arguments.update({f"r{i}": {"value": i} for i in range(redactions)})
    modifications = {"parameter_overrides": {f"o{i}": 0 for i in range(overrides)},
                     "redactions": [{"path": f"/arguments/r{i}/value"} for i in range(redactions)]}
    return {**CALL, "arguments": arguments}, modifications


def test_the_override_overlap_check_is_linear():
    # Bar's sizes: comparing every override with every redaction took 16 s, past the 5 s decision timeout.
    payload, modifications = _wide_call(40_000, 2000)
    started = time.monotonic()
    assert opa_backend._modification_problem(modifications, "steps/toolCallRequest", payload) is None
    assert time.monotonic() - started < 1.0


def test_the_linear_override_check_still_finds_an_overlap_among_many():
    payload, modifications = _wide_call(40_000, 2000)
    modifications["redactions"].append({"path": "/arguments/o39999/value"})
    assert opa_backend._modification_problem(modifications, "steps/toolCallRequest", payload) == (
        "redaction path '/arguments/o39999/value' overlaps parameter_override 'o39999' (section 6.3)")


@pytest.mark.parametrize("overrides,paths", [
    ({"a": 1, "b": 2}, ["/b", ""]),
    ({"a": 1, "b": 2}, ["", "/b"]),
    ({"a": 1, "arguments": 2}, ["/arguments/a"]),
    ({"a": 1, "b/c": 2}, ["/x", "/b~1c/d"]),
    ({"a": 1, "b": 2}, ["/arguments/a/value", "/arguments/b"]),
    ({"a": 1, "b": 2}, ["/c", "/d/a"]),
])
def test_dropping_overrides_that_cannot_overlap_keeps_the_acs_core_verdict(overrides, paths):
    from acs.core._decision import modify_composition_violation
    modifications = {"parameter_overrides": overrides, "redactions": [{"path": p} for p in paths]}
    assert modify_composition_violation(opa_backend._overlap_candidates(modifications)) == (
        modify_composition_violation(modifications))
