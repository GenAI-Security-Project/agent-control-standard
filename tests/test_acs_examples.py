"""Keep the wire examples on acs.md valid against the v0.1.0 schemas.

The overview page shipped requests for methods ACS never defined
(`acs/registerHook`, `guardian/evaluate`) and a MODIFY response the response
envelope rejects. The build and link guards accepted them, because nothing read
the JSON. Read it here.

Envelope validation alone is not enough. The envelope's `method` pattern checks
only the namespace prefix, so `steps/anything` passes it, and the envelope
accepts any object as `payload`. A request therefore has to name a method whose
payload schema exists, and its payload has to satisfy that schema. A response
has to fit the response envelope and answer a request shown beside it. Every
request is checked before indexing by ID, and duplicate IDs are rejected so
one request cannot hide another.

The schemas leave signatures and chain heads field-optional. Check their
required presence for these Core examples too. Signature and chain values
are illustrative; this guard does not verify cryptographic authenticity.

Sections join SECTIONS as their examples are rebuilt (#267). Every JSON block in
a listed section must be a JSON-RPC message; a section that needs other JSON
needs its own rule.
"""

import json
import re
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specification" / "v0.1.0"
PAGE = ROOT / "docs" / "acs.md"
SECTIONS = ["Instrumentable"]


def load_schemas():
    schemas = {}
    for path in sorted(SPEC.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            schemas[path.relative_to(SPEC).as_posix()] = doc
    return schemas


SCHEMAS = load_schemas()
REGISTRY = Registry().with_resources(
    (doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012))
    for doc in SCHEMAS.values()
)

# The base payload schema for each defined method, read from its title
# ("steps/toolCallRequest payload"). Profile variants carry a suffix and are
# left out, so a Core example is checked against the Core schema.
PAYLOADS = {
    match[1]: doc
    for doc in SCHEMAS.values()
    if (match := re.fullmatch(r"(\S+) payload", doc.get("title", "")))
}


def validate(schema, instance):
    Draft202012Validator(schema, registry=REGISTRY, format_checker=FormatChecker()).validate(instance)


def section(name):
    text = PAGE.read_text(encoding="utf-8")
    start = text.index(f"\n### {name}\n")
    following = re.search(r"\n#{1,3} ", text[start + 1:])
    return text[start:start + 1 + following.start()] if following else text[start:]


def messages(name):
    blocks = re.findall(r"```json\n(.*?)```", section(name), re.DOTALL)
    shown = [json.loads(block) for block in blocks]
    for message in shown:
        assert message.get("jsonrpc") == "2.0", f"{name} shows JSON that is not a JSON-RPC message"
    return shown


def check_request(request):
    method = request["method"]
    assert method in PAYLOADS, f"{method} is not a defined v0.1 method"
    validate(SCHEMAS["request-envelope.json"], request)
    validate(PAYLOADS[method], request["params"]["payload"])
    # system/ping is explicitly exempt from Core signature requirements.
    if method != "system/ping":
        assert "signature" in request["params"], "ACS-Core requests require params.signature"


def check_response(response, requests):
    validate(SCHEMAS["response-envelope.json"], response)
    request = requests.get(response["id"])
    assert request, f"Response {response['id']} answers no request shown beside it"
    result = response["result"]
    assert result["request_id"] == request["params"]["request_id"]
    if request["method"] != "system/ping":
        assert "signature" in result, "ACS-Core responses require result.signature"
    # This rebuilt example is a content-bearing hook (Specification §8.6).
    # Extend this check when other content-bearing examples join SECTIONS.
    if request["method"] == "steps/toolCallRequest":
        assert "chain_hash" in result, "toolCallRequest responses require result.chain_hash"
    overrides = result.get("modifications", {}).get("parameter_overrides", {})
    arguments = request["params"]["payload"].get("arguments", {})
    assert set(overrides) <= set(arguments), "parameter_overrides names an argument the request does not carry"


def split(name):
    shown = messages(name)
    requests = {}
    responses = []
    for message in shown:
        if "method" in message:
            check_request(message)
            assert message["id"] not in requests, f"{name} repeats request ID {message['id']}"
            requests[message["id"]] = message
        else:
            responses.append(message)
    return requests, responses


@pytest.mark.parametrize("name", SECTIONS)
def test_requests_use_defined_methods_and_valid_payloads(name):
    requests, _ = split(name)
    assert requests, f"{name} shows no request"


@pytest.mark.parametrize("name", SECTIONS)
def test_responses_answer_a_request_shown_beside_them(name):
    requests, responses = split(name)
    assert responses, f"{name} shows no response"
    for response in responses:
        check_response(response, requests)


def instrumentable_exchange():
    requests, responses = split("Instrumentable")
    return deepcopy(requests), deepcopy(responses[0])


@pytest.mark.parametrize("method", ["acs/registerHook", "guardian/evaluate", "steps/registerHook"])
def test_undefined_methods_are_rejected(method):
    requests, _ = instrumentable_exchange()
    request = next(iter(requests.values()))
    request["method"] = method
    with pytest.raises((AssertionError, ValidationError)):
        check_request(request)


def test_a_bare_argument_value_is_rejected():
    requests, _ = instrumentable_exchange()
    request = next(iter(requests.values()))
    request["params"]["payload"]["arguments"]["query"] = "SELECT * FROM customers"
    with pytest.raises(ValidationError):
        check_request(request)


def test_an_unsigned_core_request_is_rejected():
    requests, _ = instrumentable_exchange()
    request = next(iter(requests.values()))
    request["params"].pop("signature")
    # This is schema-valid; Core imposes the stronger presence requirement.
    validate(SCHEMAS["request-envelope.json"], request)
    with pytest.raises(AssertionError, match=r"require params\.signature"):
        check_request(request)


@pytest.mark.parametrize("field", ["signature", "chain_hash"])
def test_required_core_response_fields_cannot_be_omitted(field):
    requests, response = instrumentable_exchange()
    response["result"].pop(field)
    validate(SCHEMAS["response-envelope.json"], response)
    with pytest.raises(AssertionError, match=rf"require result\.{field}"):
        check_response(response, requests)


@pytest.mark.parametrize("invalid_first", [True, False], ids=["invalid-first", "invalid-last"])
def test_a_request_with_a_reused_id_cannot_hide_an_invalid_method(monkeypatch, invalid_first):
    requests, response = instrumentable_exchange()
    valid = next(iter(requests.values()))
    invalid = deepcopy(valid)
    invalid["method"] = "steps/notDefined"
    shown = [invalid, valid, response] if invalid_first else [valid, invalid, response]
    monkeypatch.setattr(f"{__name__}.messages", lambda _: shown)
    with pytest.raises(AssertionError, match="steps/notDefined is not a defined v0.1 method"):
        split("Instrumentable")


def test_duplicate_valid_request_ids_are_rejected(monkeypatch):
    requests, response = instrumentable_exchange()
    request = next(iter(requests.values()))
    shown = [request, deepcopy(request), response]
    monkeypatch.setattr(f"{__name__}.messages", lambda _: shown)
    with pytest.raises(AssertionError, match="repeats request ID"):
        split("Instrumentable")


@pytest.mark.parametrize("mutation", [
    pytest.param(lambda result: result.pop("modifications"), id="modify-without-modifications"),
    pytest.param(lambda result: result.pop("reasoning"), id="modify-without-reasoning"),
    pytest.param(lambda result: result.update(decision="MODIFY"), id="uppercase-decision"),
    pytest.param(lambda result: result.update(request_id="not-a-uuid"), id="non-uuid-request-id"),
    pytest.param(
        lambda result: result["modifications"].update(parameter_overrides={"table": "customers"}),
        id="override-for-an-argument-not-sent",
    ),
])
def test_malformed_modify_responses_are_rejected(mutation):
    requests, response = instrumentable_exchange()
    mutation(response["result"])
    with pytest.raises((AssertionError, ValidationError)):
        check_response(response, requests)
