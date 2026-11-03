"""The defer/subscribe schemas accept the messages of Specification 6.6 and refuse what it forbids.

The messages below are one subscription to a deferral an approver resolved: the
request, the defer/pending notification and the response. The tests hold the rules
of Specification 6.6 that a schema can express, so a later schema edit that breaks
one of them fails here.
"""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SPEC = Path(__file__).resolve().parents[1] / "specification" / "v0.1.0"
BASE = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/"

SESSION = "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"
DEFERRED = "8c1d5e2a-4b7f-4e19-a3c6-0f9e2d7b1a54"
SUBSCRIBE = "b27e4f90-1c3a-4d5b-8e6f-7a9c0d2e3f41"
SIGNATURE = {"algorithm": "HMAC-SHA256", "key_id": "2026-10", "value": "R1r68MKnbdN3tsgmm0geCJvjEfgI9yDvk5xe1KQzEvU="}

REQUEST = {
    "jsonrpc": "2.0",
    "id": 42,
    "method": "defer/subscribe",
    "params": {
        "acs_version": "0.1.0",
        "request_id": SUBSCRIBE,
        "timestamp": "2026-11-02T18:00:01Z",
        "metadata": {"agent_id": "mail-agent", "session_id": SESSION},
        "payload": {"deferred_request_id": DEFERRED},
        "signature": SIGNATURE,
    },
}
PENDING = {"jsonrpc": "2.0", "method": "defer/pending", "params": {"acs_version": "0.1.0", "deferred_request_id": DEFERRED}}
RESPONSE = {
    "jsonrpc": "2.0",
    "id": 42,
    "result": {
        "type": "final",
        "acs_version": "0.1.0",
        "request_id": SUBSCRIBE,
        "decision": "allow",
        "reasoning": "Approved by the operator; no policy objects to the step as the session now stands.",
        "defer_resolution": {
            "deferred_request_id": DEFERRED,
            "resolution_method": "human_approval",
            "resolved_at": "2026-11-02T18:04:10Z",
            "deferred_metadata": {"agent_id": "mail-agent", "session_id": SESSION, "user_context": {"user_id": "u-1001"}},
            "approval": {"approver": {"type": "human", "id": "operator-7"}, "decision": "allow", "decided_at": "2026-11-02T18:04:09Z"},
        },
        "chain_hash": "4e9b2c71d05a3f86e1c74b20a9d35f68c2e18b47d06a95f3e27c1b84d50f6a39",
        "signature": SIGNATURE,
    },
}


def _registry():
    resources = []
    for path in sorted(SPEC.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)))
    return Registry().with_resources(resources)


REGISTRY = _registry()


def _validator(ref):
    return Draft202012Validator({"$ref": BASE + ref}, registry=REGISTRY, format_checker=FormatChecker())


def test_the_request_is_valid():
    assert _validator("request-envelope.json").is_valid(REQUEST)
    assert _validator("hooks/defer-subscribe.json").is_valid(REQUEST["params"]["payload"])


def test_the_notification_and_the_response_are_valid():
    assert _validator("hooks/defer-subscribe.json#/$defs/PendingNotification").is_valid(PENDING)
    assert _validator("response-envelope.json").is_valid(RESPONSE)


def test_the_aggregator_accepts_every_message():
    aggregator = _validator("acs_schema.json")
    for message in [REQUEST, PENDING, RESPONSE]:
        assert aggregator.is_valid(message), message.get("method", "response")


def _resolution_result():
    return copy.deepcopy(RESPONSE["result"])


@pytest.mark.parametrize(
    "change",
    [
        pytest.param(lambda r: r["defer_resolution"].pop("resolved_at"), id="no-resolved_at"),
        pytest.param(lambda r: r["defer_resolution"].pop("approval"), id="human_approval-without-approval"),
        pytest.param(
            lambda r: (
                r.update(
                    decision="defer",
                    defer_details={"reason": "low_confidence", "resolution_method": "timeout", "resolution_timeout_ms": 1},
                ),
                r["defer_resolution"].update(resolution_method="additional_context"),
                r["defer_resolution"].pop("approval"),
            ),
            id="resolution-is-defer",
        ),
        pytest.param(
            lambda r: (r["defer_resolution"].update(resolution_method="session_end"), r["defer_resolution"].pop("approval")),
            id="session_end-with-allow",
        ),
        pytest.param(lambda r: r["defer_resolution"]["approval"].update(decision="deny"), id="approver-deny-resolved-to-allow"),
        pytest.param(lambda r: r.update(decision="deny", reasoning="Policy refuses it."), id="approved-then-deny-without-reason_codes"),
        pytest.param(
            lambda r: (r["defer_resolution"].update(resolution_method="timeout"), r["defer_resolution"].pop("approval")),
            id="timeout-with-allow",
        ),
    ],
)
def test_the_schemas_refuse_a_resolution_section_6_6_forbids(change):
    result = _resolution_result()
    change(result)
    assert not _validator("response-envelope.json#/$defs/AcsResult").is_valid(result)


@pytest.mark.parametrize(
    "change",
    [
        pytest.param(
            lambda r: r.update(decision="deny", reasoning="Policy refuses it.", reason_codes=["untrusted_into_consequential"]),
            id="approved-then-deny-with-reason_codes",
        ),
        pytest.param(
            lambda r: r.update(
                decision="modify",
                reasoning="The credential is redacted.",
                reason_codes=["credential_redacted"],
                modifications={"redactions": [{"path": "/arguments/body"}]},
            ),
            id="approved-then-modify",
        ),
        pytest.param(
            lambda r: (
                r.update(decision="deny", reasoning="No resolution in time."),
                r["defer_resolution"].update(resolution_method="timeout"),
                r["defer_resolution"].pop("approval"),
            ),
            id="timeout-deny",
        ),
        pytest.param(
            lambda r: (
                r.update(decision="deny", reasoning="The session ended."),
                r["defer_resolution"].update(resolution_method="session_end"),
                r["defer_resolution"].pop("approval"),
            ),
            id="session_end-deny",
        ),
    ],
)
def test_the_schemas_accept_representative_resolutions_section_6_6_allows(change):
    result = _resolution_result()
    change(result)
    assert _validator("response-envelope.json#/$defs/AcsResult").is_valid(result)


def test_a_timeout_never_resolves_to_ask():
    """An expired DEFER fails closed: `timeout_decision` allows only `deny`, and a timeout resolution is `deny`."""
    details = {"reason": "low_confidence", "resolution_method": "human_approval", "resolution_timeout_ms": 900000}
    validator = _validator("defer-details.json")
    assert validator.is_valid(dict(details, timeout_decision="deny"))
    assert not validator.is_valid(dict(details, timeout_decision="ask"))
    result = _resolution_result()
    result.update(
        decision="ask",
        reasoning="No resolution in time.",
        ask_details={"approver": {"type": "human", "id": "u-1001"}, "question": "Send it?", "timeout_seconds": 300},
    )
    result["defer_resolution"].update(resolution_method="timeout")
    result["defer_resolution"].pop("approval")
    assert not _validator("response-envelope.json#/$defs/AcsResult").is_valid(result)


@pytest.mark.parametrize(
    "location,field,value",
    [("envelope", "id", 7), ("params", "decision", "allow"), ("params", "signature", SIGNATURE)],
)
def test_a_defer_pending_with_a_forbidden_field_is_refused(location, field, value):
    pending = copy.deepcopy(PENDING)
    (pending if location == "envelope" else pending["params"])[field] = value
    assert not _validator("hooks/defer-subscribe.json#/$defs/PendingNotification").is_valid(pending)
