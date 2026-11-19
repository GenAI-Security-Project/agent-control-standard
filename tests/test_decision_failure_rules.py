"""A refusal blocks whatever the posture, a decision failure follows it, and only the agent can loosen it (#32).

The default posture is deny. The Guardian's on_decision_failure can make it stricter and never
looser, and every error but a signed -32603 is a refusal. Each test below fails if one of those
rules disappears from the text or the schemas that state it.
"""

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specification" / "v0.1.0"
SPECIFICATION = ROOT / "docs" / "spec" / "instrument" / "specification.md"


def _section(heading: str, next_heading: str) -> str:
    text = SPECIFICATION.read_text(encoding="utf-8")
    return text.split(heading, 1)[1].split(next_heading, 1)[0]


def _schema(name: str) -> dict:
    return json.loads((SPEC / name).read_text(encoding="utf-8"))


def _response_envelope_validator() -> Draft202012Validator:
    resources = []
    for path in sorted(SPEC.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)))
    return Draft202012Validator(_schema("response-envelope.json"), registry=Registry().with_resources(resources))


def test_a_decision_failure_follows_the_posture_and_a_refusal_never_does():
    honoring = _section("### 6.4 Honoring decisions (normative)", "### 6.5")
    assert "A decision failure follows the failure posture below." in honoring
    assert "signed `-32603` `Internal error`" in honoring
    assert "`429` included" in honoring
    assert "which covers every §17.1 code and any code added later" in honoring
    assert "fails `response-envelope.json`, an `allow` included" in honoring
    assert "The Observed Agent MUST block the step whatever the posture." in honoring


def test_only_the_agents_own_configuration_opts_into_proceed():
    honoring = _section("### 6.4 Honoring decisions (normative)", "### 6.5")
    assert "`deny` (fail-closed) unless the Observed Agent's own deployment configuration opts into `proceed`" in honoring
    assert "can only make it stricter" in honoring

    posture = _schema("handshake.json")["$defs"]["ServerHello"]["properties"]["on_decision_failure"]
    assert "default" not in posture, "an absent on_decision_failure leaves the agent's own posture in force"
    assert "stricter, never looser" in posture["description"]


def test_a_handshake_with_no_usable_answer_refuses_the_session_by_default():
    startup = _section("### 4.1 Handshake failure (normative)", "## 5.")
    assert "The default is `refuse`" in startup
    assert "recorded in the deployment's own audit log under either posture" in startup


def test_no_page_still_says_the_default_is_proceed():
    stale = re.compile(r"default(?:s|ing)? (?:to |is )?`proceed`|`proceed` by default|'proceed' \(default\)|\"default\": \"proceed\""
                       r"|defaults \([^)]*: proceed|time(?:s|d)? out to `?allow")
    pages = [*(ROOT / "docs" / "spec").rglob("*.md"), ROOT / "docs" / "topics" / "faq.md", *SPEC.rglob("*.json")]
    found = [f"{page.relative_to(ROOT)}: {match.group(0)}"
             for page in pages for match in stale.finditer(page.read_text(encoding="utf-8"))]
    assert not found, "\n".join(found)


def test_an_ask_never_times_out_into_an_allow():
    assert _schema("ask-details.json")["properties"]["timeout_disposition"]["enum"] == ["deny"]
    approver = _section("## 9. Approver Model", "## 10.")
    assert "resolves as `DENY`: the Observed Agent never proceeds on an ASK on its own" in approver
    assert "leaves the step blocked whatever the failure posture" in approver, "an outage must not release a pending ASK"


def test_every_registry_error_is_a_refusal_and_only_a_signed_internal_error_follows_the_posture():
    errors = _section("## 17. Error Handling", "## 18.")
    assert "Every error in this registry is a refusal" in errors
    assert "A signed `-32603` is the one error that follows the failure posture" in errors
    assert "`reason_code:" not in errors, "a chain mismatch deny uses the reason_codes array"


def test_an_error_carries_its_signature_and_the_fields_its_recovery_reads():
    error = _schema("response-envelope.json")["$defs"]["JsonRpcError"]["properties"]
    assert error["signature"]["$ref"] == "request-envelope.json#/$defs/Signature"

    validator = _response_envelope_validator()
    signed = {"jsonrpc": "2.0", "id": "rpc-1", "error": {
        "code": -32001, "message": "UNSUPPORTED_VERSION",
        "data": {"reason": "no common version", "supported_versions": ["0.2.0"]},
        "signature": {"algorithm": "HMAC-SHA256", "value": "AAAA", "key_id": "k1"}}}
    assert validator.is_valid(signed)

    not_an_object = {**signed, "error": {**signed["error"], "data": "no common version"}}
    assert not validator.is_valid(not_an_object), "the recovery column reads data as an object"

    bad_versions = {**signed, "error": {**signed["error"], "data": {"supported_versions": ["latest"]}}}
    assert not validator.is_valid(bad_versions)


def test_trace_records_the_posture_the_agent_applied():
    mapping = json.loads((SPEC / "trace" / "otel-mapping.json").read_text(encoding="utf-8"))
    values = mapping["properties"]["decision_failure_event"]["properties"]["attribute_values"]["description"]
    assert "the posture the Observed Agent applied" in values
    assert "A refusal is always fail_closed" in values
    assert "fail_open for on_decision_failure proceed" not in values, "the Guardian's proceed no longer sets the posture"


def test_a_guardian_reports_only_the_posture_it_can_know():
    mapping = json.loads((SPEC / "trace" / "otel-mapping.json").read_text(encoding="utf-8"))
    failure = mapping["properties"]["decision_failure_event"]["properties"]["attribute_values"]
    assert "unknown" in failure["default"]["acs.failure.posture"]
    assert "sets fail_closed in that case and unknown otherwise" in failure["description"]

    late = json.loads((SPEC / "trace" / "ocsf-mapping.json").read_text(encoding="utf-8"))["properties"]["decision_class"]["properties"]["late_decision"]
    assert late["properties"]["finding_types"]["default"] == ["late_decision_fail_closed", "late_decision_posture_unknown"]
    assert "true for any verdict other than allow when the posture is unknown" in late["description"]


def test_a_blocked_step_says_why_it_was_blocked():
    honoring = _section("### 6.4 Honoring decisions (normative)", "### 6.5")
    assert "with its failure class and its cause: the JSON-RPC error code, the HTTP status, or the timeout that elapsed" in honoring
    assert "SHOULD tell the user and the agent that ACS blocked it and why" in honoring
    assert "rather than copying from the response" in honoring


def test_a_decision_that_arrives_after_the_timeout_changes_nothing():
    honoring = _section("### 6.4 Honoring decisions (normative)", "### 6.5")
    assert "A decision that arrives after the negotiated timeout changes nothing" in honoring
    assert "MUST keep that outcome and discard the late answer, for that request and for any other" in honoring
    assert "Under `proceed`, the action runs even when a `DENY` arrives after the timeout but before the action has started" in honoring
    assert "SHOULD be shorter than the host framework's own hook timeout" in honoring
    conformance = (ROOT / "docs" / "spec" / "conformance.md").read_text(encoding="utf-8")
    assert "a decision that arrives after the timeout leaves that outcome as it is" in conformance
    faq = (ROOT / "docs" / "topics" / "faq.md").read_text(encoding="utf-8")
    assert "keep that outcome when a decision arrives after the timeout" in faq


def test_a_gating_hook_blocks_when_it_breaks():
    honoring = _section("### 6.4 Honoring decisions (normative)", "### 6.5")
    assert "A deployment SHOULD configure every hook that gates an action so that the host blocks the action when the hook fails" in honoring
    assert '`"onFailure": "block"` in Claude Code and `"failClosed": true` in Cursor' in honoring
