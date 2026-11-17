import hashlib

from acs.core import jcs_canonicalize

from acs_gateway.tool_digest import tool_digests

SEND = {"type": "function", "name": "send_email", "description": "Send an email to a recipient",
        "parameters": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                       "required": ["to", "body"]},
        "strict": True}


def digest(*tools):
    return tool_digests({"tools": list(tools)})


def test_the_form_is_sha256_over_the_jcs_of_the_declared_fields():
    fields = {k: SEND[k] for k in ("name", "description", "parameters", "strict")}
    assert digest(SEND) == {"send_email": "sha256:" + hashlib.sha256(jcs_canonicalize(fields)).hexdigest()}


def test_one_changed_character_changes_the_digest():
    changed = {**SEND, "description": "Send an email to a recipient."}
    assert digest(SEND)["send_email"] != digest(changed)["send_email"]


def test_key_order_does_not_change_the_digest():
    reordered = {"strict": True, "parameters": {"required": ["to", "body"], "properties": {
        "body": {"type": "string"}, "to": {"type": "string"}}, "type": "object"},
        "description": SEND["description"], "name": "send_email", "type": "function"}
    assert digest(reordered) == digest(SEND)


def test_the_schema_and_the_strict_flag_count():
    schema = {**SEND, "parameters": {**SEND["parameters"], "required": ["to"]}}
    loose = {**SEND, "strict": False}
    assert len({digest(SEND)["send_email"], digest(schema)["send_email"], digest(loose)["send_email"]}) == 3


def test_type_and_unknown_fields_are_outside_the_digest():
    assert digest({**SEND, "x_extra": 1}) == digest(SEND)


def test_a_repeated_name_hashes_every_declaration_in_order():
    other = {**SEND, "description": "Send mail"}
    both = digest(SEND, other)["send_email"]
    assert both not in (digest(SEND)["send_email"], digest(other)["send_email"])
    fields = [{k: t[k] for k in ("name", "description", "parameters", "strict")} for t in (SEND, other)]
    assert both == "sha256:" + hashlib.sha256(jcs_canonicalize(fields)).hexdigest()


def test_an_unencodable_declaration_has_no_digest():
    assert digest({**SEND, "description": "bad \ud800"}) == {}


def test_non_function_and_malformed_entries_are_skipped():
    assert tool_digests({"tools": [{"type": "web_search"}, "x", {"type": "function", "name": 7}]}) == {}
    assert tool_digests({"tools": "nope"}) == {}
    assert tool_digests({}) == {}
