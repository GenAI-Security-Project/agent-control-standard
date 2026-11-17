import pytest

from acs_gateway.apply import repeated_function_name
from acs_gateway.tool_digest import ToolDigests

SEND = {"type": "function", "name": "send_email", "description": "Send an email to a recipient",
        "parameters": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                       "required": ["to", "body"]},
        "strict": True}
# sha256 of {"description":...,"name":"send_email","parameters":...,"strict":true} in RFC 8785 form, computed apart
# from the code under test.
SEND_DIGEST = "sha256:9105b625a375975d8c67b396b3839f8a1e98fe7e51b8a5f141180efe7e561d83"


def digest(*tools, name="send_email"):
    return ToolDigests({"tools": list(tools)}).get(name)


def test_the_form_is_sha256_over_the_jcs_of_the_declared_fields():
    assert digest(SEND) == SEND_DIGEST


def test_one_changed_character_changes_the_digest():
    assert digest({**SEND, "description": "Send an email to a recipient."}) != digest(SEND)


def test_key_order_does_not_change_the_digest():
    reordered = {"strict": True, "parameters": {"required": ["to", "body"], "properties": {
        "body": {"type": "string"}, "to": {"type": "string"}}, "type": "object"},
        "description": SEND["description"], "name": "send_email", "type": "function"}
    assert digest(reordered) == digest(SEND)


def test_the_schema_and_the_strict_flag_count():
    schema = {**SEND, "parameters": {**SEND["parameters"], "required": ["to"]}}
    assert len({digest(SEND), digest(schema), digest({**SEND, "strict": False})}) == 3


def test_an_omitted_field_and_its_explicit_default_differ():
    # Fields are hashed as sent, with no default filled in.
    assert digest({k: v for k, v in SEND.items() if k != "strict"}) != digest({**SEND, "strict": False})


def test_type_and_unknown_fields_are_outside_the_digest():
    assert digest({**SEND, "x_extra": 1}) == digest(SEND)


def test_a_repeated_name_has_no_digest_and_is_named_for_refusal():
    body = {"tools": [SEND, {**SEND, "description": "Send mail"}]}
    assert ToolDigests(body).get("send_email") is None
    assert repeated_function_name(body) == "send_email"
    assert repeated_function_name({"tools": [SEND]}) is None


def test_an_unencodable_declaration_is_skipped_and_reported_once():
    skipped = []
    digests = ToolDigests({"tools": [{**SEND, "description": "bad \ud800"}]},
                          on_skip=lambda name, reason: skipped.append(name))
    assert digests.get("send_email") is None and digests.get("send_email") is None
    assert skipped == ["send_email"]


def test_any_other_error_is_raised(monkeypatch):
    import acs_gateway.tool_digest as td

    def broken(value):
        raise RuntimeError("canonicalizer bug")

    monkeypatch.setattr(td, "jcs_canonicalize", broken)
    with pytest.raises(RuntimeError):
        ToolDigests({"tools": [SEND]}).get("send_email")


def test_only_the_names_asked_for_are_hashed(monkeypatch):
    import acs_gateway.tool_digest as td
    hashed = []
    real = td.jcs_canonicalize
    monkeypatch.setattr(td, "jcs_canonicalize", lambda value: hashed.append(value["name"]) or real(value))
    digests = ToolDigests({"tools": [SEND, {**SEND, "name": "other"}]})
    digests.get("send_email")
    digests.get("send_email")
    assert hashed == ["send_email"]


@pytest.mark.parametrize("name", [None, 7, ["send_email"], ""])
def test_a_non_string_or_empty_name_gets_no_digest(name):
    assert digest(SEND, {**SEND, "name": ""}, name=name) is None


def test_non_function_and_malformed_entries_are_skipped():
    assert ToolDigests({"tools": [{"type": "web_search"}, "x", {"type": "function", "name": 7}]}).get("x") is None
    assert ToolDigests({"tools": "nope"}).get("send_email") is None
    assert ToolDigests({"tools": None}).get("send_email") is None
    assert ToolDigests({}).get("send_email") is None
