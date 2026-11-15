import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCHEMA = json.loads((ROOT / "specification" / "v0.1.0" / "handshake.json").read_text())


def test_server_hello_requires_a_signature_algorithm_for_acs_core():
    algorithms = SCHEMA["$defs"]["ServerHello"]["properties"]["signature_algorithms_supported"]
    assert algorithms["minItems"] == 1
    assert "empty list is invalid" in algorithms["description"]


def test_both_hello_messages_can_carry_authentication_and_signatures():
    for hello in ("ClientHello", "ServerHello"):
        properties = SCHEMA["$defs"][hello]["properties"]
        assert properties["authentication_mechanism"]["type"] == "string"
        assert properties["signature"]["required"] == ["algorithm", "key_id", "value"]
