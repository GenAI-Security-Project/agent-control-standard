import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCHEMA = json.loads((ROOT / "specification" / "v0.1.0" / "request-envelope.json").read_text())


def test_metadata_accepts_a_typed_executing_service_identity():
    metadata = SCHEMA["$defs"]["Metadata"]["properties"]
    assert metadata["service_identity"]["$ref"] == "#/$defs/ServiceIdentity"

    identity = SCHEMA["$defs"]["ServiceIdentity"]
    assert identity["required"] == ["type", "id"]
    assert set(identity["properties"]) == {"type", "id", "issuer", "scopes", "claims"}
