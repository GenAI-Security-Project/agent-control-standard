"""Guards for the signature envelope, the MAC wording, and the composite ML-DSA identifiers.

Specification section 10 once defined its own hybrid encoding, a 4-byte length prefix around
each component, and named pairs (`ML-DSA-65+ECDSA-P256`) that no standard defines. It also
called the HMAC baseline a signature, left the verifier free to trust the wire `algorithm`,
and recommended a five-minute skew window. These tests hold the prose and both schemas to the
fixed rules.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specification" / "v0.1.0"
DOCS = ROOT / "docs"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


SPECIFICATION = _read(DOCS / "spec" / "instrument" / "specification.md")
CONFORMANCE = _read(DOCS / "spec" / "conformance.md")
ACS = _read(DOCS / "acs.md")
README = _read(ROOT / "README.md")
HOOKS = _read(DOCS / "spec" / "instrument" / "hooks.md")
INSPECT = _read(DOCS / "spec" / "inspect" / "README.md")
REQUEST = json.loads(_read(SPEC / "request-envelope.json"))
HANDSHAKE = json.loads(_read(SPEC / "handshake.json"))

COMPOSITES = ["id-MLDSA65-ECDSA-P256-SHA512", "id-MLDSA65-RSA3072-PSS-SHA512"]
RETIRED = ["ML-DSA-65+ECDSA-P256", "ML-DSA-65+RSA-PSS-SHA256"]


def _section(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


def _signature_enum() -> list[str]:
    return REQUEST["$defs"]["Signature"]["properties"]["algorithm"]["enum"]


def _handshake_enum() -> list[str]:
    return HANDSHAKE["$defs"]["ServerHello"]["properties"]["signature_algorithms_supported"]["items"]["enum"]


def test_both_schema_enums_use_the_composite_identifiers():
    for enum in (_signature_enum(), _handshake_enum()):
        for name in COMPOSITES:
            assert name in enum
        for name in RETIRED:
            assert name not in enum


def test_the_two_enums_name_the_same_algorithms():
    assert sorted(_signature_enum()) == sorted(_handshake_enum())


def test_the_registry_lists_the_composites_and_not_the_retired_names():
    registry = _section(SPECIFICATION, "### 10.1 Algorithm registry", "### 10.2")
    for name in COMPOSITES:
        assert f"`{name}`" in registry
    for name in RETIRED:
        assert name not in registry


def test_no_retired_identifier_or_length_prefix_rule_survives():
    surfaces = [SPECIFICATION, CONFORMANCE, ACS, json.dumps(REQUEST), json.dumps(HANDSHAKE)]
    for text in surfaces:
        for name in RETIRED:
            assert name not in text
        assert "len(pqc_sig)" not in text
        assert "4-byte big-endian" not in text


def test_section_10_2_adopts_the_composite_draft():
    section = _section(SPECIFICATION, "### 10.2", "### 10.3")
    assert "RFC 10073" in section and "draft-ietf-lamps-pq-composite-sigs" in section
    assert "`mldsaSig || tradSig`" in section and "no length prefixes" in section


def test_a_composite_fails_if_either_component_fails():
    section = _section(SPECIFICATION, "### 10.2", "### 10.3")
    assert "valid only if both components verify" in section
    assert "lacks either component key" in section
    assert "`SIGNATURE_INVALID` (`-32004`, §17.1)" in section
    assert "MUST NOT accept on the one component" in section
    assert re.search(r"-32004`\s*\|\s*`SIGNATURE_INVALID`", SPECIFICATION)


def test_the_replay_skew_default_fits_ntp_and_keeps_a_documented_upper_bound():
    skew = HANDSHAKE["$defs"]["ServerHello"]["properties"]["skew_window_ms"]
    assert skew["default"] == 30000
    assert "300000" in skew["description"] and "NTP" in skew["description"]
    section = _section(SPECIFICATION, "### 10.3 Replay protection", "## 11.")
    assert "RECOMMENDED default 30000" in section
    assert "up to 300000" in section


def test_the_baseline_is_called_a_mac():
    assert "message authentication code (MAC)" in README
    assert "baseline HMAC-SHA256 signature" not in README + ACS
    assert "baseline HMAC-SHA256 message authentication code (MAC)" in ACS
    assert "signature or MAC" in CONFORMANCE
    assert "baseline MAC (HMAC-SHA256)" in CONFORMANCE
    intro = _section(SPECIFICATION, "## 10. Cryptographic Signatures", "**HMAC key derivation.**")
    assert "A signature or MAC over the §10 canonical input is REQUIRED" in intro
    assert "`HMAC-SHA256`, a MAC, is the baseline" in intro


def test_the_spec_says_why_core_uses_hmac():
    intro = _section(SPECIFICATION, "## 10. Cryptographic Signatures", "**HMAC key derivation.**")
    assert "adoption and simplicity" in intro
    assert "no non-repudiation" in intro
    assert "ECDSA-P256" in intro


def test_acs_crypto_names_the_classical_algorithms():
    crypto_line = next(line for line in ACS.splitlines() if line.startswith("- **ACS-Crypto**"))
    for name in ("ECDSA-P256", "RSA-PSS-SHA256", "ML-DSA-65", "SLH-DSA-128s"):
        assert name in crypto_line
    profile_row = next(line for line in CONFORMANCE.splitlines() if line.startswith("| `acs-crypto`"))
    assert "ECDSA-P256" in profile_row and "RSA-PSS-SHA256" in profile_row
    profile = _section(CONFORMANCE, "Adds cryptographic signature support", "Policy-author identity")
    assert "ECDSA-P256" in profile and "RSA-PSS-SHA256" in profile


def test_a_verifier_takes_the_algorithm_from_the_key_not_the_wire():
    binding = next(p for p in SPECIFICATION.split("\n\n") if p.startswith("**Algorithm binding.**"))
    assert "from that key's descriptor" in binding
    assert "MUST reject an envelope whose `algorithm` differs" in binding
    assert "MUST NOT choose the verification algorithm from the wire value" in binding
    assert "takes the algorithm from the key that `key_id` resolves to" in HOOKS
    signature = REQUEST["$defs"]["Signature"]["properties"]
    assert "MUST reject an envelope whose algorithm does not match" in signature["algorithm"]["description"]
    assert "not from the wire" in signature["key_id"]["description"]


def test_inspect_does_not_require_a_signed_bom_serialization():
    bar = _section(INSPECT, "## ACS-Inspect conformance bar", "## Triggers for AgBOM updates")
    assert "not required for conformance" in bar
    for fmt in ("CycloneDX", "SPDX", "SWID"):
        assert fmt in bar
    assert "`agbom/snapshot` and `agbom/changed`" in bar
    assert "SessionContext chain" in bar
