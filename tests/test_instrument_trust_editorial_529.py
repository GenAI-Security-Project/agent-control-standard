"""Guards for the editorial pass on the Instrument specification and the trust concept pages.

Each test holds one reviewer note to its fix, so the wording that confused a first-time
reader does not return: ACS-wide principles filed under Instrument, the model and the
harness both called "the agent", an Observed Agent that "implements ACS endpoints", a MUST
on a standard instead of an implementation, "with ACS extensions" on a JSON-RPC profile,
a section that points at itself for the bytes it signs, and trust pages that read as
levels of content trust.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specification" / "v0.1.0"


def _read(*parts: str) -> str:
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


SPECIFICATION = _read("docs", "spec", "instrument", "specification.md")
HOOKS = _read("docs", "spec", "instrument", "hooks.md")
CONFORMANCE = _read("docs", "spec", "conformance.md")
ACS = _read("docs", "acs.md")
AGENTS = _read("docs", "concepts", "agents.md")
PROVENANCE = _read("docs", "concepts", "provenance.md")
TRUST = _read("docs", "concepts", "trust.md")


def _section(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


def test_instrument_principles_are_about_the_control_loop():
    section = _section(SPECIFICATION, "## 1. Design Principles", "## 2. Architecture")
    assert "../../acs.md#design-principles" in section
    for control_loop_term in ("hook", "disposition", "Guardian"):
        assert control_loop_term in section
    for acs_wide in ("Opinionated on contract", "Facts on the wire", "Three pillars"):
        assert acs_wide not in section


def test_acs_wide_principles_live_in_the_introduction():
    section = _section(ACS, "## Design principles", "## What v0.1.0 ships")
    for acs_wide in ("Opinionated on contract", "Facts on the wire", "Three pillars"):
        assert acs_wide in section


def test_the_model_not_the_framework_is_kept_away_from_hooks():
    section = _section(SPECIFICATION, "## 1. Design Principles", "## 2. Architecture")
    assert "The agent MUST NOT have knowledge of hooks" not in SPECIFICATION
    assert "The model MUST NOT emit or observe hook traffic" in section
    assert "framework around it builds each hook request" in section


def test_the_guardian_implements_the_endpoint_and_the_observed_agent_emits():
    section = _section(SPECIFICATION, "## 2. Architecture", "The diagram below shows")
    assert "Implements ACS endpoints" not in section
    assert "emits hook requests" in section and "applies the decision" in section
    assert "implements the ACS endpoint" in section


def test_portability_is_a_design_goal_not_a_must():
    section = _section(SPECIFICATION, "## 11. Platform / OS Independence", "## 12.")
    assert "ACS MUST be deployable" not in section
    assert "Portability is a design goal" in section


def test_the_envelope_is_a_json_rpc_profile_not_an_extension():
    assert "with ACS extensions" not in CONFORMANCE
    assert "a JSON-RPC 2.0 profile" in CONFORMANCE
    for name in ("request-envelope.json", "response-envelope.json"):
        description = json.loads((SPEC / name).read_text(encoding="utf-8"))["description"]
        assert "ACS extensions" not in description
        assert description.startswith("JSON-RPC 2.0 profile")
        assert "additionalProperties: false" in description


def test_the_profile_caption_says_these_are_advertisements():
    caption = _section(CONFORMANCE, "The diagram below shows the six optional profiles", "\n")
    assert "self-declared claim" not in caption
    assert "optional conformance profiles" in caption
    assert "`profiles_supported` and `profiles_accepted` are advertisements" in caption
    assert "ordinary capability negotiation" in caption
    assert "Who verifies a conformance claim: nobody, in v0.1.0." in CONFORMANCE


def test_section_10_names_the_signed_input_once_and_points_at_it():
    section = _section(SPECIFICATION, "## 10. Cryptographic Signatures", "## 11.")
    assert "the §10 canonical input" not in section
    assert "the canonical input defined in §10" not in section
    assert "A signature over the signed input (defined below) is REQUIRED" in section
    assert "**Signed input.**" in section
    assert "over the signed input (§10, Signed input)" in section
    assert "recompute this signed input" in section
    assert "recompute this canonical form" not in section


def test_the_replay_paragraph_opens_with_a_sentence():
    section = _section(SPECIFICATION, "### 10.3 Replay protection", "## 11.")
    assert section.strip().startswith("The replay inputs are `request_id` (UUID)")


def test_no_surface_names_fabrication_as_the_alternative_to_omitting_final_chain_hash():
    schema = json.loads((SPEC / "hooks" / "subagent-stop.json").read_text(encoding="utf-8"))
    description = schema["properties"]["final_chain_hash"]["description"]
    for text in (SPECIFICATION, HOOKS, description):
        assert "fabricate a value" not in text
        assert "fabrication corrupts" not in text
    assert "absent when the framework keeps no session chain" in SPECIFICATION
    assert "absent when the framework keeps no session-chain" in HOOKS
    assert "leave this field absent" in description


def test_the_trust_between_agents_sentence_stands_alone():
    section = _section(AGENTS, "## Trust between agents", "---")
    assert "not on the fact that it arrived" not in section
    assert "Arrival on the wire does not make a claim true" in section
    for basis in ("asserted", "attached by the framework", "cryptographically attested"):
        assert basis in section
    assert "(./trust.md)" in section


def test_laundering_is_described_before_it_is_named():
    assert "lets trust launder silently" not in PROVENANCE
    assert "untrusted data can be treated as trusted on the far side" in PROVENANCE
    opener = PROVENANCE.split("\n\n")[1]
    assert "trust" not in opener.replace("trusted", "").replace("untrusted", "")
    assert "trust laundering up the spectrum" not in TRUST
    assert "That is trust laundering:" in TRUST


def test_the_spectrum_rates_the_claim_not_the_content():
    section = _section(TRUST, "## The spectrum", "## Invariants")
    assert "rate the claim, not the data it describes" in section
    attached = _section(section, "### Deterministically attached", "### Cryptographically attested")
    attested = section.split("### Cryptographically attested", 1)[1]
    assert "attaches the metadata" in attached
    assert "stays untrusted data" in attached
    assert "authenticates the emitter and the bytes" in attested
    assert "does not vouch for the content" in attested
