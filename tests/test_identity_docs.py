"""Guard the eleven identity corrections recorded in issue #539."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OVERVIEW = (ROOT / "docs" / "identity" / "overview.md").read_text(encoding="utf-8")
STANDARDS = (ROOT / "docs" / "identity" / "standards.md").read_text(encoding="utf-8")


def section(text, heading):
    return re.split(r"\n#{1,3} ", text.split(heading + "\n", 1)[1], maxsplit=1)[0]


def row(text, label):
    return next(line for line in text.splitlines() if line.startswith(f"| **{label}**"))


def test_lead_describes_five_challenges_in_plain_prose():
    lead = OVERVIEW.split("\n\n")[2]
    assert "five runtime identity challenges" in lead
    assert "traditional identity models do not fully address" in lead
    assert "aims to solve" not in lead
    assert "where existing use cases" not in lead


def test_runtime_change_is_control_flow_not_replaced_supply_chain():
    assert "may remain the supply chain approved at build time" in OVERVIEW
    assert "control flow: which tool runs, in which order, with which arguments" in OVERVIEW
    assert "is not the supply chain that executes" not in OVERVIEW


def test_valid_credentials_and_session_smuggling_need_intent_controls():
    assert "Identity supports governance and forensics" in OVERVIEW
    assert "does not close this failure class" in OVERVIEW
    example = section(OVERVIEW, "## Five Runtime Identity Challenges for Agents")
    assert "unit42.paloaltonetworks.com/agent-session-smuggling" in example
    assert "a control and Intent problem" in example
    assert "[Instrument]" in example and "[Intent]" in example
    assert "central identity challenge" not in OVERVIEW


def test_challenge_table_has_five_short_rows_linked_to_subsections():
    challenge_rows = [line for line in OVERVIEW.splitlines() if line.startswith("| [")]
    assert len(challenge_rows) == 5
    for line in challenge_rows:
        assert line.count("|") == 3
        assert len(line) < 160
        label, anchor = re.search(r"\[([^]]+)\]\(#([^)]+)\)", line).groups()
        assert f"### {label}\n" in OVERVIEW
        assert anchor == label.lower().replace(" ", "-")


def test_challenges_do_not_claim_uniqueness():
    assert "unique" not in OVERVIEW.lower()
    assert "Over-privilege and token theft are long-standing identity problems" in OVERVIEW


def test_chain_history_is_not_implicitly_enforcement_authority():
    chain = section(OVERVIEW, "### Chain Integrity")
    assert "trace reconstruction and forensics" in chain
    assert "informational only, not inputs to access control decisions" in chain
    assert "separate, unsettled design question" in chain
    assert "pseudocode rather than an ACS requirement" in chain
    assert "deny if any child grant expands its parent's scope" in chain
    assert "immediate caller does not match the final grant's delegate" in chain
    for text in (row(STANDARDS, "Delegation is single-hop"), section(STANDARDS, "### ACS handles, AIMS does not")):
        assert "forensics" in text
        assert "unsettled" in text
        assert "[example Guardian rule](overview.md#chain-integrity)" in text


def test_bearer_keys_are_distinguished_from_request_signing_keys():
    theft = section(OVERVIEW, "### Token Theft Resistance")
    assert "bearer API key or an opaque bearer token" in theft
    assert "AWS SigV4" in theft
    assert "sign requests without sending that key" in theft
    assert "bearer secrets by definition" not in OVERVIEW


def test_standards_distinguish_publication_adoption_and_amr_from_acr():
    assert "broadly adopted and form the foundation" not in STANDARDS
    assert "Published standard (adoption varies)" in STANDARDS
    assert 'OAuth21["OAuth 2.1"]:::emerging' in STANDARDS
    assert 'GNAP["GNAP (RFC 9635, limited adoption)"]' in STANDARDS
    assert "OIDC method values: AMR" in STANDARDS
    amr = row(STANDARDS, "RFC 8176, AMR")
    assert "authentication method values" in amr
    assert "`acr`, not `amr`" in amr
    assert "authentication strength" not in amr
    assert "limited adoption" in row(STANDARDS, "GNAP (RFC 9635)")


def test_action_scoped_issuance_is_distinct_from_runtime_detection():
    client = row(STANDARDS, "The client is a stable, registered software identity")
    assert "RAR can express action-scoped authorization at issuance" in client
    assert "Detecting misbehavior and checking intent at runtime are separate gaps" in client
    assert "No token-issuance standard can patch this" not in STANDARDS


def test_high_risk_credentials_need_single_use_not_just_short_lifetimes():
    for text in (
        section(OVERVIEW, "### Token Theft Resistance"),
        row(STANDARDS, "Refresh tokens"),
        row(STANDARDS, "Token lifetimes"),
    ):
        assert "single-use credentials" in text or "single-use credential" in text
        assert "where the risk warrants it" in text
        assert "replay prevention" in text
        assert "short lifetime alone is not the control" in text.lower() or "not sufficient for high-risk actions" in text
    assert "60 s" not in STANDARDS
    assert "Aggressive lifetime ceilings" not in OVERVIEW


def test_outages_default_to_deny_and_exceptions_need_justification():
    for text in (
        section(OVERVIEW, "### Last-Mile Enforcement"),
        row(STANDARDS, "The IdP is always reachable."),
    ):
        assert "fail-closed" in text.lower()
        assert "`deny`" in text
        assert "fail-open or fail-cached" in text
        assert "explicit risk justification, bounded scope and duration" in text
        assert "trace evidence" in text
        assert "/issues/32" in text
    assert "cannot validate a token rejects the call" in STANDARDS
    assert "current default on timeout is **fail-open" not in OVERVIEW
