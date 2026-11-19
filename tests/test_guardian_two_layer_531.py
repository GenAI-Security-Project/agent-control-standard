"""Guards for issue #531: Guardian two-layer handoff contract and OPA/Rego policy-engine claims.

Checks the four items raised in issue #531 across docs/spec/instrument/specification.md
(sections 2, 12.1, 12.2, and 16) and README.md:
1. Two-layer handoff contract (trigger, payload, precedence/veto, timeout) is consistent
   between section 2 and section 12.1.
2. Unfulfilled v0.1 OPA/Rego bundle-layout and baseline-bundle claims are dropped from
   section 12.1 in favor of engine-agnostic wording (D-002, D-006) and v0.2 normative
   bindings (section 16).
3. The prohibition on passing deterministic policy code to the agent layer defines what
   artifacts are barred (raw .rego source text and compiled policy bundles), states the
   harm prevented, and permits rule_id, policy_references, and structured annotations in
   the intermediate output across section 2, section 12.2, and README.md.
4. Every input field passed to the agent-layer prompt is treated as data (wrapped or
   quoted in a structured data block) regardless of its Provenance.trust value (trusted,
   semi_trusted, or untrusted).
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "spec" / "instrument" / "specification.md"
README = ROOT / "README.md"


def _section(text: str, heading: str) -> str:
    pattern = re.compile(
        rf"^{re.escape(heading)}\s*$\n(.*?)(?=^## |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    assert match, f"Heading {heading!r} not found in specification.md"
    return match.group(1)


def _subsection(text: str, heading: str) -> str:
    pattern = re.compile(
        rf"^{re.escape(heading)}\s*$\n(.*?)(?=^### |^## |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    assert match, f"Subsection {heading!r} not found in specification.md"
    return match.group(1)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_item_1_two_layer_handoff_reconciled_between_section_2_and_section_12_1():
    spec = SPEC.read_text(encoding="utf-8")
    sec2 = _norm(_section(spec, "## 2. Architecture"))
    sec12_1 = _norm(_subsection(spec, "### 12.1 Policy engine interface"))

    for label, block in (("§2", sec2), ("§12.1", sec12_1)):
        # Trigger
        assert "`*`" in block and "`on_ask`" in block, f"{label} missing chain config triggers"
        assert '`delegate_to: "agent"`' in block, f"{label} missing delegate_to trigger"
        assert "internal to the Guardian" in block, f"{label} must state handoff is internal, not wire"
        # Payload
        assert "intermediate output" in block, f"{label} missing intermediate output payload"
        assert "`policy_references`" in block and "`rule_id`" in block, (
            f"{label} missing policy_references / rule_id in handoff payload"
        )
        # Precedence / Veto
        assert "deterministic `DENY` is final" in block, f"{label} missing final deterministic DENY rule"
        assert "clear the deterministic layer's constraints" in block, (
            f"{label} missing deterministic constraint check on agent-layer output"
        )
        # Timeout
        assert "`timeout_config`" in block, f"{label} missing timeout_config bound"
        assert "`DENY` by default" in block, f"{label} missing default DENY fallback on timeout/failure"


def test_item_2_opa_rego_v01_bundle_claims_dropped_and_scoped_accurately():
    spec = SPEC.read_text(encoding="utf-8")
    sec12_1 = _norm(_subsection(spec, "### 12.1 Policy engine interface"))
    sec16 = _norm(_section(spec, "## 16. Roadmap"))

    assert "v0.1 starting reference" not in spec
    assert "policy-engine agnostic (`D-002`, `D-006`)" in sec12_1
    assert "`reference-implementations/agt`" in sec12_1
    assert "`reference-implementations/agt-go`" in sec12_1
    assert "`adapters/`" in sec12_1
    assert "normative engine bindings (OPA/Rego and Cedar) are v0.2 scope (§16)" in sec12_1
    assert "normative engine bindings (OPA/Rego and Cedar)" in sec16


def test_item_3_policy_code_separation_defined_and_justified():
    spec = SPEC.read_text(encoding="utf-8")
    sec2 = _norm(_section(spec, "## 2. Architecture"))
    sec12_2 = _norm(_subsection(spec, "### 12.2 Agent layer"))
    readme = _norm(README.read_text(encoding="utf-8"))

    for label, block in (("§2", sec2), ("§12.2", sec12_2), ("README.md", readme)):
        assert "raw deterministic policy source text" in block, (
            f"{label} must bar raw deterministic policy source text"
        )
        assert "`.rego`" in block, f"{label} must name .rego source files"
        assert "compiled policy bundles" in block, f"{label} must bar compiled policy bundles"
        assert "extract confidential detection thresholds/patterns" in block, (
            f"{label} must state confidentiality rationale"
        )
        assert "craft arguments around rule syntax" in block, (
            f"{label} must state rule-evasion rationale"
        )
        assert "`rule_id`" in block and "`policy_references`" in block, (
            f"{label} must permit rule_id and policy_references in intermediate output"
        )


def test_item_4_all_agent_layer_inputs_treated_as_data_regardless_of_trust():
    spec = SPEC.read_text(encoding="utf-8")
    sec12_2 = _norm(_subsection(spec, "### 12.2 Agent layer"))

    assert "Prompt MUST treat untrusted data as data" not in spec
    assert "Untrusted fields MUST be wrapped/quoted" not in spec
    assert "Every input field passed to the agent-layer prompt MUST be treated as data" in sec12_2
    assert "wrapped or quoted in a structured data block" in sec12_2
    assert "`Provenance.trust`" in sec12_2
    for level in ("`trusted`", "`semi_trusted`", "`untrusted`"):
        assert level in sec12_2, f"§12.2 must explicitly cover Provenance.trust={level}"
    assert "`user_input`" in sec12_2 and "`system`" in sec12_2
