"""Keep live capability updates consistent with chain and replay guarantees."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SPEC = REPO / "docs" / "spec"


def test_mid_session_hello_preserves_session_and_authentication_state():
    text = (SPEC / "instrument" / "specification.md").read_text(encoding="utf-8")
    update = text.split("### 4.2 ", 1)[1].split("## 5.", 1)[0]
    for rule in [
        "another `ClientHello` using `handshake/hello` on an existing `session_id`",
        "MUST preserve the `session_id`, the existing `SessionContext`, and `chain_hash` continuity",
        "MUST NOT reset the chain or emit another `sessionStart`",
        "MUST preserve the session's replay-detection state",
        "`request_id` and `nonce` history",
        "MUST preserve that authentication binding and the existing session keys",
        "MUST pause new hook traffic",
        "On refusal or timeout, the previous settings and session state remain in force",
        "MUST NOT use unaccepted capabilities",
        "MUST send `agbom/snapshot` before resuming content-bearing hooks",
    ]:
        assert rule in update


def test_core_conformance_supports_updates_without_a_new_method():
    text = (SPEC / "conformance.md").read_text(encoding="utf-8")
    assert "v0.1 has no separate renegotiation method" in text
    assert "mid-session `ClientHello` / `ServerHello`" in text
    assert "v0.1 defines no renegotiation" not in text
    assert "cannot begin wrapping mid-session" not in text
    assert "MUST complete that update before using newly required wrapped methods" in text


def test_recovery_and_inspect_link_to_the_live_update_contract():
    text = (SPEC / "instrument" / "specification.md").read_text(encoding="utf-8")
    recovery = text.split("### 17.1 ", 1)[1]
    assert "preserving chain, replay, and authentication state" in recovery
    assert "only after success, with fresh replay identifiers" in recovery
    for path in [SPEC / "instrument" / "hooks.md", SPEC / "inspect" / "README.md"]:
        assert "#42-mid-session-capability-updates-normative" in path.read_text(
            encoding="utf-8"
        )
