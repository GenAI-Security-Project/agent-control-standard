"""Capability negotiation (§4): intersection rules and refusals."""

from __future__ import annotations

import pytest

from acs_guardian.errors import (
    PROVENANCE_REQUIRED,
    SESSION_REFUSED,
    UNSUPPORTED_VERSION,
    AcsError,
)
from acs_guardian.handshake import negotiate, server_hello


def _hello(**overrides):
    hello = {
        "acs_versions_supported": ["0.1.0"],
        "methods_implemented": ["steps/toolCallRequest", "steps/toolCallResult"],
        "transports_supported": ["http"],
        "provenance_producer": "none",
        "profiles_supported": ["acs-core"],
    }
    hello.update(overrides)
    return hello


def test_methods_evaluated_is_the_intersection_preserving_client_order() -> None:
    terms = negotiate(
        _hello(
            methods_implemented=[
                "steps/userMessage",
                "steps/toolCallRequest",
                "protocols/MCP/tools/call",  # not implemented yet: not negotiated
                "steps/toolCallResult",
            ]
        )
    )
    assert terms.methods_evaluated == ("steps/userMessage", "steps/toolCallRequest", "steps/toolCallResult")


def test_no_common_version_is_unsupported_version() -> None:
    with pytest.raises(AcsError) as caught:
        negotiate(_hello(acs_versions_supported=["9.9.9"]))
    assert caught.value.code == UNSUPPORTED_VERSION
    assert caught.value.data == {"supported_versions": ["0.1.0"]}


def test_a_same_major_version_negotiates_an_offered_version() -> None:
    """§3 forward compat: the answer names a version the client offered (the Go rule)."""
    assert negotiate(_hello(acs_versions_supported=["0.7.3"])).negotiated_version == "0.7.3"


def test_the_highest_offered_version_sharing_the_major_wins() -> None:
    negotiated = negotiate(_hello(acs_versions_supported=["0.2.0", "0.9.0", "0.3.0"])).negotiated_version
    assert negotiated == "0.9.0"


def test_a_malformed_version_shares_no_major() -> None:
    with pytest.raises(AcsError) as caught:
        negotiate(_hello(acs_versions_supported=["0.1", "zero.1.0"]))
    assert caught.value.code == UNSUPPORTED_VERSION


def test_only_ascii_digit_parts_are_versions() -> None:
    """int() would accept signs, whitespace, underscores, non-ASCII digits and very long strings."""
    for malformed in ("+0.1.0", " 0.1.0", "-0.1.0", "0_1.0.0", "\u0661.0.0", "1" * 5000 + ".0.0"):
        with pytest.raises(AcsError) as caught:
            negotiate(_hello(acs_versions_supported=[malformed]))
        assert caught.value.code == UNSUPPORTED_VERSION


def test_version_mismatch_wins_over_every_other_refusal() -> None:
    """§4: a version mismatch terminates with -32001, whatever else is wrong."""
    with pytest.raises(AcsError) as caught:
        negotiate(_hello(acs_versions_supported=["9.9.9"], methods_implemented=["protocols/MCP/tools/call"]))
    assert caught.value.code == UNSUPPORTED_VERSION


def test_https_is_an_acceptable_client_transport() -> None:
    assert negotiate(_hello(transports_supported=["https"])).selected_transport == "https"


def test_no_common_transport_is_session_refused() -> None:
    with pytest.raises(AcsError) as caught:
        negotiate(_hello(transports_supported=["stdio"]))
    assert caught.value.code == SESSION_REFUSED
    assert caught.value.data["reason"] == "no_common_transport"


def test_provenance_requirement_refuses_a_none_producer() -> None:
    with pytest.raises(AcsError) as caught:
        negotiate(_hello(), policy_requires_provenance=True)
    assert caught.value.code == PROVENANCE_REQUIRED


def test_provenance_requirement_accepts_a_deterministic_producer() -> None:
    terms = negotiate(_hello(provenance_producer="deterministic"), policy_requires_provenance=True)
    assert terms.negotiated_version == "0.1.0"


def test_no_shared_method_negotiates_an_empty_set() -> None:
    # An empty methods_evaluated is a valid ServerHello: every method is then
    # ALLOW-by-default to the client, which is told so. Not a refusal.
    assert negotiate(_hello(methods_implemented=["protocols/MCP/tools/call"])).methods_evaluated == ()


def test_profiles_accepted_is_the_intersection() -> None:
    # acs-core is accepted (every ACS-Core item is implemented); the optional
    # profiles are not claimed.
    terms = negotiate(_hello(profiles_supported=["acs-core", "acs-trace"]))
    assert terms.profiles_accepted == ("acs-core",)


def test_server_hello_carries_the_negotiated_terms() -> None:
    hello = server_hello(negotiate(_hello(), on_decision_failure="deny", timeout_ms=1234, skew_window_ms=60000))
    assert hello["negotiated_version"] == "0.1.0"
    assert hello["selected_transport"] == "http"
    assert hello["on_decision_failure"] == "deny"
    assert hello["timeout_config"] == {"default_ms": 1234}
    assert hello["skew_window_ms"] == 60000
    assert hello["signature_algorithms_supported"] == ["HMAC-SHA256"]
