"""Capability negotiation (Specification §4).

The Guardian selects a version, a transport, and the method set it will
evaluate, and answers with a ServerHello. Two rules matter more than they look:

- ``methods_evaluated`` is the intersection of what the client declared and
  what this Guardian dispatches, and it is the *only* thing that makes a
  method enforceable for the session. A method absent from it is
  ALLOW-by-default to a conformant client (handshake.json), so naming a method
  the dispatch cannot answer claims enforcement that does not exist.
- A ClientHello that shares no transport with this Guardian is refused
  (SESSION_REFUSED, -32000), not negotiated down to a transport the client
  never offered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import mcp, methods
from .errors import (
    PROVENANCE_REQUIRED,
    SESSION_REFUSED,
    UNSUPPORTED_VERSION,
    AcsError,
)
from .schemas import HOOK_METHODS

SUPPORTED_VERSIONS = ("0.1.0",)
# "https" is accepted as a client transport because a deployment commonly
# terminates TLS in front of the Guardian; the selected transport is still the
# one the client offered, and the listener this tree ships speaks plain HTTP.
SUPPORTED_TRANSPORTS = ("http", "https")
# Every ACS-Core item in docs/spec/conformance.md is implemented (handshake,
# envelopes, the 19 hooks, all five dispositions, the chain, replay, the HMAC
# baseline, liveness, wrapped MCP), so the Guardian accepts acs-core. Trace,
# Inspect, Provenance, Crypto, and Audit are not claimed.
SUPPORTED_PROFILES: tuple[str, ...] = ("acs-core",)
SIGNATURE_ALGORITHMS = ("HMAC-SHA256",)
DEFAULT_TIMEOUT_MS = 5000
DEFAULT_SKEW_WINDOW_MS = 300_000

# Every native method this Guardian dispatches. Wrapped MCP methods are
# negotiated separately: a handler reads them, and the client must declare the
# protocol in wrapped_protocols. agbom/* is defined but never negotiated (the
# Inspect profile is not implemented).
IMPLEMENTED_METHODS: tuple[str, ...] = (*HOOK_METHODS, "system/ping")


@dataclass
class NegotiatedTerms:
    negotiated_version: str
    methods_evaluated: tuple[str, ...]
    selected_transport: str
    profiles_accepted: tuple[str, ...]
    on_decision_failure: str
    timeout_ms: int
    skew_window_ms: int


def declared_wrapped_protocols(client_hello: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    declared: dict[str, tuple[str, ...]] = {}
    entries = client_hello.get("wrapped_protocols")
    if not isinstance(entries, list):
        return declared
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        protocol, version = entry.get("protocol"), entry.get("version")
        if not isinstance(protocol, str) or not isinstance(version, str):
            continue
        declared[protocol.upper()] = (*declared.get(protocol.upper(), ()), version)
    return declared


def evaluates(name: str, declared: dict[str, tuple[str, ...]]) -> bool:
    """Whether this Guardian will evaluate a method the client declared (handshake.evaluated)."""
    if name in IMPLEMENTED_METHODS:
        return True
    split = methods.split_wrapped(name)
    if split is None:
        return False
    protocol, version, inner = split
    if protocol.upper() != mcp.PROTOCOL:
        return False
    if not mcp.supports(inner):
        return False
    versions = declared.get(protocol.upper(), ())
    if not versions:
        # The protocol must be declared in wrapped_protocols; a method naming
        # an undeclared protocol is not negotiated.
        return False
    # The protocols/ form pins no version; the explicit-version form is
    # negotiated only at a declared version.
    return version is None or version in versions


def _select_version(client_versions: list[str]) -> str:
    for supported in SUPPORTED_VERSIONS:
        major = supported.split(".")[0]
        if any(version.split(".")[0] == major for version in client_versions):
            return supported
    raise AcsError(
        UNSUPPORTED_VERSION,
        "no common ACS version",
        data={"supported_versions": list(SUPPORTED_VERSIONS)},
    )


def _select_transport(client_transports: list[str]) -> str:
    for transport in SUPPORTED_TRANSPORTS:
        if transport in client_transports:
            return transport
    raise AcsError(
        SESSION_REFUSED,
        "no common transport",
        data={"reason": "no_common_transport", "supported_transports": list(SUPPORTED_TRANSPORTS)},
    )


def negotiate(
    client_hello: dict[str, Any],
    *,
    on_decision_failure: str = "proceed",
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    skew_window_ms: int = DEFAULT_SKEW_WINDOW_MS,
    policy_requires_provenance: bool = False,
) -> NegotiatedTerms:
    """Build the session terms from a ClientHello, or refuse with a registry code.

    The refusal order is version, transport, provenance, methods: a version
    mismatch terminates with ``UNSUPPORTED_VERSION`` (§4) regardless of what
    else the ClientHello got wrong, so the client's recovery action
    (re-handshake with a version from ``data.supported_versions``) is the one
    it is told to take.
    """
    negotiated_version = _select_version(
        [v for v in client_hello.get("acs_versions_supported", []) if isinstance(v, str)]
    )
    selected_transport = _select_transport(
        [t for t in client_hello.get("transports_supported", []) if isinstance(t, str)]
    )

    if policy_requires_provenance and client_hello.get("provenance_producer") != "deterministic":
        raise AcsError(
            PROVENANCE_REQUIRED,
            "policy requires provenance and the client declared provenance_producer: none",
        )

    declared = declared_wrapped_protocols(client_hello)
    client_methods = [m for m in client_hello.get("methods_implemented", []) if isinstance(m, str)]
    evaluated: list[str] = []
    for name in client_methods:
        if name not in evaluated and evaluates(name, declared):
            evaluated.append(name)
    # An empty intersection is a valid ServerHello: the client is told the
    # Guardian evaluates none of its methods, and a method absent from
    # methods_evaluated is ALLOW-by-default to it (handshake.json). The
    # Guardian does not refuse the session over it.
    methods_evaluated = tuple(evaluated)

    client_profiles = [p for p in client_hello.get("profiles_supported", []) if isinstance(p, str)]
    return NegotiatedTerms(
        negotiated_version=negotiated_version,
        methods_evaluated=methods_evaluated,
        selected_transport=selected_transport,
        profiles_accepted=tuple(p for p in client_profiles if p in SUPPORTED_PROFILES),
        on_decision_failure=on_decision_failure,
        timeout_ms=timeout_ms,
        skew_window_ms=skew_window_ms,
    )


def server_hello(terms: NegotiatedTerms) -> dict[str, Any]:
    """The ServerHello result object (handshake.json $defs/ServerHello)."""
    return {
        "negotiated_version": terms.negotiated_version,
        "methods_evaluated": list(terms.methods_evaluated),
        "selected_transport": terms.selected_transport,
        "signature_algorithms_supported": list(SIGNATURE_ALGORITHMS),
        "timeout_config": {"default_ms": terms.timeout_ms},
        "skew_window_ms": terms.skew_window_ms,
        "on_decision_failure": terms.on_decision_failure,
        "profiles_accepted": list(terms.profiles_accepted),
    }
