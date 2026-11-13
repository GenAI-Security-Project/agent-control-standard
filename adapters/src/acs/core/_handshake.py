from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_SEMVER = re.compile(r"\d+\.\d+\.\d+")


def method_evaluated(server_hello: dict | None, method: str) -> bool:
    """handshake.json: a method missing from methods_evaluated is ALLOW-by-default; with no list, every method is evaluated."""
    if not isinstance(server_hello, dict):
        return True
    evaluated = server_hello.get("methods_evaluated")
    if not isinstance(evaluated, list):
        return True
    return method in evaluated


def _positive_int(value: object) -> bool:
    """JSON Schema's integer of at least 1: 5000.0 qualifies, booleans do not."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return (isinstance(value, int) or value.is_integer()) and value >= 1


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def server_hello_problem(server_hello: Mapping[str, Any], offered: Mapping[str, Any]) -> str | None:
    """Why the ServerHello does not answer the ClientHello `offered`, or None."""
    version = server_hello.get("negotiated_version")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        return "negotiated_version is not a semantic version"
    majors = {v.split(".", 1)[0] for v in offered.get("acs_versions_supported", []) if isinstance(v, str)}
    if version.split(".", 1)[0] not in majors:
        return f"negotiated_version {version} matches no offered major version"
    if not _strings(server_hello.get("methods_evaluated")):
        return "methods_evaluated is not a list of method names"
    transport = server_hello.get("selected_transport")
    if transport not in offered.get("transports_supported", []):
        return f"selected_transport {transport!r} was not offered"
    timeouts = server_hello.get("timeout_config")
    if not isinstance(timeouts, Mapping) or not _positive_int(timeouts.get("default_ms")):
        return "timeout_config.default_ms is not a positive integer"
    per_method = timeouts.get("per_method_ms", {})
    if not isinstance(per_method, Mapping) or not all(_positive_int(ms) for ms in per_method.values()):
        return "timeout_config.per_method_ms is not a map of positive integers"
    posture = server_hello.get("on_decision_failure", "proceed")
    if posture not in ("proceed", "deny"):
        return f"on_decision_failure {posture!r} is neither proceed nor deny"
    accepted = server_hello.get("profiles_accepted")
    if accepted is not None:
        if not _strings(accepted):
            return "profiles_accepted is not a list of profile names"
        unclaimed = sorted(set(accepted) - set(offered.get("profiles_supported", [])))
        if unclaimed:
            return f"profiles_accepted includes {unclaimed}, which the client did not claim"
    return None
