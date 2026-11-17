"""The one name and the one parser for the example Guardian's response signing setting (issue #576).

Lab convention until issue #460 settles key publication and issue #316 settles which algorithms a verifier
accepts. It lives apart from decision_keys so the example Guardian can read the setting at import without
loading cryptography on the default path.
"""
from __future__ import annotations

import os
from collections.abc import Mapping

RESPONSE_SIGNING_ENV = "ACS_RESPONSE_SIGNING"
ML_DSA_65 = "ML-DSA-65"
# Unset, blank, and the HMAC name all mean today's Guardian: every response signed with the HMAC session key.
_OFF_VALUES = frozenset({"", "HMAC-SHA256"})


def response_signing_name(env: Mapping[str, str] = os.environ) -> str:
    """Which response signing was asked for: "" for today's HMAC path, else the name as given."""
    value = env.get(RESPONSE_SIGNING_ENV, "").strip()
    return "" if value in _OFF_VALUES else value


def response_signing_problem(name: str) -> str | None:
    """Why the Guardian must not start with this name, or None. No hybrid goes on the wire (PREMORTEM P7)."""
    if name in ("", ML_DSA_65):
        return None
    return (f"{RESPONSE_SIGNING_ENV}={name!r} is not supported. Use {ML_DSA_65}, or leave it unset for HMAC-SHA256 "
            "(lab convention, issue #316)")
