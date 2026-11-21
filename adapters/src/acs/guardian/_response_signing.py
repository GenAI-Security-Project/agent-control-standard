"""The one name and the one parser for the example Guardian's response signing setting (issue #576).

Lab convention until issue #460 settles key publication and issue #316 settles which algorithms a verifier
accepts. It lives apart from decision_keys so the example Guardian can read the setting at import without
loading cryptography on the default path.
"""
from __future__ import annotations

import os
from collections.abc import Mapping

from acs.client._key_document import ML_DSA_65, RESPONSE_SIGNING_ENV, RESPONSE_SIGNING_OFF_VALUES

__all__ = ["ML_DSA_65", "RESPONSE_SIGNING_ENV", "response_signing_name", "response_signing_problem"]


def response_signing_name(env: Mapping[str, str] = os.environ) -> str:
    """Which response signing was asked for: "" for today's HMAC path, else the name as given."""
    value = env.get(RESPONSE_SIGNING_ENV, "").strip()
    return "" if value in RESPONSE_SIGNING_OFF_VALUES else value


def response_signing_problem(name: str) -> str | None:
    """Why the Guardian must not start with this name, or None. No hybrid goes on the wire (PREMORTEM P7)."""
    if name in ("", ML_DSA_65):
        return None
    return (f"{RESPONSE_SIGNING_ENV}={name!r} is not supported. Use {ML_DSA_65}, or leave it unset for HMAC-SHA256 "
            "(lab convention, issue #316)")
