"""The one name and the one parser for the example Guardian's policy backend setting.

Lab convention until issue #531 settles the OPA binding. It lives apart from opa_backend so the example Guardian
can read the setting at import without loading the OPA backend on the default path.
"""
from __future__ import annotations

import os
from collections.abc import Mapping

POLICY_BACKEND_ENV = "ACS_POLICY_BACKEND"


def policy_backend_name(env: Mapping[str, str] = os.environ) -> str:
    """Which policy backend was asked for. Any non-empty name counts, an unknown one included."""
    return env.get(POLICY_BACKEND_ENV, "").strip()
