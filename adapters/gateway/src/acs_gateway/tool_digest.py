"""The digest of each function tool a request declares, carried in tool.version (A.10).

Lab convention until issue #38 settles how a tool call binds to its declaration. tool-call-request.json types
tool.version as a free string, so the schema is unchanged, and no adapter outside the gateway sends it.
"""
from __future__ import annotations

import hashlib
from typing import Any

from acs.core import jcs_canonicalize

# The parts of a Responses API function tool a model reads. "type" is always "function" here, so it adds nothing.
DIGEST_FIELDS = ("name", "description", "parameters", "strict")


def tool_digests(body: dict[str, Any]) -> dict[str, str]:
    """Each declared function name mapped to "sha256:" plus the hex SHA-256 of the RFC 8785 form of its declaration.

    A name declared more than once hashes the list of its declarations in request order. The policy can't know
    which one the model read, so the digest matches no single pinned declaration. A name whose declaration RFC 8785
    can't encode gets no digest, which the policy sees the same way as a call to a function the request never
    declared.
    """
    tools = body.get("tools")
    declared: dict[str, list[dict[str, Any]]] = {}
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict) or tool.get("type") != "function" or not isinstance(tool.get("name"), str):
            continue
        declared.setdefault(tool["name"], []).append({k: tool[k] for k in DIGEST_FIELDS if k in tool})
    digests = {}
    for name, declarations in declared.items():
        try:
            canonical = jcs_canonicalize(declarations[0] if len(declarations) == 1 else declarations)
        except Exception:  # noqa: BLE001
            continue
        digests[name] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return digests
