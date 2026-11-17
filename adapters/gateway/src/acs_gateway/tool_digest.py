"""The digest of each function tool a request declares, carried in tool.version (A.10).

Lab convention until issue #38 settles how a tool call binds to its declaration. tool-call-request.json and
tool-call-result.json type tool.version as a free string, so the schema is unchanged, and no adapter outside the
gateway sends it. The client asserts the declaration, so the digest is no tamper evidence on its own. Only a policy
that compares it with a pinned digest catches a change.
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable

from acs.core import jcs_canonicalize
from rfc8785 import CanonicalizationError

# The parts of a Responses API function tool a model reads, hashed as sent with no default filled in. "type" is
# always "function" here, so it adds nothing.
DIGEST_FIELDS = ("name", "description", "parameters", "strict")


def declared_functions(body: dict[str, Any]) -> list[dict[str, Any]]:
    """The request's function tool declarations that carry a non-empty string name, in request order."""
    tools = body.get("tools")
    return [t for t in (tools if isinstance(tools, list) else [])
            if isinstance(t, dict) and t.get("type") == "function" and isinstance(t.get("name"), str) and t["name"]]


class ToolDigests:
    """One request's declaration digests, each computed the first time a gated step asks for it.

    A digest is "sha256:" plus the hex SHA-256 of the RFC 8785 form of the declaration's DIGEST_FIELDS. A name the
    request declares more than once has none, since the policy can't know which declaration the model read. Enforce
    refuses such a request before anything is gated. on_skip hears each name whose declaration RFC 8785 can't
    encode, once per request.
    """

    def __init__(self, body: dict[str, Any], on_skip: Callable[[str, str], None] | None = None) -> None:
        self._declared: dict[str, dict[str, Any] | None] = {}
        for tool in declared_functions(body):
            # A second declaration of a name leaves None, so the name gets no digest.
            self._declared[tool["name"]] = None if tool["name"] in self._declared else tool
        self._digests: dict[str, str | None] = {}
        self._on_skip = on_skip

    def get(self, name: Any) -> str | None:
        """The digest for name, or None when name isn't a non-empty string the request declared exactly once in a
        form RFC 8785 can encode."""
        if not isinstance(name, str) or not name:
            return None
        if name not in self._digests:
            self._digests[name] = self._compute(name)
        return self._digests[name]

    def _compute(self, name: str) -> str | None:
        tool = self._declared.get(name)
        if tool is None:
            return None
        try:
            canonical = jcs_canonicalize({k: tool[k] for k in DIGEST_FIELDS if k in tool})
        except (CanonicalizationError, UnicodeError) as e:
            # rfc8785 raises CanonicalizationError for a value it can't encode, but a lone surrogate in an object key
            # escapes as a bare UnicodeEncodeError from its key sort. Both are encoding failures, and nothing else is.
            if self._on_skip is not None:
                self._on_skip(name, str(e))
            return None
        return "sha256:" + hashlib.sha256(canonical).hexdigest()
