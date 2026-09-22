"""The method table: every method the standard defines, how the Guardian routes
it, and which dispositions each hook permits.

The disposition rules are hooks.md's per-hook "Decision:" lines:

- audit-only hooks (``subagentStop``, ``skillUnload``, ``turnEnd``,
  ``sessionEnd``) permit ALLOW only — the action has already happened;
- ``postCompact`` permits ALLOW and MODIFY but not DENY — the compaction has
  already happened;
- ``toolCallRequest`` and every wrapped call permit all five;
- everything else permits ALLOW, DENY, and (except the hooks hooks.md lists
  without it) MODIFY.

Wrapped calls are ``protocols/<NAME>/<method>`` and the explicit-version form
``wrapped:<name>-<version>/<method>`` (§3). The protocol name is matched
case-insensitively; the method within it is the handler's to read.
"""

from __future__ import annotations

from .engine import ALLOW, ASK, DEFER, DENY, MODIFY

HANDSHAKE = "handshake/hello"
PING = "system/ping"
AGBOM_METHODS = ("agbom/snapshot", "agbom/changed")
PROTOCOLS_PREFIX = "protocols/"
WRAPPED_PREFIX = "wrapped:"

ROUTE_HANDSHAKE = "handshake"
ROUTE_PING = "ping"
ROUTE_HOOK = "hook"
ROUTE_WRAPPED = "wrapped"
ROUTE_UNSUPPORTED = "unsupported"
ROUTE_UNDEFINED = "undefined"

_ALL_FIVE = (ALLOW, DENY, MODIFY, ASK, DEFER)

# hooks.md "Decision:" per native hook.
PERMITTED: dict[str, tuple[str, ...]] = {
    "steps/sessionStart": (ALLOW, DENY),
    "steps/agentTrigger": (ALLOW, DENY, MODIFY),
    "steps/turnStart": (ALLOW, DENY),
    "steps/userMessage": (ALLOW, DENY, MODIFY),
    "steps/agentResponse": (ALLOW, DENY, MODIFY),
    "steps/knowledgeRetrieval": (ALLOW, DENY, MODIFY),
    "steps/memoryContextRetrieval": (ALLOW, DENY, MODIFY),
    "steps/memoryStore": (ALLOW, DENY, MODIFY),
    "steps/toolCallRequest": _ALL_FIVE,
    "steps/toolCallResult": (ALLOW, DENY, MODIFY),
    "steps/preCompact": (ALLOW, DENY),
    "steps/postCompact": (ALLOW, MODIFY),
    "steps/subagentStart": (ALLOW, DENY),
    "steps/subagentStop": (ALLOW,),
    "steps/skillRegister": (ALLOW, DENY),
    "steps/skillLoad": (ALLOW, DENY),
    "steps/skillUnload": (ALLOW,),
    "steps/turnEnd": (ALLOW,),
    "steps/sessionEnd": (ALLOW,),
}

def route(name: str) -> str:
    """How the Guardian answers a method name."""
    if name == HANDSHAKE:
        return ROUTE_HANDSHAKE
    if name == PING:
        return ROUTE_PING
    if name in AGBOM_METHODS:
        # Defined by the standard, never negotiated by this Guardian: the
        # Inspect profile is not implemented, so agbom/* is CapabilityNotNegotiated.
        return ROUTE_UNSUPPORTED
    if name.startswith(PROTOCOLS_PREFIX) or name.startswith(WRAPPED_PREFIX):
        return ROUTE_WRAPPED
    if name in PERMITTED:
        return ROUTE_HOOK
    return ROUTE_UNDEFINED


def split_wrapped(name: str) -> tuple[str, str | None, str] | None:
    """Split ``protocols/<NAME>/<method>`` or ``wrapped:<name>-<version>/<method>``.

    Returns ``(protocol, version, method)``; version is None for the
    ``protocols/`` form, which pins none.
    """
    if name.startswith(WRAPPED_PREFIX):
        rest = name[len(WRAPPED_PREFIX) :]
        explicit = True
    elif name.startswith(PROTOCOLS_PREFIX):
        rest = name[len(PROTOCOLS_PREFIX) :]
        explicit = False
    else:
        return None
    protocol, _, method = rest.partition("/")
    version: str | None = None
    if explicit:
        protocol, separator, version = protocol.partition("-")
        if not separator or not version:
            return None
    if not protocol or not method:
        return None
    return protocol, version, method


def permitted_dispositions(name: str) -> tuple[str, ...]:
    """The dispositions a hook permits; a wrapped call permits all five."""
    return PERMITTED.get(name, _ALL_FIVE)


def override_pointer(name: str, argument: str) -> str:
    """The JSON pointer a ``parameter_overrides`` key addresses in this method's payload.

    Native hooks address the tool argument of that name (modifications.json);
    a wrapped MCP call addresses a member of the wrapped message's
    ``params.arguments`` — the wrapped form of the same rule.
    """
    escaped = argument.replace("~", "~0").replace("/", "~1")
    if route(name) == ROUTE_WRAPPED:
        return f"/params/arguments/{escaped}"
    return f"/arguments/{escaped}"
