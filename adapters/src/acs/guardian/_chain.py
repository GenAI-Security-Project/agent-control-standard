"""Which requests the example Guardian adds to a session's audit chain (section 8).

The Guardian answers system/ping and handshake/hello without chaining them, and chains every other method that
passes its signature, skew, replay and nonce checks: steps/*, protocols/*, agbom/*, and any method it doesn't know,
which it denies. acs.testing.verify reads this predicate too (issue #584), so the rule exists once. It lives apart
from example_guardian so a reader can import it without loading the Guardian.
"""
from __future__ import annotations

PING_METHOD = "system/ping"
HANDSHAKE_METHOD = "handshake/hello"
UNCHAINED_METHODS = frozenset({PING_METHOD, HANDSHAKE_METHOD})


def chains_method(method: object) -> bool:
    """Whether the Guardian chains a request with this method once it passes the request checks."""
    return isinstance(method, str) and method not in UNCHAINED_METHODS
