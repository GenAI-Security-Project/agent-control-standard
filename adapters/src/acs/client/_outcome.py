from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Decided:
    """A response bound to its request, correctly signed, carrying a result."""
    response: dict[str, Any]


@dataclass(frozen=True)
class Undecided:
    """No usable decision arrived, so the §6.4 fail posture decides."""
    cause: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    message: str = ""


@dataclass(frozen=True)
class Refused:
    """The Guardian refused the envelope, or the answer cannot be trusted; the step fails closed whatever the posture."""
    cause: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    message: str = ""


Outcome = Decided | Undecided | Refused


@dataclass(frozen=True)
class Negotiated:
    """The Guardian answered the handshake with a verified ServerHello; the session's steps go to it."""
    server_hello: Mapping[str, Any]
    # The session's sessionStart got no decision ({"cause", "fields"}); each hook's fail posture settles its steps.
    start_failure: Mapping[str, Any] | None = None
    # The reasoning the Guardian gave when it allowed the session's sessionStart.
    start_context: str = ""


@dataclass(frozen=True)
class SessionRefused:
    """The Guardian refused the session, or its answer failed its checks; every step of the session is denied."""
    cause: str
    fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NoAnswer:
    """No ServerHello arrived: the session sends nothing more, and each hook's startup posture settles its steps."""
    cause: str
    fields: Mapping[str, Any] = field(default_factory=dict)


Handshake = Negotiated | SessionRefused | NoAnswer
