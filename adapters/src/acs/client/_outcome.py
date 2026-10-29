"""What one Guardian round trip produced: a usable decision, no usable decision, or an answer that must not be trusted."""
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
