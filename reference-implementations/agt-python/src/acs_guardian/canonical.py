"""The ACS §10 signing input: JCS canonicalization with the signature removed.

The signed input is the RFC 8785 (JCS) canonicalization of the request or
response envelope with the ``signature`` field removed, encoded as UTF-8
(Specification §10). A request carries its signature at ``params.signature``;
a response carries it at ``result.signature`` or ``error.signature`` (the
location the Go port in open PR #169 uses for the two shapes
``response-envelope.json`` defines no signature field for: a ``ServerHello``
result and an error).

Canonicalization is delegated to the ``rfc8785`` package rather than
hand-rolled: JCS number formatting follows ECMAScript ``Number::toString``
(``1.0`` canonicalizes to ``1``, not ``1.0``), and an implementation that
gets that wrong produces signatures only it can verify.
"""

from __future__ import annotations

from typing import Any

import rfc8785

REQUEST_SIGNATURE_HOLDER = "params"
RESPONSE_SIGNATURE_HOLDERS = ("result", "error")


def canonical_bytes(value: Any) -> bytes:
    """RFC 8785 (JCS) canonicalization, UTF-8 encoded."""
    return rfc8785.dumps(value)


def _without_signature(envelope: dict[str, Any], holder: str) -> dict[str, Any]:
    """The envelope minus the signature, copied shallowly on purpose.

    A ``copy.deepcopy`` here raised ``RecursionError`` on a signed request
    nested a few hundred levels deep (the parser accepts such a body, so it
    arrives), and an exception on the signing path is an unsigned answer the
    Observed Agent can turn into a run with its ``on_decision_failure``
    posture. Only the top level and the holder are copied; nothing below is
    touched, and the caller's envelope is never mutated.
    """
    unsigned = dict(envelope)
    container = unsigned.get(holder)
    if isinstance(container, dict):
        unsigned[holder] = {key: value for key, value in container.items() if key != "signature"}
    return unsigned


def request_signing_input(envelope: dict[str, Any]) -> bytes:
    """Canonical input for a request envelope: the envelope minus ``params.signature``."""
    return canonical_bytes(_without_signature(envelope, REQUEST_SIGNATURE_HOLDER))


def response_signing_input(envelope: dict[str, Any]) -> bytes:
    """Canonical input for a response envelope: the envelope minus its signature holder.

    A response carries exactly one of ``result`` or ``error``
    (``response-envelope.json``'s ``oneOf``), so the holder is whichever is
    present.
    """
    holder = "result" if "result" in envelope else "error"
    return canonical_bytes(_without_signature(envelope, holder))
