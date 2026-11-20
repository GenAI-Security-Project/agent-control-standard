from __future__ import annotations

from typing import Any


try:
    import rfc8785 as _rfc8785  # type: ignore[import-not-found]
except ImportError as _rfc8785_import_error:
    # §10 permits no other canonicalization, so a missing rfc8785 fails the import instead of falling back.
    raise ImportError(
        "ACS adapters require the `rfc8785` package for RFC 8785 (JCS) "
        "canonical signing — spec §10 permits no alternative "
        "canonicalization. Install it: pip install rfc8785"
    ) from _rfc8785_import_error


# Every way canonicalizing a value can fail: rfc8785's own errors (the integer and float domain errors among them),
# a lone surrogate that can't encode as UTF-8, and a value nested past the interpreter's recursion limit.
CANONICALIZATION_ERRORS: tuple[type[BaseException], ...] = (
    _rfc8785.CanonicalizationError, UnicodeEncodeError, RecursionError)


def jcs_canonicalize(obj: Any) -> bytes:
    return _rfc8785.dumps(obj)
