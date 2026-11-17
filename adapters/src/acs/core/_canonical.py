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


def jcs_canonicalize(obj: Any) -> bytes:
    return _rfc8785.dumps(obj)
