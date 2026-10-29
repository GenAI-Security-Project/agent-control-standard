"""RFC 8785 (JCS) canonicalization, the only form §10 signs."""
from __future__ import annotations

from typing import Any


# ----- Canonicalization -----

try:
    import rfc8785 as _rfc8785  # type: ignore[import-not-found]
except ImportError as _rfc8785_import_error:
    # HARD dependency, deliberately. Spec §10: "Alternative
    # canonicalization is not permitted in v0.1." A sorted-keys
    # json.dumps fallback diverges from RFC 8785 on floats (1.0 vs 1),
    # -0.0, large exponents, and non-BMP key ordering. The failure mode
    # is a silent policy bypass (divergent canonicalization →
    # SIGNATURE_INVALID → fail posture), so refuse to import instead.
    raise ImportError(
        "ACS adapters require the `rfc8785` package for RFC 8785 (JCS) "
        "canonical signing — spec §10 permits no alternative "
        "canonicalization. Install it: pip install rfc8785"
    ) from _rfc8785_import_error


def jcs_canonicalize(obj: Any) -> bytes:
    """RFC 8785 (JSON Canonicalization Scheme) via the `rfc8785` package.

    A hard dependency — see the import block above for why there is
    deliberately no fallback."""
    return _rfc8785.dumps(obj)
