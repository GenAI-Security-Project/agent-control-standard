from __future__ import annotations

from importlib.resources import files
from pathlib import Path

_BUNDLED = Path(str(files("acs.core") / "schemas"))
_CHECKOUT = Path(__file__).resolve().parents[4] / "specification" / "v0.1.0"


def schemas_dir(override: str | None = None) -> Path:
    """Return `override` if given, else the schemas bundled in the wheel, else a source checkout's specification/v0.1.0."""
    if override:
        return Path(override)
    for candidate in (_BUNDLED, _CHECKOUT):
        if (candidate / "request-envelope.json").is_file():
            return candidate
    raise FileNotFoundError(
        "ACS schemas not found: install acs-adapters from a built wheel, "
        "run from a repository checkout, or set ACS_SPEC_DIR")
