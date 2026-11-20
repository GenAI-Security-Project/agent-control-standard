from __future__ import annotations

import os


_ALLOWED_GUARDIAN_SCHEMES = frozenset({"http", "https"})


def validate_guardian_url(url: str) -> None:
    """Refuse a scheme other than http(s), which urlopen would follow to file:// or data://, and a host outside ACS_GUARDIAN_HOST_ALLOWLIST when set."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_GUARDIAN_SCHEMES:
        raise ValueError(
            f"Guardian URL scheme {parsed.scheme!r} not allowed; "
            f"only {sorted(_ALLOWED_GUARDIAN_SCHEMES)} permitted")
    allow = os.environ.get("ACS_GUARDIAN_HOST_ALLOWLIST", "").strip()
    if allow:
        allowed_hosts = {h.strip().lower() for h in allow.split(",") if h.strip()}
        host = (parsed.hostname or "").lower()
        if host not in allowed_hosts:
            raise ValueError(
                f"Guardian host {host!r} not in ACS_GUARDIAN_HOST_ALLOWLIST "
                f"({sorted(allowed_hosts)})")
