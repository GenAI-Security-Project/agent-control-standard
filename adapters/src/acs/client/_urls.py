"""Guardian URL checks: an http(s) scheme, and the optional host allowlist."""
from __future__ import annotations

import os


# ----- URL scheme allowlist (defends against SSRF / file:// disclosure) -----

_ALLOWED_GUARDIAN_SCHEMES = frozenset({"http", "https"})


def validate_guardian_url(url: str) -> None:
    """Reject Guardian URLs whose scheme is not http/https.

    urllib.request.urlopen happily accepts file://, ftp://, data://, etc.
    An attacker who controls ACS_GUARDIAN_URL could use file:// to read
    arbitrary files the adapter user has access to, or data:// to feed
    a crafted response. The adapter and any other code POSTing to the
    Guardian MUST call this before urlopen.

    Optionally also restricts the hostname against an operator-provided
    `ACS_GUARDIAN_HOST_ALLOWLIST` (comma-separated). Defense in depth
    against env-var attacks that smuggle a real http:// URL to an
    internal service the adapter shouldn't reach.
    """
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
