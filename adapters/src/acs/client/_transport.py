from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid

from acs.client._urls import validate_guardian_url
from acs.core import ACS_VERSION, iso8601_now


def ping(guardian_url: str, *, echo: str = "ping", timeout: float = 2.0) -> dict | None:
    """Send system/ping (§13: unsigned, outside the chain); the result, or None on failure."""
    request = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "system/ping",
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": str(uuid.uuid4()),
            "timestamp": iso8601_now(),
            "metadata": {"agent_id": "ping-client", "session_id": str(uuid.uuid4())},
            "payload": {"echo": echo},
        },
    }
    try:
        validate_guardian_url(guardian_url)
    except ValueError:
        return None
    try:
        body = json.dumps(request).encode("utf-8")
        req = urllib.request.Request(
            guardian_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")).get("result")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        return None
