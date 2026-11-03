"""Runs when the adapter's own dependencies fail to import, so it imports only modules that load without rfc8785."""
from __future__ import annotations

import io
import os
import sys
from collections.abc import Callable
from importlib import import_module

from acs.client._audit import audit_event
from acs.client._config import Config

UNAVAILABLE_REASON = ("ACS adapter unavailable (dependency missing); "
                      "failing closed per the deployment posture")
CRASHED_REASON = "ACS adapter error before the session posture was known; failing closed"


def run_hook(module: str, *, event_key: str, event_name: Callable[[str], str],
             deny: Callable[[str, str], int], allow: Callable[[str], int] = lambda name: 0) -> int:
    """Run the adapter's main(): an adapter that cannot load follows ACS_DEFAULT_DENY, one that raises denies, and both are audited."""
    if sys.argv[1:2] == ["--version"]:
        # Flags are answered without reading an event, so stdin may stay open.
        try:
            return import_module(module).main()
        except ImportError as error:
            sys.stderr.write(f"acs-adapter unavailable: {error}\n")
            return 1
    raw = sys.stdin.read()
    sys.stdin = io.StringIO(raw)
    try:
        main = import_module(module).main
    except ImportError as error:
        return _settle(event_key, event_name(raw), deny, allow, error, audit_type="adapter_unavailable",
                       reason=UNAVAILABLE_REASON, detail="adapter could not load; no envelope was sent",
                       fail_closed=False)
    except Exception as error:  # noqa: BLE001
        return _settle(event_key, event_name(raw), deny, allow, error, audit_type="adapter_crashed",
                       reason=CRASHED_REASON, detail="adapter raised while loading; no envelope was sent",
                       fail_closed=True)
    try:
        return main()
    except Exception as error:  # noqa: BLE001
        # An exit 1 would let the host proceed with no record of the step.
        return _settle(event_key, event_name(raw), deny, allow, error, audit_type="adapter_crashed",
                       reason=CRASHED_REASON, detail="adapter raised before settling the step",
                       fail_closed=True)


def _settle(event_key: str, name: str, deny: Callable[[str, str], int], allow: Callable[[str], int],
            error: Exception, *, audit_type: str, reason: str, detail: str, fail_closed: bool) -> int:
    config = Config.from_env(os.environ)
    if config.disabled:
        # The adapter's main() reads the kill switch, and it never ran to completion on this path.
        audit_event("acs_disabled_bypass", **{event_key: name},
                    detail="ACS_DISABLED=1 — hook bypassed with no Guardian "
                           "traffic; every step proceeds ungoverned")
        return allow(name)
    deny_on_failure = fail_closed or config.posture.deny_on_failure
    audit_event(audit_type, **{event_key: name},
                posture="deny" if deny_on_failure else "proceed",
                error=f"{type(error).__name__}: {str(error).splitlines()[0] if str(error) else ''}",
                detail=detail)
    return deny(name, reason) if deny_on_failure else 0
