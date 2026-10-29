"""Start a hook command so that an adapter that cannot load still writes an audit record and honors ACS_DEFAULT_DENY.

Imports only modules that load without rfc8785, because it runs exactly when
the adapter's own dependencies fail to import.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from importlib import import_module

from acs.client._audit import audit_event
from acs.client._config import Config

UNAVAILABLE_REASON = ("ACS adapter unavailable (dependency missing); "
                      "failing closed per the deployment posture")


def run_hook(module: str, *, event_key: str, event_name: Callable[[], str],
             deny: Callable[[str, str], int]) -> int:
    """Import the adapter module and run its main(); if the import fails, record that and apply the configured posture."""
    try:
        main = import_module(module).main
    except ImportError as error:
        return _unavailable(error, event_key, event_name, deny)
    return main()


def _unavailable(error: ImportError, event_key: str, event_name: Callable[[], str],
                 deny: Callable[[str, str], int]) -> int:
    config = Config.from_env(os.environ)
    name = event_name()
    if config.disabled:
        # The adapter's main() reads the kill switch, and it never runs on this path.
        audit_event("acs_disabled_bypass", **{event_key: name},
                    detail="ACS_DISABLED=1 — hook bypassed with no Guardian "
                           "traffic; every step proceeds ungoverned")
        return 0
    deny_on_failure = config.posture.deny_on_failure
    audit_event("adapter_unavailable", **{event_key: name},
                posture="deny" if deny_on_failure else "proceed",
                error=str(error).split("\n")[0],
                detail="adapter could not load; no envelope was sent")
    return deny(name, UNAVAILABLE_REASON) if deny_on_failure else 0
