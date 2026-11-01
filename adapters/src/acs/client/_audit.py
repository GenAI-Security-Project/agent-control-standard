"""Structured ACS_AUDIT records, on stderr and in ACS_AUDIT_FILE."""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from acs.core import iso8601_now


# ----- Audit events (§6.4 fail-open recording) -----

def audit_event(event_type: str, **fields: Any) -> None:
    """Emit a structured audit-event line to stderr and, when
    `ACS_AUDIT_FILE` is set, append it to that file (created 0600).

    §6.4 requires every undecided proceed to be recorded; stderr alone
    is not durable, so deployments SHOULD set ACS_AUDIT_FILE. Single-line
    JSON for line-oriented ingestion.
    """
    payload = {
        "acs_audit_event": event_type,
        "timestamp": iso8601_now(),
        **fields,
    }
    line = "ACS_AUDIT " + json.dumps(payload, sort_keys=True) + "\n"
    sys.stderr.write(line)
    sys.stderr.flush()
    audit_file = os.environ.get("ACS_AUDIT_FILE", "").strip()
    if audit_file:
        try:
            fd = os.open(audit_file,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(line)
        except OSError as e:
            # Never crash the hook path over the audit sink, but say so.
            sys.stderr.write(
                f"ACS_AUDIT_SINK_ERROR cannot append to {audit_file!r}: {e}\n")
            sys.stderr.flush()


def audit_modify_unsupported(detail: str, **fields: Any) -> None:
    """Record a MODIFY the client cannot apply and treats as DENY, under reason code modify_unsupported (§6.5)."""
    audit_event("modify_unsupported", reason_codes=["modify_unsupported"], detail=detail, **fields)
