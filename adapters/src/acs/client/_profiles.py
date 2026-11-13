from __future__ import annotations

from acs.client._audit import audit_event
from acs.client._store import mark_once


def record_mcp_use(session_id: str | None, *, tool: str, workspace: str | None = None) -> None:
    """Record, once per session, that using MCP leaves its acs-core claim partial: protocols/MCP/* is not wrapped."""
    if session_id and mark_once(session_id, "profile_claim_degraded", workspace=workspace):
        audit_event("profile_claim_degraded", profile="acs-core", session_id=session_id, tool=tool,
                    detail="the session uses MCP; the adapter governs MCP tools/call through the "
                           "tool hooks and does not wrap protocols/MCP/*")
