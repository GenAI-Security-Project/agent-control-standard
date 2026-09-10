# SPDX-License-Identifier: Apache-2.0
"""FastMCP client instrumentation for ACS (sample).

Wraps any object with ``await call_tool(name, arguments)`` (a real
``fastmcp.Client`` or a test double — no fastmcp import required here):
every call first emits a steps/toolCallRequest envelope to the Guardian
URL and honors the verdict BEFORE the tool runs.

v0.1 semantics, stated plainly: allow → proceed; deny → raise without
calling; modify | ask | defer → treated as deny (the sample has no
modification/approval loop; production clients MUST implement them
rather than downgrading to allow).
"""

from __future__ import annotations

import json
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Optional


class GovernedDenied(RuntimeError):
    """The Guardian denied this tool call: the tool never ran."""

    def __init__(self, tool: str, reasoning: str) -> None:
        super().__init__(f"guardian denied {tool!r}: {reasoning}")
        self.tool = tool
        self.reasoning = reasoning


def build_tool_call_envelope(tool: str, arguments: dict,
                             agent_id: str = "sample-agent",
                             session_id: Optional[str] = None,
                             acs_version: str = "0.1.0") -> dict:
    """Pure envelope builder (no I/O, fully testable)."""
    return {
        "jsonrpc": "2.0",
        "method": "steps/toolCallRequest",
        "id": 1,
        "params": {
            "acs_version": acs_version,
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "agent_id": agent_id,
                "session_id": session_id or str(uuid.uuid4()),
            },
            "payload": {
                "tool": {"name": tool},
                "arguments": arguments,
            },
        },
    }


def post_envelope(guardian_url: str, envelope: dict,
                  timeout: float = 5.0) -> dict:
    """POST one envelope, return the decoded JSON-RPC response."""
    data = json.dumps(envelope).encode()
    req = urllib.request.Request(
        guardian_url.rstrip("/") + "/acs", data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


class GovernedClient:
    """fastmcp.Client wrapper enforcing Guardian verdicts pre-execution."""

    def __init__(self, inner: Any, guardian_url: str,
                 agent_id: str = "sample-agent",
                 session_id: Optional[str] = None) -> None:
        self._inner = inner
        self._guardian_url = guardian_url
        self._agent_id = agent_id
        self._session_id = session_id or str(uuid.uuid4())

    async def call_tool(self, name: str, arguments: Optional[dict] = None) -> Any:
        """Govern, then (only on allow) delegate to the inner client."""
        envelope = build_tool_call_envelope(
            name, arguments or {}, self._agent_id, self._session_id)
        try:
            response = post_envelope(self._guardian_url, envelope)
        except Exception as exc:
            # Guardian unreachable: fail CLOSED (no silent allow).
            raise GovernedDenied(name, f"guardian unreachable: {exc}"[:200])
        result = response.get("result") if isinstance(response, dict) else None
        decision = result.get("decision") if isinstance(result, dict) else None
        reasoning = (result.get("reasoning", "") if isinstance(result, dict) else "")
        if decision == "allow":
            return await self._inner.call_tool(name, arguments or {})
        if decision in ("modify", "ask", "defer"):
            raise GovernedDenied(
                name, f"verdict {decision!r} unsupported by this sample "
                      f"(treated as deny): {reasoning}")
        raise GovernedDenied(name, reasoning or f"verdict {decision!r}")


def require_fastmcp() -> None:
    """Import check with a helpful error (real-client path only)."""
    try:
        import fastmcp  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "the live demo needs the 'fastmcp' package "
            "(pip install fastmcp); unit tests use a fake client"
        ) from exc


# --- live demo (needs fastmcp + a running guardian; not a test) ------------
async def demo(guardian_url: str = "http://127.0.0.1:8787") -> None:  # pragma: no cover
    require_fastmcp()
    from fastmcp import Client

    client = Client("https://example.com/mcp")  # replace with a real server
    governed = GovernedClient(client, guardian_url)
    async with client:
        print(await governed.call_tool("greet", {"name": "acs"}))
