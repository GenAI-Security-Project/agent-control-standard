"""The FinBot routes the lab drives, and the one mapping from scenario steps to requests.

Version 0.1.0. Owner: Rock Lambros.

Read in GenAI-Security-Project/finbot-ctf at commit 1450fc4. The scenario tests and the
scenario driver both import this module, so every request the driver sends is a route
the tests pinned to a FinBot file and line. finbot/main.py:161-165 mounts each app under
its prefix, and each app's API router adds /api/v1. Stdlib only, like the rest of the CLI.
"""
from __future__ import annotations

import re
import string

# main.py:222, returns csrf_token and namespace for the session cookie.
SESSION_STATUS = ("GET", "/api/session/status")
# apps/vendor/routes/api.py:89, starts the orchestrator in BackgroundTasks (:118).
REGISTER_VENDOR = ("POST", "/vendor/api/v1/vendors/register")
# apps/vendor/routes/api.py:178, the vendor record and its status.
VENDOR = ("GET", "/vendor/api/v1/vendors/{vendor_id}")
# apps/vendor/routes/api.py:531, starts the orchestrator in BackgroundTasks (:571).
CREATE_INVOICE = ("POST", "/vendor/api/v1/invoices")
# apps/vendor/routes/api.py:608, one invoice and its status.
INVOICE = ("GET", "/vendor/api/v1/invoices/{invoice_id}")
# apps/vendor/routes/api.py:804, finstripe transactions for the current vendor.
TRANSFERS = ("GET", "/vendor/api/v1/payments/transactions")
# apps/vendor/routes/api.py:978, the current vendor's inbox.
VENDOR_INBOX = ("GET", "/vendor/api/v1/messages")
# apps/vendor/routes/api.py:1169, the vendor chat stream.
VENDOR_CHAT = ("POST", "/vendor/api/v1/chat")
# apps/vendor/routes/api.py:1199, saved vendor chat turns.
VENDOR_HISTORY = ("GET", "/vendor/api/v1/chat/history")
# apps/vendor/routes/api.py:1211, clears vendor chat history (the driver rule).
CLEAR_VENDOR_HISTORY = ("DELETE", "/vendor/api/v1/chat/history")
# apps/admin/routes/api.py:501, the copilot chat stream.
COPILOT_CHAT = ("POST", "/admin/api/v1/copilot/chat")
# apps/admin/routes/api.py:525, saved copilot chat turns.
COPILOT_HISTORY = ("GET", "/admin/api/v1/copilot/history")
# apps/admin/routes/api.py:537, clears copilot chat history (the driver rule).
CLEAR_COPILOT_HISTORY = ("DELETE", "/admin/api/v1/copilot/history")
# apps/darklab/routes/api.py:75. A fresh namespace has no server row, and this GET creates
# it (:87-95). Without it the PUT below returns 404 (core/data/repositories.py:653-662).
SERVER = ("GET", "/darklab/api/v1/supply-chain/servers/{server}")
# apps/darklab/routes/api.py:107, sets tool description overrides.
TOOL_OVERRIDES = ("PUT", "/darklab/api/v1/supply-chain/servers/{server}/tools")
# apps/darklab/routes/api.py:129, restores the default tool descriptions.
RESET_TOOLS = ("POST", "/darklab/api/v1/supply-chain/servers/{server}/reset-tools")
# apps/darklab/routes/api.py:215, mail to addresses FinBot can't resolve.
DEAD_DROP = ("GET", "/darklab/api/v1/toolkit/dead-drop")

# apps/vendor/routes/api.py:154, the session's current vendor id, which a registration made on FinBot's own page sets.
VENDOR_ME = ("GET", "/vendor/api/v1/vendors/me")
# The current vendor's invoices, as FinBot's invoices page lists them (static/js/vendor/invoice.js:343).
INVOICES = ("GET", "/vendor/api/v1/invoices")

ROUTES = frozenset({
    SESSION_STATUS, REGISTER_VENDOR, VENDOR, CREATE_INVOICE, INVOICE, TRANSFERS, VENDOR_INBOX, VENDOR_ME, INVOICES,
    VENDOR_CHAT, VENDOR_HISTORY, CLEAR_VENDOR_HISTORY, COPILOT_CHAT, COPILOT_HISTORY,
    CLEAR_COPILOT_HISTORY, SERVER, TOOL_OVERRIDES, RESET_TOOLS, DEAD_DROP,
})

# MCP servers a scenario may override, with their tools: the @mcp.tool functions in each file.
TOOLS = {
    # mcp/servers/finmail/server.py:64, :130, :187, :210, :260.
    "finmail": frozenset({"send_email", "list_inbox", "read_email", "search_emails", "mark_as_read"}),
    # mcp/servers/finstripe/server.py:47, :99, :117, :131.
    "finstripe": frozenset({"create_transfer", "get_transfer", "get_account_balance", "list_transfers"}),
}

# A path parameter is an id or a server name. Anything else could walk the path or add a query.
_SAFE_VALUE = re.compile(r"[A-Za-z0-9_-]+")


def fill(template: str, **values: object) -> str:
    """Put values into a route's path, refusing a missing name or a value that isn't one segment."""
    names = {name for _, name, _, _ in string.Formatter().parse(template) if name}
    filled = {}
    for name in names:
        value = str(values[name])
        if not _SAFE_VALUE.fullmatch(value):
            raise ValueError(f"unsafe value for {name}")
        filled[name] = value
    return template.format(**filled)


def step_route(step: dict) -> tuple[str, str]:
    """The request a scenario step sends. Each step sends exactly one."""
    kind = step["kind"]
    if kind == "register_vendor":
        return REGISTER_VENDOR
    if kind == "create_invoice":
        return CREATE_INVOICE
    if kind == "chat":
        return VENDOR_CHAT if step["surface"] == "vendor" else COPILOT_CHAT
    if kind == "tool_override":
        return TOOL_OVERRIDES
    if kind == "reset_tools":
        return RESET_TOOLS
    raise ValueError(f"unknown step kind {kind!r}")


def probe_route(probe: dict) -> tuple[str, str] | None:
    """The request a probe reads, or None for quiet, which reads the gateway's model input log."""
    kind = probe["kind"]
    if kind == "dead_drop":
        return DEAD_DROP
    if kind == "inbox":
        return VENDOR_INBOX
    if kind == "transfers":
        return TRANSFERS
    if kind == "invoice_status":
        return INVOICE
    if kind == "chat_reply":
        return VENDOR_HISTORY if probe["surface"] == "vendor" else COPILOT_HISTORY
    if kind == "quiet":
        return None
    raise ValueError(f"unknown probe kind {kind!r}")
