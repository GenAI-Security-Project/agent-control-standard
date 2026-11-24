<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# ACS adapter: FastMCP

In-process server middleware and client wrapper that connect [FastMCP](https://gofastmcp.com/) servers and clients to an ACS Guardian. Every call speaks the signed ACS v0.1.0 wire contract through `acs.core` and `acs.client`.

## How it works

The adapter exposes two integration surfaces sharing one session engine:

- **`ACSFastMCPMiddleware`** attaches to any `FastMCP` server (`mcp.add_middleware(...)`) and intercepts every `tools/call` in `on_call_tool`.
- **`GovernedFastMCPClient`** wraps any `fastmcp.Client` (`async with GovernedFastMCPClient(client) as governed:`) and enforces verdicts before `call_tool` reaches the remote MCP server.

On each tool call, the adapter:

1. Opens the ACS session once per middleware or client scope (`handshake/hello` followed by `steps/sessionStart`), off the asyncio event loop (`asyncio.to_thread`).
2. Translates the tool name and arguments into a `steps/toolCallRequest` envelope ([mapping.md](./mapping.md)) with every argument wrapped in `{value: ...}`.
3. Signs the RFC 8785 canonical envelope with HMAC-SHA256 using an HKDF-derived per-session key (`ACS_HMAC_SECRET_FILE` or `ACS_HMAC_SECRET`, under `ACS_HMAC_KEY_ID`).
4. Verifies the Guardian's response signature, binding, and schema before applying the verdict: `allow` runs the tool; `modify` applies validated `parameter_overrides`; `deny`, `ask`, `defer`, or any refusal raises `ACSGuardianDenied` before execution.
5. Sends `steps/toolCallResult` linked via `request_id_ref` after execution (including `exit_status: "failure"` when the tool raises, propagating the tool's original exception unchanged) and applies `modified_content` or output withholding when requested.
6. Seals the session with `steps/sessionEnd` (including per-class `summary.decision_failures`) when the scope closes.

### Decision honoring (§6.4)

ACS-Core §6.4 requires the framework to wait for the verdict before executing the action. Both `ACSFastMCPMiddleware.on_call_tool` and `GovernedFastMCPClient.call_tool` await the Guardian verdict before invoking `call_next` or `inner.call_tool`. A deny, refusal, or fail-closed decision failure raises `ACSGuardianDenied` before the tool handler runs (`tests/integrations/fastmcp/test_live.py` asserts denied tools execute zero times).

## Install and use

Install `acs-adapters` with the `fastmcp` extra:

```bash
export ACS_REPO=/path/to/your/clone
pip install "$ACS_REPO/adapters[fastmcp]"
```

### 1. Start a Guardian with a shared HMAC secret

```bash
mkdir -p -m 700 ~/.acs
openssl rand -hex 32 > ~/.acs/hmac.key
chmod 600 ~/.acs/hmac.key

ACS_HMAC_SECRET_FILE=~/.acs/hmac.key ACS_HMAC_KEY_ID=2026-11 \
  acs-example-guardian --port 8787
```

The adapter also works unchanged against the Go reference Guardian (`reference-implementations/agt-go`).

### 2. Attach server middleware

```python
from fastmcp import FastMCP
from acs.integrations.fastmcp import ACSFastMCPMiddleware

mcp = FastMCP("payments")
mw = ACSFastMCPMiddleware(guardian_url="http://127.0.0.1:8787/acs")
mcp.add_middleware(mw)

@mcp.tool
def search_docs(query: str) -> str:
    return f"results for {query}"
```

### 3. Or wrap a FastMCP client

```python
from fastmcp import Client
from acs.integrations.fastmcp import GovernedFastMCPClient

async with GovernedFastMCPClient(
    Client("http://127.0.0.1:8000/mcp"),
    guardian_url="http://127.0.0.1:8787/acs",
) as client:
    result = await client.call_tool("search_docs", {"query": "acs"})
```

## Verify the install

Run the emission conformance, security invariants, and live in-memory FastMCP integration suites from `adapters/`:

```bash
cd "$ACS_REPO/adapters"
uv sync --locked --extra fastmcp --group test
uv run python run_conformance.py fastmcp
```

Without the `fastmcp` extra installed, `tests/integrations/fastmcp/test_emission.py` and `tests/integrations/fastmcp/test_adapter.py` still run all schema-emission, concurrency, and failure-mode checks using lightweight stand-ins; `test_live.py` runs real in-memory `FastMCP` + `Client(mcp)` + `acs-example-guardian` tests once `--extra fastmcp` is installed.

## Configuration

The adapter reads environment variables once via `acs.client.Config.from_env(os.environ)` and applies explicit constructor kwargs on top via `dataclasses.replace`, so environment switches remain authoritative:

| Variable | Default | Purpose |
|---|---|---|
| `ACS_GUARDIAN_URL` | `http://127.0.0.1:8787/acs` | Guardian endpoint (`http`/`https` only; validated against SSRF rules). |
| `ACS_HMAC_SECRET_FILE` | (unset) | Path to a mode `0600` file holding the shared HMAC secret (>= 32 bytes). |
| `ACS_HMAC_SECRET` | (unset) | Inline shared secret (prefer `ACS_HMAC_SECRET_FILE` in production). |
| `ACS_HMAC_KEY_ID` | (unset) | Key identifier required alongside the shared secret (§10). |
| `ACS_DEFAULT_DENY` | (unset -> fail-closed) | Set to `0` to opt into fail-open on decision failures; Guardian refusals and ServerHello `on_decision_failure: deny` still fail closed. |
| `ACS_STARTUP_POSTURE` | `refuse` | `proceed` or `refuse` when the handshake receives no answer (§4.1). |
| `ACS_REQUIRE_PROFILES` | (unset) | Comma-separated profiles the Guardian must accept in `ServerHello`. |
| `ACS_HANDSHAKE` | `1` | Set to `0` to skip `handshake/hello` (`ACS_STARTUP_POSTURE` then governs every step). |
| `ACS_AGENT_ID` | `fastmcp-server` / `fastmcp-client` | Identifier sent in `metadata.agent_id`. |
| `ACS_AUDIT_FILE` | (unset) | Optional mode `0600` file receiving `ACS_AUDIT` JSON lines in addition to stderr. |
| `ACS_DISABLED` | (unset) | `1` disables governance and sends zero Guardian traffic. |
| `ACS_RESPONSE_ALGORITHMS` / `ACS_GUARDIAN_KEYS` | (unset) | Optional ML-DSA-65 response verification when installed with `[pqc]` (`docs/signing.md`). |

## Conformance status

Honest, item-by-item against the ACS-Core baseline in `docs/spec/conformance.md`. Tests verify **emission conformance** (validating every wire byte against canonical v0.1.0 schemas via `CaptureGuardian`) plus live round-trip enforcement against `acs-example-guardian` — this is an emission and reference-stack posture, not a full requirement-by-requirement certification.

| ACS-Core item | Status |
|---|---|
| Handshake (`handshake/hello`) | ✓ Sends `ClientHello` once per session off the event loop; `advertised == emitted` (`sessionStart`, `toolCallRequest`, `toolCallResult`, `sessionEnd`). |
| Profiles (`profiles_supported` / `profiles_accepted`) | ✓ Claims `acs-core`; refuses sessions with missing/short secrets or missing `key_id` before any network traffic; honors `ACS_REQUIRE_PROFILES`. |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ Every emitted envelope and hook payload validates against `specification/v0.1.0/` in `tests/integrations/fastmcp/test_emission.py` and `test_live.py` with UUID and RFC 3339 checks. |
| Hook taxonomy (Core minimum set) | ⚠ Partial by host boundary. Emits `sessionStart`, `toolCallRequest`, `toolCallResult`, and `sessionEnd`. FastMCP exposes MCP tool boundaries rather than LLM prompt/reply streams, so `userMessage` and `agentResponse` are not emitted and not advertised. See [mapping.md](./mapping.md). |
| Dispositions (`ALLOW`/`DENY`/`MODIFY`/`ASK`/`DEFER`) | ✓ `ALLOW` proceeds; `DENY` blocks pre-execution (`ACSGuardianDenied`) and withholds post-execution output; `MODIFY` applies `parameter_overrides` pre-execution and `modified_content` post-execution, failing closed on §6.3 composition violations; `ASK` and `DEFER` substitute to `DENY` with audit. |
| Unknown-disposition fail posture | ✓ Any disposition outside the five known values fails closed and is audited as `malformed_response`. |
| SessionContext + `request_id_ref` | ✓ Fresh UUID `session_id` per session; `toolCallResult.request_id_ref` links to its originating `toolCallRequest.request_id`. |
| Replay protection (`request_id` + `timestamp`) | ✓ Unique UUID `request_id` and RFC 3339 timestamp on every step; Guardian refusals (`-32005`, `-32006`) always fail closed. |
| Baseline integrity (HMAC-SHA256 signature) | ✓ HKDF-derived per-session key signs every request and verifies every response under `ACS_HMAC_KEY_ID`; unsigned or tampered responses fail closed. |
| Decision honoring (§6.4) | ✓ Tool handler never runs on pre-execution deny/refusal; tool exceptions propagate unchanged (never masked as Guardian deny); `sessionEnd` reports `summary.decision_failures`. |
| Liveness `system/ping` | ⚠ Guardian-side only. The adapter does not send `system/ping`; rely on continuous observed tool traffic or external health checks. |
| `nonce` (optional replay field) | ✗ Not emitted (optional in v0.1). |
| Wrapped MCP `protocols/MCP/*` | ⚠ Partial. Governs MCP `tools/call` through `steps/toolCallRequest` and `steps/toolCallResult` and records `profile_claim_degraded` once per session via `record_mcp_use`. Non-tool MCP surfaces (`resources/read`, `prompts/get`, notifications) are not wrapped. Known limitation. |
