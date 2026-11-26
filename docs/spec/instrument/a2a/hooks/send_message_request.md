###  Send Message Request (Client)

!!! note "Planned for specification v0.2.0"
    A2A wrapping is not part of specification v0.1.0. The `protocols/A2A/*` namespace is reserved, and the wrapping rules are planned for specification v0.2.0 ([D-008](../../../../decisions/index.md#d-008-defer-the-hardest-protocol-features-past-v01)). This page shows the intended design. Nothing on it is normative yet, including the lines that say "must", and its message shapes predate the v0.1.0 envelope schemas. [Instrument A2A](../extend_a2a.md) explains the planned flow.

#### 1. Description
This hook is called when the observed client agent sends a message to server agent to initiate a new interaction or to continue an existing one through A2A protocol.<br>
This hook **must** be used before the observed agent sends the A2A-compliant message to server agent.

#### 2. Method
`message/send`

#### 3. Response
The response is a [response envelope](../../specification.md#6-disposition-vocabulary) object.

| Decision | Behavior |
| :--------- | :---------- |
| `allow` | The observed agent should send the A2A-compliant to the target agent. |
| `deny` | The A2A-compliant message should be blocked and not sent to the target agent. |
| `modify` | The observed agent should send the A2A message with the modified content found in `modifiedRequest` field. |

#### 4. A2A payload
   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "message/send",
     "params": {
       "message": {
         "role": "agent",
         "parts": [
           {
             "kind": "text",
             "text": "how to prepare a cheese cake?"
           }
         ],
         "messageId": "9229e770-767c-417b-a0b0-f0741243c589"
       },
       "metadata": {}
     }
   }
   ```

#### 5. ACS payload
   ```json
   {
        "jsonrpc": "2.0",
        "id": "03c5db45-6455-4081-897a-4225267113ce",
        "method": "message/send",
        "params": {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "agent",
                        "parts": [
                        {
                            "kind": "text",
                            "text": "how to prepare a cheese cake?"
                        }
                        ],
                        "messageId": "9229e770-767c-417b-a0b0-f0741243c589"
                    },
                    "metadata": {}
                }
            },
            "reasoning": "Best to complete the task is to delegate it to the agent that specializes in cakes.",
            "context": {
                "from": {
                    "agent": {
                        "name": "Cooking assistant",
                        "url": "https://cooking-assistant.example.com/api/v1",
                        "instructions": "You are a helpful assistant that can answer questions and help with tasks related to cooking.",
                        "version": "1.0.0",
                        "provider": {
                            "name": "Example Model Provider",
                            "url": "https://provider.example.com"
                        },
                        "identity": {
                            "signatures": [{
                                "header": {
                                    "kid": "agent-key-12345",
                                    "alg": "RS256"
                                },
                                "protected": "eyJuYW1lIjoiQ29va2luZyBhc3Npc3RhbnQiLCJwcm92aWRlciI6eyJuYW1lIjoiT3BlbkFJIiwidXJsIjoiaHR0cHM6Ly9vcGVuYWkuY29tIn0sInVybCI6Imh0dHBzOi8vY29va2luZy1hc3Npc3RhbnQub3BlbmFpLmNvbS9hcGkvdjEiLCJ2ZXJzaW9uIjoiMS4wLjAifQ",
                                "signature": "SVTs6pMuMD0fWfHTyEFGtRWHkt1MjFegctKkuVJF0iyNahOU51Dh1Lc_Dz8P18OsMszW0et7q7mcm9aORhLopQ"
                            }]
                        }
                    },
                    "role": "client"
                },
                "to": {
                    "agent": {
                        "url": "https://cakes.example.org/v1",
                        "name": "Cake Baker",
                        "version": "1.0.0",
                        "identity": {
                            "signatures": [{
                                "header": {
                                    "alg": "ES256",
                                    "kid": "agent-key-789"
                                },
                                "protected": "eyJuYW1lIjoiQ2FrZSBCYWtlciIsInByb3ZpZGVyIjp7Im5hbWUiOiJBenVyZUFJRm91bmRyeSIsInVybCI6Imh0dHBzOi8vYWkuYXp1cmUuY29tIn0sInVybCI6Imh0dHBzOi8vYXBpLmNha2ViYWtlci5jb20vdjEiLCJ2ZXJzaW9uIjoiMS4wLjAifQ",
                                "signature": "5oWZfnfwGyz43fPq-9VnCHF0h8KNdxeX3hNfDKcjB5bfm0hqojgsORfoNidXWyJlAi94JuyKPfcNirfdP5jGeg"
                            }]
                        }
                    },
                    "role": "server"
                }
            }
        }
    }
   ```


###  Send Message Request (Server)

#### 1. Description
This hook is called when the observed server agent received send message request.<br>
This hook **must** be used before the observed agent processes the A2A-compliant message.

#### 2. Method
`message/send`

#### 3. Response
The response is a [response envelope](../../specification.md#6-disposition-vocabulary) object.

| Decision | Behavior |
| :--------- | :---------- |
| `allow` | The observed agent should process the A2A-compliant. |
| `deny` | The A2A-compliant message should be ignored and not processed by the server agent. |
| `modify` | The observed agent should process the A2A message with the modified content found in `modifiedRequest` field. |

#### 4. A2A payload
   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "message/send",
     "params": {
       "message": {
         "role": "agent",
         "parts": [
           {
             "kind": "text",
             "text": "how to prepare a cheese cake?"
           }
         ],
         "messageId": "9229e770-767c-417b-a0b0-f0741243c589"
       },
       "metadata": {}
     }
   }
   ```
#### 5. ACS payload
   ```json
   {
        "jsonrpc": "2.0",
        "id": "03c5db45-6455-4081-897a-4225267113ce",
        "method": "message/send",
        "params": {
            "payload": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "agent",
                        "parts": [
                        {
                            "kind": "text",
                            "text": "how to prepare a cheese cake?"
                        }
                        ],
                        "messageId": "9229e770-767c-417b-a0b0-f0741243c589"
                    },
                    "metadata": {}
                }
            },
            "context": {
                "from": {
                    "agent": {
                        "url": "https://cooking-assistant.example.com/api/v1",
                        "name": "Cooking assistant",
                        "version": "1.0.0",
                        "identity": {
                            "signatures": [{
                                "header": {
                                    "kid": "agent-key-12345",
                                    "alg": "RS256"
                                },
                                "protected": "eyJuYW1lIjoiQ29va2luZyBhc3Npc3RhbnQiLCJwcm92aWRlciI6eyJuYW1lIjoiT3BlbkFJIiwidXJsIjoiaHR0cHM6Ly9vcGVuYWkuY29tIn0sInVybCI6Imh0dHBzOi8vY29va2luZy1hc3Npc3RhbnQub3BlbmFpLmNvbS9hcGkvdjEiLCJ2ZXJzaW9uIjoiMS4wLjAifQ",
                                "signature": "SVTs6pMuMD0fWfHTyEFGtRWHkt1MjFegctKkuVJF0iyNahOU51Dh1Lc_Dz8P18OsMszW0et7q7mcm9aORhLopQ"
                            }]
                        }
                    },
                    "role": "client"
                },
                "to": {
                    "agent": {
                        "name": "Cake Baker",
                        "url": "https://cakes.example.org/v1",
                        "instructions": "You are a helpful assistant that specializies in answering questions and tasks related to cake baking.",
                        "version": "1.0.0",
                        "provider": {
                            "name": "Example Agent Platform",
                            "url": "https://platform.example.net"
                        },
                        "identity": {
                            "signatures": [{
                                "header": {
                                    "alg": "ES256",
                                    "kid": "agent-key-789"
                                },
                                "protected": "eyJuYW1lIjoiQ2FrZSBCYWtlciIsInByb3ZpZGVyIjp7Im5hbWUiOiJBenVyZUFJRm91bmRyeSIsInVybCI6Imh0dHBzOi8vYWkuYXp1cmUuY29tIn0sInVybCI6Imh0dHBzOi8vYXBpLmNha2ViYWtlci5jb20vdjEiLCJ2ZXJzaW9uIjoiMS4wLjAifQ",
                                "signature": "5oWZfnfwGyz43fPq-9VnCHF0h8KNdxeX3hNfDKcjB5bfm0hqojgsORfoNidXWyJlAi94JuyKPfcNirfdP5jGeg"
                            }]
                        }
                    },
                    "role": "server"
                }
            }
        }
    }
   ```