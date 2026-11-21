### Stream Message Request (Client)

!!! note "Planned for specification v0.2.0"
    A2A wrapping is not part of specification v0.1.0. The `protocols/A2A/*` namespace is reserved, and the wrapping rules are planned for specification v0.2.0 ([D-008](../../../../decisions/index.md#d-008-defer-the-hardest-protocol-features-past-v01)). This page shows the intended design. Nothing on it is normative yet, including the lines that say "must", and its message shapes predate the v0.1.0 envelope schemas. [Instrument A2A](../extend_a2a.md) explains the planned flow.

#### 1. Description
This hook is called when the observed client agent sends a message to server agent to initiate a new interaction or to continue an existing one AND subsribes to real-time updates for the task through A2A protocol.<br>
This hook **must** be used before the observed agent sends the A2A-compliant message to server agent.

#### 2. Method
`message/stream`


#### 3. Reponse
The response is an [response envelope](../../specification.md#6-disposition-vocabulary) object.

| Decision | Behavior |
| :--------- | :---------- |
| `allow` | The observed agent should send the A2A-compliant message to the target agent. |
| `deny` | The A2A-compliant message should be blocked and not sent to the target agent. |
| `modify` | The observed agent should send the A2A message with the modified content found in `modifiedRequest` field. |

#### 4. A2A payload
   ```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "message/stream",
  "params": {
    "message": {
      "role": "user",
      "parts": [
        {
          "kind": "text",
          "text": "write a long paper describing the attached pictures"
        },
        {
          "kind": "file",
          "file": {
            "mimeType": "image/png",
            "data": "<base64-encoded-content>"
          }
        }
      ],
      "messageId": "bbb7dee1-cf5c-4683-8a6f-4114529da5eb"
    },
    "configuration": {
        "acceptedOutputModes": [],
        "pushNotificationConfig": {
            "url": "https://notifications.example.com/webhooks/1234567"
        }
    },
    "metadata": {}
  }
}
   ```
#### 5. ACS payload
   ```json
{
    "jsonrpc": "2.0",
    "id": "56e55ffd-fe11-4c64-b7c9-ddc936dbaed2",
    "method": "message/stream",
    "params": {
        "payload":{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [
                        {
                        "kind": "text",
                        "text": "write a long paper describing the attached pictures"
                        },
                        {
                        "kind": "file",
                        "file": {
                            "mimeType": "image/png",
                            "data": "<base64-encoded-content>"
                        }
                        }
                    ],
                    "messageId": "bbb7dee1-cf5c-4683-8a6f-4114529da5eb"
                },
                "configuration": {
                    "acceptedOutputModes": [],
                    "pushNotificationConfig": {
                        "url": "https://notifications.example.com/webhooks/1234567"
                    }
                },
                "metadata": {}
            }
        },
        "reasoning": "I will deelegate this request to the specialized agent.",
        "context": {
            "from": {
                "agent": {
                    "name": "Content generator",
                    "url": "https://cooking-assistant.example.com/api/v1",
                    "instructions": "You are a helpful assistant that can answer questions and help with tasks.",
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
                            "protected": "eyJuYW1lIjoiQ29udGVudCBnZW5lcmF0b3IiLCJwcm92aWRlciI6eyJuYW1lIjoiT3BlbkFJIiwidXJsIjoiaHR0cHM6Ly9vcGVuYWkuY29tIn0sInVybCI6Imh0dHBzOi8vY29va2luZy1hc3Npc3RhbnQub3BlbmFpLmNvbS9hcGkvdjEiLCJ2ZXJzaW9uIjoiMS4wLjAifQ",
                            "signature": "eyJhbGciOiJFUzI1NiIsImtpZCI6InRlbXAtMzJjNGI5YWYtZjkzYS00YWYyLTkxYmMtMmNmNDQxNmI1NWFiIiwidHlwIjoiSldTIn0.eyJuYW1lIjoiQ29udGVudCBnZW5lcmF0b3IiLCJwcm92aWRlciI6eyJuYW1lIjoiT3BlbkFJIiwidXJsIjoiaHR0cHM6Ly9vcGVuYWkuY29tIn0sInVybCI6Imh0dHBzOi8vY29va2luZy1hc3Npc3RhbnQub3BlbmFpLmNvbS9hcGkvdjEiLCJ2ZXJzaW9uIjoiMS4wLjAifQ.fQ2XQ5PN8dDKoMoW8dllPTiNldrdzxH3G_GOaA4AxtHqqYPkWhHdNJH80BPt2j7VIUBcXl_btOHV0vZplO-0Ww"
                        }]
                    }
                },
                "role": "client"
            },
            "to": {
                "agent": {
                    "url": "https://story.example.org/v1",
                    "name": "Story teller",
                    "version": "1.0.0",
                    "identity": {
                        "signatures": [{
                            "header": {
                                "alg": "ES256",
                                "kid": "agent-key-789"
                            },
                            "protected": "eyJuYW1lIjoiU3RvcnkgdGVsbGVyIiwicHJvdmlkZXIiOnsibmFtZSI6IkF6dXJlQUlGb3VuZHJ5IiwidXJsIjoiaHR0cHM6Ly9haS5henVyZS5jb20ifSwidXJsIjoiaHR0cHM6Ly9hcGkuc3RvcnkuY29tL3YxIiwidmVyc2lvbiI6IjEuMC4wIn0",
                            "signature": "1sG5nRS8qcAGYtEPf9BM-mqNGDRY8X1W3eS2QinlC4MHKA0x6s5x1-OuEmkgOjFnO_mBuvp1xZze4PROlRu-bQ"
                        }]
                    }
                },
                "role": "server"
            }
        }
    }
}
   ```


### Stream Message Request (Server)
#### 1. Description
This hook is called when the observed server agent receves stream message request from a client agent.<br>
This hook **must** be used before the observed agent processes the A2A-compliant message.

#### 2. Method
`message/stream`


#### 3. Reponse
The response is an [response envelope](../../specification.md#6-disposition-vocabulary) object.

| Decision | Behavior |
| :--------- | :---------- |
| `allow` | The observed agent should process the A2A-compliant message. |
| `deny` | The A2A-compliant message should be ignored and not processed by the server agent. |
| `modify` | The observed agent should process the A2A message with the modified content found in `modifiedRequest` field. |

#### 4. A2A payload
   ```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "message/stream",
  "params": {
    "message": {
      "role": "user",
      "parts": [
        {
          "kind": "text",
          "text": "write a long paper describing the attached pictures"
        },
        {
          "kind": "file",
          "file": {
            "mimeType": "image/png",
            "data": "<base64-encoded-content>"
          }
        }
      ],
      "messageId": "bbb7dee1-cf5c-4683-8a6f-4114529da5eb"
    },
    "configuration": {
        "acceptedOutputModes": [],
        "pushNotificationConfig": {
            "url": "https://notifications.example.com/webhooks/1234567"
        }
    },
    "metadata": {}
  }
}
   ```
#### 5. ACS payload
   ```json
{
    "jsonrpc": "2.0",
    "id": "56e55ffd-fe11-4c64-b7c9-ddc936dbaed2",
    "method": "message/stream",
    "params": {
        "payload":{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [
                        {
                        "kind": "text",
                        "text": "write a long paper describing the attached pictures"
                        },
                        {
                        "kind": "file",
                        "file": {
                            "mimeType": "image/png",
                            "data": "<base64-encoded-content>"
                        }
                        }
                    ],
                    "messageId": "bbb7dee1-cf5c-4683-8a6f-4114529da5eb"
                },
                "configuration": {
                    "acceptedOutputModes": [],
                    "pushNotificationConfig": {
                        "url": "https://notifications.example.com/webhooks/1234567"
                    }
                },
                "metadata": {}
            }
        },
        "context": {
            "from": {
                "agent": {
                    "name": "Content generator",
                    "url": "https://cooking-assistant.example.com/api/v1",
                    "version": "1.0.0",
                    "identity": {
                        "signatures": [{
                            "header": {
                                "kid": "agent-key-12345",
                                "alg": "RS256"
                            },
                            "protected": "eyJuYW1lIjoiQ29udGVudCBnZW5lcmF0b3IiLCJwcm92aWRlciI6eyJuYW1lIjoiT3BlbkFJIiwidXJsIjoiaHR0cHM6Ly9vcGVuYWkuY29tIn0sInVybCI6Imh0dHBzOi8vY29va2luZy1hc3Npc3RhbnQub3BlbmFpLmNvbS9hcGkvdjEiLCJ2ZXJzaW9uIjoiMS4wLjAifQ",
                            "signature": "eyJhbGciOiJFUzI1NiIsImtpZCI6InRlbXAtMzJjNGI5YWYtZjkzYS00YWYyLTkxYmMtMmNmNDQxNmI1NWFiIiwidHlwIjoiSldTIn0.eyJuYW1lIjoiQ29udGVudCBnZW5lcmF0b3IiLCJwcm92aWRlciI6eyJuYW1lIjoiT3BlbkFJIiwidXJsIjoiaHR0cHM6Ly9vcGVuYWkuY29tIn0sInVybCI6Imh0dHBzOi8vY29va2luZy1hc3Npc3RhbnQub3BlbmFpLmNvbS9hcGkvdjEiLCJ2ZXJzaW9uIjoiMS4wLjAifQ.fQ2XQ5PN8dDKoMoW8dllPTiNldrdzxH3G_GOaA4AxtHqqYPkWhHdNJH80BPt2j7VIUBcXl_btOHV0vZplO-0Ww"
                        }]
                    }
                },
                "role": "client"
            },
            "to": {
                "agent": {
                    "url": "https://story.example.org/v1",
                    "name": "Story teller",
                    "instruction": "You are a very creative story teller.",
                    "provider": {
                        "name": "Example Agent Platform",
                        "url": "https://platform.example.net"
                    },
                    "version": "1.0.0",
                    "identity": {
                        "signatures": [{
                            "header": {
                                "alg": "ES256",
                                "kid": "agent-key-789"
                            },
                            "protected": "eyJuYW1lIjoiU3RvcnkgdGVsbGVyIiwicHJvdmlkZXIiOnsibmFtZSI6IkF6dXJlQUlGb3VuZHJ5IiwidXJsIjoiaHR0cHM6Ly9haS5henVyZS5jb20ifSwidXJsIjoiaHR0cHM6Ly9hcGkuc3RvcnkuY29tL3YxIiwidmVyc2lvbiI6IjEuMC4wIn0",
                            "signature": "1sG5nRS8qcAGYtEPf9BM-mqNGDRY8X1W3eS2QinlC4MHKA0x6s5x1-OuEmkgOjFnO_mBuvp1xZze4PROlRu-bQ"
                        }]
                    }
                },
                "role": "server"
            }
        }
    }
}
   ```