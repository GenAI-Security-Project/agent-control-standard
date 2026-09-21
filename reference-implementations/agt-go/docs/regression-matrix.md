# Regression matrix

This matrix records the external ACS findings checked against the Go Guardian.
It links each independently described failure to the test that exercises the
same observable contract here. The external data is not copied into this tree.

## Open reference-implementation findings

Checked against the open issues on 2026-09-21. All six remain open and have no linked implementation.

| Finding | Required behavior | Go tests |
| --- | --- | --- |
| [#160](https://github.com/GenAI-Security-Project/agent-control-standard/issues/160) | Reject a method the session did not negotiate. | `guardian.TestMethodRouting` |
| [#163](https://github.com/GenAI-Security-Project/agent-control-standard/issues/163) | Classify malformed JSON as `PARSE_ERROR` and a non-JSON-RPC request as `INVALID_REQUEST`. | `guardian.TestTransportErrors`, `guardian.TestInvalidJSONRPCPrecedesSignatureVerification` |
| [#164](https://github.com/GenAI-Security-Project/agent-control-standard/issues/164) | Reject hook traffic before a successful handshake. | `guardian.TestMethodRouting` |
| [#165](https://github.com/GenAI-Security-Project/agent-control-standard/issues/165) | Select a transport offered by both peers, or refuse the session. | `guardian.TestHandshakeRefusals`, `internal/handshake.TestEvaluatedMethods` |
| [#166](https://github.com/GenAI-Security-Project/agent-control-standard/issues/166) | Bind a negotiated session to its signing key and `agent_id`. The standard leaves the meaning of `user_context` to deployment policy, so the Guardian passes it to the policy engine instead of treating it as an immutable identity. | `guardian.TestKeyBoundToSession`, `guardian.TestAgentIDBoundToSession` |
| [#167](https://github.com/GenAI-Security-Project/agent-control-standard/issues/167) | Dispatch `steps/sessionStart` through the policy engine. | `guardian.TestCoreFloor` |

## ACS-Core vectors

The [ACS-Core negative conformance suite](https://github.com/probityai/agent-evidence-vectors/tree/main/vectors-acs-core)
contains 32 declarations. Nineteen cite a requirement assigned to the Guardian.
Twelve of those exercise behavior implemented by the Guardian itself.

| External vector | Contract | Go tests |
| --- | --- | --- |
| `v412653087b92cb07`, `v78927805373a6c06`, `vae2037ee96435463` | Negotiate a compatible `0.1.x` version and reject another major version. | `guardian.TestHandshakeRefusals`, `internal/handshake.TestSelectVersion` |
| `vb87b86b4930665ca`, `vd67cd207a4eb6798` | Reject an invalid signature over the complete canonical request. | `guardian.TestSignatureRequired`, `internal/envelope.TestSigningInputCoversEverythingButTheSignature` |
| `v3e946bcfde26bbe2`, `vef655ce2a45f618b` | Accept a fresh request and reject a repeated `request_id`. | `guardian.TestReplayAndSkew` |
| `va6d6e952d417c5a1`, `vb10df32610db1173` | Accept a timestamp inside the negotiated window and reject one outside it. | `guardian.TestReplayAndSkew`, `guardian.TestWithinSkew` |
| `v25f01d8fe1e91bf5`, `v7b0b32fb369136c1` | Publish the signed chain head and reject a stale Observed Agent head. | `guardian.TestChainPublication`, `guardian.TestChainMismatch` |
| `va200b64093301e14` | Do not return `ASK` when the Observed Agent cannot resolve it. | `guardian.TestConfiguredAskSubstitution`, `guardian.TestClientSubstitutions` |

`v82b6d110b4d68e7c` declares its timestamp-revocation case unmeasurable and
therefore creates no executable expectation.

The remaining six Guardian-labelled vectors concern approver authentication or
strict-scope policy. In this implementation those decisions belong to the
injected `guardian.PolicyEngine`; the Guardian validates the returned ACS shape
and maintains the session chain, but it must not invent deployment identity or
authorization policy. `guardian.TestIntentExtension` and
`guardian.TestEngineFailuresAreDenials` cover that interface boundary.
