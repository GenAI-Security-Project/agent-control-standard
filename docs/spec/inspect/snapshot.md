# agbom/snapshot

`agbom/snapshot` is an Inspect method that sends the Observed Agent's full component inventory to the Guardian.
ACS-Inspect deployments send it after `sessionStart`, before content-bearing hooks, and after handshake renegotiation.
It uses the shared ACS envelope and joins the session's existing chain.

The Guardian normally returns ALLOW. It can return DENY when policy refuses a component in the inventory.
Restrict access to this inventory: its services and data-access map can aid reconnaissance.

- [Payload schema](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/hooks/agbom-snapshot.json)
- [Shared method contract](../instrument/hooks.md#agbomsnapshot)
- [AgBOM graph and conformance](./README.md)
- [Runtime inventory changes](./changed.md)
