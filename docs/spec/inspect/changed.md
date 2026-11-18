# agbom/changed

`agbom/changed` is an Inspect method that reports a component added, removed, or version-changed during a session.
ACS-Inspect-Dynamic deployments send either a full inventory or a diff with `added`, `removed`, and `changed` entries.
The base ACS-Inspect profile does not require this method.

The method uses the shared ACS envelope and records the mutation in the session chain.
The Guardian can return DENY to block a hot-swap. Restrict access to these inventory updates as you would a full snapshot.

- [Payload schema](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/hooks/agbom-changed.json)
- [Shared method contract](../instrument/hooks.md#agbomchanged)
- [AgBOM graph and conformance](./README.md)
- [Full inventory snapshots](./snapshot.md)
