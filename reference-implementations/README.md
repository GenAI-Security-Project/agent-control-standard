# ACS reference implementations

This directory holds the reference implementations of the Agent Control Standard. A reference implementation is working code that shows the ACS wire contract in use.

## Expectations for Guardian reference implementations

This section is a working tool for reviewing pull requests that add or change Guardian reference implementations, so that every implementation is reviewed against the same expectations.

### Project-level requirements

#### Maintained implementations

The project maintains one Guardian reference implementation, in TypeScript. Implementations in other languages are added as they merge.

#### Shared host integrations

Host adapters are maintained separately from Guardian reference implementations and communicate with them through the ACS wire contract.

Existing shims and client code will be moved to the shared host-adapter area. A new Guardian language does not require a separate host integration.

#### Shared contract tests

The project will maintain a language-independent contract test suite that exercises Guardians through their HTTP API.

The suite checks ACS protocol behavior and externally observable guarantees. It does not require each implementation to port the TypeScript conformance toolkit or establish certification beyond its tested scope.

### Requirements for each maintained implementation

#### ACS API

The implementation is expected to follow the ACS wire contract for its supported capabilities and to accurately declare those capabilities through the handshake.

#### Actual AGT runtime

Policy evaluation is expected to use AGT's policy runtime, `agent_control_specification`, at the commit and SDK version recorded in [`agt/agt.lock`](agt/agt.lock). It can be reached through an official SDK, a native binding to its Rust core, or a process or service that runs it. Reimplementing the runtime's behavior or directly evaluating its policy bundle is not an acceptable substitute.

AGT's Go module, `agent-governance-golang`, is a different policy engine and does not qualify.

#### Architectural boundaries

Transport handling, ACS processing, AGT integration, message signing, state storage, and logging should have clearly defined responsibilities. The Guardian is expected to expose a transport-independent processing entry point.

Concrete APIs, packages, classes, and file layouts can follow language conventions. Host integrations are outside the Guardian's scope.

#### Signing keys and secrets

Implementations are expected to sign and verify ACS messages as [§10 of the specification](../docs/spec/instrument/specification.md#10-cryptographic-signatures) defines, including the HMAC-SHA256 key derivation and the meaning of `key_id`.

In addition to the specification, implementations are expected to meet the following:

- key material is base64-encoded, decodes to at least 32 bytes, and is read from a file or an environment variable;
- key material is not hard-coded and does not appear in ACS messages or logs;
- the documentation says how key material is configured and replaced.

#### Configurable storage

Session and security state should be accessed through a storage-provider interface selected through configuration. Internal storage schemas and formats are implementation-defined. Cross-implementation storage compatibility and session migration are not required. Supported storage providers and their durability and multi-instance guarantees are expected to be documented.

#### Concurrency and session consistency

The Guardian is expected to safely handle concurrent invocations independently of the transport's threading or execution model.

Concurrent requests within a session should preserve replay protection, audit-chain consistency, and policy state. They should not cause duplicate evaluation of the same request or lost state updates.

Synchronization mechanisms and internal processing algorithms are implementation-defined.

#### Bounded processing

Request waiting and policy evaluation should be bounded by configurable time and resource limits. This is a target. The TypeScript Guardian does not meet it yet.

#### Bounded logging

Retained logs should be subject to a configurable total size limit, enforced by the implementation or its logging infrastructure. Defaults should bound retained log volume. Log formats and rotation mechanisms are implementation-defined. This is a target. The TypeScript Guardian does not meet it yet.

#### Verification

Once the shared contract test suite exists, the implementation is expected to pass the tests that apply to it.
