# ACS reference implementations

This directory holds the reference implementations of the Agent Control Standard. A reference implementation is working code that shows the ACS wire contract in use.

## Expectations for Guardian reference implementations

This section is a working tool for reviewing pull requests that add or change Guardian reference implementations, so that every implementation is reviewed against the same expectations.

### Project-level requirements

#### Maintained implementations

The project maintains the following Guardian reference implementations: TypeScript, Python, Rust, and Go. Other languages may be supported through community implementations.

#### Shared host integrations

Host adapters are maintained separately from Guardian reference implementations and communicate with them through the ACS wire contract.

Existing shims and client code will be moved to the shared host-adapter area. A new Guardian language does not require a separate host integration.

#### Shared contract tests

The project maintains a language-independent contract test suite that exercises Guardians through their HTTP API.

The suite checks ACS protocol behavior and externally observable guarantees. It does not require each implementation to port the TypeScript conformance toolkit or establish certification beyond its tested scope.

### Requirements for each maintained implementation

#### ACS API

The implementation is expected to follow the ACS wire contract for its supported capabilities and to accurately declare those capabilities through the handshake.

#### Actual AGT runtime

Policy evaluation is expected to use the upstream AGT runtime through an official SDK, native binding, or integration with a process or service running AGT. Reimplementing AGT runtime behavior or directly evaluating its policy bundle is not an acceptable substitute.

#### Architectural boundaries

Transport handling, ACS processing, AGT integration, state storage, and logging should have clearly defined responsibilities. The Guardian is expected to expose a transport-independent processing entry point.

Concrete APIs, packages, classes, and file layouts can follow language conventions. Host integrations are outside the Guardian's scope.

#### Signing keys and secrets

Implementations are expected to sign and verify ACS messages according to the specification.

For the HMAC-SHA256 baseline, per-session keys are expected to be derived with HKDF using SHA-256, an empty salt, the `session_id` as info, and a 32-byte output.

Each configured key has an identifier. The default identifier is `default`. A sender should set `key_id` to the identifier of the key it signed with. A verifier should select the key by `key_id` and treat an unknown `key_id` as an invalid signature. A signed response should carry the same `key_id` as the request it answers.

Key material is expected to be a string of at least 32 bytes, read from a file or an environment variable. Leading and trailing whitespace should be removed. The remaining bytes are the HKDF input keying material. No decoding is applied.

Key material should be supplied through deployment configuration. It should not be hard-coded and should not appear in ACS messages or logs.

Documentation is expected to describe how key material is configured and replaced.

#### Configurable storage

Session and security state should be accessed through a storage-provider interface selected through configuration. Internal storage schemas and formats are implementation-defined. Cross-implementation storage compatibility and session migration are not required. Supported storage providers and their durability and multi-instance guarantees are expected to be documented.

#### Concurrency and session consistency

The Guardian is expected to safely handle concurrent invocations independently of the transport's threading or execution model.

Concurrent requests within a session should preserve replay protection, audit-chain consistency, and policy state. They should not cause duplicate evaluation of the same request or lost state updates.

Synchronization mechanisms and internal processing algorithms are implementation-defined.

#### Bounded processing

Request waiting and policy evaluation should be bounded by configurable time and resource limits.

#### Bounded logging

Retained logs should be subject to a configurable total size limit, enforced by the implementation or its logging infrastructure. Defaults should bound retained log volume. Log formats and rotation mechanisms are implementation-defined.

#### Verification

The implementation is expected to pass the applicable shared ACS contract tests.
