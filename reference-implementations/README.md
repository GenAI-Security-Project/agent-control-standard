# ACS reference implementations

This directory holds the reference Guardians of the OWASP GenAI Security Project Agent Control Standard. A reference implementation is working code that shows the ACS wire contract in use. Release 0.1.5 ships three Guardians, two here and one in [`adapters/`](../adapters/README.md):

| Guardian | Where | Policy | Signs and verifies | Hosts it serves | Start with |
|---|---|---|---|---|---|
| TypeScript Guardian | [`agt/`](agt/) | AGT policy through AGT's runtime | No, the wire is unauthenticated | Claude Code and OpenCode, through its own shims | [`agt/README.md`](agt/README.md) |
| Go Guardian | [`agt-go/`](agt-go/) | AGT policy through AGT's runtime, the same checked-in policies | Yes, HMAC-SHA256, with replay protection | Codex and OpenCode examples, and Claude Code, Cursor and NAT through the reference adapters | [`agt-go/README.md`](agt-go/README.md) |
| Python example Guardian | [`adapters/src/acs/guardian/`](../adapters/src/acs/guardian/) | A small built-in rule set, or OPA as an opt-in lab convention | Yes, HMAC-SHA256, and opt-in ML-DSA-65 decision signing | Claude Code, Cursor and NAT through the reference adapters, and the gateway | [`adapters/docs/guardian/README.md`](../adapters/docs/guardian/README.md) |

The Python example Guardian is a teaching artifact and a test substrate, not a production Guardian, and it doesn't evaluate AGT policy. The expectations below apply to the two AGT Guardians in this directory.

## Expectations for Guardian reference implementations

This section is a working tool for reviewing pull requests that add or change Guardian reference implementations, so that every implementation is reviewed against the same expectations.

"Is expected to" marks a check that blocks a merge. "Should" marks a check a reviewer raises but that does not block one.

An expectation an implementation does not meet yet is marked **Not met yet**, with the issue that tracks it. The gap is then public and tracked, so it is handled as an issue rather than as a security report ([SECURITY.md](../SECURITY.md)). A gap without an issue is not a documented gap.

### Project-level requirements

#### Maintained implementations

The project maintains two Guardian reference implementations here: the TypeScript Guardian under [`agt/`](agt/) and the Go Guardian under [`agt-go/`](agt-go/). Each keeps its own record of which ACS-Core requirements it meets: the TypeScript Guardian's [status table](agt/README.md#what-this-project-is-and-is-not), and the Go Guardian's [conformance table](agt-go/docs/conformance.md), with its deliberate differences from the TypeScript Guardian in [differences.md](agt-go/docs/differences.md). The project has not yet decided who keeps an implementation working once it has merged.

#### Shared host integrations

Host adapters are meant to live apart from Guardian implementations and talk to them only through the ACS wire contract, so a new Guardian language needs no host integration of its own. Today the TypeScript shims sit inside the TypeScript workspace, in [`agt/hosts/`](agt/hosts/) and [`agt/packages/host-adapter/`](agt/packages/host-adapter/), and the Go Guardian carries its own Codex and OpenCode hooks. The Python adapters in [`adapters/`](../adapters/README.md) already talk to a Guardian only through the wire contract, and the Go Guardian serves them, as [its adapter guide](agt-go/docs/adapters.md) shows. Where shared host adapters will live is not decided yet.

#### Shared contract tests

A language-independent contract test suite that exercises Guardians through their HTTP API is planned. It does not exist yet. It would check ACS protocol behavior and guarantees a host can observe, and it would not require an implementation to port the TypeScript conformance toolkit.

### Requirements for each maintained implementation

#### ACS API

The implementation is expected to follow the ACS wire contract, including every ACS-Core requirement in [conformance.md](../docs/spec/conformance.md#acs-core-mandatory-baseline). It is expected to declare its capabilities accurately in the handshake, and to list any ACS-Core requirement it does not meet in its README.

**Not met yet** by the TypeScript Guardian: its ServerHello is constants, and it does not read the ClientHello.

The Go Guardian negotiates the handshake from the ClientHello and records each ACS-Core requirement it meets, and the tests behind it, in [conformance.md](agt-go/docs/conformance.md).

#### Policy evaluation with the AGT runtime

Policy evaluation is expected to use AGT's policy runtime built from the AGT commit `agt_ref` in [`agt/agt.lock`](agt/agt.lock). It is published as `agent-control-specification` on npm, and other languages reach the same runtime through their own package or a native binding to its Rust core. Each implementation records the package and version it uses in its own lock file, and its CI is expected to fail when that commit differs from `agt_ref`.

Both AGT Guardians evaluate with AGT's runtime. The Go Guardian builds the runtime library from the commit pinned in [`agt-go/agt-native.lock`](agt-go/agt-native.lock), and a test requires that commit to match `agt_ref` in `agt/agt.lock`.

Reimplementing the runtime's behavior, or evaluating its policy bundle directly, is not an acceptable substitute. AGT's Go module, `agent-governance-golang`, is a different policy engine and does not qualify.

AGT's runtime is the only evaluator a maintained implementation ships, so every port runs the same policy engine and is reviewed against one rule. A test may compare AGT's decisions with another evaluator's, for example to catch drift, as long as that evaluator never answers a request.

#### Architectural boundaries

Transport handling, ACS processing, AGT integration, message signing, state storage, and logging should each have a clearly defined responsibility. The Guardian should expose a processing entry point that does not depend on the transport. APIs, packages, classes, and file layouts follow the language's conventions.

**Not met yet** by the TypeScript Guardian: processing sits inside its HTTP handler.

The Go Guardian runs as a standalone command or as a Go library, with interfaces for its policy engine, store, signer and audit log ([extending.md](agt-go/docs/extending.md)).

#### Signing and verification

Implementations are expected to sign and verify ACS messages as [§10 of the specification](../docs/spec/instrument/specification.md#10-cryptographic-signatures) defines, in particular its "HMAC key derivation" and "`key_id` for HMAC" paragraphs. A reviewer checks these points.

- `key_id` comes from configuration, has no built-in default, and is neither the `session_id` nor derived from the secret.
- A verifier rejects an unknown `key_id` with `SIGNATURE_INVALID` and never falls back to another secret.
- A signed response uses the `key_id` of the request it answers.
- The secret meets §10's length and randomness rule.
- Configuration maps each `key_id` to one secret and accepts at least two at once, so a secret is replaced without an outage. The documentation describes how.

These repository conventions sit on top of §10.

- The secret is stored as standard base64 (RFC 4648 §4), with padding, and with surrounding whitespace ignored. The decoded bytes, not the base64 text, are the secret §10 names and the HKDF input.
- It is read from a file, an environment variable, or a secret store, and is never hard-coded.
- Neither the secret nor any key derived from it appears in ACS messages, error data, logs, or trace exports.

**Not met yet** by the TypeScript Guardian: it does not sign or verify messages.

The Go Guardian signs and verifies HMAC-SHA256 under a configured `key_id`, reads its secret as base64, and accepts previous keys during a rotation ([configuration.md](agt-go/docs/configuration.md)).

#### Configurable storage

Session and security state should be reached through a storage-provider interface that configuration selects. Storage formats are the implementation's choice, and moving a session between implementations is not required. Each storage provider's durability and multi-instance guarantees are expected to be documented.

**Not met yet** by the TypeScript Guardian: it has one in-memory store, and only code can swap it.

The Go Guardian's `storage.provider` setting selects the store, and `memory` is the one provider its command ships. A host that embeds the Go library passes its own `SessionContextStore` for durability or replicas ([configuration.md](agt-go/docs/configuration.md)).

#### Concurrency and session consistency

The Guardian is expected to handle concurrent requests safely, whatever threading model its transport uses. Concurrent requests in one session are expected to keep §10.3's replay protection, the audit chain, and policy state consistent. No request is evaluated twice, and no state update is lost.

**Not met yet** by the TypeScript Guardian: it rejects no replay. Two concurrent steps in one session can overwrite each other's information-flow labels.

The Go Guardian rejects replay and reserves each request and its chain entry atomically, as the replay protection and SessionContext rows of [conformance.md](agt-go/docs/conformance.md) record.

#### Bounded processing

Reading a request and evaluating policy are expected to be bounded by configurable limits on time, body size, and concurrent requests, with documented defaults. The default time limit is below the `timeout_config` the Guardian declares. A request that exceeds a limit gets an honoured `deny` with a reason code, not an error, so it never falls into the host's fail-open posture (§6.4).

**Not met yet** by the TypeScript Guardian.

The Go Guardian bounds request reads, body size, sessions and concurrent policy evaluations with `server.*` and `limits.*` settings, each documented with its default in [configuration.md](agt-go/docs/configuration.md).

#### Bounded logging

Every log, the audit log included, is expected to have a configurable size cap with a finite documented default, and reaching the cap never blocks a decision. A full log rotates, and the rotated file can move to an archive such as object storage or a telemetry backend. A diagnostic log may drop its oldest entries. The audit events §6.4, §6.5 and §9.2 require, and the §8 session chain, are never dropped: if the Guardian cannot rotate or archive them, it answers `deny` rather than lose an audit record.

**Not met yet** by the TypeScript Guardian.

The Go Guardian rotates both audit logs at configured sizes and answers DENY `audit_unavailable` for a step whose required record it can't write ([configuration.md](agt-go/docs/configuration.md)).

#### Verification

Once the planned shared contract test suite exists, an implementation is expected to pass the tests that apply to it. The capabilities it declares in its ServerHello decide which tests apply, and the suite checks that each declared capability behaves as declared. Until then, a port is verified the way the [root README](../README.md#port-it-to-another-language) describes: `bun run conformance` from `agt/` against the running port. The Go Guardian's `make conformance` runs that shared harness against it, and `make check` runs it with the Go tests ([README](agt-go/README.md#verification)).
