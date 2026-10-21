# ACS reference implementations

This directory holds the reference implementations of the Agent Control Standard. A reference implementation is working code that shows the ACS wire contract in use.

## Expectations for Guardian reference implementations

This section is a working tool for reviewing pull requests that add or change Guardian reference implementations, so that every implementation is reviewed against the same expectations.

"Is expected to" marks a check that blocks a merge. "Should" marks a check a reviewer raises but that does not block one.

An expectation an implementation does not meet yet is marked **Not met yet**, with the issue that tracks it. The gap is then public and tracked, so it is handled as an issue rather than as a security report ([SECURITY.md](../SECURITY.md)). A gap without an issue is not a documented gap.

### Project-level requirements

#### Maintained implementations

The project maintains one Guardian reference implementation, in TypeScript, under [`agt/`](agt/). Its own [status table](agt/README.md#what-this-project-is-and-is-not) is the current record of which ACS-Core requirements it meets. Implementations in other languages join when they merge. Who keeps one working after that is decided in issue #318.

#### Shared host integrations

Host adapters are meant to live apart from Guardian implementations and talk to them only through the ACS wire contract, so a new Guardian language needs no host integration of its own. Today the TypeScript shims sit inside the TypeScript workspace, in [`agt/hosts/`](agt/hosts/) and [`agt/packages/host-adapter/`](agt/packages/host-adapter/), and some ports carry their own. Where shared host adapters live is decided in issue #313.

#### Shared contract tests

The project will maintain a language-independent contract test suite that exercises Guardians through their HTTP API, tracked in issue #311. It checks ACS protocol behavior and guarantees a host can observe. It does not require an implementation to port the TypeScript conformance toolkit.

### Requirements for each maintained implementation

#### ACS API

The implementation is expected to follow the ACS wire contract, including every ACS-Core requirement in [conformance.md](../docs/spec/conformance.md#acs-core-mandatory-baseline). It is expected to declare its capabilities accurately in the handshake, and to list any ACS-Core requirement it does not meet in its README.

**Not met yet** by the TypeScript Guardian: its ServerHello is constants, and it does not read the ClientHello (issue #165, issue #312).

#### Policy evaluation with the AGT runtime

Policy evaluation is expected to use AGT's policy runtime built from the AGT commit `agt_ref` in [`agt/agt.lock`](agt/agt.lock). It is published as `agent-control-specification` on npm, and other languages reach the same runtime through their own package or a native binding to its Rust core. Each implementation records the package and version it uses in its own lock file, and its CI is expected to fail when that commit differs from `agt_ref` (issue #314).

Reimplementing the runtime's behavior, or evaluating its policy bundle directly, is not an acceptable substitute. AGT's Go module, `agent-governance-golang`, is a different policy engine and does not qualify.

An implementation may also ship another evaluator, under three conditions. AGT is the default, and the implementation's tests and any conformance claim run against AGT. The other evaluator is never used as an automatic fallback when AGT fails to load. Every decision it makes names it in `metadata.evaluator`, so a trace shows which evaluator decided.

#### Architectural boundaries

Transport handling, ACS processing, AGT integration, message signing, state storage, and logging should each have a clearly defined responsibility. The Guardian should expose a processing entry point that does not depend on the transport. APIs, packages, classes, and file layouts follow the language's conventions.

**Not met yet** by the TypeScript Guardian: processing sits inside its HTTP handler (issue #312).

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

**Not met yet** by the TypeScript Guardian: it does not sign or verify messages. PR #229 adds signing (issue #184, issue #312).

#### Configurable storage

Session and security state should be reached through a storage-provider interface that configuration selects. Storage formats are the implementation's choice, and moving a session between implementations is not required. Each storage provider's durability and multi-instance guarantees are expected to be documented.

**Not met yet** by the TypeScript Guardian: it has one in-memory store, and only code can swap it (issue #312).

#### Concurrency and session consistency

The Guardian is expected to handle concurrent requests safely, whatever threading model its transport uses. Concurrent requests in one session are expected to keep §10.3's replay protection, the audit chain, and policy state consistent. No request is evaluated twice, and no state update is lost.

**Not met yet** by the TypeScript Guardian: it rejects no replay (issue #184, PR #229). Two concurrent steps in one session can overwrite each other's information-flow labels (issue #310).

#### Bounded processing

Reading a request and evaluating policy are expected to be bounded by configurable limits on time, body size, and concurrent requests, with documented defaults. The default time limit is below the `timeout_config` the Guardian declares. A request that exceeds a limit gets an honoured `deny` with a reason code, not an error, so it never falls into the host's fail-open posture (§6.4).

**Not met yet** by the TypeScript Guardian (issue #312).

#### Bounded logging

Each retained diagnostic log is expected to have a configurable size cap with a finite documented default, and reaching it never blocks a decision. The cap does not apply to the audit events §6.4, §6.5 and §9.2 require, or to the §8 session chain. When audit storage is full, the Guardian answers `deny` rather than drop an audit record.

**Not met yet** by the TypeScript Guardian (issue #312).

#### Verification

Once the shared contract test suite exists (issue #311), an implementation is expected to pass the tests that apply to it. The capabilities it declares in its ServerHello decide which tests apply, and the suite checks that each declared capability behaves as declared. Until then, a port is verified the way the [root README](../README.md#port-it-python-go-rust-codex) describes: `bun run conformance` from `agt/` against the running port.
