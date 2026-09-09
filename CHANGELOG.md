# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.0. Pre-1.0 releases MAY change the ACS-Core baseline in patch versions; the wire format version (`acs_version` in the handshake) evolves separately in the `specification/` directory.

## [0.1.3] — 2026-09-09

### Changed — ACS-Core baseline (relaxations)

- `MODIFY` is now SHOULD-support rather than MUST-support. Deployments whose framework cannot mutate a request (shell-hook integrations, IDE plugins without an argument-mutation surface) or that disable `MODIFY` for auditability reasons are conformant without it. See new [§6.5 MODIFY-incapable clients](docs/spec/instrument/specification.md#65-modify-incapable-clients-normative).
- `subagentStop` is now SHOULD-emit rather than MUST-emit; `subagentStart` remains MUST-emit for subagent-capable frameworks.
- `system/ping` is now SHOULD-implement rather than MUST-implement, provided the deployment declares an alternative liveness mechanism (transport-level keepalive on HTTP; process supervision or heartbeat on stdio; continuous observed hook traffic). Omitting `system/ping` without a declared alternative is non-conformant.
- Wrapped MCP (`protocols/MCP/*`) MUST be implemented by deployments whose sessions involve MCP at any point (tools, resources, prompts, notifications), and MAY be omitted by deployments whose sessions never involve MCP. Deployments that declared no MCP at handshake MUST NOT spawn or register MCP servers mid-session; renegotiation is undefined in v0.1.

### Changed — ACS-Core baseline (additions)

- `subagentStart` is now part of the MUST-emit minimum hook set for subagent-capable frameworks. A client whose framework has no sub-agent abstraction has nothing to emit; the Guardian determines client subagent-emission capability by deployment-defined means (mirroring the [§9.2 ASK precedent](docs/spec/instrument/specification.md#92-approver-incapable-clients-normative)).

### Added

- **§6.5 MODIFY-incapable clients (normative)** in `docs/spec/instrument/specification.md`. Defines Guardian-side substitution (`DENY` with `reason_codes: ["modify_unsupported"]` + audit event) and client-side fallback (a client receiving an unapplicable `MODIFY` MUST treat it as `DENY` + audit event).
- Audit-event mandate in **§9.2** (approver-incapable clients): the Guardian MUST record the ASK-substitution as an audit event, so the substitution rate is machine-detectable rather than only reachable by grepping log prose.

### Changed — normative force harmonization

- **§6.3** (malformed MODIFY): `SHOULD record an audit event` → `MUST record an audit event`. All fallback / substitution rules now use consistent MUST-audit language across §6.3, §6.4, §6.5, and §9.2.

### Changed — schema

- `specification/v0.1.0/hooks/subagent-stop.json`: `final_chain_hash` moved from `required` to optional. Frameworks that maintain no session-chain (shell-hook integrations without an internal audit chain) MAY omit the field rather than fabricate a value; fabrication would corrupt the exact artifact the field exists to produce. A conformant Guardian MUST treat omission as "chain not maintained by this framework" rather than as an integrity failure.

### Related issues

- Guardian-side hook-coverage unfalsifiability tracked at [#31](https://github.com/GenAI-Security-Project/agent-control-standard/issues/31); out of scope for this release, needed for the enforcement side of `subagentStart`'s security rationale to be checkable.

## [0.1.2] — 2026-09-09

### Fixed

- `specification/v0.1.0/response-envelope.json`: `result` is now a `oneOf` over `AcsResult` and `handshake.json#/$defs/ServerHello`. It referenced `AcsResult` unconditionally, which requires `decision`, so a conformant `handshake/hello` response could not satisfy the envelope that carries it. Implementers who skipped response validation for that one method can stop. The change only widens what validates, so every response that validated before still does (see [#59](https://github.com/GenAI-Security-Project/agent-control-standard/pull/59)).

## [0.1.1] — 2026-08-11

### Changed

- Relicensed to [Apache License 2.0](LICENSE) for code and schemas and [CC BY-SA 4.0](LICENSE-DOCS) for documentation. No specification content changed. The release marker exists so implementers can pin to the relicensed distribution.
- The release version and the specification version now move independently. `sync_version.py` owns the release version alone and no longer rewrites the `version` field in `acs_schema.json` or the Version line in `specification.md`, both of which had drifted out of agreement with the schema `$id` and every `$ref` around them (see [`1af1f92`](https://github.com/GenAI-Security-Project/agent-control-standard/commit/1af1f92)).

## [0.1.0] — 2026-06-05

- Initial canonical v0.1.0 spec integrated (see [#2](https://github.com/GenAI-Security-Project/agent-control-standard/pull/2)).
