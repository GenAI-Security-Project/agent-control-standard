# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.0. Pre-1.0 releases MAY change the ACS-Core baseline in patch versions; the wire format version (`acs_version` in the handshake) evolves separately in the `specification/` directory.

## [0.1.3] — 2026-09-09

### Changed — ACS-Core baseline (relaxations)

- `MODIFY` is now SHOULD-support rather than MUST-support. Deployments whose framework cannot mutate a request (shell-hook integrations, IDE plugins without an argument-mutation surface) or that disable `MODIFY` for auditability reasons are conformant without it. See new [§6.5 MODIFY-incapable clients](docs/spec/instrument/specification.md#65-modify-incapable-clients-normative).
- `subagentStart` is promoted from SHOULD-emit to MUST-emit for subagent-capable frameworks; `subagentStop` remains SHOULD-emit, unchanged since 0.1.0. A client whose framework has no sub-agent abstraction has nothing to emit; the Guardian determines client subagent-emission capability by deployment-defined means (mirroring the [§9.2 ASK precedent](docs/spec/instrument/specification.md#92-approver-incapable-clients-normative)).
- `system/ping` is now SHOULD-implement rather than MUST-implement, provided the deployment declares an alternative liveness mechanism (transport-level keepalive on HTTP; process supervision or heartbeat on stdio; continuous observed hook traffic). Omitting `system/ping` without a declared alternative is non-conformant.
- Wrapped MCP (`protocols/MCP/*`) MUST be implemented by deployments whose sessions involve MCP at any point, and MAY be omitted by deployments whose sessions never involve MCP. MCP `tools/call` MAY flow through the generic tool hooks when tool-level policy suffices; the requirement exists for the surfaces the generic hooks cannot see (`initialize`, `prompts/get`, `resources/read`, `notifications/*`). Mid-session MCP addition under a no-MCP handshake is a documented v0.1 limitation (no renegotiation; wrapped coverage begins at the next session), not a prohibition — see [Conformance › ACS-Core](docs/spec/conformance.md#acs-core-mandatory-baseline).

### Added

- **§6.5 MODIFY-incapable clients (normative)** in `docs/spec/instrument/specification.md`. Defines Guardian-side substitution (`DENY` with `reason_codes: ["modify_unsupported"]` + audit event) and client-side fallback (a client receiving an unapplicable `MODIFY` MUST treat it as `DENY` + audit event), with an explicit exemption for `postCompact`, where `DENY` is not a legal disposition (the Guardian returns `ALLOW` + audit event there).
- Audit-event mandate in **§9.2** (approver-incapable clients): the Guardian MUST record the ASK-substitution as an audit event, so the substitution rate is machine-detectable rather than only reachable by grepping log prose.
- Guardian handling of an omitted `subagentStop.final_chain_hash` specified in **§8.6**: omission means "chain not maintained by this framework," never an integrity failure.

### Changed — normative force harmonization

- **§6.3** (malformed MODIFY): `SHOULD record an audit event` → `MUST record an audit event`. All fallback / substitution rules now use consistent MUST-audit language across §6.3, §6.4, §6.5, and §9.2.
- **§6.4** now names the §6.5 substitution as the one conformant deviation from verdict application, instead of contradicting it.
- **§13** opens with the SHOULD it links from, instead of calling a liveness method required.

### Changed — schema

- `specification/v0.1.0/hooks/subagent-stop.json`: `final_chain_hash` moved from `required` to optional. Frameworks that maintain no session-chain (shell-hook integrations without an internal audit chain) MAY omit the field rather than fabricate a value; fabrication would corrupt the exact artifact the field exists to produce. Guardian handling of the omission lives in §8.6.

### Related issues

- Guardian-side hook-coverage unfalsifiability tracked at [#31](https://github.com/GenAI-Security-Project/agent-control-standard/issues/31); out of scope for this release, needed for the enforcement side of `subagentStart`'s security rationale to be checkable.

## [0.1.2] — 2026-09-09

- The landing page, MkDocs documentation, and all 44 schema URIs are published from this repository via GitHub Pages on every merge to `main`; the deploy fails on any unresolved `$id` or `$ref`, and a monitor rechecks every published URI every six hours.
- The schema namespace moved onto a project-controlled base URI, and every schema is required to live at the path its `$id` declares.
- The response envelope can carry a ServerHello ([#59](https://github.com/GenAI-Security-Project/agent-control-standard/pull/59)).
- The skill lifecycle hooks (`skillRegister`, `skillLoad`, `skillUnload`) joined the Specification §5 taxonomy table, with a guard test that reads the schema titles so the views cannot drift again ([#56](https://github.com/GenAI-Security-Project/agent-control-standard/pull/56)).
- The Identity for Agents workstream overview and standards survey landed, with identity woven into the core concepts.
- A third-party content guard protects the published site, with its residual gaps recorded.
- Governance reconciliation: `GOVERNANCE.md` as the authoritative roster, OWASP Nest project metadata, the single-contact policy, and the human-authorship rule for commits ([#61](https://github.com/GenAI-Security-Project/agent-control-standard/pull/61)).

## [0.1.1] — 2026-08-11

- Relicensed: Apache 2.0 for code and schemas, CC BY-SA 4.0 for prose documentation. Everything through v0.1.0 remains MIT.
- Repository and documentation URLs moved to `GenAI-Security-Project/agent-control-standard` and the current domain.
- Repository security posture and CI supply chain hardened.
- Python floor raised to unblock Dependabot security updates.
- Release version decoupled from the specification version: `version.txt` and `pyproject.toml` carry the release, while schema `$id` URIs keep the spec version (`v0.1.0`).

## [0.1.0] — 2026-06-05

- Initial canonical v0.1.0 spec integrated (see [#2](https://github.com/GenAI-Security-Project/agent-control-standard/pull/2)).
