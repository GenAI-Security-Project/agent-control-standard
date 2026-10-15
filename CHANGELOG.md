# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.0. Pre-1.0 releases MAY change the ACS-Core baseline and the Trace mappings in patch versions. The wire format version (`acs_version` in the handshake, and the `v0.1.0` in every schema `$id`) evolves separately in the `specification/` directory.

## [0.1.4] - 2026-10-16

This release changes ACS-Trace for producers and consumers. The specification version stays v0.1.0, so the files at the `/schema/v0.1.0/` URIs change in place, and the handshake cannot tell the old rules from the new. Name this release, or its commit, when you claim ACS-Trace conformance.

### Changed: Trace (breaking)

- Every step span now requires `acs.request_id` and `acs.session.id`. A reader joins the two parties' spans on that pair. An exporter that omits either no longer conforms ([PR #275](https://github.com/GenAI-Security-Project/agent-control-standard/pull/275), issue #228).
- The OCSF decision class now requires `finding_info`, `finding_info.title`, `action_id`, `action`, `disposition_id`, `disposition`, `evidences` and `metadata.correlation_uid`, and decision events list the `security_control` profile. `defer` maps to `disposition_id` 99. `is_alert` is true exactly when `severity_id` is 3 or higher, so deny, ask and defer alert, and allow and modify don't. A decision that arrives late is emitted and flagged in `finding_info.types`, where it used to be suppressed (PR #275).
- A decision event records the Guardian's verdict, not the enforced outcome. A matching `acs.decision.failure` in either party's stream means the decision MUST NOT be counted as enforced (PR #275).
- The four `policy_references` fields and the provenance `source_id` now require `minLength: 1` (PR #275, issue #263).
- The OCSF mapping is pinned to OCSF 1.9.0 and uses its class names. Three rows on class 5001 set `activity_id` 2, and `required_fields` includes `finding_info` ([PR #258](https://github.com/GenAI-Security-Project/agent-control-standard/pull/258)).

### Added

- The `acs.decision.failure` span event, and the extra `acs.decision` attributes a reader needs to replay a decision from the trace alone (PR #275).
- Per-hook `conditional_attributes` in `otel-mapping.json` ([PR #261](https://github.com/GenAI-Security-Project/agent-control-standard/pull/261)).
- Trace mappings for the skill lifecycle hooks, `steps/skillRegister`, `steps/skillLoad` and `steps/skillUnload`, in both OpenTelemetry and OCSF ([PR #63](https://github.com/GenAI-Security-Project/agent-control-standard/pull/63), issue #57, issue #58).
- The reference Guardian exports OTLP traces to a file and over HTTP, and a converter turns the host adapter's audit log into the same format. It covers the two hook methods the Guardian evaluates and is not an ACS-Trace conformance claim ([PR #244](https://github.com/GenAI-Security-Project/agent-control-standard/pull/244), issue #91).
- A committed sample trace, a test that holds the exporter to the mapping, and "Produce a trace", a walkthrough from a fresh clone to a trace file, tested natively and with Docker ([PR #277](https://github.com/GenAI-Security-Project/agent-control-standard/pull/277), issue #266).
- "How the reference Guardian produces a trace" on the Trace with OpenTelemetry page, with diagrams of both streams and of one tool call, and a Troubleshooting list in the Guardian README ([PR #280](https://github.com/GenAI-Security-Project/agent-control-standard/pull/280)).

### Changed: reference implementation

- The audit converter's spans carry `service.name` `acs-reference-audit-converter`, no longer the Guardian's `acs-reference-guardian`. A query that filtered on the old value for converter spans needs updating (PR #277, issue #274).
- The converter refuses to write to an output file that already exists and exits 1. It used to append, which could write OTLP lines into the audit log or double every span on a rerun (PR #277).
- `otel-collector.yaml` stays on loopback, keeps its file across restarts, writes owner-only, and pins its container image by digest (PR #277, issue #276).
- `OTEL_TRACES_*`, `OTEL_SPAN_*`, `OTEL_ATTRIBUTE_*`, `OTEL_BSP_*` and OTLP compression variables no longer change what the Guardian or the converter exports. `OTEL_EXPORTER_OTLP_*HEADERS` still apply (PR #277).
- A loopback trace endpoint is added to whichever of `NO_PROXY` and `no_proxy` is set, keeping the user's own entries, and the Guardian warns at startup when a proxy is set and loopback isn't exempt. The walkthrough says to stop the Guardian and the collector before deleting `.acs` ([PR #279](https://github.com/GenAI-Security-Project/agent-control-standard/pull/279), issue #274).

### Removed

- `acs.provenance.lineage_depth` and `acs.provenance.origins_compacted` from the OTel mapping (PR #261).

### Changed: dependencies

- urllib3 2.7.0 to 2.8.0 ([PR #202](https://github.com/GenAI-Security-Project/agent-control-standard/pull/202)).

## [0.1.3] — 2026-10-05

### Changed — ACS-Core baseline

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

### Repository

- Commits land under human authorship ([#61](https://github.com/GenAI-Security-Project/agent-control-standard/pull/61)).

### Related issues

- Guardian-side hook-coverage unfalsifiability tracked at [#31](https://github.com/GenAI-Security-Project/agent-control-standard/issues/31); out of scope for this release, needed for the enforcement side of `subagentStart`'s security rationale to be checkable.

## [0.1.2] — 2026-09-09

- The landing page, MkDocs documentation, and all 44 schema URIs are published from this repository via GitHub Pages on every merge to `main`; the deploy fails on any unresolved `$id` or `$ref`, and a monitor rechecks every published URI every six hours.
- The schema namespace moved onto a project-controlled base URI, and every schema is required to live at the path its `$id` declares.
- The response envelope can carry a ServerHello ([#59](https://github.com/GenAI-Security-Project/agent-control-standard/pull/59)).
- The skill lifecycle hooks (`skillRegister`, `skillLoad`, `skillUnload`) joined the Specification §5 taxonomy table, with a guard test that reads the schema titles so the views cannot drift again ([#56](https://github.com/GenAI-Security-Project/agent-control-standard/pull/56)).
- The Identity for Agents workstream overview and standards survey landed, with identity woven into the core concepts.
- A third-party content guard protects the published site, with its residual gaps recorded.
- Governance reconciliation: `GOVERNANCE.md` as the authoritative roster, OWASP Nest project metadata, and the single-contact policy.

## [0.1.1] — 2026-08-11

- Relicensed: Apache 2.0 for code and schemas, CC BY-SA 4.0 for prose documentation. Everything through v0.1.0 remains MIT.
- Repository and documentation URLs moved to `GenAI-Security-Project/agent-control-standard` and the current domain.
- Repository security posture and CI supply chain hardened.
- Python floor raised to unblock Dependabot security updates.
- Release version decoupled from the specification version: `version.txt` and `pyproject.toml` carry the release, while schema `$id` URIs keep the spec version (`v0.1.0`).

## [0.1.0] — 2026-06-05

- Initial canonical v0.1.0 spec integrated (see [#2](https://github.com/GenAI-Security-Project/agent-control-standard/pull/2)).
