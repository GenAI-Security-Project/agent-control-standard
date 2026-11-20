# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.0. Pre-1.0 releases MAY change the ACS-Core baseline and the Trace mappings in patch versions. The wire format version (`acs_version` in the handshake, and the `v0.1.0` in every schema `$id`) evolves separately in the `specification/` directory.

## [0.1.5] - 2026-11-20

Release 0.1.5 ships the `integration` branch as decided in D-049. It adds the reference adapters, an OpenAI Responses API gateway, a Go Guardian, and experimental ML-DSA-65 decision signing. The specification version stays v0.1.0. The files at the `/schema/v0.1.0/` URIs change in place again, so name this release, or its commit, when you claim conformance.

ML-DSA-65 signing is experimental and off by default. It is a lab convention for the December 9, 2026 guided lab, and this release makes no ACS-Crypto or ACS-Core conformance claim for it. HMAC-SHA256 stays the default. The gateway is a reference implementation built for the same lab.

### Changed: act on these before you upgrade

- An HMAC secret file is now refused when its directory is world-writable and not sticky, when another user owns the file or its directory, when the file exceeds 64 KiB, or when it is a FIFO. A root-owned file is accepted. A group-writable directory passes, such as the 0775 that `mkdir` gives under umask 002. Move a refused secret into a directory you own, such as one made with `mkdir -p -m 700 ~/.acs`. `adapters/README.md` describes what changes for an existing setup ([PR #618](https://github.com/GenAI-Security-Project/agent-control-standard/pull/618)).
- On Windows, the example Guardian refuses its secret file by default, because Windows reports every ordinary file as `0o666`. Restrict the file with the `icacls` command the error names, then set `ACS_ALLOW_UNCHECKED_KEY_PERMS=1` ([PR #525](https://github.com/GenAI-Security-Project/agent-control-standard/pull/525)).
- The Claude Code `PreToolUse` hook in the AGT reference implementation now fails closed, and it needs Claude Code v2.1.295 or later ([PR #462](https://github.com/GenAI-Security-Project/agent-control-standard/pull/462), issue #376).
- The client and the example Guardian now accept only the canonical base64 spelling of an HMAC-SHA256 signature. A request the client can't bind is refused before any network call as `request_envelope_invalid`, which replaces `response_binding_mismatch` for that case. A non-2xx answer with a malformed body now reports the failure class `guardian_error` in telemetry. Update any alert or query that matched the old names ([PR #600](https://github.com/GenAI-Security-Project/agent-control-standard/pull/600)).
- An OCSF consumer now receives an allow decision as Application Lifecycle (`class_uid` 6002), not Application Activity ([PR #278](https://github.com/GenAI-Security-Project/agent-control-standard/pull/278), issue #198).

### Changed: specification

- §10 now fixes the HMAC key derivation: HKDF with SHA-256, no salt, `info` set to the exact `metadata.session_id` string, and a 32-byte output. Both parties MUST derive the key this way. `key_id` for HMAC is an opaque label the deployment chooses, and a verifier MUST reject an unknown `key_id` and MUST NOT fall back to another secret ([PR #272](https://github.com/GenAI-Security-Project/agent-control-standard/pull/272), issue #118).
- §8.6 and §10 now say that an HMAC signature attributes a message to neither party, because both hold the session key. Non-repudiation needs the asymmetric ACS-Crypto profile (PR #272).
- The `toolCallResult` payload carries `request_id_ref`, the `request_id` of the originating `toolCallRequest`. A Guardian MUST record the reference in its audit record when it can't resolve it (PR #272).
- §6.4 now requires an audit record for every decision failure under either posture, not only under `proceed`. `sessionEnd.summary` gains `decision_failures`, a count per failure class that the Observed Agent SHOULD report. A session that ends without it reads as unmeasurable ([PR #273](https://github.com/GenAI-Security-Project/agent-control-standard/pull/273), issue #37).
- §4.1 surfaces a session started unguarded as an `acs.decision.failure` event with class `handshake_failure`, and its posture comes from the startup posture (PR #273).
- A Guardian MUST NOT emit `acs.decision` or `acs.decision.failure` under the pair of a request it rejects before trusting it: an envelope that fails validation, `SIGNATURE_INVALID`, `REPLAY_DETECTED` or `TIMESTAMP_OUT_OF_WINDOW` (PR #273).
- `ocsf-mapping.json` gains `allow_class`, which sends an allow to Application Lifecycle (6002) with `severity_id` 1 unless the deployment records allows as Detection Findings (PR #278).
- The §3 envelope row now places `acs_version` in `params` and `result`, as the envelope schemas do ([PR #254](https://github.com/GenAI-Security-Project/agent-control-standard/pull/254), issue #194).
- The ACS-Trace quick reference says OTel or OCSF, as the profile does. Nothing normative changes ([PR #323](https://github.com/GenAI-Security-Project/agent-control-standard/pull/323)).
- The AgBOM update triggers now cover a skill registered, unloaded or changed, so every component type has a trigger ([PR #338](https://github.com/GenAI-Security-Project/agent-control-standard/pull/338), issue #120).

### Added

- `adapters/`, the `acs-adapters` package. It wires Claude Code, Cursor and NVIDIA NAT 1.7.0 to a Guardian through each host's own hook or middleware configuration, with no agent code changes. It ships `acs.core`, `acs.client`, a runnable example Guardian, and the conformance and emission suites. The default is fail closed ([PR #22](https://github.com/GenAI-Security-Project/agent-control-standard/pull/22), issue #134).
- A Go Guardian in `reference-implementations/agt-go/`. It runs the same AGT Rego policies through the AGT runtime and is also usable as a Go library. Its answers were compared with the TypeScript Guardian's on recorded sessions, and `docs/differences.md` lists every deliberate difference between the two Guardians and the reason for each ([PR #169](https://github.com/GenAI-Security-Project/agent-control-standard/pull/169), issue #87).
- An OpenAI Responses API gateway in `adapters/gateway/`, a reference implementation for the December 9 guided lab. A client sets `OPENAI_BASE_URL` to the gateway and becomes an ACS Observed Agent without other changes. Every `function_call` goes to the Guardian as `steps/toolCallRequest` before the client sees it, and every `function_call_output` goes as `steps/toolCallResult` before the model sees it. `ACS_LAB_MODE` is off by default, and shadow and enforce are opt-in. The gateway's own configuration sets its failure posture, and no ServerHello can loosen it ([PR #599](https://github.com/GenAI-Security-Project/agent-control-standard/pull/599), issue #577).
- Governed streaming in the gateway. Shadow and enforce now govern streamed requests, where they answered 501 before. Enforce holds each call until its decision and streams message text as it arrives ([PR #633](https://github.com/GenAI-Security-Project/agent-control-standard/pull/633)).
- Upstream modes in the gateway. `ACS_UPSTREAM` selects `live`, `capture` or `replay`, and unset means live. Capture records each exchange. Replay answers offline from the recordings with no network and no credentials, and a request with no recording gets a fixed `resp_replay_miss` answer and a `replay_miss` audit line (PR #633).
- Tool digest pinning in the gateway. In shadow and enforce, `tool.version` carries `sha256:` plus the SHA-256 of the RFC 8785 form of the tool's declaration, so a policy can pin a tool and catch a changed description. A `call_id` repeated under a changed digest is withheld. Using `tool.version` this way is a lab convention. The specification doesn't define a tool declaration's integrity binding yet (PR #633).
- ASK approval in the gateway. With `ACS_GATEWAY_APPROVER_PORT` and `ACS_GATEWAY_APPROVER_TOKEN_FILE` set, enforce holds a call that gets an ASK and lists it on an approver page that binds `127.0.0.1` by default. The Guardian's next decision, not the gateway, releases or blocks the call. Without the port, every ASK denies, as before. The field that carries the approver's answer is a lab convention. The specification doesn't define how an approver's answer reaches the Guardian yet (PR #633).
- OpenTelemetry tracing in the gateway. With `OTEL_EXPORTER_OTLP_ENDPOINT` set, the gateway spans each session, model call and Guardian step in one trace and exports over OTLP HTTP. Unset, tracing is off and no OpenTelemetry module loads. Spans go straight to Jaeger's OTLP port, with no collector between them (PR #633).
- Transcript signing in the gateway. The gateway writes every Guardian envelope through `acs.client`'s `on_wire` hook, so the transcript starts with the ClientHello and ServerHello and holds refusals and tampered answers verbatim. With `ACS_RESPONSE_ALGORITHMS=ML-DSA-65` and the gateway's `pqc` extra, it verifies every decision against the pinned key document. The gateway sends `steps/sessionEnd` whenever it drops a session (PR #633, part of issue #577).
- Experimental ML-DSA-65 (FIPS 204) signing and keyring verification in `acs.core` and `acs.client`, behind the `pqc` extra and off by default. The verifier takes the algorithm from the key, never the envelope, and `key_id` stays opaque. ECDSA-P256 is a benchmark primitive only, and no hybrid ships, because the specification doesn't define a hybrid construction yet (PR #600).
- One response-binding rule, `acs.core.response_binding_problem`, which every verification path decides through (PR #600).
- Experimental ML-DSA-65 decision signing in the example Guardian, on with `ACS_RESPONSE_SIGNING=ML-DSA-65`. The Guardian serves its public key document at `GET /keys` and binds each signed answer to its request by hash. A ClientHello that doesn't offer ML-DSA-65 is refused with `-32000` and `data.reason` `unsupported_signature_algorithm`. The key document and both handshake fields are lab conventions. The specification doesn't yet define how an asymmetric key is published or which algorithms a verifier accepts (PR #618, issue #576).
- `acs-verify`, run as `python -m acs.testing.verify`, which checks a session transcript offline: the hash chain, each response's signature under the key document or the HMAC secret, request binding, and the ServerHello. It names the entry where a tampered transcript fails and never calls a transcript complete on an unsigned claim (PR #618, issue #584).
- A reproducible size and timing benchmark for HMAC-SHA256, ECDSA P-256 and ML-DSA-65, and a published docs page generated from the committed results (PR #618, issue #583).
- An opt-in OPA policy backend for the example Guardian, on with `ACS_POLICY_BACKEND=opa` and `ACS_OPA_URL`. Every OPA failure denies with a reason code that names it, such as `opa_unreachable` or `opa_timeout`. Under the backend, `toolCallResult` is judged, so a result can be denied or redacted. The backend is a lab convention. The specification doesn't define an OPA binding yet ([PR #602](https://github.com/GenAI-Security-Project/agent-control-standard/pull/602)).
- A one-page ACS conformance claim template ([PR #168](https://github.com/GenAI-Security-Project/agent-control-standard/pull/168), issue #93).
- A decision log at `docs/decisions/index.md` that records 50 project decisions with date, deciding role, status and source ([PR #572](https://github.com/GenAI-Security-Project/agent-control-standard/pull/572)).
- An FAQ under Topics, linked from the landing page ([PR #20](https://github.com/GenAI-Security-Project/agent-control-standard/pull/20), issue #133, [PR #357](https://github.com/GenAI-Security-Project/agent-control-standard/pull/357)).
- A `steps/toolCallRequest` MODIFY exchange in the Instrumentable section of `acs.md`, with a guard that validates every message against the v0.1.0 schemas ([PR #271](https://github.com/GenAI-Security-Project/agent-control-standard/pull/271)).
- The Guardian reference implementation README states what the project expects from each maintained Guardian, and marks each expectation the TypeScript Guardian doesn't meet yet ([PR #256](https://github.com/GenAI-Security-Project/agent-control-standard/pull/256)).

### Changed: reference implementation

- The example Guardian refuses a repeated nonce in a session with `-32005`, as §10.3 asks. An envelope with no nonce skips the check ([PR #526](https://github.com/GenAI-Security-Project/agent-control-standard/pull/526), part of issue #524).
- The example Guardian now starts on Windows ([PR #525](https://github.com/GenAI-Security-Project/agent-control-standard/pull/525)).
- The example Guardian's built-in protected-path and traversal denies now run for every file tool and every path argument name. A wrong-typed argument denies with `argument_type_invalid` instead of crashing the handler. Every malformed request gets a JSON-RPC answer instead of a dropped connection. The README states these denies are a best-effort lexical check, not a security boundary (PR #602).
- The reference TypeScript Guardian records a request it can't vouch for as a `guardian.rejected_request` span, never under the ids the request claimed ([PR #309](https://github.com/GenAI-Security-Project/agent-control-standard/pull/309)).
- The reference Guardian follows the `request_id_ref` rule (PR #272).
- The conformance tests clean up their temporary directories when `trash` is absent ([PR #345](https://github.com/GenAI-Security-Project/agent-control-standard/pull/345), issue #73).
- The OCSF walkthrough in `docs/acs.md` uses a Process Activity example in place of an invented event ([PR #247](https://github.com/GenAI-Security-Project/agent-control-standard/pull/247)).

### Security

- One reader, `acs.client.read_trusted_file`, now opens every secret and trusted file: the HMAC secret, the Guardian's ML-DSA-65 seed and its key document. It checks owner, mode, directory and size on the open descriptors, follows no symlink and doesn't block on a FIFO (PR #618).
- The client trusts a key document only when the running user or root owns the document and its directory, or when `ACS_GUARDIAN_KEY_FINGERPRINT` pins it. The Guardian pins its own key document to its seed's fingerprint, so a writer can change the published validity windows and revoked list but not the key (PR #618).
- `acs-verify` escapes every transcript-derived string by Unicode category before printing, so a forged transcript can't repaint its verdict in a terminal (PR #618).
- The gateway's transcript and log lines escape non-ASCII text as `\uXXXX`, and a lone surrogate in a request never crashes it (PR #599).
- The example Guardian passes every request-derived log value through one escaping function (PR #602).
- One ML-DSA key signs every session, and a response carries no `session_id` (§10), so an answer matched only by its ids could be relayed from one session to another. The example Guardian closes that relay: every ML-DSA-signed answer carries `x_acs_lab_request_sha256`, a hash of the request it answers, inside the signed bytes, and the client requires it. The field is a lab convention until the specification settles a response binding. TLS to the Guardian stays required, as `adapters/docs/signing.md` says (PR #600, PR #618).

### Changed: repository and site

- The site serves from owaspacs.org ([PR #416](https://github.com/GenAI-Security-Project/agent-control-standard/pull/416)). The landing page shows the release number beside the specification version, and published docs prose names the release wherever it names the specification version ([PR #426](https://github.com/GenAI-Security-Project/agent-control-standard/pull/426), [PR #451](https://github.com/GenAI-Security-Project/agent-control-standard/pull/451), issue #450).
- The landing page and the docs share one header and one navigation pane, sourced from `mkdocs.yml`, and each page links its stylesheet by content hash ([PR #366](https://github.com/GenAI-Security-Project/agent-control-standard/pull/366), [PR #445](https://github.com/GenAI-Security-Project/agent-control-standard/pull/445), [PR #448](https://github.com/GenAI-Security-Project/agent-control-standard/pull/448), issue #447).
- The landing page shows the reference implementation demo and no longer shows the Workstreams section ([PR #437](https://github.com/GenAI-Security-Project/agent-control-standard/pull/437), [PR #441](https://github.com/GenAI-Security-Project/agent-control-standard/pull/441), issue #440).
- A failed scheduled site monitor run opens or updates a "Site monitor failing" issue ([PR #432](https://github.com/GenAI-Security-Project/agent-control-standard/pull/432)).
- A `dco` check fails a pull request that has a commit with no sign-off, and CONTRIBUTING.md shows how to sign one ([PR #407](https://github.com/GenAI-Security-Project/agent-control-standard/pull/407), [PR #417](https://github.com/GenAI-Security-Project/agent-control-standard/pull/417)). A pull request no lead asked for gets a `status:needs-triage` label and one comment ([PR #406](https://github.com/GenAI-Security-Project/agent-control-standard/pull/406), issue #362).
- SECURITY.md replaces fixed response times with an aim of about a week until 1.0, says advisories start at 1.0, and keeps inviting specification flaw reports without scoring them ([PR #413](https://github.com/GenAI-Security-Project/agent-control-standard/pull/413), [PR #418](https://github.com/GenAI-Security-Project/agent-control-standard/pull/418), [PR #420](https://github.com/GenAI-Security-Project/agent-control-standard/pull/420), issue #145). CONTRIBUTING.md states the same first-response aim for issues ([PR #409](https://github.com/GenAI-Security-Project/agent-control-standard/pull/409)) and points security timing at SECURITY.md ([PR #372](https://github.com/GenAI-Security-Project/agent-control-standard/pull/372), issue #265).
- CODEOWNERS drops three owners without write access and gains an `/adapters/` entry ([PR #414](https://github.com/GenAI-Security-Project/agent-control-standard/pull/414), issue #144, [PR #513](https://github.com/GenAI-Security-Project/agent-control-standard/pull/513), [PR #592](https://github.com/GenAI-Security-Project/agent-control-standard/pull/592)). Almog Langleben is now an owner of `/adapters/` and `/tests/` ([PR #634](https://github.com/GenAI-Security-Project/agent-control-standard/pull/634)).
- CONTRIBUTORS.md lists the authors of merged pull requests, and a name now goes on the list for work that reached `main`, not for comments ([PR #423](https://github.com/GenAI-Security-Project/agent-control-standard/pull/423)).
- The project is called the OWASP GenAI Security Project Agent Control Standard everywhere, and the landing page links to the project's page on genai.owasp.org ([PR #639](https://github.com/GenAI-Security-Project/agent-control-standard/pull/639)).
- AGENTS.md gives coding agents the same contribution rules people follow, and the Code of Conduct gains Part 2, on how work enters the repository: start from an assigned issue, keep your queue small, review when asked, and answer for what your account posts (D-051, [PR #636](https://github.com/GenAI-Security-Project/agent-control-standard/pull/636)).
- The nightly health issue links milestones correctly, reads `GH-N` as an issue reference, reports an admin merge unless a reviewer with write access approved it, and reads the workstream table through one parser ([PR #408](https://github.com/GenAI-Security-Project/agent-control-standard/pull/408), [PR #410](https://github.com/GenAI-Security-Project/agent-control-standard/pull/410), [PR #411](https://github.com/GenAI-Security-Project/agent-control-standard/pull/411), [PR #412](https://github.com/GenAI-Security-Project/agent-control-standard/pull/412)).
- The third-party content guard catches five HTML and CSS forms it missed ([PR #415](https://github.com/GenAI-Security-Project/agent-control-standard/pull/415), issue #392).

### Changed: dependencies

- certifi 2026.7.22 to 2026.10.19 ([PR #327](https://github.com/GenAI-Security-Project/agent-control-standard/pull/327)).
- New `pqc` extra in `acs-adapters`: `cryptography>=50,<51`, locked at 50.0.2. It can't share an environment with the `nat` extra while the NAT adapter depends on `nvidia-nat-core`. A move from NAT to NVIDIA NeMo Relay is planned (PR #600).
- The gateway is its own uv project, pinning `starlette` 1.10.0, `httpx` 0.28.1 and `uvicorn` 0.54.0 (PR #599). It adds `opentelemetry-sdk` 1.45.2, `opentelemetry-exporter-otlp-proto-http` 1.45.2 and its own `pqc` extra (PR #633).
- Every package now carries the release version. `acs-adapters` moves from 0.2.0 to 0.1.5, which is lower, and `acs-gateway` moves from 0.1.0 to 0.1.5. A pin on `acs-adapters` 0.2.0 or later no longer matches (PR #633).
- Dependabot now covers the AGT Bun workspace and the Go module ([PR #126](https://github.com/GenAI-Security-Project/agent-control-standard/pull/126), issue #127, PR #169).

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
- The Guardian's `main.ts`, not the trace exporter, now reads the proxy environment and applies the loopback exemption, and `close()` applies the same bounded drain whether trace export is on or off (Ariel's review on PR #286).

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
