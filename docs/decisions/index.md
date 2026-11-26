# Decision Log

This page records what the project has decided and why, newest first. When a later decision changes an earlier one, the earlier entry stays in place, marked superseded, so you can see how the project got to where it is.

Each entry links to the public issue or pull request where the decision was made. That link is the source of record. Where an entry and its source disagree, the source wins, and where the source is the specification, the specification wins. Some decisions were made on a leads' call. Call notes are not published, so those entries name the call and link the issue that carries the work.

A decision marked **spec change pending** is settled, but the specification text does not say it yet. Until that change lands, the published specification describes current behavior.

## Record a decision

Add an entry at the top of the log in the pull request that carries out the decision, or in a follow-up pull request when the decision was made on an issue or a call. Give it the next number. Never renumber or delete an entry. To reverse one, add a new entry and mark the old one superseded.

This log leaves out private vulnerability reports and anything about an unfixed security issue, account and permission details, partner conversations, and personal matters. Report a vulnerability through the process in [SECURITY.md](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/SECURITY.md).

## Decisions

### D-052: Land 0.2 specification work on `release/0.2`

**Date:** 2026-11-26 · **Decided by:** a project lead · **Status:** decided

`release/0.2` carries out [D-049](#d-049-promote-integration-as-015-then-branch-02). It starts from the 0.1.5 work on `integration`. A pull request targets `release/0.2` when it changes normative text under `docs/spec/`, a schema under `specification/`, or a conformance requirement, or when its issue is in the v0.2.0 milestone, because [D-048](#d-048-version-by-what-changed-until-10) makes a specification change a minor release. Code that carries out a specification change on `release/0.2` goes there with it, such as an adapter that enforces a rule only the 0.2 specification has. Other fixes to shipped code, adapters, reference implementation work, and documentation of shipped behavior stay on `integration` and ship in 0.1.x. A workflow opens a pull request that merges `integration` into `release/0.2` whenever `integration` moves ahead, so those fixes reach both lines ([PR #677](https://github.com/GenAI-Security-Project/agent-control-standard/pull/677)).

**Source:** [Issue #99](https://github.com/GenAI-Security-Project/agent-control-standard/issues/99), which tracks how release branches are versioned.

### D-051: Adopt Part 2 of the Code of Conduct

**Date:** 2026-11-20 · **Decided by:** a project lead · **Status:** decided

[Part 2 of the Code of Conduct](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CODE_OF_CONDUCT.md#part-2-how-work-enters-the-repository) sets how work enters the repository. It caps how many open pull requests and assigned issues one account holds, and it sets a review bar: an approval names the commit, what the reviewer ran, and what they did not check. A person answers for everything their account posts, and nothing posts unattended. Repeated breaches follow an enforcement ladder of notice, restriction, and removal. Part 2 enforces [D-041](#d-041-review-a-pull-request-only-when-it-closes-assigned-accepted-work) and [D-042](#d-042-start-schema-hook-and-event-changes-with-a-discussion), and it ends assignment after the fact, so a pull request opened before a lead assigns the work is closed with an invitation to reopen. The other project leads review Part 2 at the next milestone review, as the Code of Conduct says.

**Source:** [PR #636](https://github.com/GenAI-Security-Project/agent-control-standard/pull/636).

### D-050: Require an SDK for 1.0

**Date:** 2026-11-12 · **Decided by:** project leads · **Status:** decided

ACS 1.0 ships with SDKs in Python and TypeScript, and the SDK focuses on moving data across the wire, not on Guardian logic. An SDK lets a team build a control once and deploy it on many agents. Until an SDK exists, the documentation names no package ([D-033](#d-033-remove-sdk-examples-from-the-documentation)).

**Source:** project leads' call, 2026-11-12.

### D-049: Promote integration as 0.1.5, then branch 0.2

**Date:** 2026-11-12 · **Decided by:** project leads · **Status:** decided

The current `integration` work, the reference adapters included, ships as release 0.1.5. Spec work for 0.2 then continues on its own branch, and bug and security fixes are carried back to 0.1.

**Source:** project leads' call, 2026-11-12.

### D-048: Version by what changed until 1.0

**Date:** 2026-11-12 · **Decided by:** project leads · **Status:** decided

Before 1.0, a patch release changes code, a minor release changes the specification, and a major release marks a milestone. Breaking changes are allowed before 1.0, and the project coordinates them with known adopters. A backward-compatibility policy is required by 1.0. This follows the breaking minor release accepted in [D-024](#d-024-require-join-keys-on-every-trace-step-span).

**Source:** project leads' call, 2026-11-12. Working group call, 2026-11-05.

### D-047: Use symmetric keys inside a trust domain and asymmetric keys across trust domains

**Date:** 2026-11-12 · **Decided by:** project leads · **Status:** decided, spec change pending

ACS supports both. Shared-secret signing suits a deployment inside one trust domain without standing up a PKI, and public-key signing covers agents that cross trust boundaries. Which hooks require which kind waits until after 0.2 ships.

**Source:** project leads' call, 2026-11-12. Work tracked in [issue #532](https://github.com/GenAI-Security-Project/agent-control-standard/issues/532).

### D-046: Treat HTTP 429 as a refusal

**Date:** 2026-11-12 · **Decided by:** project leads · **Status:** decided, spec change pending

An HTTP 429 from the Guardian blocks the step, whatever the failure posture says, and the error the Observed Agent records must say why. Flooding the Guardian is the cheapest way for an attacker to cause a decision failure, so a 429 cannot follow the posture. This moves 429 out of the "no usable answer" group in [D-040](#d-040-split-decision-failures-from-refusals).

**Source:** project leads' call, 2026-11-12. [Issue #32](https://github.com/GenAI-Security-Project/agent-control-standard/issues/32).

### D-045: Only the Observed Agent's own configuration can opt into proceed

**Date:** 2026-11-12 · **Decided by:** project leads · **Status:** decided, spec change pending

A deployment fails open only when the Observed Agent's own configuration says `proceed`. A Guardian's `on_decision_failure` can make the posture stricter but never looser. The Guardian sits within an attacker's reach, so it cannot be the party that relaxes the posture. This supersedes the part of [D-040](#d-040-split-decision-failures-from-refusals) that let a Guardian declaring `proceed` get `proceed`.

**Source:** project leads' call, 2026-11-12. [Issue #32](https://github.com/GenAI-Security-Project/agent-control-standard/issues/32).

### D-044: Manage AgBOM as an ACS sub-stream and map it to CycloneDX first

**Date:** 2026-11-12 · **Decided by:** project leads · **Status:** decided

AgBOM stays inside ACS rather than joining the separate AI BOM effort, which covers models. The first step maps AgBOM fields and terms to CycloneDX 2.0 and records the gaps. AgBOM is a workstream label on issues.

**Source:** project leads' call, 2026-11-12.

### D-043: Treat ASK as a soft deny

**Date:** 2026-11-05 · **Decided by:** Spec lead · **Status:** decided, spec change pending

The Guardian owns the ASK timeout, and no answer in time means deny. The Observed Agent never turns an ASK into an allow by itself, so `timeout_disposition: allow` loses its meaning. If the Guardian is unreachable when the timeout falls, that is an ordinary decision failure.

**Source:** [PR #342](https://github.com/GenAI-Security-Project/agent-control-standard/pull/342). Related: [issue #175](https://github.com/GenAI-Security-Project/agent-control-standard/issues/175).

### D-042: Start schema, hook, and event changes with a Discussion

**Date:** 2026-11-05 · **Decided by:** project leads · **Status:** decided

Before proposing a change to the canonical schemas, the hook set, or the event catalog, open a [GitHub Discussion](https://github.com/GenAI-Security-Project/agent-control-standard/discussions). Everything else in ACS depends on those three, so the reasoning should be settled before anyone writes text.

**Source:** working group call, 2026-11-05.

### D-041: Review a pull request only when it closes assigned, accepted work

**Date:** 2026-11-05 · **Decided by:** project leads · **Status:** decided

A pull request gets reviewed when it references an issue carrying `status:accepted` and a lead has assigned that issue to its author. Editorial corrections are exempt. A new idea starts as an issue, not a pull request. Contributions had outrun review capacity, and this keeps reviewers on planned work. Splitting a large pull request is advice, not a rule.

**Source:** working group call, 2026-11-05. The rule is in [CONTRIBUTING.md](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CONTRIBUTING.md#how-work-gets-accepted).

### D-040: Split decision failures from refusals

**Date:** 2026-11-04 · **Decided by:** Spec lead · **Status:** decided, spec change pending. Partly superseded by D-045 and D-046.

A step ends one of three ways. A verified decision is honored. A step with no usable answer follows `on_decision_failure`: the Guardian is silent past the timeout, the connection or TLS handshake fails, an HTTP error arrives with no JSON-RPC body, or the Guardian answers with a signed `-32603`. A refusal or an integrity failure blocks the step whatever the posture: any unsigned error, any other signed error, a bad signature, an unknown `key_id`, or a mismatched id.

**Source:** [Issue #32](https://github.com/GenAI-Security-Project/agent-control-standard/issues/32), building on [issue #308](https://github.com/GenAI-Security-Project/agent-control-standard/issues/308).

### D-039: Sign every request and response

**Date:** 2026-11-04 · **Decided by:** Spec lead · **Status:** decided, spec change pending

Every request and every response is signed, errors and the ServerHello included. The one exception besides `system/ping` is the `SIGNATURE_INVALID` error for an unknown `key_id`, and the Observed Agent blocks it like any unsigned error. A ServerHello signature matters more under a default deny, because a rewritten ServerHello declaring `proceed` is the remaining way to fail open.

**Source:** [PR #339](https://github.com/GenAI-Security-Project/agent-control-standard/pull/339). Related: [issue #387](https://github.com/GenAI-Security-Project/agent-control-standard/issues/387).

### D-038: Carry model identity as fields on existing hooks

**Date:** 2026-11-04 · **Decided by:** Spec leads · **Status:** proposal accepted in shape, details open

ACS records which model a turn starts with, and which models answered, through an optional `model` object on existing hooks rather than through a new pair of model-call hooks. Three details stay open on the issue before the spec pull request.

**Source:** [Issue #363](https://github.com/GenAI-Security-Project/agent-control-standard/issues/363) and [Discussion #321](https://github.com/GenAI-Security-Project/agent-control-standard/discussions/321).

### D-037: Keep SDK defaults equal to specification defaults

**Date:** 2026-11-03 · **Decided by:** project leads · **Status:** decided

Whatever default the specification sets, an ACS SDK uses the same one. A reader should never get one posture from the specification and another from the code.

**Source:** project leads' call, 2026-11-03.

### D-036: Default the failure posture to deny

**Date:** 2026-11-03 · **Decided by:** project leads · **Status:** decided, spec change pending. Supersedes D-009.

When no usable decision arrives, the Observed Agent blocks the step, and the startup posture follows. A denial of service that induces a decision failure would let every action through under `proceed`, and ACS is a security standard that should not ship an insecure default. The posture stays configurable, and the documentation will state the effect of each setting. [D-045](#d-045-only-the-observed-agents-own-configuration-can-opt-into-proceed) settles who may loosen it.

**Source:** project leads' call, 2026-11-03. [Issue #32](https://github.com/GenAI-Security-Project/agent-control-standard/issues/32).

### D-035: Require a sign-off on every commit

**Date:** 2026-11-01 · **Decided by:** project lead · **Status:** decided

Every non-merge commit in a pull request carries a `Signed-off-by:` line, as OWASP requires, and the `dco` check enforces it.

**Source:** [Issue #52](https://github.com/GenAI-Security-Project/agent-control-standard/issues/52).

### D-034: Allow admin merges for small fixes, but not for trust files

**Date:** 2026-11-01 · **Decided by:** project lead · **Status:** decided

An administrator may merge a small fix that passes its tests on the merged tree. Changes to trust and governance files, such as `CODEOWNERS`, `GOVERNANCE.md`, and workflows, still need a second person. The roadmap health issue reports every admin merge.

**Source:** [Issue #365](https://github.com/GenAI-Security-Project/agent-control-standard/issues/365).

### D-033: Remove SDK examples from the documentation

**Date:** 2026-11-01 · **Decided by:** project lead · **Status:** decided

ACS publishes no SDK package, so code samples that import one come out of the documentation rather than staying with an "illustrative" label. A reader who copies an import should never reach a package the project does not own. [D-050](#d-050-require-an-sdk-for-10) plans the real SDK.

**Source:** [Issue #267](https://github.com/GenAI-Security-Project/agent-control-standard/issues/267).

### D-032: Publish no security advisories before 1.0

**Date:** 2026-11-01 · **Decided by:** project lead · **Status:** decided

ACS is a public preview, so it does not issue advisories or CVEs before 1.0. Reports go through GitHub private vulnerability reporting, and fixes ship as public pull requests at a time agreed with the reporter. Advisories start at 1.0.

**Source:** [PR #413](https://github.com/GenAI-Security-Project/agent-control-standard/pull/413) and [SECURITY.md](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/SECURITY.md).

### D-031: Establish Intent once per session

**Date:** 2026-10-31 · **Decided by:** project lead, confirming shipped text · **Status:** decided

Intent is established once, at `sessionStart` or at the first `agentTrigger`, and the first one wins. The rule shipped in release 0.1.4 in [Intent](../concepts/intent.md), and the schemas are being aligned to it.

**Source:** [Issue #149](https://github.com/GenAI-Security-Project/agent-control-standard/issues/149).

### D-030: Put the public site in scope for evaluators

**Date:** 2026-10-31 · **Decided by:** project lead · **Status:** decided. Next review 2026-12-09.

Site changes are in-focus work when they help an evaluator find, install, or run the Guardian.

**Source:** [Issue #265](https://github.com/GenAI-Security-Project/agent-control-standard/issues/265).

### D-029: Verify a response against the request it answers

**Date:** 2026-10-28 · **Decided by:** Spec lead · **Status:** decided

The Observed Agent verifies a response's signature with the key of the request it sent, and checks that the JSON-RPC id and `result.request_id` match that request. A reply that fails either check blocks the step whatever the posture says, and is recorded as an integrity failure of class `signature_invalid`, not as a DENY.

**Source:** [Issue #308](https://github.com/GenAI-Security-Project/agent-control-standard/issues/308).

### D-028: Keep reference implementations independent

**Date:** 2026-10-22 · **Decided by:** Reference Implementation workstream · **Status:** decided

Reference implementations follow shared architecture rules, such as separating processing from transport, but none depends on another. One or two solid implementations matter more than covering every language.

**Source:** [PR #256](https://github.com/GenAI-Security-Project/agent-control-standard/pull/256). Working group call, 2026-10-22.

### D-027: Wait seven days before taking a dependency update

**Date:** 2026-10-22 · **Decided by:** project lead · **Status:** decided

Dependabot waits seven days after a release before proposing it, in every ecosystem. A compromised release does the most damage in the hours after it is published, and registries usually pull one within days.

**Source:** [`.github/dependabot.yml`](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/.github/dependabot.yml).

### D-026: Treat key_id as an opaque label

**Date:** 2026-10-13 · **Decided by:** Spec lead · **Status:** decided

`key_id` is a label the deployment chooses to name one configured secret. The specification reserves no values. A verifier rejects an unknown `key_id`, never falls back to another secret, and a `key_id` is never derived from the secret. Before this rule, implementations that each guessed a different value could not verify one another.

**Source:** [Issue #118](https://github.com/GenAI-Security-Project/agent-control-standard/issues/118) and [PR #272](https://github.com/GenAI-Security-Project/agent-control-standard/pull/272).

### D-025: Add signature and handshake failure classes

**Date:** 2026-10-13 · **Decided by:** Spec lead · **Status:** decided

A response that fails signature verification gets its own failure class, `signature_invalid`, so tampering stands out from ordinary failures. A blocked handshake is recorded as `handshake_failure` on the session span, so an unguarded session does not read as clean.

**Source:** [Issue #37](https://github.com/GenAI-Security-Project/agent-control-standard/issues/37).

### D-024: Require join keys on every Trace step span

**Date:** 2026-10-12 · **Decided by:** Spec leads · **Status:** decided

`acs.request_id` and `acs.session.id` are required on every step span, so traces join on the session and request pair, and a retry counts as its own request. This breaks existing Trace exporters, and the leads accepted a breaking minor release for it. The same decision set aligns the OpenTelemetry and OCSF decision events and pads the policy arrays to the length of `policy_references`.

**Source:** [Issue #228](https://github.com/GenAI-Security-Project/agent-control-standard/issues/228).

### D-023: Record decision failures as their own Trace event

**Date:** 2026-10-08 · **Decided by:** Spec lead · **Status:** decided. The countable part waits for v0.2.

A decision failure gets a separate event, `acs.decision.failure`, rather than a variant of `acs.decision`. A failure has no verdict and no evaluator, and a separate event makes the failure rate a count of one event name. A count that can be proven complete is v0.2 work.

**Source:** [Issue #37](https://github.com/GenAI-Security-Project/agent-control-standard/issues/37).

### D-022: Mark Trace attributes that depend on the payload as conditional

**Date:** 2026-10-08 · **Decided by:** Spec lead · **Status:** decided

Each hook in the Trace mapping carries a `conditional_attributes` list, filled whenever the payload has the field. An attribute that comes from an optional field is never listed as required.

**Source:** [Issue #227](https://github.com/GenAI-Security-Project/agent-control-standard/issues/227).

### D-021: Build Trace on OpenTelemetry first

**Date:** 2026-10-08 · **Decided by:** project lead · **Status:** decided

The first Trace work in the reference Guardian exports OpenTelemetry, with OCSF after it. Evaluators asked for OpenTelemetry output they could analyze offline.

**Source:** working group call, 2026-10-08. [Issue #91](https://github.com/GenAI-Security-Project/agent-control-standard/issues/91).

### D-020: Leave conformance checks to the reviewer

**Date:** 2026-10-05 · **Decided by:** project leads · **Status:** decided

The Testing and Validation workstream is dropped. Whoever reviews a change checks it against the conformance requirements it touches. In practice, testing was not separate from implementation.

**Source:** [PR #218](https://github.com/GenAI-Security-Project/agent-control-standard/pull/218).

### D-019: Keep the conformance suite in this repository

**Date:** 2026-10-05 · **Decided by:** project lead · **Status:** decided

The official ACS-Core conformance suite lives here. The Spec workstream owns it and versions it with each specification release. An outside suite can contribute vectors through pull requests, but it is never named as the official one, because whatever defines "conformant" has to move on the project's release schedule.

**Source:** [Issue #19](https://github.com/GenAI-Security-Project/agent-control-standard/issues/19). Related: [issue #188](https://github.com/GenAI-Security-Project/agent-control-standard/issues/188) and [issue #33](https://github.com/GenAI-Security-Project/agent-control-standard/issues/33).

### D-018: Set the ACS-Core floor

**Date:** 2026-10-05 · **Decided by:** Spec leads · **Status:** decided

ACS-Core relaxes MODIFY and `system/ping` to SHOULD. A deployment without `system/ping` must declare another liveness mechanism. Wrapped MCP is a MUST for sessions that use MCP, `subagentStart` is a MUST where the framework has subagents, and `subagentStop` is a SHOULD. A June draft had made both subagent hooks MUST, and the merged text replaced it. A client that cannot apply a MODIFY treats it as DENY.

**Source:** [PR #21](https://github.com/GenAI-Security-Project/agent-control-standard/pull/21) and [Conformance Profiles](../spec/conformance.md).

### D-017: Keep the roadmap in GitHub milestones

**Date:** 2026-10-04 · **Decided by:** project lead · **Status:** decided

GitHub milestones are the roadmap, and targets are calendar quarters rather than dates, so a volunteer project can change plans with one edit. The project board is the authoritative view of each item's state.

**Source:** [PR #201](https://github.com/GenAI-Security-Project/agent-control-standard/pull/201). Working group call, 2026-10-22.

### D-016: Resolve and record request_id_ref

**Date:** 2026-09-17 · **Decided by:** Spec leads · **Status:** decided

A Guardian SHOULD resolve a `toolCallResult`'s `request_id_ref` against the `toolCallRequest` records it holds for the session, and MUST record the reference when it cannot resolve it. Whether an unresolved reference is grounds to deny stays the vendor's policy. A missing `request_id_ref` stays optional and is recorded as a finding when absent.

**Source:** [Issue #118](https://github.com/GenAI-Security-Project/agent-control-standard/issues/118) and [issue #305](https://github.com/GenAI-Security-Project/agent-control-standard/issues/305).

### D-015: Land changes on integration and promote to main

**Date:** 2026-09-10 · **Decided by:** project leads · **Status:** decided

Every pull request targets `integration`. `main` publishes the site and the schema URIs, and it moves only through a deliberate promotion, so published schemas change on a decision rather than on every merge.

**Source:** [PR #64](https://github.com/GenAI-Security-Project/agent-control-standard/pull/64).

### D-014: Base schema identifiers on the repository

**Date:** 2026-09-09 · **Decided by:** project lead · **Status:** decided

Schema `$id` values sit under the GitHub organization and repository path, not a project domain, so schema identity survives a domain or hosting change. Every schema lives at the path its `$id` declares, and `$id` carries the specification version, not the release version.

**Source:** release 0.1.2 in the [changelog](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CHANGELOG.md).

### D-013: Version the release apart from the specification

**Date:** 2026-08-11 · **Decided by:** project lead · **Status:** decided

The release version, such as 0.1.4, lives in `version.txt` and `pyproject.toml`. The specification version, such as v0.1.0, is what the protocol and the schema identifiers carry. A release can ship without a specification change.

**Source:** release 0.1.1 in the [changelog](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CHANGELOG.md).

### D-012: License code under Apache 2.0 and prose under CC BY-SA 4.0

**Date:** 2026-08-11 · **Decided by:** project lead · **Status:** decided. Supersedes D-001's MIT license.

Code and schemas are Apache 2.0, and prose documentation is CC BY-SA 4.0. Everything through v0.1.0 remains MIT.

**Source:** release 0.1.1 in the [changelog](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CHANGELOG.md).

### D-011: Build the first reference Guardian on the Agent Governance Toolkit

**Date:** 2026-07-30 · **Decided by:** Spec leads · **Status:** decided

The first reference Guardian uses Microsoft's open-source Agent Governance Toolkit as its policy engine, mapped to the ACS contract. ACS stays the neutral contract, and the toolkit is one conformant implementation of it, not the standard.

**Source:** working group calls, 2026-07-15 and 2026-07-30. The implementation is in [`reference-implementations/agt`](https://github.com/GenAI-Security-Project/agent-control-standard/tree/main/reference-implementations/agt).

### D-010: Join the OWASP GenAI Security Project

**Date:** 2026-07-02 · **Decided by:** project lead · **Status:** decided

ACS joined the OWASP GenAI Security Project as a project, not as an initiative inside another project.

**Source:** working group call, 2026-07-02.

### D-009: Default the failure posture to proceed

**Date:** 2026-06-05 · **Decided by:** Spec leads · **Status:** superseded by D-036

Specification v0.1.0 set `on_decision_failure` to default to `proceed`, so a slow or unreachable Guardian would not halt production.

**Source:** [PR #2](https://github.com/GenAI-Security-Project/agent-control-standard/pull/2).

### D-008: Defer the hardest protocol features past v0.1

**Date:** 2026-05-07 · **Decided by:** Spec leads · **Status:** decided

Streaming for wrapped protocols, recursive approvals, multi-tenant isolation, normative A2A wrapping, and a Cedar policy binding are v0.2 work or later. v0.1 reserves the A2A namespace without defining its semantics.

**Source:** working group call, 2026-05-07. [Specification](../spec/instrument/specification.md).

### D-007: Keep sessions stateful

**Date:** 2026-05-07 · **Decided by:** Spec leads · **Status:** decided

A session carries state from start to end, including its context, intent, and hash chain. Some compositional threats cannot be controlled without state across steps.

**Source:** working group call, 2026-05-07.

### D-006: Use Rego as the reference policy language

**Date:** 2026-05-07 · **Decided by:** Spec leads · **Status:** decided

The reference deterministic layer uses OPA Rego. Cedar is more opinionated, and Rego fits more use cases. The specification itself stays engine-agnostic, and a Cedar binding is planned for v0.2.

**Source:** working group call, 2026-05-07.

### D-005: Separate the Guardian's deterministic and AI layers

**Date:** 2026-05-07 · **Decided by:** Spec leads · **Status:** decided

A Guardian runs a deterministic policy layer first. An optional AI layer can follow, using any kind of model, and the two never feed each other. Policy facts stay apart from generated reasoning.

**Source:** working group call, 2026-05-07. [Specification](../spec/instrument/specification.md).

### D-004: Speak JSON-RPC 2.0 and require a handshake

**Date:** 2026-05-07 · **Decided by:** Spec leads · **Status:** decided

ACS messages are JSON-RPC 2.0 over HTTP or stdio, the same base as MCP and A2A. Every session opens with a handshake, so both sides agree on a version and a downgrade attack has nowhere to start.

**Source:** working group call, 2026-05-07.

### D-003: Offer five dispositions

**Date:** 2026-05-07 · **Decided by:** Spec leads · **Status:** decided

A Guardian answers allow, deny, modify, ask, or defer.

**Source:** working group call, 2026-05-07. [Supported Hooks](../spec/instrument/hooks.md).

### D-002: Be opinionated on the contract, not the implementation

**Date:** 2026-05-07 · **Decided by:** Spec leads · **Status:** decided

ACS defines what crosses the wire and leaves the implementation open. The framework enforces a disposition, not the model, and the observed agent does not know the hooks exist. ACS stays vendor-neutral, and reference implementations show what is possible rather than the one way to do it.

**Source:** working group calls, 2026-05-07 and 2026-09-24.

### D-001: Rename AOS to ACS and focus on runtime control

**Date:** 2026-04-10 · **Decided by:** project lead · **Status:** decided. The MIT license was superseded by D-012.

The Agent Observability Standard became the Agent Control Standard. The project moved from watching agents to controlling them at runtime. The project was MIT-licensed at the time.

**Source:** project history. [FAQ](../topics/faq.md).
