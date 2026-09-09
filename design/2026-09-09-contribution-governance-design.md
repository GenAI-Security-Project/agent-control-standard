# Contribution governance for the OWASP re-launch

Version: 1.0
Owner: ACS project lead
Date: 2026-09-09
Status: design, approved for planning

The OWASP re-launch kick-off runs Thursday, September 10, 2026. The core team sync on
September 8 named the problem plainly: many people want to contribute, and the project has
no framework for what a valid contribution is. `CONTRIBUTING.md` exists and is too
permissive. Issues arrive self-directed, followed immediately by a pull request nobody
asked for. The Strategic Adoption Plan v3 puts a number on the pressure. It counted
eighteen open issues on September 5. There are twenty-four today, four days later and
before the kick-off has happened.

This design turns the plan's committed outcome into the filter that decides what the
project accepts, and wires that filter into branches, labels, forms, templates, and
rulesets so it holds without a maintainer in the loop for every decision.

## Goal

A contributor arriving from the kick-off can answer three questions from the repository
alone: what is the project working on right now, does my idea belong in that, and what do
I do next. A maintainer can answer one question in seconds: does this issue enter the
backlog. Neither answer depends on anyone remembering a rule.

## What this is answering

| Decision from the sync | Where it lands here |
|---|---|
| `CONTRIBUTING.md` is too permissive | Current Priority Scope, plus the acceptance gate |
| `main` locked, `integration` gates all pull requests | Branching and pull request flow |
| Contributors fork, sync, and test before submitting | Pull request gate, testing attestation |
| Only team members assign tags, only tagged issues enter the backlog | Labels, issue intake |
| Project needs a communicated focus so contributors self-direct | Current Priority Scope |
| Define what code contribution is actually needed | Seeded onramp |
| Ask the community to dogfood AGT with ACS and document failures | Conformance report form, seeded onramp |
| Tiered contributor roles with capacity caps | Contributor sign-up form |
| Review bottlenecks are real | Docs lane, non-blocking triage, milestones |

## Current Priority Scope

The project's acceptance filter is one named thing, stated once, in a section at the top of
`CONTRIBUTING.md`. Every other surface links to it. A readable paraphrase in an issue form
drifts from what it paraphrases and then outranks it in practice, which is why nothing else
restates it.

The name is **Current Priority Scope**. The section's job is to answer whether a piece of
work is in or out, and *scope* draws a boundary where *focus* only describes attention. The
failure mode from the sync was people opening self-directed issues and pull requests, which
is a boundary problem.

The section opens with the plan's commitment quoted directly, then splits the world three
ways.

**In focus** is work that feeds the runnable Guardian, the AGT interoperability benchmark,
or the conformance evidence that makes either credible:

- PR #21, the mandatory floor decision, which gates everything behind it
- PR #22, the Claude Code, Cursor, and NVIDIA NAT adapters
- PR #60, the AGT reference implementation under `reference-implementations/agt`
- Ports of that reference implementation to other runtimes: Python, Go, Rust, Codex
- Production-hardening the reference implementation, including span batching and
  OpenTelemetry collection
- Resolving the fail-open default, which issues #32 and #37 attack from opposite ends
- The ACS-Core conformance claim template
- Milestone #33, the requirement ledger and behavioral tests
- Closing the Cursor file-read gap
- Conformance and dogfooding reports that document where ACS fails in practice

**Deferred** is work that is real, tracked, and lands after Day 90. The plan enumerates the
v0.2.0 window, so this list is quoted rather than invented: async and composition,
streaming, batching semantics, recursive ask, quorum, multi-tenant isolation, the Cedar
binding, and AgBOM federation across A2A peers. Negative conformance vectors sit here too,
tracked in #53.

One distinction has to be explicit, because it will otherwise get argued in a pull request.
*Batching semantics in the specification* is deferred to v0.2.0. *Batching in the reference
implementation* is in focus, because Ariel named it as a foot gun in the naive
implementation and it is exactly the production-hardening the plan wants. The two share a
word and nothing else.

**Out of scope** is what ACS deliberately leaves to deployments: the policy engine itself,
the signature algorithm, the transport, the authentication mechanism, and the policy
content. The specification is opinionated on the contract and permissive on the
implementation, and that is a design position rather than a gap waiting to be filled.

The section carries a review date instead of a timestamp, because a timestamp in a cached
prefix is drift with no signal. The current window is Day 0 to Day 30, reviewed October 9,
2026. A scheduled workflow opens an issue when that date passes. It does not fail the
build, since a stale scope is a governance problem and blocking a documentation deploy on
it helps nobody.

## Branching and pull request flow

Four kinds of branch.

| Branch | Receives | Publishes |
|---|---|---|
| `main` | docs-lane pull requests, promotion pull requests | site, all 44 schema `$id` URIs |
| `integration` | specification, schemas, reference implementations, adapters, tests, CI | nothing |
| `release/vX.Y.Z` | stabilization for a tagged specification version | nothing until merged |
| fork branches | contributor work | nothing |

`main` stays the repository default. This is deliberate and runs against the sync's
shorthand that all pull requests target `integration`, so the reasoning matters. The
`protect-main` ruleset currently keys its condition on `~DEFAULT_BRANCH`. Moving the default
to `integration` transfers that protection to `integration` and leaves `main` bare, which is
a silent security regression rather than a visible one. Keeping `main` as default also gives
the documentation lane, which will carry the most contributors and the least GitHub
fluency, the path with no base-branch step, while a mistargeted specification pull request
is caught by a guard at no maintainer cost.

Treating the specification as code is the sync's other instruction, and it decides the
allowlist below.

### The docs lane allowlist

Paths that may target `main` directly are a positive allowlist. An allowlist fails closed. A
blocklist leaks every time somebody adds a directory.

| May target `main` | Everything else targets `integration` |
|---|---|
| `docs/topics/**`, `docs/README.md` | `specification/**`, `docs/spec/**` |
| `README.md`, `CONTRIBUTORS.md`, `CODE_OF_CONDUCT.md` | `docs/concepts/**`, `docs/identity/**` |
| `CONTRIBUTING.md`, `GOVERNANCE.md`, `SECURITY.md` | `tests/`, `tools/`, `.github/` |
| `STYLE.md`, `LICENSING.md`, `NOTICE` | `reference-implementations/`, `adapters/` |
| `design/**` | `mkdocs.yml`, `overrides/`, `landing/`, `docs/stylesheets/`, `docs/assets/` |
| | `pyproject.toml`, `uv.lock`, `version.txt`, `LICENSE`, `LICENSE-DOCS` |

The lane is narrower than the phrase "documentation" suggests, and three groups deserve
their reasons stated.

`docs/spec/**` sits on the `integration` side because it is normative prose. The hazard the
allowlist closes is a documentation pull request landing on `main` and publishing a
description of a schema change still sitting on `integration`, which would put the site
ahead of the wire contract it documents. `docs/concepts/**` and `docs/identity/**` go with
it, since those pages define the terms the specification uses, including Intent, Capability,
Provenance, and Trust Basis.

`mkdocs.yml`, `overrides/`, `landing/`, `docs/stylesheets/`, and `docs/assets/` also sit on
the `integration` side, even though a reader would call all five documentation. CODEOWNERS
already treats them as privilege-escalation surfaces and says why: `mkdocs.yml` accepts a
`hooks:` key that executes Python inside the build job, the overrides directory holds
templates the build renders into every page, and a stylesheet or asset reaches a third party
through `url()`, `@font-face`, or `@import` with no script at all. A lane that deploys to
the live site on merge is the wrong lane for any of them.

What remains in the documentation lane is editorial and governance prose that publishes
without executing anything: the topics pages, the root meta files, and this design
directory. A typo fix in a concepts page therefore takes the `integration` path and
publishes on the next promotion. That cost is accepted, because a wide lane fails open and
the whole point of an allowlist is that it does not.

### The base-branch guard

GitHub rulesets cannot express "the paths in the diff decide the base branch," so a guard
does it. The guard splits in two so that the logic is tested and the wiring is thin.

`tools/base_branch_guard.py` holds a pure function that takes a set of changed paths and
returns the ones that require `integration`. Anything not matched by the allowlist is
returned, which is what makes an unanticipated new directory a failure rather than a silent
pass. The same module carries a `main()` that reads the changed files and the refs from the
environment and exits nonzero with a message naming each offending file.

`.github/workflows/pr-base-guard.yml` runs on pull requests targeting `main` and calls it.

Three cases the guard has to get right. A promotion pull request from `integration` or from
a `release/*` branch touches specification paths by definition and must pass. A guard that
*skips* on those heads would leave a required status check permanently pending and block the
merge forever, so it runs and passes rather than skipping. A mixed diff carrying both
documentation and specification fails, which forces the split instead of letting the
specification ride in on a documentation change.

Two automated producers currently open pull requests against the default branch and touch
paths outside the allowlist. Dependabot gets `target-branch: "integration"` in
`.github/dependabot.yml`. `sync_version.yml` moves its trigger from a push to `version.txt`
on `main` to the same push on `integration`. Neither gets an exemption in the guard, because
an exemption keyed on an actor is a hole an actor can be impersonated through.

### Promotion

A promotion is a pull request from `integration` to `main`, opened by a maintainer, merged
with a merge commit rather than a squash. Squashing a promotion flattens every specification
commit into one and destroys the history that makes a schema change reviewable after the
fact. `protect-main` currently allows only squash and rebase, so `merge` gets added.

Promotion is when the 44 schema URIs change. That is a property worth keeping: the URIs are
a machine-consumed contract, and batching their changes into a deliberate promotion is
better than republishing on every specification merge.

`integration` needs to stay current with `main`, since `main` receives documentation commits
independently. `.github/workflows/sync-integration.yml` runs on every push to `main` and
merges `main` into `integration`, so a promotion pull request stays conflict-free. It runs
on push rather than on a schedule because the divergence starts at the merge, and a nightly
job would leave a day of drift for a promotion to collide with.

## Labels

### The axes

Labels become prefixed axes rather than a flat pile, and the axes split by who sets them.

| Axis | Values | Applied by |
|---|---|---|
| `type:` | `bug`, `proposal`, `refimpl`, `conformance`, `docs` | the issue form, automatically |
| `scope:` | `in-focus`, `deferred`, `out` | maintainers |
| `status:` | `needs-triage`, `accepted`, `blocked`, `needs-info` | forms set `needs-triage`, maintainers set the rest |
| `priority:` | `P0`, `P1`, `P2` | maintainers |
| `workstream:` | `spec`, `coding-agents`, `sdk`, `identity`, `outreach` | maintainers |

`priority:P0` is reserved for the four links in the plan's serial chain, so the label means
something narrower than "important."

Dates live in GitHub Milestones rather than labels. Day 14 through Day 90 become milestones
carrying the plan's committed outcomes as their descriptions, which gives the weekly call a
burndown instead of a status round. The plan's own risk register prescribes using that call
for triage, and a milestone view is what makes that possible.

`workstream:` uses the five names in `GOVERNANCE.md`. The plan names Reference
Implementation, Documentation, and Testing and Validation as open lead seats, and none of
those three is a workstream in `GOVERNANCE.md`. That mismatch is a governance question for
the project lead and gets a tracked issue. Inventing three workstreams inside a label file
would settle it by accident.

### Who applies what

The rule is that a submitter never sets a decision label. Enforcement is structural rather
than social, in one specific place: **no issue form is permitted to stamp a `scope:`,
`priority:`, `status:accepted`, or `workstream:` label.** That is the actual leak, because
outside contributors already cannot apply labels at all under GitHub's permission model.
What remains is a collaborator with triage access mislabeling, and that population is the
maintainer roster itself.

A workflow that strips decision labels applied by an account below write access was
considered and is not in this design. It buys enforcement against people the project has
already decided to trust, it requires a permission lookup whose behavior under
`GITHUB_TOKEN` needs verification, and it adds a write-scoped workflow to `.github/`, which
CODEOWNERS treats as a privilege-escalation surface. The documented rule plus forms that
cannot stamp decisions closes the real gap. This is recorded as tracked follow-up rather
than dropped.

### Migration from the current labels

The repository carries the eleven GitHub defaults plus two Dependabot labels. Renaming
preserves assignments on existing issues, so renaming is preferred to deleting.

`bug` becomes `type:bug`. `documentation` becomes `type:docs`. `enhancement` becomes
`type:proposal`. `dependencies`, `github-actions`, `python`, and `python:uv` stay as they
are, since Dependabot creates and expects them. `invalid`, `wontfix`, `duplicate`, and
`question` get deleted, because GitHub's native close reasons and the Discussions routing in
`config.yml` already cover them.

Deletion removes a label from every issue carrying it, so implementation confirms each of
those four is unused before deleting rather than assuming it from a listing.

## Issue intake

### Forms

`blank_issues_enabled` moves to `false`. Every issue arrives through a form, which is what
makes automatic `type:` and `status:needs-triage` labeling reliable.

Five forms, each with a distinct triage path:

1. **Bug report.** Something is broken: a schema error, a specification defect, the site, CI,
   or tooling. Fields cover what is broken, where, what the specification says, and the
   impact on implementers.
2. **Feature or specification proposal.** A new capability. Fields cover the problem, why
   the wire has to carry it, which of the six constituencies in `SPEC_REVIEW_PRINCIPLES.md`
   it affects, alternatives considered, and a link to the required Discussion.
3. **Reference implementation work.** A port, a hardening task, or a new adapter. Fields
   cover the target runtime, what it proves, which part of the ninety-day outcome it feeds,
   and whether the filer intends to implement it themselves.
4. **Conformance or dogfooding report.** The community ask Ariel proposed: install ACS
   against a real harness and document where it fails. Fields cover what was run, what was
   expected, what happened, and the specification section involved. The form leads with the
   redirect to private vulnerability reporting, because this is the form most likely to
   surface a security gap.
5. **Documentation.** The low-friction lane. Page, what is wrong or missing.

Every form ends with the same required dropdown asking which part of the Current Priority
Scope the work serves, including an honest option for "this is deferred or out of scope and
I am filing it to be tracked." A filer who picks that option has done the triage themselves.

The existing `config.yml` contact links are correct and stay. Security reporting continues
to route to private vulnerability reporting, and questions continue to route to Discussions.

### Triage

Triage assigns `scope:`, then `status:`, then `priority:` and `workstream:` for anything
accepted. Only `status:accepted` enters the backlog, which is the sync's rule stated
mechanically.

An issue that is in focus and accepted gets a milestone. An issue that is deferred gets
`scope:deferred` and a pointer to the v0.2.0 window rather than a close, because closing
real work tells a contributor their finding was worthless. An issue that is out of scope
gets `scope:out` and a close with a reason.

### Milestones

Day 14 (September 24), Day 30 (October 9), Day 60 (November 6), and Day 90 (December 4),
each carrying the plan's committed outcome as its description.

## Pull request gate

A pull request that touches specification or code references an issue carrying
`status:accepted`. A documentation-lane pull request to `main` needs no issue. The base
branch therefore tells a reviewer which rule applies, which is the property that makes the
gate cheap to explain.

The important question is what happens to a pull request whose issue is filed but not yet
accepted. It is neither closed nor reviewed. Closing destroys work and reads as hostile.
Reviewing spends the capacity the gate exists to protect. It carries `status:needs-triage`,
a comment explains why nobody is looking at it yet, and it waits. The seeded onramp below
means most contributors never reach that wait, because an accepted issue already exists for
the work they came to do.

`.github/workflows/pr-intake.yml` reads the pull request body, resolves referenced issues,
and posts the explanatory comment plus `status:needs-triage` when no referenced issue
carries `status:accepted`. It is deliberately **not** a required status check. Mistargeting
a base branch is a mechanical error with one correct answer and belongs in a required
check. Missing acceptance is a queue state that resolves on its own, and turning it into a
red required check would make the gate feel like a rejection.

The pull request template changes in four ways. It asks which issue the work implements and
states the documentation-lane exemption inline. It asks the contributor to confirm they
synced their branch and ran the guards, which is Helen's requirement from the sync and the
one that keeps sloppy work out of review. It adds the base branch to the checklist. It keeps
the existing specification, DCO, style, and security sections, which are already correct.

## Repository governance

### Rulesets

`protect-main` is rewritten and hardened. Its condition moves from `~DEFAULT_BRANCH` to the
literal `refs/heads/main`, which removes the silent-failure mode where a future default
change unprotects it. Required approvals rise from one to two. Required status checks gain
the base-branch guard alongside `test` and `build`. Allowed merge methods gain `merge` for
promotions. Deletion and non-fast-forward protection stay.

One honest limitation. The sync's phrasing was that nobody except a few key people can ever
merge into `main`. GitHub rulesets do not offer a direct "only these accounts may merge a
pull request" control, so this design approximates it with two required approvals plus the
existing CODEOWNERS requirement. Implementation verifies whether the current ruleset schema
exposes a stronger restriction before settling for the approximation.

`protect-integration` is new and mirrors the current `protect-main`: one approval, CODEOWNERS
review, `test` and `build` required, stale-review dismissal, last-push approval, thread
resolution, deletion and non-fast-forward protection, squash and rebase only.

`protect-release` is new and covers `refs/heads/release/*` with deletion and
non-fast-forward protection, one approval, and the same status checks.

The `restrict-transfers-deletions` repository ruleset is unaffected.

### CODEOWNERS

`/reference-implementations/` and `/adapters/` get owner entries once #60 and #22 land.
Everything else in the file is already correct. The invitation caveat at the top of the file
stays accurate and stays.

## Authorship and AI assistance

The current `CONTRIBUTING.md` mandates that a maintainer drops any `Co-Authored-By` trailer
naming a model when a pull request is squashed. That mandate is removed. It is replaced by a
named section that mandates neither direction.

The human `Signed-off-by` line stays required, because the DCO is a certification about the
origin of code and only a person can make one. Every other trailer is the contributor's
choice. Maintainers will not add one and will not remove one, and its presence has no effect
on review. A trailer naming a model certifies nothing and moves no responsibility.

Two reasons this is the right posture for this project specifically. Some employers require
their people to disclose AI assistance, and a visible trailer is the simplest way to satisfy
that. More pointedly, ACS is a standard about agent provenance and traceability, and a
project whose premise is that you should be able to see what an agent did cannot coherently
erase the record of what an agent did to its own commits.

This constrains work already planned. Issue #52 proposes enforcing the DCO in CI once the
current pull requests land. That check verifies `Signed-off-by` and stays indifferent to
every other trailer, so nobody implements a gate that rejects or rewrites `Co-Authored-By`.

## Seeded onramp

The gate and the invitation have to be the same artifact, or the gate suppresses exactly the
contributions Track 1 needs. Ariel's invitation in the sync was open: if somebody wants to
open a reference implementation against Codex, have at it. A gate requiring an accepted
issue turns that invitation into a queue wait unless the accepted issue already exists.

So maintainers file them before the kick-off. Each carries `scope:in-focus`,
`status:accepted`, `help wanted`, a workstream, and a priority:

1. Port the AGT reference implementation to Python
2. Port the AGT reference implementation to Go
3. Port the AGT reference implementation to Rust
4. Build a reference implementation against Codex
5. Add span batching to the reference implementation
6. Configure OpenTelemetry collection and export in the reference implementation
7. Dogfood AGT with ACS and file a conformance report
8. Publish the one-page ACS-Core conformance claim template
9. Choose and reserve a distribution name for the reference implementation

Items 8 and 9 are open decisions in the plan with Day 30 dates. Filing them as issues puts
them where the weekly call can burn them down.

## Contributor sign-up form

The sync's plan, taken from FinBot, is a form that collects contact details and role
interest, with a role closed once capacity is reached. The transcript is explicit that this
drops in the Slack channel after Thursday rather than at the kick-off, so it is specified
here and not built as a repository change.

Roles offered: reference implementation engineer, adapter engineer, specification reviewer,
documentation, testing and validation, conformance and dogfooding, adoption and outreach.

Fields collected: name, email, GitHub handle, LinkedIn, employer and whether the work
happens on work time, role preference with a second choice, languages and runtimes, hours
per week, timezone, prior OWASP involvement, and acknowledgement of the Code of Conduct and
the DCO. Asking for the GitHub handle and LinkedIn up front is Helen's point about not
chasing people afterward.

The employer question is not idle curiosity. ACS is a vendor-neutral standard whose last
single-vendor dependency is being unwound, and knowing where contributors work is what makes
that neutrality auditable.

## Testing

The base-branch guard is the only new logic that can be wrong in an interesting way, so it
gets real tests over its pure function, in `tests/test_base_branch_guard.py`, following the
existing guard idiom.

- An allowlisted documentation path against `main` passes
- A `specification/` path against `main` fails and names the file
- A `docs/spec/` path against `main` fails, since normative prose is not documentation
- `mkdocs.yml` against `main` fails, since it executes Python inside the build job
- A mixed diff of one allowlisted and one specification path fails
- A path under a directory nobody anticipated fails, which is the fail-closed property
- A promotion head of `integration` passes with specification paths in the diff
- A `release/*` head passes the same way
- Any base other than `main` passes without consulting the allowlist
- Path matching is prefix-correct, so `docs/specimen.md` is not mistaken for `docs/spec/`

The last case matters. A naive prefix check on `docs/spec` matches `docs/specimen.md` and
routes an ordinary documentation file to `integration` for no reason.

## Verification

Guards prove themselves by injection rather than by reading, since `tests/conftest.py` has
broken on nearly every change to this suite. After implementation:

- `uv run pytest -v` passes locally and the new tests are collected, not skipped
- A scratch branch touching only `specification/` and targeting `main` trips the guard in a
  real pull request, and the failure message names the file
- A scratch branch touching only `docs/topics/` and targeting `main` passes
- `gh label list` matches the taxonomy exactly, with no orphaned defaults
- Opening each of the five forms produces the expected `type:` and `status:needs-triage`
  labels and no decision label
- The `integration` ruleset rejects a direct push
- `uv run mkdocs build --strict` still passes with the rewritten `CONTRIBUTING.md`

## Sequencing before Thursday

The project lead's instruction is that everything lands before the kick-off. The ordering
below exists because two of the six open pull requests are close to merge and the sync's
plan was to merge #21, align #20, then review #22.

Merging what is ready happens first, against `main`, before `integration` exists. Creating
`integration` from `main` afterward means the remaining pull requests retarget onto a branch
identical to their current base, so their diffs do not change and no contributor redoes any
work. Retargeting before those merges would put a branch move in front of a demo.

Retargeting is per pull request: #63, #24, #22, and #60 move to `integration` if still open,
and #20, the FAQ, may stay on `main` under the documentation lane. Whether a base change
re-triggers the required checks needs confirmation at the time rather than assumption, since
this repository's workflows declare no `pull_request` types and a base change fires an
`edited` event that the default type list does not include.

## Out of scope, with reasons

**The org-level project board.** The sync assigned this to Scott because creating a board is
an org-level operation. The label and milestone taxonomy here is designed to feed one, so
the board can be built without reworking anything. It is not a repository change and cannot
land tonight.

**Declarative logic CI for specification contradictions.** Ariel's Datalog proposal is a
real idea and a research task. Nothing about it is achievable before Thursday, and
scaffolding it badly would be worse than leaving it open.

**The label-strip enforcement workflow.** Reasoned through above. The structural fix is that
forms cannot stamp decision labels.

**Enforcing contributor role capacity.** The form closes roles at capacity through the form
tool, not through GitHub.

**The three open workstream lead seats.** A governance decision for the project lead, not a
repository change.

## Tracked follow-up

Each of these gets an issue filed as part of implementation, so nothing here depends on
somebody remembering this document exists.

1. Workstream vocabulary mismatch between `GOVERNANCE.md` and the plan's open lead seats
2. Label-strip enforcement workflow, if the permission lookup proves workable
3. Org-level project board fed by the label and milestone taxonomy
4. Declarative logic CI for specification contradiction detection
5. Release-branch versioning, since `sync_version.yml` moving to `integration` leaves the
   `release/*` case unspecified
6. The DCO CI check in #52 stays indifferent to non-sign-off trailers
