# Contributing to ACS

We're building trustworthy AI agents together. Your contributions make the future of agent observability and control possible.

**Before spending lots of time on something, ask for feedback on your idea first!**

Search existing issues and pull requests to avoid duplicating efforts.

## Current Priority Scope

Reviewed at each milestone. Current window: Day 0 to Day 30. Next review October 9, 2026.

The project has one committed outcome:

> A runnable Guardian Agent reference implementation, benchmarked for interoperability
> against Microsoft Agent Governance Toolkit, in the hands of external evaluators within
> ninety days of the September 10, 2026 kick-off. Everything else either feeds that
> outcome or gets deferred.

Every issue and every pull request is accepted against that sentence. This section is the
only place that scope is stated, so if something here disagrees with a form, a template,
or a comment, this wins.

**In focus.** Work that feeds the runnable Guardian, the interoperability benchmark, or
the conformance evidence that makes either credible:

- The mandatory floor decision in PR #21, which gates everything behind it
- The Claude Code, Cursor, and NVIDIA NAT adapters in PR #22
- The AGT reference implementation in PR #60
- Ports of that reference implementation to other runtimes: Python, Go, Rust, Codex
- Production-hardening it, including span batching and OpenTelemetry collection
- Resolving the fail-open default, which issues #32 and #37 attack from opposite ends
- The ACS-Core conformance claim template
- The requirement ledger and behavioral tests in milestone #33
- Closing the Cursor file-read gap
- Conformance and dogfooding reports that document where ACS fails in practice

**Deferred to v0.2.0.** Real work, tracked, landing after Day 90: async and composition,
streaming, batching semantics, recursive ask, quorum, multi-tenant isolation, the Cedar
binding, and AgBOM federation across A2A peers. Negative conformance vectors sit here
too, in #53.

One distinction, because it will otherwise get argued in a pull request. *Batching
semantics in the specification* is deferred. *Batching in the reference implementation*
is in focus, because it is exactly the production-hardening the project asked for. The
two share a word and nothing else.

**Out of scope.** What ACS leaves to deployments by design: the policy engine, the
signature algorithm, the transport, the authentication mechanism, and the policy content.
The specification is opinionated on the contract and permissive on the implementation.
That is a position, not a gap waiting to be filled.

A proposal that is deferred or out of scope is still worth filing. It gets a label and a
tracking issue rather than a close, because a finding the project cannot act on this
quarter is not a finding without value.

## How work gets accepted

Anyone may open an issue. Only an issue carrying `status:accepted` enters the backlog,
and only a maintainer applies that label.

A pull request that changes behavior, alters normative text, or adds code references an
accepted issue. An editorial correction does not, wherever it lands: a typo, a grammar
fix, a broken link, or a formatting repair that leaves the meaning untouched needs no
issue.

If you open a pull request against an issue that is not accepted yet, it will not be
reviewed and nothing about it is rejected. It waits, and a comment will say so. A pull
request that sits untriaged for a long time may be closed with an invitation to reopen
once its issue is accepted. Start from an issue labeled `help wanted` if you want work
that is already accepted.

Maintainers apply `scope:`, `priority:`, `workstream:`, and `status:accepted`. No issue
form can apply them, which is what makes the rule hold rather than depend on everyone
remembering it.

## Code of Conduct

This project follows our [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## How to Contribute

**Ideas**: Join issue discussions or start new ones. Your voice shapes ACS direction.

**Writing**: Expand documentation with your expertise. Clear explanations help everyone.

**Copy Editing**: Fix typos, clarify language, improve quality. Every word matters. Follow our [styling guide](./STYLE.md).

**Code**: Implement specifications, build tools, create examples.

**Standards**: Help Improve ACS, extend CycloneDX, SPDX, SWID for agent components.

## Local Development

```bash
uv pip install -e .          # install dependencies
uv run mkdocs serve          # preview docs at http://localhost:8000
uv run mkdocs build          # build static docs
uv run pytest -v             # run the guards (same command CI runs)
```

The guards in `tests/` check things the build itself will not catch, including spec heading structure, published schema URIs, and the third-party asset rules for the site. They run in the `test` job of `deploy-pages.yml`, and the build job depends on them, so a failing guard blocks the deploy rather than shipping a broken page.

Put new guards in `tests/`. Collection is scoped there by `testpaths` in `pyproject.toml`, so a test written anywhere else never runs in CI and will pass review looking like coverage it does not provide. A suite that needs dependencies outside `uv.lock` belongs in its own workflow with its own environment, because the deploy gate installs only what the lockfile carries.

For prose contributions, follow the [editorial style guide](./STYLE.md). For schema contributions, validate `specification/v0.1.0/acs_schema.json` against the JSON Schema spec before submitting.

All submissions go through GitHub pull request review. See [GitHub's PR guide](https://docs.github.com/en/pull-requests) if you're new to the workflow.

## Development Process

1. **Fork the repository** and clone your fork
2. **Branch from `integration`.** Use `spec/`, `refimpl/`, `fix/`, or `docs/` followed by
   a short description
3. **Make your changes** following the style guide
4. **Sync with `integration` and run the guards** before you open anything. `uv run
   pytest -v` and `uv run mkdocs build --strict` both have to pass on your machine
5. **Sign your commits** with `git commit -s` (required by the DCO below)
6. **Open a pull request against `integration`**
7. **Address review feedback** to land your change

`integration` is the default branch, so a pull request opened from the GitHub interface
already targets it. `main` publishes the site and all 44 schema `$id` URIs on merge, so
it takes only two kinds of change: a promotion from `integration`, and an editorial
change to a path on the allowlist below. A guard enforces this and will tell you to
retarget if you get it wrong.

Paths that may target `main` directly: `docs/topics/`, `design/`, `docs/README.md`,
`README.md`, `CONTRIBUTORS.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`,
`SECURITY.md`, `STYLE.md`, `LICENSING.md`, and `NOTICE`. Everything else goes to
`integration`, including `docs/spec/`, `docs/concepts/`, `docs/identity/`, `mkdocs.yml`,
`overrides/`, `landing/`, `docs/stylesheets/`, and `docs/assets/`.

For changes to the spec itself (`acs_schema.json`, hooks, events), open a
[Discussion](https://github.com/GenAI-Security-Project/agent-control-standard/discussions)
before submitting a PR. These affect downstream implementers and warrant a longer
conversation.

## Authorship and AI assistance

Commits land under human authorship. The DCO below is a certification about the origin of
code, and only a person can make one, so every commit carries a `Signed-off-by` line
naming a human who takes responsibility for what the commit contains. That requirement
does not move.

The rest of the trailers are your call. Many contributors here write with AI assistance.
If you want to record that with a `Co-Authored-By` trailer naming the tool, keep it. If
you would rather not, leave it off. Maintainers will not add one and will not remove one,
and its presence has no effect on how a change is reviewed.

A trailer naming a model certifies nothing and moves no responsibility. The human on the
`Signed-off-by` line answers for the change either way. Some employers require their
people to disclose AI assistance, and a visible trailer is the simplest way to satisfy
that. ACS is also a standard about agent provenance, and a project built on the premise
that you should be able to see what an agent did has no business erasing the record of
what an agent did to its own commits.

## What We Need

Start with [issues labeled `help wanted`](https://github.com/GenAI-Security-Project/agent-control-standard/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).
Every one of them is already accepted, which means you can open a pull request against it
without waiting on triage.

The highest-value contribution right now is running ACS against a real harness and
documenting where it fails. Install the reference implementation, wire it to a coding
agent, and file a conformance report when the behavior and the specification disagree.
That is worth more to this project than a patch nobody asked for.

## Release Process

Project maintainers handle formal releases. Focus on contributing great features and fixes.

## Reporting Security Issues

**Do not file public issues for security vulnerabilities.** Use GitHub's [private vulnerability reporting](https://github.com/GenAI-Security-Project/agent-control-standard/security/advisories/new) to disclose privately. We'll acknowledge within 72 hours and coordinate a fix and disclosure timeline with you.

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

- (a) The contribution was created in whole or in part by me and I have the right to
  submit it under the open source license indicated in the file; or

- (b) The contribution is based upon previous work that, to the best of my knowledge, is
  covered under an appropriate open source license and I have the right under that license
  to submit that work with modifications, whether created in whole or in part by me, under
  the same open source license (unless I am permitted to submit under a different
  license), as indicated in the file; or

- (c) The contribution was provided directly to me by some other person who certified
  (a), (b) or (c) and I have not modified it.

- (d) I understand and agree that this project and the contribution are public and that a
  record of the contribution (including all personal information I submit with it,
  including my sign-off) is maintained indefinitely and may be redistributed consistent
  with this project or the open source license(s) involved.

By contributing, you agree that your contributions will be licensed under the license that governs the file you touch. Code and schemas fall under the [Apache License 2.0](./LICENSE). Documentation falls under [CC BY-SA 4.0](./LICENSE-DOCS). See [LICENSING.md](./LICENSING.md) for the scope map.

This guide is based on [github-contributing](https://raw.githubusercontent.com/standard/.github/refs/heads/master/CONTRIBUTING.md).

## Before the first Pages deploy

`.github/workflows/deploy-pages.yml` and `.github/workflows/monitor-pages.yml` both
assume GitHub Pages is already enabled for this repository. Until it is, the deploy fails
at the Configure Pages step and the monitor fails on its schedule.

Enabling it is a one-time repository setting, done by an administrator: Settings, then
Pages, then set Build and deployment Source to GitHub Actions. Do this before merging any
change that turns those workflows on, not after.

## Community

- **[GitHub Discussions](https://github.com/GenAI-Security-Project/agent-control-standard/discussions)**: Ask questions, share ideas
- **[Issues](https://github.com/GenAI-Security-Project/agent-control-standard/issues)**: Report bugs, request features

We're building the future of AI agent observability and control. Join us.
