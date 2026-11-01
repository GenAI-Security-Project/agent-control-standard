# Agent Instructions

Follow these rules before editing files, opening work, or reviewing changes in this repository. [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) own the underlying policies; when a rule here and its source disagree, the source wins.

## About this repository

The OWASP GenAI Security Project Agent Control Standard (ACS) is a wire specification. It lets a separate Guardian Agent inspect what an AI agent is about to do and permit, deny, or modify that action before it happens, over an authenticated channel, with an audit trail that reconstructs after the fact. The agent under watch is the Observed Agent. ACS groups its capabilities into three pillars: Instrument (hooks), Trace (events), and Inspect (the Agent Bill of Materials, or AgBOM).

Contributor work lands on `integration`, the default branch. On it:

- `docs/spec/` holds the specification text, one directory per pillar, plus the conformance requirements in `docs/spec/conformance.md`.
- `specification/` holds the JSON schemas. Each schema sits at the path its `$id` declares.
- `docs/` holds the documentation site that `mkdocs.yml` builds. The decision log is `docs/decisions/index.md`.
- `reference-implementations/` holds the Guardian reference implementations.
- `adapters/` holds the reference adapters that connect agent frameworks to a Guardian, with an example Guardian and their own conformance suite.
- `tests/` holds the repository guards CI runs.
- `tools/` holds the scripts the workflows call, such as schema publishing and pull request intake, plus a few maintainer tools.

Read [README.md](./README.md) and [Core Concepts](./docs/topics/core_concepts.md) for detail. The release version lives in `version.txt` and the spec version in each schema's `$id`. They can differ, so never state one as the other.

## Start with CONTRIBUTING.md

Read [CONTRIBUTING.md](./CONTRIBUTING.md) before starting work. Pay close attention to:

- [Current Priority Scope](./CONTRIBUTING.md#current-priority-scope) to confirm work belongs in focus
- [How work gets accepted](./CONTRIBUTING.md#how-work-gets-accepted) before writing code or opening a pull request
- [Authorship and AI assistance](./CONTRIBUTING.md#authorship-and-ai-assistance) for sign-off and disclosure rules

Never file a public issue or pull request for a suspected security vulnerability. Report it privately through [SECURITY.md](./SECURITY.md).

## Human accountability and workflow rules

1. **A person answers for everything.** Do not open a pull request, file an issue, submit a review, post a comment, or mutate upstream repository or workflow state (such as direct pushes, `gh` mutations, or workflow reruns) unless the person running you approves that specific action. Nothing posts or mutates upstream unattended. Before marking a pull request ready for review, the human author must be able to explain every change without the tool. See [Answer for Your Account](./CODE_OF_CONDUCT.md#answer-for-your-account) and [Authorship and AI assistance](./CONTRIBUTING.md#authorship-and-ai-assistance).
2. **Work starts from an assigned issue.** Any pull request that changes behavior, normative text, or code requires an issue labeled `status:accepted` that a project or workstream lead assigned to the contributor before the pull request opens. Editorial fixes—typos, grammar, broken links, and formatting that leave meaning unchanged—need no issue. A pull request opened before the assignment gets closed, with an invitation to reopen once a lead assigns the work. See [Start From an Assigned Issue](./CODE_OF_CONDUCT.md#start-from-an-assigned-issue), [How work gets accepted](./CONTRIBUTING.md#how-work-gets-accepted), and [Triage authority](./GOVERNANCE.md#triage-authority).
3. **Spec changes start as a Discussion.** Start changes to the JSON schemas, hook set, or event catalog in [GitHub Discussions](https://github.com/GenAI-Security-Project/agent-control-standard/discussions), not a pull request. Load [SPEC_REVIEW_PRINCIPLES.md](./SPEC_REVIEW_PRINCIPLES.md) when designing or critiquing specification changes. See [Development Process](./CONTRIBUTING.md#development-process).
4. **No bulk activity.** Post one item at a time, and keep open pull requests and assigned issues within the limits in [Keep Your Queue Small](./CODE_OF_CONDUCT.md#keep-your-queue-small). Do not batch-open issues, pull requests, reviews, or comments.

## Commits and branches

- **Base contributor pull requests on `integration`.** Only the editorial allowlist in [Development Process](./CONTRIBUTING.md#development-process) targets `main` directly; project leads promote `integration` to `main`. A pull request that adds a documentation page updates `mkdocs.yml`, so it targets `integration`.
- **Keep DCO sign-off with the human contributor.** Every commit carries a `Signed-off-by` trailer (`git commit -s`) naming the person certifying the [Developer's Certificate of Origin 1.1](./CONTRIBUTING.md#developers-certificate-of-origin-11). Only a human can make that certification: never put a tool, model, or bot identity in `Signed-off-by`, and do not sign off a commit under a person's name unless they reviewed and approved it. See [How to sign your commits](./CONTRIBUTING.md#how-to-sign-your-commits).
- **Tool trailers stay optional.** Keep or omit a `Co-Authored-By` trailer naming a tool based on the contributor's preference. See [Authorship and AI assistance](./CONTRIBUTING.md#authorship-and-ai-assistance).
- **Follow the editorial style guide.** Every prose edit—documentation, specifications, and comments—follows [STYLE.md](./STYLE.md).

## Run checks before proposing a pull request

Run the repository guards locally before asking a person to open a pull request:

```bash
uv run pytest -v
uv run mkdocs build --strict
```

For changes under `adapters/`, also run the adapter conformance suite in its own `uv` environment as described in [Local Development](./CONTRIBUTING.md#local-development). Put any new repository guards in `tests/`, where `pyproject.toml` collects them for CI.

## Review guidelines

Approve or request changes only when the pull request's author or a lead asked for the review, or when the person running you is a code owner for the changed paths. Anyone may leave a comment review that reports a specific finding someone else can reproduce. Review one pull request at a time, and post nothing until the person running you approves it. See [Review When Asked, and Show Your Work](./CODE_OF_CONDUCT.md#review-when-asked-and-show-your-work).

A summary of the diff is not a review. Every approval states:

- **Commit reviewed:** exact commit SHA inspected
- **Checks run:** commands executed and their outcome (or `none`)
- **Not checked:** areas, environments, or paths left unverified

When reviewing specification or schema changes, apply [SPEC_REVIEW_PRINCIPLES.md](./SPEC_REVIEW_PRINCIPLES.md). When reviewing prose, check it against [STYLE.md](./STYLE.md).

## Repository invariants

Preserve these operational rules when touching site builds, metadata, or schemas:

- **Hosting and `mkdocs.yml`:** `.github/workflows/deploy-pages.yml` builds the landing page (`landing/`), MkDocs documentation (`/docs/`), and JSON schemas (`/schema/<spec-version>/`) for **owaspacs.org**, the project's only site. Never name or link an earlier project domain in this repository, an issue, a pull request, or a discussion. `mkdocs.yml` is a landing build input whose values are escaped as untrusted text. Verify published schemas at their `github.io` `$id` URIs so the 301 redirect is tested, and verify site navigation directly at `https://owaspacs.org/` rather than through the redirect (see [`.github/workflows/monitor-pages.yml`](./.github/workflows/monitor-pages.yml)).
- **Deploy rollback:** Before a maintainer re-runs an older Pages deploy, they must set `gh variable set ROADMAP_REFRESH_ENABLED --body false` so the 05:15 UTC nightly job does not redeploy `main`. Expect the navigation job in [`.github/workflows/monitor-pages.yml`](./.github/workflows/monitor-pages.yml) to stay red until the revert reaches `main`; re-enable the variable only after the revert deploys. If navigation verification fails right after a green deploy, wait for edge cache refresh, re-run once, and read the step summary.
- **Contact channels:** `rock.lambros@owasp.org` is the sole contact address carried by this repository (see [`SECURITY.md`](./SECURITY.md), [`landing/index.html`](./landing/index.html), and [`tests/test_landing_page.py`](./tests/test_landing_page.py)). Add no other contact addresses to docs, `project.owasp.yaml`, or site config, and keep conduct reports on [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md). Use RFC 2606 reserved domains (`example.com`, `example.net`, `example.org`) for examples.
- **Schema `$id` namespace:** Keep every schema `$id` under `https://genai-security-project.github.io/agent-control-standard/schema/<spec-version>/`—never rebase `$id` onto `owaspacs.org` or another domain—place each schema at the exact path its `$id` declares under `specification/`, and keep internal `$ref`s relative so all schemas share one base. Version `$id` by **spec** version rather than release version ([`.github/workflows/sync_version.py`](./.github/workflows/sync_version.py) leaves `$id` alone). [`tools/publish_schemas.py`](./tools/publish_schemas.py) and [`tests/test_publish_schemas.py`](./tests/test_publish_schemas.py) enforce the `$id` base, publish-path match, and resolution of references inside the ACS namespace.
