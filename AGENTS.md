# Agent Instructions

Follow these rules before editing files, opening work, or reviewing changes in this repository. [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) own the underlying policies; when a rule here and its source disagree, the source wins.

## Start with CONTRIBUTING.md

Read [CONTRIBUTING.md](./CONTRIBUTING.md) before starting work. Pay close attention to:

- [Current Priority Scope](./CONTRIBUTING.md#current-priority-scope) to confirm work belongs in focus
- [How work gets accepted](./CONTRIBUTING.md#how-work-gets-accepted) before writing code or opening a pull request
- [Authorship and AI assistance](./CONTRIBUTING.md#authorship-and-ai-assistance) for sign-off and disclosure rules

Never file a public issue or pull request for a suspected security vulnerability. Report it privately through [SECURITY.md](./SECURITY.md).

## Human accountability and workflow rules

1. **A person answers for everything.** Do not open a pull request, file an issue, submit a review, post a comment, or mutate upstream repository or workflow state (such as direct pushes, `gh` mutations, or workflow reruns) unless the person running you approves that specific action. Nothing posts or mutates upstream unattended. Before marking a pull request ready for review, the human author must be able to explain every change without the tool. See [Authorship and AI assistance](./CONTRIBUTING.md#authorship-and-ai-assistance) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
2. **Work starts from an assigned issue.** Any pull request that changes behavior, normative text, or code requires an issue labeled `status:accepted` that a project lead assigned to the contributor before the pull request opens. Editorial fixes—typos, grammar, broken links, and formatting that leave meaning unchanged—need no issue. See [How work gets accepted](./CONTRIBUTING.md#how-work-gets-accepted) and [Triage authority](./GOVERNANCE.md#triage-authority).
3. **Spec changes start as a Discussion.** Start changes to the JSON schemas, hook set, or event catalog in [GitHub Discussions](https://github.com/GenAI-Security-Project/agent-control-standard/discussions), not a pull request. Load [SPEC_REVIEW_PRINCIPLES.md](./SPEC_REVIEW_PRINCIPLES.md) when designing or critiquing specification changes. See [Development Process](./CONTRIBUTING.md#development-process).
4. **No bulk activity.** Work on one item at a time and keep a small queue of open items. Do not batch-open issues, pull requests, or comments. See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) for conduct and participation limits.

## Commits and branches

- **Base pull requests on `integration`.** Only the narrow editorial allowlist in [Development Process](./CONTRIBUTING.md#development-process) targets `main`. A pull request that adds a documentation page updates `mkdocs.yml`, so it targets `integration`.
- **Sign every commit as a human.** Every commit carries a `Signed-off-by` trailer (`git commit -s`) naming the person certifying the [Developer's Certificate of Origin 1.1](./CONTRIBUTING.md#developers-certificate-of-origin-11). Never put a tool, model, or bot identity in `Signed-off-by`. See [How to sign your commits](./CONTRIBUTING.md#how-to-sign-your-commits).
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

Review a pull request only when a person explicitly asks you to review it. See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

A summary of the diff is not a review. Every review or approval states:

- **Commit reviewed:** exact commit SHA inspected
- **Checks run:** commands executed and their outcome (or `none`)
- **Not checked:** areas, environments, or paths left unverified

When reviewing specification or schema changes, apply [SPEC_REVIEW_PRINCIPLES.md](./SPEC_REVIEW_PRINCIPLES.md). When reviewing prose, check it against [STYLE.md](./STYLE.md).

## Repository invariants

Preserve these operational rules when touching site builds, metadata, or schemas:

- **Hosting and `mkdocs.yml`:** `.github/workflows/deploy-pages.yml` builds the landing page (`landing/`), MkDocs documentation (`/docs/`), and JSON schemas (`/schema/<spec-version>/`) for **owaspacs.org**. `mkdocs.yml` is a landing build input whose values are escaped as untrusted text. **agentcontrolstandard.org** is a separate repository; nothing here publishes to it.
- **Deploy rollback:** Before a maintainer re-runs an older Pages deploy, they must set `gh variable set ROADMAP_REFRESH_ENABLED --body false` so the 05:15 UTC nightly job does not redeploy `main`. Expect the navigation job in `monitor-pages.yml` to stay red until the revert reaches `main`, then re-enable the variable. If navigation verification fails right after a green deploy, wait for edge cache refresh, re-run once, and read the step summary.
- **Contact channels:** `rock.lambros@owasp.org` is the sole contact address carried by this repository (on the landing page). Add no other contact addresses to docs, `project.owasp.yaml`, or site config. Use RFC 2606 reserved domains (`example.com`, `example.net`, `example.org`) for examples.
- **Schema `$id` namespace:** Keep every schema `$id` under `https://genai-security-project.github.io/agent-control-standard/schema/<spec-version>/`—never rebase `$id` onto `owaspacs.org` or another domain. Keep every `$ref` relative so all schemas share one base, place each schema at the exact path its `$id` declares under `specification/`, and version `$id` by **spec** version rather than release version.
