# Contributing to ACS

We're building trustworthy AI agents together. Your contributions make the future of agent observability and control possible.

**Before spending lots of time on something, ask for feedback on your idea first!**

Search existing issues and pull requests to avoid duplicating efforts.

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

For changes under `adapters/` (the reference adapters, example Guardian, and their test suites), run the adapter conformance gate before opening a PR — it lives in its own workflow (`.github/workflows/adapter_tests.yml`) with its own environment, per the rule above:

```bash
pip install -r adapters/requirements-test.txt
cd adapters
python3 run_conformance.py claude cursor     # shared Guardian checks + those adapter suites
# NAT needs the NVIDIA runtime; run its suite with an interpreter that has
# nvidia-nat-core installed (see adapters/nat/requirements.txt):
python3 run_conformance.py claude cursor nat
```

The command reports passes, skips, and failures separately, and fails on any failure or unexpected skip. See `adapters/README.md` for what the suite proves and its scope.

For prose contributions, follow the [editorial style guide](./STYLE.md). For schema contributions, validate `specification/v0.1.0/acs_schema.json` against the JSON Schema spec before submitting.

All submissions go through GitHub pull request review. See [GitHub's PR guide](https://docs.github.com/en/pull-requests) if you're new to the workflow.

## Development Process

1. **Fork the repository** and clone your fork
2. **Create a feature branch.** Use `feature/<short-description>` or `fix/<short-description>`
3. **Make your changes** following the style guide
4. **Sign your commits** with `git commit -s` (required by the DCO below)
5. **Open a pull request** against `main`
6. **Address review feedback** to land your change

For changes to the spec itself (`acs_schema.json`, hooks, events), open a [Discussion](https://github.com/GenAI-Security-Project/agent-control-standard/discussions) before submitting a PR. These affect downstream implementers and warrant a longer conversation.

Commits land under human authorship. Many of us write with AI assistance, and the project takes no position on which tools you use. The sign-off is what matters here. The DCO below is a certification a person makes about the origin of the code, and only a person can make it. Keep your `Signed-off-by` line, and leave AI tools out of the commit trailers. If a `Co-Authored-By` naming a model reaches a pull request, a maintainer drops it when the pull request is squashed, and your authorship and sign-off carry through unchanged.

## What We Need

**High Priority:**
Look for unassigned [Open Issues](https://github.com/GenAI-Security-Project/agent-control-standard/issues).

**Always Welcome:**
- Documentation improvements
- Real-world use case examples
- Security analysis and feedback
- Performance optimizations

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
