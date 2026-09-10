## What changed

<!-- One or two sentences. What does this PR do and why? -->

## Which issue does this implement

Closes #

<!-- A change that alters behavior, normative text, or adds code needs an issue carrying
     `status:accepted`. If yours is not accepted yet, open the PR anyway. It will wait
     rather than be closed. See Current Priority Scope in CONTRIBUTING.md. -->

- [ ] This is an editorial correction (typo, grammar, link, formatting) with no change in
      meaning, so it needs no issue

## Base branch

- [ ] `integration`, because this touches the specification, schemas, a reference
      implementation, an adapter, tests, or CI
- [ ] `main`, because every changed path is on the documentation lane allowlist in
      CONTRIBUTING.md

## Type of change

- [ ] Specification change (schema, hooks, events, AgBOM)
- [ ] Reference implementation or adapter
- [ ] Documentation
- [ ] Tooling or CI
- [ ] Governance (licensing, security policy, contributor docs)

## Specification changes

<!-- Delete this section if you touched nothing under specification/ or docs/spec/. -->

- [ ] I opened a [Discussion](https://github.com/GenAI-Security-Project/agent-control-standard/discussions) before this PR
- [ ] Schema changes validate against the JSON Schema spec
- [ ] I described the impact on downstream implementers below

**Breaking for implementers?** <!-- yes or no, and what breaks -->

## I tested this

- [ ] I synced my branch with the base branch before opening this
- [ ] `uv run pytest -v` passes on my machine
- [ ] `uv run mkdocs build --strict` passes on my machine

<!-- These three are the difference between a review and a debugging session. A PR that
     has not been run is not ready for someone else's afternoon. -->

## Checklist

- [ ] Commits are signed off with `git commit -s` (required by the DCO)
- [ ] Prose follows [STYLE.md](../STYLE.md)
- [ ] No secrets, tokens, or internal URLs in the diff

## Security

- [ ] This change has no security impact

<!-- If it does, describe it. Do not open a PR for an unreported vulnerability.
     Report it privately first: see SECURITY.md. -->
