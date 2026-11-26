## What changed

<!-- One or two sentences. What does this PR do and why? -->

## Which issue does this implement

<!-- Write one spelling right before each issue number, on the same line.
     Close an issue this change completes with Closes, Fixes, or Resolves.
     Contribute to an issue without closing it with Part of, Refs, or Contributes to.
     The closing-choice check fails a reference with neither.

     A change that alters behavior, normative text, or adds code needs an issue carrying
     `status:accepted` that a lead assigned to you before you opened this PR. If no lead
     has assigned you yet, ask on the issue and wait for the assignment. A PR opened
     before the assignment is closed, and you can reopen it once a lead assigns the work.
     See "Start
     From an Assigned Issue" in Part 2 of CODE_OF_CONDUCT.md, and Current Priority Scope
     in CONTRIBUTING.md. -->

- [ ] This is an editorial correction (typo, grammar, link, formatting) with no change in
      meaning, so it needs no issue

## Base branch

- [ ] `integration`. Every pull request targets `integration`, documentation included.
      Only a promotion targets `main` (see CONTRIBUTING.md)

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
