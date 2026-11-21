# Security Policy

ACS is a specification, and this repository also ships code people install and run: hook adapters, three Guardians, and a gateway that sits between an agent and its model. Report anything you find. A flaw in the specification propagates into every implementation that follows it, and a flaw in the code reaches every developer who wires it into an agent.

## Report a vulnerability

**Do not open a public issue.**

Use GitHub's [private vulnerability reporting](https://github.com/GenAI-Security-Project/agent-control-standard/security/advisories/new). Reports land with the maintainers and stay private until a fix ships.

Include what you have:

- What you found and where, with a file path or a link to the specific line
- How to reproduce it, or the reasoning chain if the flaw is in the specification rather than in code
- What an attacker gains
- Any suggested fix

Partial reports are welcome. We would rather triage something incomplete than never hear about it.

## Security contact

Rock Lambros ([rock.lambros@owasp.org](mailto:rock.lambros@owasp.org)) is the project's named security contact. Send reports through private vulnerability reporting above, so every maintainer sees them and the report stays tracked. Write to this address to reach a person about a report you already filed, or if private vulnerability reporting is unavailable to you.

## What is in scope

| In scope | Out of scope |
| --- | --- |
| Flaws in the ACS specification that lead implementers into insecure designs | The marketing site at agentcontrolstandard.org, which is built and deployed from a separate repository |
| Errors in the JSON Schemas under `specification/` | Findings against third-party agent frameworks that happen to implement ACS |
| The build and publish tooling in `tools/` and the GitHub Actions workflows in `.github/workflows/` | Automated scanner output with no demonstrated impact |
| Hook or event definitions that leak sensitive data by design | Missing security headers on sites we do not operate |
| Supply-chain issues in this repository's dependencies | Social engineering of maintainers or contributors |
| The published site at owaspacs.org, including the landing page, the documentation, and the schema endpoints | Missing security response headers on the Pages site, which GitHub Pages does not allow us to set |
| The code under `adapters/` and `reference-implementations/`: the hook adapters, the example Guardian, the gateway, `acs-verify`, and the TypeScript and Go Guardians, all runnable code people install and wire into a live development environment | Gaps an implementation documents about itself, which are tracked as issues rather than handled as reports |

Specification flaws are welcome here too. If a hook definition forces implementers to log secrets, or an event schema makes an authorization bypass easy to write, please tell us, even though no code here executes.

Code here does execute. The adapters under `adapters/` install hooks into a coding agent,
the gateway there listens on the network and can hold a model API key, and the Guardians
under `adapters/` and `reference-implementations/` run as their own processes. A report
against any of them is in scope on the same terms as everything else above. Read the
documents that state each one's limits first. `adapters/SECURITY.md` is the threat model for
everything under `adapters/`. `reference-implementations/README.md` lists the expectations
each Guardian does not meet yet, among them that the TypeScript Guardian under
`reference-implementations/agt/` neither signs nor rejects replayed requests. A report that
restates a documented gap is better filed as an issue where the discussion is public.

## Response times

We try to acknowledge reports within about a week, and we work with you on timing from there. We will publish response SLAs with version 1.0.

We use [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) for severity.

## Coordinated disclosure

We fix reports in a public pull request, and we agree the timing with you first. Starting at version 1.0, we publish an advisory when a finding needs one. If a fix takes longer than expected, we tell you why.

Tell us if you want credit and how. If you say nothing, we leave your name out.

If you believe a finding is being actively exploited, say so in the report. That moves it to the front of the queue.

## Safe harbor

We will not pursue or support legal action against research conducted under this policy, provided you:

- Report through the private channel above and give us a reasonable chance to fix the issue before disclosing it. If we stop replying, you have given us that chance.
- Avoid privacy violations, data destruction, and interruption of any service
- Access only the minimum data needed to demonstrate the finding, and delete it once you have reported
- Do not exploit a finding beyond what proving it requires

Work in good faith under these terms and we treat your research as authorized. If a third party brings action against you for research that followed this policy, we will make that authorization clear.

## Signing and provenance

Contributors sign off commits under the Developer Certificate of Origin. See [CONTRIBUTING.md](./CONTRIBUTING.md).

Report suspected compromise of a maintainer account or a release artifact through the private channel above, marked urgent.
