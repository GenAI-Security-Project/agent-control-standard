# Governance

ACS is an OWASP project. This file records who leads the work, which workstream owns which surface, and how leadership changes.

## Project lead

| Role | Name |
| --- | --- |
| Project Lead | Rock Lambros ([@rocklambros](https://github.com/rocklambros)) |

## Workstream leads

Each workstream owns a slice of the standard and runs its own review. Two leads per
workstream keeps decisions moving when one is unavailable.

Identity currently runs with one lead. That second seat is open, and it is open in the
same sense as the Reference Implementation, Documentation, and Testing and Validation
seats: the work continues, and a single point of failure sits on it until somebody
takes it.

| Workstream | Leads |
| --- | --- |
| Coding Agents | Almog Langleben ([@almogbhl](https://github.com/almogbhl)), Stefano Amorelli ([@stefanoamorelli](https://github.com/stefanoamorelli)) |
| Development (SDK) | Rock Lambros ([@rocklambros](https://github.com/rocklambros)), Fred Wilmot ([@fewdisc](https://github.com/fewdisc)) |
| Identity | Richard Bird ([@RbBuiltWrong](https://github.com/RbBuiltWrong)) |
| Outreach | Eva Benn ([@evabenn](https://github.com/evabenn)), Aruneesh Salhotra ([@aruneeshsalhotra](https://github.com/aruneeshsalhotra)) |
| Spec | Bar Kaduri ([@bar-capsule](https://github.com/bar-capsule)), Ariel Fogel ([@afogel](https://github.com/afogel)) |

## Triage authority

Workstream leads and the project lead apply the decision labels: `scope:`, `priority:`,
`workstream:`, and `status:accepted`. Nobody else does, and no issue form can.

Minimum triage on a new issue is two labels, `scope:` and `status:`. `priority:` and
`workstream:` are enrichment applied to accepted work. Requiring four decisions per issue
is how a taxonomy stops getting used in month two.

`priority:P0` is reserved for work on the serial chain the Strategic Adoption Plan names:
the mandatory floor decision, the adapters, the installable Guardian, and the
interoperability benchmark. It does not mean important.

Triage runs on the weekly call. Promotion from `integration` to `main` is a standing item
on the same call, and the project lead owns merging it.

## Origins

Michael Bargury ([@mbrg](https://github.com/mbrg)) and Ory Segal ([@oorryy](https://github.com/oorryy)) created ACS. Both remain project leaders.

## Why this roster and project.owasp.yaml differ

`project.owasp.yaml` feeds the OWASP Nest project index. Its schema caps `leaders` at five entries and gives each person a name, an email, a GitHub handle, and a Slack handle. No field carries a role, a workstream, or a founding credit.

That file therefore names three people: the project lead and the two creators. This file is the authoritative roster.

## How leadership changes

Existing leads propose additions and removals. The project lead confirms the change, then opens a pull request that touches this file, `project.owasp.yaml`, and `.github/CODEOWNERS` together.

The CODEOWNERS update is not optional. A lead who loses write access stops being a valid owner, and GitHub fails the entry silently rather than flagging it.

## Related

- [CONTRIBUTING.md](./CONTRIBUTING.md) covers how to get involved.
- [CONTRIBUTORS.md](./CONTRIBUTORS.md) credits contribution, not role.
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) applies to everyone here, leads included.
