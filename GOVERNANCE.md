# Governance

ACS is an OWASP project. This file records who leads the work, which workstream owns which surface, and how leadership changes.

## Project leads

| Role | Name |
| --- | --- |
| Project Lead | Rock Lambros ([@rocklambros](https://github.com/rocklambros)) |
| Project Lead | Ariel Fogel ([@afogel](https://github.com/afogel)) |
| Project Lead | Bar Kaduri ([@bar-capsule](https://github.com/bar-capsule)) |

## Workstream leads

Each workstream owns a slice of the standard and runs its own review. Two leads per
workstream keeps decisions moving when one is unavailable.

Reference Implementation and Documentation run with one lead each so far. The work in each
continues, but it carries a single point of failure until somebody takes the second seat.

There is no Testing and Validation workstream for now. Whoever reviews a change checks it
against the conformance requirements it touches.

| Workstream | Leads |
| --- | --- |
| Coding Agents | Almog Langleben ([@almogbhl](https://github.com/almogbhl)), Stefano Amorelli ([@stefanoamorelli](https://github.com/stefanoamorelli)) |
| Development (SDK) | Rock Lambros ([@rocklambros](https://github.com/rocklambros)), Fred Wilmot ([@fewdisc](https://github.com/fewdisc)) |
| Documentation | Lance Dye ([@Lrd0036](https://github.com/Lrd0036)) |
| Identity | Eva Benn ([@evabenn](https://github.com/evabenn)), Richard Bird ([@RbBuiltWrong](https://github.com/RbBuiltWrong)) |
| Outreach | Eva Benn ([@evabenn](https://github.com/evabenn)), Aruneesh Salhotra ([@aruneeshsalhotra](https://github.com/aruneeshsalhotra)) |
| Reference Implementation | Evgeniy Kokuykin ([@artmaro](https://github.com/artmaro)) |
| Spec | Bar Kaduri ([@bar-capsule](https://github.com/bar-capsule)), Ariel Fogel ([@afogel](https://github.com/afogel)) |

## Triage authority

Workstream leads and the project leads apply the decision labels `scope:`, `priority:`, and
`workstream:`. No issue form can apply one.

Anyone holding the repository's `triage` role or higher accepts an issue, either by
applying `status:accepted` or by setting a milestone. The roadmap sync applies
`status:accepted` to a milestoned issue, so the two mean the same thing.

A workstream lead or a project lead may assign a volunteer or contributor to triage
alongside them. An assigned volunteer applies any label, decision labels included, and the
lead who assigned them reviews those calls and owns them. A project lead grants them the
repository's `triage` role and write access to the
[project board](https://github.com/orgs/GenAI-Security-Project/projects/9), and lists them
under Triage volunteers below.

An issue counts as delivered when the change that closed it is on `main`. A close with no
pull request or commit behind it counts as delivered only when a project lead made it.
Anyone else's such close waits for a project lead to confirm it.

Minimum triage on a new issue is two labels, `scope:` and `status:`. `priority:` and
`workstream:` are enrichment applied to accepted work. Requiring four decisions per issue
is how a taxonomy stops getting used in month two.

`priority:P0` is reserved for work on the serial chain the Strategic Adoption Plan names:
the mandatory floor decision, the adapters, the installable Guardian, and the
interoperability benchmark. It does not mean important.

Triage runs on the weekly call. Promotion from `integration` to `main` is a standing item
on the same call, and a project lead opens and merges it.

The pinned "Roadmap health" issue, rewritten nightly by the roadmap sweep, is the weekly
call's triage agenda.

Repository admins can bypass the rulesets on `main`, `integration`, and `release/*`. The
health issue reports every bypassed merge and every direct push.

## Triage volunteers

A project lead adds a row when a volunteer accepts the `triage` role, and removes it when
they step back.

| Volunteer | Assigned by |
| --- | --- |
| Victor Hernandez ([@victorm-hernandez](https://github.com/victorm-hernandez)) | Rock Lambros |

## Origins

Michael Bargury ([@mbrg](https://github.com/mbrg)) and Ory Segal ([@oorryy](https://github.com/oorryy)) created ACS. Both remain project leaders.

## Why this roster and project.owasp.yaml differ

`project.owasp.yaml` feeds the OWASP Nest project index. Its schema caps `leaders` at five entries and gives each person a name, an email, a GitHub handle, and a Slack handle. No field carries a role, a workstream, or a founding credit.

That file therefore names five people: the three project leads and the two creators, which fills the cap. This file is the authoritative roster.

## How leadership changes

Existing leads propose additions and removals. The project leads confirm the change, then one of them opens a pull request that updates this file and `.github/CODEOWNERS` together. When the change touches a project lead or a creator, the same pull request updates `project.owasp.yaml`, since those are the only people it names.

The CODEOWNERS update is not optional. A lead who loses write access stops being a valid owner, and GitHub fails the entry silently rather than flagging it.

## Related

- [CONTRIBUTING.md](./CONTRIBUTING.md) covers how to get involved.
- [CONTRIBUTORS.md](./CONTRIBUTORS.md) credits contribution, not role.
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) applies to everyone here, leads included.
