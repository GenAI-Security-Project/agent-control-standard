# Roadmap rollout: decisions, follow-up changes, and the milestone migration

Version: 1.1
Owner: ACS project leads
Date: 2026-10-04
Status: design, premortem round 1 folded in

Phase 0 of the roadmap merged as #201 and reached `main` with promotion #203. It is inert
until three repository variables are set. This document records the project leads' answers to
the open decisions in `design/2026-10-04-roadmap-page-design.md`, specifies the changes those
answers require, and orders the work that turns the roadmap on.

Two constraints govern every choice below. ACS is a volunteer project, so dates slip and a
target moves with one edit. Nothing here may depend on an OWASP org owner acting, so every
control is one a project lead can set at the repository level.

## Decisions

All eleven decisions from "Decisions for the project lead" were answered on October 4, 2026.

| # | Decision | Answer |
| --- | --- | --- |
| 1 | Phase 0 before the custom page | Phase 0, already merged |
| 2 | "Closes #N" for accepted work | Adopted and enforced. A required check on `integration` makes every pull request that references an accepted issue choose between closing it and contributing to it |
| 3 | Does setting a milestone accept an issue | Yes, for anyone holding the triage role or higher. GOVERNANCE.md and the README change to say so |
| 4 | Whose closes count as delivered | CODEOWNERS, the GOVERNANCE.md lead tables, and a new Triage volunteers table |
| 5 | OWASP sheet columns | Initiative is the Agentic Security Initiative, in the sheet's dropdown spelling. Workstream Name is Agent Control Standard. Workstream Lead is the three project leads. Initiative Co-Owners copies the value the sheet's other Agentic Security Initiative rows carry |
| 6 | Day N milestones | Deleted after migration |
| 7 | Whether #178's taxonomy is adopted | Not decided. The roadmap keeps today's labels, and #178 stays out of every milestone |
| 8 | Q4 2026 targets | All eight stay in Q4 2026. Targets move with one UI edit whenever capacity changes |
| 9 | `pull-requests: read` on the sweep | Granted, with the on-`main` verification built |
| 10 | Who closes a milestone | Any of the three project leads, once its work is on `main` |
| 11 | Rulesets | `main` takes merge commits only. A project lead or an OWASP org owner must approve changes to the roster files |

Decision 10 came with a leadership change: the project leads are now Rock Lambros, Ariel Fogel,
and Bar Kaduri.

Four further decisions came out of the first premortem round, on October 4, 2026.

- **Admin bypass stays.** Admins keep `bypass_mode: always` on every ruleset, which is how
  most merges land today. Decisions 2 and 11 therefore bind contributors. The nightly sweep
  lists every pull request merged without an approving review, so a bypass is visible on the
  weekly call.
- **Promotion is prompted, not automated.** The org policy that blocks Actions from opening
  pull requests stays as it is. The health issue says when `integration` is ahead of `main`
  and gives the command, and a project lead opens and merges the promotion.
- **Contribution spellings.** A pull request closes an accepted issue with `Closes`, `Fixes`,
  or `Resolves`, or contributes to it with `Part of`, `Refs`, or `Contributes to`. The check
  enforces the choice, and CONTRIBUTING.md and the pull request template teach it.
- **No org-owner requests.** The earlier request to Scott Clinton is withdrawn. The roster
  rule uses CODEOWNERS lines instead of a team, because creating a team that holds
  non-members needs an org owner.

## Already done

- Promotion #203 was opened by hand and merged, so `main` carries phase 0.
- Akira Brand was invited with the triage role on October 4. The invitation expires on
  October 12 and was still pending when this version was written.
- Victor Hernandez holds the triage role.
- Project board 9 write access for Victor Hernandez and Akira Brand was granted on October 4.
- Scott's OWASP sheet carries hand-entered ACS rows that link to the repository's milestones
  page.

## Work packages

### A. Leadership and roster

GOVERNANCE.md requires a leadership change to update its files together, so A lands as one
change.

- GOVERNANCE.md, "## Project lead" becomes "## Project leads", with three rows in the existing
  linked-handle format: Rock Lambros, Ariel Fogel, and Bar Kaduri.
- GOVERNANCE.md gains a "## Triage volunteers" section after Triage authority, holding a table
  with two columns, Volunteer and Assigned by. Victor Hernandez (@victorm-hernandez) is listed,
  assigned by Rock Lambros. Akira Brand is added only after the invitation is accepted, in the
  same pull request if that happens before it merges, otherwise in a follow-up.
- Every sentence that gives "the project lead" a duty becomes "a project lead" or "the project
  leads", as the duty requires. Today those are the Triage authority paragraphs, the promotion
  sentence, "Why this roster and project.owasp.yaml differ", and "How leadership changes".
- Triage authority gains two sentences. Setting a milestone on an issue accepts it, unless a
  standing triage label says otherwise. Any project lead closes a roadmap milestone once its
  work is on `main`.
- GOVERNANCE.md states that admins can bypass every ruleset, and that the health issue lists
  each merge made without an approving review.
- README.md: "Only a maintainer can move an issue to `status:accepted`" becomes a sentence
  saying anyone with the triage role or higher accepts an issue, by applying the label or by
  setting a milestone.
- `project.owasp.yaml` lists five leaders: the three project leads and the two creators. Its
  comment changes from "the project lead and the two creators" to match. Five is the schema's
  cap, so a sixth leader can never be added here.
- CODEOWNERS: the header names the project leads, and the pending-invitation comment states the
  current state, which is that the three lapsed Identity and Outreach invitations are not being
  re-sent. A new `/project.owasp.yaml` line carries the roster owners (see E).
- `tools/roadmap_model.py`:
  - `parse_governance` reads "Project leads" and also accepts the old "Project lead" heading,
    so the parser works on either side of the merge.
  - It parses the Triage volunteers table into the trusted set. The table may have no rows.
    Each Volunteer cell must be one linked handle, with the same strict link checks the lead
    tables get. Each Assigned by cell must name a project lead or workstream lead already in
    the roster, by name or handle. Any other cell shape raises, and the trusted set falls back
    to the safe failure the sweep already uses.
  - `roadmap_sync._sweep` loads the roster inside its `try`, so a malformed GOVERNANCE.md
    degrades the health issue instead of crashing the job.
  - Tests cover both headings, a populated table, an empty table, a malformed Volunteer cell,
    and an assigner who is not in the roster.

`tools/render_landing.py` reads only the Workstream leads table. A test confirms the landing
render still passes with the new sections.

### B. OWASP skill mapping

The skill lives in `~/.claude/skills/owasp-acs-roadmap`, outside the repository. Its columns
follow decision 5.

- The written Initiative value and the row filter are separate constants. `INITIATIVE` becomes
  the dropdown value `Agentic Security Initaitive`, with a comment naming the misspelling so the
  value changes in one place if OWASP fixes the list. The filter that finds this project's rows
  matches `Workstream Name == "Agent Control Standard"`. Filtering on Initiative would match
  other ASI teams' rows, report them as orphaned, and invite deleting them.
- Workstream Name: `Agent Control Standard` on every row.
- Workstream Lead: the project leads from `roadmap.json`.
- Initiative Co-Owners: the stripped value of the Initiative Co-Owners cell on the sheet's
  Agentic Security Initiative rows that are not ACS rows. When those rows carry more than one
  distinct stripped value, or none, the skill refuses with a new code `E_COOWNERS` and writes no
  rows. The value is written to the output file and never printed.
- Type: `roadmap_model.DELIVERABLE_TYPES` becomes the sheet's dropdown list exactly:
  `Application/Tool`, `Cheat Sheet`, `Code Sample`, `Document`, `OSS Project`, `Other`. The
  milestone descriptions created in G use these values. A milestone whose `Type:` line is not in
  the list is reported in the health issue, as today.
- The `Workstream:` description line stays for the health issue and the page. The health issue
  stops reporting its absence as an OWASP problem.
- The first run after migration may move a row from In Progress, as hand-entered, to Planning,
  because the skill derives status from closed work. The skill's value stands, and no one is
  asked to reconcile it.
- Tests cover a sheet with another team's ASI rows, a sheet with two co-owner spellings, and a
  milestone type outside the list. The plugin zip is rebuilt and validated after the change.

### C. Closing-choice check

A new workflow, `.github/workflows/closing-choice.yml`, holds one job named `closing-choice`.
It is separate from `pr-intake.yml` so its triggers can include `synchronize`, which a required
check needs, or the check goes missing after every push.

- Trigger: `pull_request_target` with `opened`, `edited`, `synchronize`, and `reopened`, on
  every base branch. Permissions: `issues: read` and `pull-requests: read`. No checkout. The
  body reaches the script through `env:`.
- It reads only the template section, from the line `## Which issue does this implement` to
  the next `## ` heading. A body without that heading fails, with a message naming the heading.
- It extracts every issue reference in the section, in three shapes: `#N`, `owner/repo#N` for
  this repository, and this repository's issue URL. References to other repositories are
  ignored.
- For each referenced issue carrying `status:accepted`, the section must reference it through
  one of the six spellings: `Closes`, `Fixes`, `Resolves`, `Part of`, `Refs`, or
  `Contributes to`, case-insensitive, with an optional colon. Any accepted issue referenced
  without one fails the check.
- It passes when the editorial checkbox is checked, when the author is `dependabot[bot]`, and
  for the promotion pull request from `integration` to `main`.
- An API failure fails the check, so a GitHub outage blocks merges on `integration` rather than
  waving them through. Rerunning the job clears it.
- The failure message names the issue numbers, the six spellings, and the heading. It prints
  nothing from the body.
- `pr-intake.yml`'s keyword-flag step stays, unchanged. It warns about closing keywords on any
  roadmap issue, which the new check does not cover.
- CONTRIBUTING.md and the pull request template explain the choice in one sentence each. The
  template's `Closes #` line becomes `Closes #` with a comment listing the contributing
  spellings.
- Tests pin the workflow's triggers, permissions, and absence of a checkout, and exercise the
  extraction and decision logic against a fake GitHub API: each spelling, each reference shape,
  prose outside the section, a missing heading, a cross-repository reference, each exemption,
  and an API failure.

Making the check required is sequenced. The workflow merges to `integration` first and must
appear on at least one pull request. Open pull requests then get the check by a close and
reopen, which runs the workflow without a push. G's migration runs before the check is made
required, so `status:accepted` reflects the new milestones when it starts binding. Only then
does `protect-integration` gain `closing-choice` as a required check.

### D. Sweep additions

All three additions are integers and numbers in the health issue. No fetched title or body text
reaches it.

On-`main` verification:

- The sweep and dryrun jobs gain `pull-requests: read`, and their guard tests change to match.
- For each milestone in the Ready to publish state, a separate sweep-only GraphQL query reads
  each done issue's `ClosedEvent.closer`. When the closer is a merged pull request in this
  repository with a merge commit, the sweep compares that commit with `main` through
  `compare/{sha}...main`. Status `ahead` or `identical` means on `main`. Status `behind` or
  `diverged` means not on `main`.
- The milestone section splits into "on `main`, close now" and "awaiting promotion or
  verification". Each awaiting issue carries one reason: closed by hand, not yet on `main`, no
  merge commit, or closed from another repository.
- A reverted commit still reads as on `main`. That is accepted, because a revert reopens the
  issue in normal practice and the check is a prompt, not a gate.

Promotion prompt:

- The sweep reads `compare/main...integration`. When `ahead_by` is above zero and no open pull
  request runs from `integration` to `main`, the health issue says "Promotion pending:
  `integration` is N commits ahead of `main`" and gives the one-line `gh pr create` command with
  the title and body `open-promotion.yml` uses today.
- `open-promotion.yml` loses its `schedule` trigger and keeps `workflow_dispatch`, with a
  comment saying the dispatch works only if the org policy changes. Its guard test changes to
  match.

Bypass log:

- The sweep lists pull requests merged into `integration` or `main` in the last seven days whose
  `reviewDecision` is not `APPROVED`. Each line gives the number, the base branch, and the
  merger's login. A login that does not match GitHub's login pattern prints as `unknown`.
- Direct pushes by an admin do not appear. That residual is accepted, since none has happened
  and the rule-suites API that would show them needs an administration grant `GITHUB_TOKEN`
  cannot have.

Tests cover each closer case, each compare status, the promotion line on and off, and the bypass
list with approved, unapproved, and old pull requests, using the fake GitHub.

### E. Rulesets and the roster rule

- `protect-main` allows only merge commits. The promotion pull request's body already asks for
  one.
- `protect-integration` allows only squash merges. A rebase merge lets each commit message close
  issues on the default branch, which `integration` is, so a closing keyword in a commit message
  would bypass C. With squash only, the squash message is the pull request body that C reads.
- `protect-integration` adds `closing-choice` as a required check, in the order C states.
- The roster rule needs no team. The CODEOWNERS lines for `/GOVERNANCE.md`, `/.github/`, and
  the new `/project.owasp.yaml` list the three project leads and the three OWASP org owners
  (@GangGreenTemperTatum, @mamicidal, @sclintonowasp), who stay on those lines by standing
  decision. Code-owner review is already required on `main` and `integration`, so one of those
  six must approve a roster change. Fred Wilmot leaves these three lines and keeps his other
  entries.
- `tools/apply_governance.py`'s `desired_rulesets()` follows the live rulesets in two steps, so
  a full run never reverts them. Step 1 of the order declares squash only on
  `protect-integration`. Step 3 adds `closing-choice` to its required checks, in the same change
  that makes the check required, so a full run before then cannot require a check that has never
  run. `protect-release` keeps its current shape. `protect-main` stays outside the tool, as today.
  The nightly board job runs `--only board` and never touches rulesets.

### F. Access grants

Done on October 4. The three lapsed lead invitations, for Eva Benn, Richard Bird, and Aruneesh
Salhotra, are not re-sent. The Identity workstream may be retired, so its inert CODEOWNERS
entries stay for now.

### G. Milestone migration

This runs after A, B, C, D, and E's merge-method rules reach `main`, so the trusted set is
current and the health issue reports the new sections from its first run. It follows the
migration steps in the roadmap design, with these changes:

- The milestone table is the one agreed on October 4, without #178.
- The eight in-focus issues missing from that table are placed as agreed on October 4:

  | Issue | Milestone |
  | --- | --- |
  | #16, #31, #51 | Spec and docs fixes for v0.1 |
  | #19 | Conformance claim template |
  | #74 | Installable reference Guardian |
  | #43 | v0.2.0 |
  | #52 | None while it carries `status:blocked`. A project lead places it when it is unblocked. |
  | #67 | None. The `protect-branch-existence` ruleset (id 22712052) now blocks deleting `integration`, so #67 is verified against that ruleset and closed with a note citing it. |

- #19 will be closed in favor of #33. It is closed as "not planned" with the comment
  "Superseded by #33", so the roadmap counts it as dropped, not delivered, and the conformance
  claim template milestone can publish without claiming #19's suite, registry, or steward.
- The milestones on the TrustX path, the Responsible AI Institute's planned use of ACS as a
  conformance target, are the ACS-Core conformant reference Guardian, Fail-open decision,
  Reference adapters on main (which carries the ACS-Core floor, #132 and PR #21), Conformance
  claim template, and Installable reference Guardian milestones. All are in Q4 2026.
- Every milestone description carries `Type:` and `Workstream:` lines, with `Type:` from the
  list in B, and the benchmark carries `Committed: 2026-12-09`.
- Before the first `--apply`, the migrate dry run's plan is saved to the scratch directory as
  the undo log: each issue's prior milestone and labels. Undoing is replaying that log with
  `gh`.
- The migration runs with `ROADMAP_SYNC_ENABLED` off, so the event job does not race the
  migration's own label writes.
- The Day N milestones are deleted, not closed, after #93 and #94 move.
- Then `ROADMAP_SYNC_ENABLED` turns on, and the next sweep creates the health issue. A project
  lead pins it and sets `ROADMAP_HEALTH_ISSUE`. Until that variable is set, the monitor's health
  check reports "not configured" without failing. `ROADMAP_RENDER_ENABLED` and
  `ROADMAP_REFRESH_ENABLED` follow, and deploy-pages runs on `main`.
- C's check becomes required now, as C orders.
- The skill produces per-milestone rows. Its first run reports the hand-entered ACS rows as
  orphaned, and Rock replaces them. Rows of other ASI teams are never touched.

## Order

1. A, C, D, and E's merge-method rules, with the matching `desired_rulesets()` change, land as
   one pull request to `integration`, followed by a promotion. B ships at the same time, outside the repository.
2. G runs after step 1 reaches `main`.
3. `closing-choice` becomes required on `integration`, with the matching `desired_rulesets()`
   change, as the last step.

## Out of scope

- The #178 label migration.
- The custom roadmap page, phase 1.
- Changing the OWASP sheet's dropdown spelling, which is the sheet owner's.
- Any change needing an OWASP org owner, including the Actions pull request setting and teams.
