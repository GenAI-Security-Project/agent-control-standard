# Roadmap rollout: decisions, follow-up changes, and the milestone migration

Version: 1.2
Owner: ACS project leads
Date: 2026-10-04
Status: design, premortem rounds 1 and 2 folded in

Phase 0 of the roadmap merged as #201 and reached `main` with promotion #203. It is inert
until three repository variables are set. This document records the project leads' answers to
the open decisions in `design/2026-10-04-roadmap-page-design.md`, specifies the changes those
answers require, and orders the work that turns the roadmap on.

Two constraints govern every choice below. ACS is a volunteer project, so dates slip and a
target moves with one edit. Nothing here may depend on an OWASP org owner acting, so every
control is one a project lead can set at the repository level. A third rule follows from the
roadmap's purpose: lateness is acceptable, but a false claim of delivery is not.

## Decisions

All eleven decisions from "Decisions for the project lead" were answered on October 4, 2026.

| # | Decision | Answer |
| --- | --- | --- |
| 1 | Phase 0 before the custom page | Phase 0, already merged |
| 2 | "Closes #N" for accepted work | Adopted and enforced. A required check on `integration` makes every pull request state, for each issue it names, whether it closes the issue or contributes to it |
| 3 | Does setting a milestone accept an issue | Yes, for anyone holding the triage role or higher |
| 4 | Whose closes count as delivered | CODEOWNERS, the GOVERNANCE.md lead tables, and a new Triage volunteers table |
| 5 | OWASP sheet columns | Initiative is the Agentic Security Initiative, in the sheet's dropdown spelling. Workstream Name is Agent Control Standard. Workstream Lead is the three project leads. Initiative Co-Owners copies the value the sheet's other Agentic Security Initiative rows carry |
| 6 | Day N milestones | Deleted after migration |
| 7 | Whether #178's taxonomy is adopted | Not decided. The roadmap keeps today's labels, and #178 stays out of every milestone |
| 8 | Q4 2026 targets | All eight stay in Q4 2026. Targets move with one UI edit whenever capacity changes |
| 9 | `pull-requests: read` on the sweep | Granted, with the on-`main` verification built |
| 10 | Who closes a milestone | Any of the three project leads, once its work is on `main` |
| 11 | Rulesets | `main` takes merge commits only. A project lead or an OWASP org owner must approve changes to the roster files and to the code that reads them |

Decision 10 came with a leadership change: the project leads are now Rock Lambros, Ariel Fogel,
and Bar Kaduri.

Four further decisions came out of the first premortem round, on October 4, 2026.

- **Admin bypass stays.** Admins keep `bypass_mode: always` on the rulesets that carry it today.
  Decisions 2 and 11 therefore bind contributors. The nightly sweep reports bypassed merges, so
  they are visible on the weekly call.
- **Promotion is prompted, not automated.** The org policy that blocks Actions from opening
  pull requests stays as it is. The health issue says when `integration` is ahead of `main`
  and gives the command, a project lead opens and merges the promotion, and the monitor alarms
  when promotion is more than eight days overdue.
- **Contribution spellings.** A pull request closes an issue with `Closes`, `Fixes`, or
  `Resolves`, or contributes to it with `Part of`, `Refs`, or `Contributes to`. The check
  enforces the choice, and CONTRIBUTING.md and the pull request template teach it.
- **No org-owner requests.** The earlier request to Scott Clinton is withdrawn. The roster
  rule uses CODEOWNERS lines instead of a team, because creating a team that holds non-members
  needs an org owner.

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

A lands as its own pull request. Its body records the change as GOVERNANCE.md requires: the
three project leads agreed it on October 4, 2026, and this document is the record.

GOVERNANCE.md:

- "## Project lead" becomes "## Project leads", with three rows in the existing linked-handle
  format: Rock Lambros, Ariel Fogel, and Bar Kaduri.
- A "## Triage volunteers" section follows Triage authority. It holds a table with two columns,
  Volunteer and Assigned by. Victor Hernandez (@victorm-hernandez) is listed, assigned by Rock
  Lambros. Akira Brand is added only after the invitation is accepted.
- Every sentence that gives "the project lead" a duty becomes "a project lead" or "the project
  leads", as the duty requires.
- Triage authority gains three sentences. Setting a milestone on an issue accepts it, unless a
  standing triage label says otherwise. Any project lead closes a roadmap milestone once its
  work is on `main`. Issues accepted by someone outside the roster and the Triage volunteers
  table are reviewed by a project lead on the weekly call.
- "Why this roster and project.owasp.yaml differ" and "How leadership changes" are rewritten.
  `project.owasp.yaml` names the project leads first, then the creators, up to the schema's cap
  of five. When the cap binds, a creator moves to the Origins credit in this file only.
  Adding or removing a project lead needs the agreement of the other project leads, recorded in
  the pull request that makes the change. The person being added or removed does not count
  toward that agreement.
- A sentence states that admins can bypass the rulesets on `main`, `integration`, and
  `release/*`, that `protect-branch-existence` has no bypass by design (see #67), and that the
  health issue reports bypassed merges as D describes.

Other files:

- README.md: "Only a maintainer can move an issue to `status:accepted`" becomes a sentence that
  points to GOVERNANCE.md's Triage authority for who accepts work and how.
- `project.owasp.yaml` lists five leaders: the three project leads and the two creators. Its
  comment matches the new GOVERNANCE.md rule.
- CODEOWNERS:
  - The header names the project leads.
  - The pending-invitation comment states the current state. @artmaro holds write access. The
    three lapsed Identity and Outreach invitations are not being re-sent.
  - The roster owners are the three project leads plus the three OWASP org owners
    (@GangGreenTemperTatum, @mamicidal, @sclintonowasp), who stay by standing decision. They own
    `/GOVERNANCE.md`, `/.github/`, a new `/project.owasp.yaml` line, and new lines for
    `/tools/roadmap_model.py`, `/tools/roadmap_sync.py`, and `/tests/test_roadmap_model_*.py`,
    the code that turns those files into the trusted set. The new code lines come after the
    `/tools/` and `/tests/` lines, because the last matching pattern wins. Fred Wilmot keeps his
    other entries.

`tools/roadmap_model.py`:

- `parse_governance` reads "Project leads" and also accepts the old "Project lead" heading, so
  the parser works on either side of the merge.
- HTML comments are stripped from GOVERNANCE.md before any table is parsed, so a hidden row
  cannot grant trust.
- The Triage volunteers table is parsed into the trusted set. `_table_rows` gains an
  `allow_empty` parameter, used only for this table, so a header-only table is valid. Each
  Volunteer cell must be one linked handle with the lead tables' strict link checks. A row
  whose Assigned by cell names nobody in the lead tables is left out of the trusted set and
  reported, by its row number, in the health issue. Any other malformed cell raises, as today.
- `roadmap_sync._sweep` loads the roster inside its `try`, so a malformed GOVERNANCE.md degrades
  the health issue instead of crashing the job.
- Tests cover both headings, a populated table, an empty table, a commented-out row, a malformed
  Volunteer cell, and an unknown assigner.

`tools/render_landing.py` reads only the Workstream leads table. A test confirms the landing
render still passes with the new sections.

### B. OWASP skill mapping

The skill lives in `~/.claude/skills/owasp-acs-roadmap`, outside the repository.

- The written Initiative value and the row filter are separate constants. `INITIATIVE` becomes
  the dropdown value `Agentic Security Initaitive`, with a comment naming the misspelling. The
  filter that finds this project's rows requires `Workstream Name` to equal
  `Agent Control Standard` and the Repository Link to start with this repository's milestone
  URL. Filtering on Initiative alone would match other ASI teams' rows.
- Workstream Name is `Agent Control Standard` on every row, and Workstream Lead is the project
  leads from `roadmap.json`.
- Initiative Co-Owners is a constant, `CO_OWNERS = "John"`, read from the sheet on October 4,
  2026. The skill compares it with the stripped Co-Owners cell on the other ASI rows and prints
  `COOWNERS_DRIFT` when they differ. It still writes rows, so another team's typo cannot block
  the report.
- Every cell written to the output passes through `sanitize()`.
- Instructions that target an existing row carry the milestone number with the row number.
  SKILL.md tells the user to find the row by its Repository Link before pasting, because other
  teams insert and sort rows between the export and the paste.
- The first run after migration may move a row from In Progress, as hand-entered, to Planning.
  The skill's value stands.
- Tests cover a sheet with other teams' ASI rows, a co-owner drift, a row whose Workstream Name
  matches but whose link does not, and a milestone type outside the list. The plugin zip is
  rebuilt and validated.

### C. Closing-choice check

A new workflow, `.github/workflows/closing-choice.yml`, holds one job named `closing-choice`.
It is separate from `pr-intake.yml` so its triggers can include `synchronize`, which a required
check needs.

The rule reads only the pull request body, never issue state. It needs no API call, so it
cannot go stale when an issue is accepted later, cannot fail on a GitHub outage, and cannot
spend the shared token budget.

- Trigger: `pull_request_target` with `opened`, `edited`, `synchronize`, and `reopened`.
  Permissions: `contents: read` only. The job checks out `main`, never the pull request's head,
  with `persist-credentials: false`, and runs `tools/closing_choice.py` from it with
  `python3 -I -S`. Until that file exists on `main`, the job passes with a notice. The body
  reaches the script through `env:`. A concurrency group per pull request number cancels runs
  in progress.
- The section is the text from the line `## Which issue does this implement` to the next `## `
  heading. A reference is `#N`, `GenAI-Security-Project/agent-control-standard#N`, or this
  repository's issue or pull request URL, case-insensitive. References to other repositories
  are ignored.
- It fails when any of these holds:
  - The section is missing.
  - A reference in the section is not directly preceded by one of the six spellings, with an
    optional colon. A comma-separated list after one spelling counts for each reference in it.
  - The same issue is both closed and contributed to.
  - A GitHub closing keyword (`close`, `closes`, `closed`, `fix`, `fixes`, `fixed`, `resolve`,
    `resolves`, `resolved`) precedes a reference of this repository anywhere outside the
    section.
  - The section holds more than 50 references.
- The editorial checkbox exempts a body only when it holds no closing keyword anywhere.
- Further exemptions: pull requests opened by `dependabot[bot]`, the promotion pull request,
  and the sync pull request. Promotion means head `integration` and base `main`, and sync means
  head `main` and base `integration`. In both, the head repository must be this repository, so
  a fork branch named `integration` is not exempt.
- Repository variable `CLOSING_CHOICE_SINCE` holds an ISO date. While it is unset, the job
  passes with a notice and states what it would have failed. A pull request created before that
  date passes with a notice. Unsetting the variable is the kill switch.
- The failure message names the rule that failed and the six spellings. It prints issue
  numbers and nothing else from the body.
- The template drops its prefilled `Closes #`. The section instead holds a comment that names
  the six spellings and says to write one before each issue number. CONTRIBUTING.md explains
  the choice in one sentence.
- `pr-intake.yml`'s keyword-flag step stays unchanged.
- The rule is a stdlib-only function in `tools/closing_choice.py`. The sweep's bypass report
  reuses it. Tests cover each spelling,
  each reference shape, lists, closing and contributing to the same issue, a keyword outside
  the section, the reference cap, a missing section, each exemption including a fork head named
  `integration`, the editorial exemption with and without a keyword, the date gate, and the
  unmodified new template. A guard test pins the triggers, the permissions, the concurrency
  group, and a checkout of `main` that never names the pull request's head.

Making the check required follows the Order. Pull requests older than `CLOSING_CHOICE_SINCE`
get a run on their next push or edit. A lead can also close and reopen one at merge time,
after confirming its head repository still exists.

### D. Sweep and monitor additions

Every addition prints integers, branch names, and logins that match GitHub's login pattern. No
fetched title or body text reaches the health issue. Each addition is its own section with its
own `try`, so one failed read marks that section "Could not be read on this run" and leaves the
rest intact. The sweep stops its reads after ten minutes and writes what it has, before the
job's fifteen-minute timeout.

Git reads replace API calls where they can. The sweep job checks out with `fetch-depth: 0`,
so ancestry and branch distance come from `git merge-base --is-ancestor` and
`git rev-list --count`.

On-`main` verification:

- The sweep and dryrun jobs gain `pull-requests: read`, and their guard tests change to match.
- For each milestone in the Ready to publish state, and each milestone closed in the last 90
  days, the sweep reads each done issue's closer. A merged pull request in this repository
  supplies its merge commit. When the closer is a person, the sweep collects the merged
  pull requests that reference the issue, through the existing cross-reference query and
  `delivered_by()`. Each merge commit is checked for ancestry against `origin/main`.
- Ready milestones split into "on `main`, close now" and "awaiting promotion or verification".
  Each awaiting issue carries one reason: not yet on `main`, no linked merged pull request, or
  closed from another repository.
- A closed milestone with any issue not on `main` is listed under "Published but not verified
  on `main`", with the login that closed the milestone.
- A reverted commit still reads as on `main`. That is accepted, because a revert normally
  reopens the issue.

Hand closes:

- The health issue lists each issue closed as completed by a person other than a project lead
  in the last seven days. Decision 4 still counts these as done. The list makes each one
  visible for a lead to confirm or reopen.

Promotion prompt:

- When `integration` is ahead of `main` and no open pull request runs from this repository's
  `integration` to `main`, the health issue says "Promotion pending: `integration` is N commits
  ahead of `main`". It gives the one-line `gh pr create` command, with the title and body
  `open-promotion.yml` uses today. It also writes a machine line,
  `<!-- acs-promotion: ahead N since YYYY-MM-DD -->`, where the date is the oldest commit on
  `integration` that `main` lacks.
- `monitor_roadmap.py` fails when that date is more than eight days old, so the existing alarm
  carries an overdue promotion.
- `open-promotion.yml` loses its `schedule` trigger and keeps `workflow_dispatch`, with a
  comment that dispatch works only if the org policy changes. Its guard test changes to match.

Bypass report:

- The health issue gives the count of pull requests merged into `integration` or `main` in the
  last seven days whose `reviewDecision` is not `APPROVED`, with promotions counted
  separately.
- It lists individually only the merges that matter:
  - a merge touching GOVERNANCE.md, `.github/`, `project.owasp.yaml`, or the roster code from A,
    read from the pull request files API
  - a merge from a fork whose review was not approved
  - a merge whose body fails the closing-choice rule
  - a merge where the merger is also the author
- Direct pushes by an admin do not appear. The rule-suites API that would show them needs an
  administration grant `GITHUB_TOKEN` cannot have, so that residual is accepted.

Starting the sweep:

- `roadmap-sync.yml`'s `workflow_dispatch` gains a `mode` input, `dryrun` by default. `mode:
  sweep` runs the sweep job, which still requires `ROADMAP_SYNC_ENABLED`. G uses it so the
  health issue exists minutes after sync turns on.

Deliverable types:

- `roadmap_model.DELIVERABLE_TYPES` becomes the sheet's dropdown list exactly:
  `Application/Tool`, `Cheat Sheet`, `Code Sample`, `Document`, `OSS Project`, `Other`.
  `RULES_VERSION` is bumped, the fixture uses `OSS Project`, and a test asserts every fixture
  milestone parses without description errors.
- The health issue stops reporting a missing `Workstream:` line as an OWASP problem.

Migration support:

- `migrate`'s dry run prints each entry's current milestone number, or `none`, next to its
  labels. Saved, that output is the undo log.

Tests cover each closer case, ancestry true and false, a closed milestone with unverified
work, the promotion line on and off and the monitor's eight-day rule, a fork head named
`integration`, each bypass category, a failed read in one section, the dispatch mode, and the
migrate line, using the fake GitHub and a temporary git repository.

### E. Rulesets

- `protect-main` allows only merge commits. The promotion pull request's body already asks for
  one.
- `protect-integration` allows only squash merges. A rebase merge lets each commit message close
  issues on `integration`, which is the default branch, outside anything C reads. With squash
  only, the squash message is the pull request body, which C reads in full.
- `protect-integration` gains `closing-choice` as a required check, in the Order's last step.
- Every required check carries `integration_id: 15368`, the GitHub Actions app, so a commit
  status or another app's check with the same name cannot satisfy it.
- Live ruleset edits are made with a read, modify, and write of the full ruleset JSON, so no
  live field is dropped.

`tools/apply_governance.py`:

- `desired_rulesets()` declares squash only on `protect-integration` from the first change. It
  adds `closing-choice` in the Order's last step, in the same change that makes the check
  required.
- `Ruleset` gains `required_check_integration_id` and
  `require_extra_approval_for_unattributed_changes`, both compared and rendered, so a full run
  neither drops nor ignores them.
- `_protect_main_payload` copies every live pull-request parameter and the bypass actors before
  changing anything, so it cannot strip code-owner review from `main`. A test pins that.
- Ruleset planning refuses to run unless the checkout's `HEAD` equals `origin/integration`, so a
  stale clone cannot revert the live rulesets.
- The nightly board job runs `--only board` and never touches rulesets.

### F. Access grants

Done on October 4. The three lapsed lead invitations, for Eva Benn, Richard Bird, and Aruneesh
Salhotra, are not re-sent. The Identity workstream may be retired, so its CODEOWNERS entries
stay for now.

### G. Milestone migration

This runs once the three pull requests in the Order reach `main`. It follows the migration
steps in the roadmap design, with these changes:

- The milestone table is the one agreed on October 4, without #178.
- The eight in-focus issues missing from that table are placed as agreed on October 4:

  | Issue | Milestone |
  | --- | --- |
  | #16, #31, #51 | Spec and docs fixes for v0.1 |
  | #19 | Conformance claim template |
  | #74 | Installable reference Guardian |
  | #43 | v0.2.0 |
  | #52 | None while it carries `status:blocked`. A project lead places it when it is unblocked. |
  | #67 | None. The `protect-branch-existence` ruleset (id 22712052) blocks deleting `integration` and has no bypass actors. #67 is closed with a note citing the ruleset and saying its empty bypass list is what fixes the bug. |

- #19 is not closed during the migration. When a project lead later closes it, it is closed as
  "not planned", and the comment names where each part of its scope went: #33 for the
  requirement ledger, #188 for the suite, and a new issue for the registry, steward, and
  revocation path. The same change updates `docs/spec/conformance.md`, which names #19 as the
  tracking issue.
- Several Q4 2026 milestones carry the work an outside conformance lab needs to test against
  ACS: the ACS-Core conformant reference Guardian, Fail-open decision, Reference adapters on
  main (which carries the ACS-Core floor, #132 and PR #21), Conformance claim template, and
  Installable reference Guardian. Together they deliver a self-attested claim template and a
  suite that does not block merges. Independent verification and a steward are not on that
  path.
- Every milestone description carries `Type:` and `Workstream:` lines, with `Type:` from the
  list in D, and the benchmark carries `Committed: 2026-12-09`. Each description also says that
  GitHub's percentage counts every closed issue, including ones closed as not planned, and
  points to the health issue for verified progress.
- Before the first `--apply`, the dry run's output is saved to the scratch directory as the undo
  log.
- The migration runs with `ROADMAP_SYNC_ENABLED` off, so the event job does not race the
  migration's own writes.
- Then a project lead sets `ROADMAP_SYNC_ENABLED`, dispatches `roadmap-sync.yml` with
  `mode: sweep`, pins the health issue it creates, and sets `ROADMAP_HEALTH_ISSUE`. The window in
  which the monitor sees sync on without a health issue is minutes. `ROADMAP_RENDER_ENABLED` and
  `ROADMAP_REFRESH_ENABLED` follow, and deploy-pages runs on `main`.
- The Day N milestones are deleted after #93 and #94 move and one sweep reports `ok`.
- The skill produces per-milestone rows. Its first run reports the hand-entered ACS rows as
  orphaned, and Rock replaces them. Rows of other ASI teams are never touched.

## Order

1. Three pull requests to `integration`, in this order:
   - A, the leadership and roster change.
   - C and E's merge-method rules, with the matching `desired_rulesets()` and `Ruleset`
     changes. `CLOSING_CHOICE_SINCE` stays unset, so the check reports without failing.
   - D.

   B ships alongside, outside the repository. One promotion carries all three to `main`.
2. G runs after the promotion.
3. A project lead sets `CLOSING_CHOICE_SINCE` to that day's date. A final small pull request
   adds `closing-choice` to `desired_rulesets()`, and the same lead adds it to
   `protect-integration` as a required check.

## Out of scope

- The #178 label migration.
- The custom roadmap page, phase 1.
- Changing the OWASP sheet's dropdown spelling, which is the sheet owner's.
- Any change needing an OWASP org owner, including the Actions pull request setting and teams.
- Repository role changes. Whether any admin should hold a lesser role is a separate decision.
