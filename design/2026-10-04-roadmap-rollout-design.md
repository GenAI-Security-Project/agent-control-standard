# Roadmap rollout: decisions, follow-up changes, and the milestone migration

Version: 1.0
Owner: ACS project leads
Date: 2026-10-04
Status: design, awaiting approval of the written spec

Phase 0 of the roadmap merged as #201 and reached `main` with promotion #203. It is inert
until three repository variables are set. This document records the project lead's answers to
the open decisions in `design/2026-10-04-roadmap-page-design.md`, specifies the changes those
answers require, and orders the work that turns the roadmap on.

## Decisions

All ten decisions from "Decisions for the project lead" were answered on October 4, 2026.

| # | Decision | Answer |
| --- | --- | --- |
| 1 | Phase 0 before the custom page | Phase 0, already merged |
| 2 | "Closes #N" for accepted work | Adopted. A required check makes every pull request that references an accepted issue say either `Closes #N` or `Part of #N` |
| 3 | Does setting a milestone accept an issue | Yes, for anyone holding the triage role or higher. GOVERNANCE.md changes to say so |
| 4 | Whose closes count as delivered | CODEOWNERS, the GOVERNANCE.md lead tables, and a new Triage volunteers table listing Victor Hernandez and Akira Brand |
| 5 | OWASP sheet columns | Initiative is the Agentic Security Initiative, using the sheet's dropdown spelling. Workstream Name is Agent Control Standard. Workstream Lead is the three project leads. Initiative Co-Owners copies the value the sheet's existing Agentic Security Initiative rows carry |
| 6 | Day N milestones | Deleted after migration |
| 7 | Whether #178's taxonomy is adopted | Not decided. The roadmap keeps today's labels, and #178 stays out of every milestone |
| 8 | Q4 2026 targets | All eight stay in Q4 2026. Targets move with one UI edit whenever capacity changes |
| 9 | `pull-requests: read` on the sweep | Granted, with the on-`main` verification built |
| 10 | Who closes a milestone | Any of the three project leads, once its work is on `main` |
| 11 | Rulesets | `main` takes merge commits only. A project lead must approve changes to the roster files |

Decision 10 came with a leadership change: the project leads are now Rock Lambros, Ariel Fogel,
and Bar Kaduri.

## Already done

- Promotion: the org policy blocks the repository setting that lets Actions open pull
  requests, and only an org owner can change it. Scott Clinton has the request. Promotion #203
  was opened by hand and merged, so `main` carries phase 0.
- Akira Brand was invited with the triage role on October 4. The invitation expires on
  October 12.
- Scott's OWASP sheet carries hand-entered ACS rows that link to the repository's milestones
  page.

## Work packages

The packages are independent unless a dependency is named.

### A. Leadership and roster

One pull request, because GOVERNANCE.md requires a leadership change to update its files
together.

- GOVERNANCE.md, "Project lead" becomes "Project leads", with three rows: Rock Lambros, Ariel
  Fogel, and Bar Kaduri, each as a linked handle in the existing format.
- GOVERNANCE.md gains a "Triage volunteers" table under Triage authority, listing Victor
  Hernandez (@victorm-hernandez) and Akira Brand (@AkiraBrand), with the lead who assigned
  each.
- GOVERNANCE.md, Triage authority, gains two sentences: setting a milestone on an issue accepts
  it unless a standing triage label says otherwise, and any project lead closes a roadmap
  milestone once its work is on `main`.
- `project.owasp.yaml` lists five leaders: the three project leads and the two creators. Its
  comment changes from "the project lead and the two creators" to match.
- CODEOWNERS: Ariel and Bar already appear on every owner line. The header comment changes to
  name the project leads, and the pending-invitation comment is corrected to the current state.
- `tools/roadmap_model.py` parses the Triage volunteers table into the trusted set, with the
  same strict link checks the lead tables get. Tests cover the new table, an empty table, and a
  malformed row.

`tools/render_landing.py` reads only the Workstream leads table, so the landing page needs no
change. A test confirms the landing render still passes with the new sections.

### B. OWASP skill mapping

The skill's columns follow decision 5 instead of the milestone's `Workstream:` line.

- Initiative: the dropdown value `Agentic Security Initaitive`, matching the sheet's validation
  list. The script names the misspelling in a comment so the value changes in one place once
  OWASP fixes the list.
- Workstream Name: `Agent Control Standard`.
- Workstream Lead: the project leads from `roadmap.json`.
- Initiative Co-Owners: read from the sheet's existing rows whose Initiative is the Agentic
  Security Initiative. More than one distinct value is reported, never guessed.
- `roadmap.json` already carries the project leads, so the build needs no change. The
  `Workstream:` description line stays useful for the health issue, which no longer reports its
  absence as an OWASP problem.

The skill is installed in `~/.claude/skills`, and the plugin zip is rebuilt after the change.

### C. Closing-keyword choice check

A new job in `pr-intake.yml`, named `closing-choice`, runs on the same `pull_request_target`
events with no checkout.

- It reads the body from the event through `env:` and extracts every `#N` reference.
- It fails when any referenced issue carries `status:accepted` and the body does not reference
  that issue with a closing keyword or with `Part of #N`.
- It passes for a body that references no accepted issue and for the editorial checkbox. It also
  passes for pull requests opened by `dependabot[bot]` and for the promotion pull request, from
  `integration` to `main`. The job checks those two cases itself, because the existing intake
  exempts only the editorial checkbox.
- Its failure message names the issue numbers and the two accepted forms, and nothing from the
  body.
- `protect-integration` adds `closing-choice` to its required checks. This changes a ruleset,
  approved under decision 2.

### D. On-`main` verification in the sweep

- `roadmap-sync.yml`'s sweep job gains `pull-requests: read`, and its guard test changes to
  match.
- For each Ready to publish milestone, the sweep reads each done issue's `ClosedEvent.closer`.
  When the closer is a merged pull request, it compares the merge commit with `main` through
  `compare/{sha}...main`, where `ahead` or `identical` means on `main`.
- The section splits into "on `main`, close now" and "awaiting promotion or verification", with
  the reason per issue: closed by hand, not yet on `main`, or no merge commit.
- Tests cover each case with a fake GitHub.

### E. Rulesets

- `protect-main` allows only merge commits. The promotion pull request's body already asks for a
  merge commit, so nothing else changes.
- Create a team `acs-project-leads` holding the three project leads. Add a ruleset rule
  requiring that team's review for `.github/CODEOWNERS`, `GOVERNANCE.md`, and
  `project.owasp.yaml` on `integration` and `main`. If org policy prevents a member from
  creating a team, the work stops there and the request goes to an org owner with the promotion
  setting.

### F. Access grants

- Project board 9 write access for Victor Hernandez and Akira Brand, as GOVERNANCE.md gives
  every triage volunteer. This needs the `project` scope on the project lead's `gh` token, which
  they add with `gh auth refresh -s project`.
- The three lapsed lead invitations, for Eva Benn, Richard Bird, and Aruneesh Salhotra, are a
  separate decision for the project leads, since re-sending them re-grants write access.

### G. Milestone migration

This runs after A, so the trusted set is current, and after the project leads place the
remaining issues. It follows the migration steps in the roadmap design, with these changes from
the decisions:

- The milestone table is the one agreed on October 4, without #178.
- The project leads place the eight unassigned in-focus issues: #16, #19, #31, #43, #51, #52,
  #67, and #74.
- Every milestone description carries `Type:` and `Workstream:` lines, and the benchmark carries
  `Committed: 2026-12-09`.
- The Day N milestones are deleted, not closed, after #93 and #94 move.
- Then `ROADMAP_SYNC_ENABLED` turns on, the sweep creates the health issue, and the project
  leads set `ROADMAP_HEALTH_ISSUE` and pin it. `ROADMAP_RENDER_ENABLED` and
  `ROADMAP_REFRESH_ENABLED` follow, and deploy-pages runs on `main`.
- The skill produces per-milestone rows. Its first run reports the hand-entered rows as
  orphaned, and those rows are replaced.

## Order

1. A, B, C, D, and E's merge-commit rule land as one pull request to `integration`, then a
   promotion. They share no files except tests.
2. E's team rule and F wait on org permissions and the project scope, and run when those
   arrive.
3. G runs after step 1 reaches `main`.

## Out of scope

- The #178 label migration.
- The custom roadmap page, phase 1.
- Changing the OWASP sheet's dropdown spelling, which is the sheet owner's.
