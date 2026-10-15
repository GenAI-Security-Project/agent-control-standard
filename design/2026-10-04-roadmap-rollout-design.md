# Roadmap rollout: decisions, follow-up changes, and the milestone migration

Version: 1.4
Owner: ACS project leads
Date: 2026-10-04
Status: design, five premortem rounds folded in

Phase 0 of the roadmap merged as #201 and reached `main` with promotion #203. It is inert
until three repository variables are set. This document records the project leads' answers to
the open decisions in `design/2026-10-04-roadmap-page-design.md`, specifies the changes those
answers require, and orders the work that turns the roadmap on.

Four rules govern every choice below. ACS is a volunteer project, so dates slip and a target
moves with one edit. Nothing may depend on an OWASP org owner acting. Lateness is acceptable,
but a false claim of delivery is not. Anything that does not prevent a false claim or a broken
mechanism is left out.

## Decisions

The eleven decisions from "Decisions for the project lead" were answered on October 4, 2026.
Decisions 12 to 17 followed the premortem the same day.

| # | Decision | Answer |
| --- | --- | --- |
| 1 | Phase 0 before the custom page | Phase 0, already merged |
| 2 | "Closes #N" for accepted work | Adopted. A required check on `integration` makes a pull request say, for each issue in its issue section, whether it closes or contributes to it |
| 3 | Does setting a milestone accept an issue | Yes, for anyone holding the triage role or higher |
| 4 | Whose closes count as delivered | CODEOWNERS, the GOVERNANCE.md lead tables, and a new Triage volunteers table, narrowed by decision 12 |
| 5 | OWASP sheet columns | Initiative is the Agentic Security Initiative, in the sheet's dropdown spelling. Workstream Name is Agent Control Standard. Workstream Lead is the three project leads. Initiative Co-Owners copies the value the sheet's other Agentic Security Initiative rows carry |
| 6 | Day N milestones | Deleted after migration |
| 7 | Whether #178's taxonomy is adopted | Not decided. The roadmap keeps today's labels, and #178 stays out of every milestone |
| 8 | Q4 2026 targets | All eight stay in Q4 2026. Targets move with one UI edit whenever capacity changes |
| 9 | `pull-requests: read` on the sweep | Granted, with the on-`main` verification built |
| 10 | Who closes a milestone | Any of the three project leads, once its work is on `main` |
| 11 | Rulesets | `main` takes merge commits only. A project lead must approve changes to the roster files |
| 12 | Who attests delivery by hand | Only a project lead. A close with no pull request or commit behind it counts as delivered only when a project lead made it. Anyone else's such close awaits a lead's confirmation |
| 13 | `pull-requests: read` on the deploy build job | Granted, so `roadmap.json` can verify pull request closes |
| 14 | Admin bypass | Stays. Decisions 2 and 11 bind contributors, and the health issue reports bypasses |
| 15 | Promotion | Prompted in the health issue, opened and merged by a project lead. The org policy that blocks Actions from opening pull requests stays |
| 16 | Contribution spellings | Close with `Closes`, `Fixes`, or `Resolves`. Contribute with `Part of`, `Refs`, or `Contributes to` |
| 17 | Who hears an alarm | Every project lead, by @mention on the health issue when the monitor starts failing. `issues: write` is granted on the monitor job for this |

Decision 10 came with a leadership change: the project leads are now Rock Lambros, Ariel Fogel,
and Bar Kaduri. The earlier request to Scott Clinton is withdrawn, and Fred Wilmot's admin role
stays as it is.

## Already done

- Promotion #203 was opened by hand and merged, so `main` carries phase 0.
- Akira Brand was invited with the triage role on October 4. The invitation expires on
  October 12 and was still pending when this version was written.
- Victor Hernandez holds the triage role.
- Project board 9 write access for Victor Hernandez and Akira Brand was granted on October 4.
- Scott's OWASP sheet carries hand-entered ACS rows that link to the repository's milestones
  page.

## Work packages

### A. Leadership, roster, and governance text

A lands as its own pull request, under GOVERNANCE.md's current rule that the project lead
confirms a leadership change.

GOVERNANCE.md:

- "## Project lead" becomes "## Project leads", with three rows in the existing linked-handle
  format: Rock Lambros, Ariel Fogel, and Bar Kaduri.
- A "## Triage volunteers" section follows Triage authority, with a table of two columns,
  Volunteer and Assigned by. Victor Hernandez (@victorm-hernandez) is listed, assigned by Rock
  Lambros. Akira Brand is added once the invitation is accepted.
- Every "the project lead" duty becomes "a project lead" or "the project leads", as the duty
  requires. "How leadership changes" says the project leads confirm a change. "Why this roster
  and project.owasp.yaml differ" says that file names the project leads and the creators.
- Triage authority says anyone with the triage role or higher accepts an issue, by applying
  `status:accepted` or by setting a milestone, and that only a project lead's hand close counts
  as delivered (decision 12).
- One sentence on bypass: repository admins can bypass the rulesets on `main`, `integration`,
  and `release/*`, and the health issue reports bypassed merges and direct pushes.

Other files:

- README.md: "Only a maintainer can move an issue to `status:accepted`" points to GOVERNANCE.md's
  Triage authority instead.
- `landing/index.html`: "Only an issue a maintainer marks `status:accepted` enters the backlog"
  becomes "Only an accepted issue enters the backlog".
- `project.owasp.yaml` lists the three project leads and the two creators, which is the
  schema's cap of five. Its comment says so.
- CODEOWNERS: the header names the project leads, and the pending-invitation comment states
  that @artmaro holds write access and that the three lapsed invitations are not being re-sent.
  The `/GOVERNANCE.md` and `/.github/` lines, a new `/project.owasp.yaml` line, and new lines for
  `/tools/roadmap_model.py`, `/tools/fetch_roadmap.py`, and `/tools/closing_choice.py` list the
  three project leads plus @GangGreenTemperTatum, @mamicidal, and @sclintonowasp. The new code
  lines come after `/tools/`, because the last matching pattern wins.

`tools/roadmap_model.py`:

- `parse_governance` reads "Project leads", and still accepts "Project lead".
- HTML comments are stripped before tables are parsed, so a hidden row cannot grant trust.
- The Triage volunteers table joins the trusted set. It may be empty. Each Volunteer cell must
  be one linked handle with the lead tables' strict checks. Any malformed row raises, as today.
- The model exposes the project leads as their own set, for decision 12.
- `roadmap_sync._sweep` loads the roster inside its `try`, so a malformed GOVERNANCE.md degrades
  the health issue instead of crashing the job.
- Tests cover both headings, a populated table, an empty table, a commented-out row, and a
  malformed row.

### B. OWASP skill mapping

The skill lives in `~/.claude/skills/owasp-acs-roadmap`, outside the repository.

- `INITIATIVE` becomes the dropdown value `Agentic Security Initaitive`, with a comment naming
  the misspelling.
- A sheet row is ACS's own when its stripped Workstream Name is `Agent Control Standard` and its
  Repository Link starts with `https://github.com/GenAI-Security-Project/agent-control-standard/`.
  The hand-entered rows link to `/milestones`, so they match and are reported as orphaned. A row
  matches a milestone only when its link is exactly that milestone's URL.
- Workstream Name is `Agent Control Standard` on every row, and Workstream Lead is the project
  leads.
- Initiative Co-Owners is a constant, `CO_OWNERS = "John"`, read from the sheet on October 4,
  2026. The skill prints `COOWNERS_DRIFT` when the other ASI rows carry a different value, and
  still writes rows.
- Instructions that target an existing row carry the milestone number, and SKILL.md tells the
  user to find the row by its Repository Link before pasting.
- Tests cover other teams' ASI rows, a trailing space in Workstream Name, a hand-entered row,
  and co-owner drift. The plugin zip is rebuilt and validated.

### C. Closing-choice check

A new workflow, `.github/workflows/closing-choice.yml`, holds one job named `closing-choice`. It
is early feedback for contributors. D is what stops a false claim, so C catches ordinary
mistakes and does not try to be airtight.

- Trigger: `pull_request_target` with `opened`, `edited`, `synchronize`, and `reopened`, on base
  `integration`. Permissions: `contents: read`. The job checks out `main`, never the pull
  request's head, with `persist-credentials: false`, and runs `tools/closing_choice.py` with
  `python3 -I -S`. Title and body reach the script through `env:`. A concurrency group per pull
  request cancels runs in progress.
- The script normalizes `\r\n` to `\n`, rewrites `[text](url)` to `text`, and removes `*` and `_`
  emphasis. Text longer than 65,536 characters is truncated. Patterns are linear, with no
  nested quantifiers.
- The issue section runs from the line `## Which issue does this implement` to the next `## `
  line. A reference is `#N`, `GenAI-Security-Project/agent-control-standard#N`, or this
  repository's issue URL. Other repositories are ignored.
- GitHub's closing keywords are `close`, `closes`, `closed`, `fix`, `fixes`, `fixed`, `resolve`,
  `resolves`, and `resolved`, with an optional colon, and each applies to the one reference
  after it. A contributing spelling may introduce a comma-separated list.
- The check fails when the section is missing, when a reference in it has no spelling before it,
  when one issue is both closed and contributed to, or when a closing keyword precedes a
  reference outside the section or in the title.
- It passes, with a notice, for the editorial checkbox and for `dependabot[bot]` when neither
  title nor body holds a closing keyword. It also passes for the sync pull request: head `main`
  in this repository, opened by a login in the trusted set.
- Repository variable `CLOSING_CHOICE_SINCE` holds an ISO date. While it is unset, or for a pull
  request created before it, the job passes with a notice saying what it would have failed.
  Unsetting it is the kill switch.
- The failure message names the rule and the six spellings, and prints issue numbers only.
- The template drops its prefilled `Closes #` for a comment naming the six spellings.
  CONTRIBUTING.md explains the choice in one sentence.
- `tools/closing_choice.py` is stdlib only and exposes the parser that D reuses. Tests cover each
  spelling and reference shape, a contributing list, a closing list where only the first
  reference closes, both kinds on one issue, a keyword outside the section, a keyword in the
  title, CRLF text, a markdown link, each exemption, the date gate, the unmodified template, and
  a 65,536-character adversarial body that must finish in under a second. A guard test pins the
  triggers, base branch, permissions, concurrency, and a checkout of `main`.

### D. Delivery verification

An issue counts as delivered only when the data says so.

#### What the fetch reads

- `fetch_roadmap.py` extends its issue query with the close event's `closer`: a pull request's
  number, repository, merged flag, and merge commit oid and message, or a commit's oid and
  message. A hand close has no closer, and the event's actor is the login. It also reads the
  merged pull requests from this repository that reference the issue, with their merge commit
  oids.
- For each message, the fetch runs `closing_choice.declared_closes(message, number)` and keeps
  two booleans: a closing keyword precedes a reference to the issue, and a contributing spelling
  does. The whole message is read, because squash messages from before C, such as #174's
  "Closes #95.", carry the keyword in prose. The text is discarded.
- The fetch imports `closing_choice` inside `main()`'s `try`, after adding `tools/` to
  `sys.path`, so an import failure still writes the fetch's failure record. A parse error on one
  message gives that issue reason `unparsed`, never a failed fetch.
- The fetch then asks git about ancestry. It first confirms the clone is complete and that
  `refs/remotes/origin/main` resolves. If not, the fetch fails with a new failure class,
  `verification`, which the build treats like any other data failure, so the page reads
  unavailable and no schema publish is blocked. Each oid is checked against `^[0-9a-f]{40}$`,
  then with `git cat-file -e`, then with `git merge-base --is-ancestor` against
  `refs/remotes/origin/main`, each call with a ten-second timeout. A merge commit is also treated
  as reverted when `git log refs/remotes/origin/main` holds "This reverts commit <oid>" or
  "Reverts GenAI-Security-Project/agent-control-standard#<pull request>".
- The fetch writes per-issue facts: closer kind, the two booleans, and whether the closer's
  commit and every referencing merged pull request's commit are on `main` and not reverted.
  `classify` stays pure and reads only those facts.
- The deploy build job and the sweep and dryrun jobs check out with `fetch-depth: 0`. The build
  job gains `pull-requests: read` (decision 13), and the guard tests change to match.

#### The rule

`classify(issue, trusted, leads)` makes a close as completed by a trusted login `done` when
either holds:

- The closer is a pull request in this repository, or a commit, whose message closes the issue
  and contributes to it nowhere, and whose commit is on `main` and not reverted.
- The closer is a project lead's hand close.

In both cases, every merged pull request from this repository that references the issue must
also be on `main`. Any other close as completed is `unverified`, with one reason code:
`not_on_main`, `reverted`, `no_close_declared`, `contributing`, `other_repository`,
`not_a_lead`, `untrusted_closer`, `unparsed`, or `unknown_closer`. That last code covers any
other closer kind, such as a project board.

`unverified` already counts as remaining work. So does every open issue in a milestone,
whatever its labels: an issue whose `status:accepted` was replaced by `status:blocked` is still
open work. `milestone_state` and the progress total count untriaged issues as remaining, and the
state tests change to match. A milestone with remaining work reads In Progress while open and
In Review once closed. It never reads Published.

`roadmap.json` keeps its integer lists and gains `unverified_reasons`, a map from issue number to
reason code, which the contract test pins. `RULES_VERSION` is bumped.

Tests cover each closer kind and reason code, a prose "Closes #N." from before C, a "Fixes #N"
subject over a "Part of #N" body, a lead's hand close with an unpromoted pull request behind it,
a revert, a shallow clone, and a missing commit.

#### Health issue

Every addition prints integers, reason codes, `main`, `integration`, and logins that match
GitHub's login pattern. No fetched title, body, or message reaches it.

- **Unverified closes.** Each unverified issue with its milestone and reason code replaces
  today's "awaiting confirmation" section, with one remedy per code. For `not_on_main` and
  `reverted` the remedy is to promote or reopen, never to reclose. For `not_a_lead` the remedy
  is for a project lead to reclose.
- **Promotion.** When `integration` has commits `main` lacks and
  `git merge-tree --write-tree origin/main origin/integration` differs from `main`'s tree, the
  issue says "Promotion pending since YYYY-MM-DD". The date is the committer date of the oldest
  such commit. It names an open promotion pull request, or gives the `gh pr create` command with
  the title and body `open-promotion.yml` uses today. A squashed sync never triggers it, because
  the trees match.
- **Bypasses.** The count of pull requests merged into `integration` or `main` in the last seven
  days without an approving review, plus an individual line for any such merge that touched a
  roster file or the code lines from A, and for any first-parent commit with no pull request,
  which is a direct push.
- `open-promotion.yml` loses its `schedule` trigger and keeps `workflow_dispatch`.

#### Alerting the project leads

A failed monitor run emails only whoever last edited its cron line. Decision 17 extends the
alarm to every project lead.

- `monitor-roadmap.yml` gains `issues: write` on its one job (decision 17), and its guard test
  changes to match.
- When the monitor's result changes from passing to failing, it comments on the issue named by
  `ROADMAP_HEALTH_ISSUE`, @mentioning each project lead read from GOVERNANCE.md. When the result
  returns to passing, it comments once more without mentions. A run whose result matches the
  last comment posts nothing, so a failure that lasts days produces one comment.
- The sweep locks the health issue every night, and GitHub refuses comments on a locked issue
  even from the Actions token. On a state change only, the monitor unlocks the issue, comments,
  and locks it again. If the relock fails, the next sweep relocks it.
- The last state is read from a marker in the bot's most recent such comment,
  `<!-- acs-roadmap-alarm: failing -->` or `<!-- acs-roadmap-alarm: passing -->`, counting only
  comments by `github-actions[bot]`.
- The comment holds fixed text and the fixed names of the failed checks. Nothing fetched reaches
  it.
- If `ROADMAP_HEALTH_ISSUE` is unset or the comment fails, the run still fails, and the cron
  editor's email is the fallback.
- `monitor-roadmap.yml`'s `workflow_dispatch` gains a boolean `test_alarm` input, false by
  default, which runs the failing-then-recovery comment pair without a real failure.
- Tests cover a locked issue, the test input, the transition to failing, a repeated failure,
  recovery, a missing variable, a
  failed comment, and a comment by another login carrying the marker.

#### Sweep and model housekeeping

- The sweep and dryrun jobs gain `pull-requests: read`. A failed read in a new section degrades
  the sweep, as any failed read does today. Every `gh` call in the sweep uses a 30-second
  timeout, so the job finishes inside its fifteen-minute limit.
- `roadmap-sync.yml`'s `workflow_dispatch` gains a `mode` input, `dryrun` by default, and
  `sweep`, which still requires `ROADMAP_SYNC_ENABLED`.
- `DELIVERABLE_TYPES` becomes the sheet's list: `Application/Tool`, `Cheat Sheet`, `Code Sample`,
  `Document`, `OSS Project`, `Other`. The fixture follows, and the roadmap design points to the
  tuple instead of repeating the list.
- The health issue stops reporting a missing `Workstream:` line as an OWASP problem.
- `migrate`'s dry run prints each entry's current milestone number, which makes its saved output
  the undo log.

### E. Rulesets

- `protect-main` allows only merge commits.
- `protect-integration` allows only squash merges, and the repository setting
  `allow_rebase_merge` is turned off.
- `protect-integration` gains `closing-choice` as a required check in the Order's last step.
  Every required check carries `integration_id: 15368`, the GitHub Actions app.
- Live ruleset edits read the full ruleset, change it, and write it back, so no live field is
  dropped.
- `tools/apply_governance.py` declares squash only on `protect-integration`, keeps each check's
  `integration_id`, and builds its payloads from the live ruleset's full JSON. Ruleset planning
  refuses to run unless the working tree is clean and `HEAD` equals the live tip of
  `integration`. The `closing-choice` declaration lands with the Order's last step.

### F. Access grants

Done on October 4. The three lapsed lead invitations are not re-sent.

### G. Milestone migration

This runs after the Order's promotion. It follows the roadmap design's migration steps with
these changes:

- The milestone table is the one agreed on October 4, without #178.
- The eight in-focus issues missing from that table are placed as agreed:

  | Issue | Milestone |
  | --- | --- |
  | #16, #31, #51 | Spec and docs fixes for v0.1 |
  | #19 | Conformance claim template |
  | #74 | Installable reference Guardian |
  | #43 | v0.2.0 |
  | #52 | None while it carries `status:blocked` |
  | #67 | None. It is closed with a note that the `protect-branch-existence` ruleset (id 22712052), which has no bypass actors, blocks deleting `integration` |

- #19 stays open. When a lead closes it, it is closed as "not planned" with a comment naming #33,
  #188, and a new issue for the registry and steward, and `docs/spec/conformance.md` stops
  naming #19 as the tracking issue.
- The Conformance claim template's description says it delivers a self-attested template, with
  no independent verification or steward.
- Every milestone description carries `Type:` and `Workstream:` lines, and the benchmark carries
  `Committed: 2026-12-09`.
- The migration runs with `ROADMAP_SYNC_ENABLED` off, after saving the dry run as the undo log.
- A project lead then sets `ROADMAP_SYNC_ENABLED`, dispatches `roadmap-sync.yml` with
  `mode: sweep`, pins the health issue, and sets `ROADMAP_HEALTH_ISSUE`.
  `ROADMAP_RENDER_ENABLED` and `ROADMAP_REFRESH_ENABLED` follow.
- After `ROADMAP_HEALTH_ISSUE` is set, a lead dispatches `monitor-roadmap.yml` with its
  `test_alarm` input, which posts the failing comment and then the recovery comment through the
  real unlock, comment, and relock path. Each project lead confirms the @mention arrived.
- The Day N milestones are deleted once Day 30 holds no open issues.
- The skill's first run reports the hand-entered ACS rows as orphaned, and Rock replaces them.

## Order

1. Three pull requests to `integration`: A, then C with E, then D. B ships alongside, outside the
   repository. One promotion carries all three to `main`.
2. G runs after the promotion.
3. A project lead sets `CLOSING_CHOICE_SINCE`, and a final pull request adds `closing-choice`
   to `apply_governance.py` as the lead makes it required on `protect-integration`.

## Out of scope

- The #178 label migration and the custom roadmap page.
- The OWASP sheet's dropdown spelling.
- Anything needing an OWASP org owner, and any repository role change.
- Proving the health issue was written by the sweep.
- A closed issue added to a milestone after it was closed. It counts by its close, as today.
