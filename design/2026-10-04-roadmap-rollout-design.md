# Roadmap rollout: decisions, follow-up changes, and the milestone migration

Version: 1.3
Owner: ACS project leads
Date: 2026-10-04
Status: design, premortem rounds 1 to 3 folded in

Phase 0 of the roadmap merged as #201 and reached `main` with promotion #203. It is inert
until three repository variables are set. This document records the project leads' answers to
the open decisions in `design/2026-10-04-roadmap-page-design.md`, specifies the changes those
answers require, and orders the work that turns the roadmap on.

Three rules govern every choice below. ACS is a volunteer project, so dates slip and a target
moves with one edit. Nothing may depend on an OWASP org owner acting, so every control is one a
project lead can set at the repository level. Lateness is acceptable, but a false claim of
delivery is not, so delivery is verified from data nobody can edit after a merge.

## Decisions

All eleven decisions from "Decisions for the project lead" were answered on October 4, 2026.

| # | Decision | Answer |
| --- | --- | --- |
| 1 | Phase 0 before the custom page | Phase 0, already merged |
| 2 | "Closes #N" for accepted work | Adopted. A required check on `integration` makes a pull request state, for each issue named in its issue section, whether it closes the issue or contributes to it. Delivery is then verified from the landed commit, as D describes |
| 3 | Does setting a milestone accept an issue | Yes, for anyone holding the triage role or higher |
| 4 | Whose closes count as delivered | CODEOWNERS, the GOVERNANCE.md lead tables, and a new Triage volunteers table form the trusted set. D adds verification on top: a close counts as delivered only when D can verify it |
| 5 | OWASP sheet columns | Initiative is the Agentic Security Initiative, in the sheet's dropdown spelling. Workstream Name is Agent Control Standard. Workstream Lead is the three project leads. Initiative Co-Owners copies the value the sheet's other Agentic Security Initiative rows carry |
| 6 | Day N milestones | Deleted after migration |
| 7 | Whether #178's taxonomy is adopted | Not decided. The roadmap keeps today's labels, and #178 stays out of every milestone |
| 8 | Q4 2026 targets | All eight stay in Q4 2026. Targets move with one UI edit whenever capacity changes |
| 9 | `pull-requests: read` on the sweep | Granted |
| 10 | Who closes a milestone | Any of the three project leads, once its work is on `main` |
| 11 | Rulesets | `main` takes merge commits only. One of the roster code owners in A must approve changes to the roster files and the code that reads them. Any repository admin can bypass that, and the bypass is reported |

Decision 10 came with a leadership change: the project leads are now Rock Lambros, Ariel Fogel,
and Bar Kaduri.

Four further decisions came out of the first premortem round, on October 4, 2026.

- **Admin bypass stays.** Admins keep `bypass_mode: always` on the rulesets that carry it today.
  Decisions 2 and 11 therefore bind contributors. The nightly sweep reports bypassed merges and
  direct pushes.
- **Promotion is prompted, not automated.** The org policy that blocks Actions from opening
  pull requests stays as it is. The health issue says when `integration` holds content `main`
  lacks and gives the command, and a project lead opens and merges the promotion.
- **Contribution spellings.** A pull request closes an issue with `Closes`, `Fixes`, or
  `Resolves`, or contributes to it with `Part of`, `Refs`, or `Contributes to`.
- **No org-owner requests.** The earlier request to Scott Clinton is withdrawn. The roster
  rule uses CODEOWNERS lines instead of a team, because creating a team that holds non-members
  needs an org owner.

Round 3 changed how decision 4 works in practice. A volunteer with the triage role cannot merge,
so every close a volunteer makes is a close by hand. Under D, a hand close counts as delivered
only when a project lead made it. A volunteer's hand close therefore shows as awaiting
confirmation until a lead confirms it. A volunteer's close as "not planned" still counts as
dropped, which is a triage call the role already carries.

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

A lands as its own pull request. It carries approving reviews from @afogel and @bar-capsule,
which record the project leads' agreement to the change.

GOVERNANCE.md:

- "## Project lead" becomes "## Project leads", with three rows in the existing linked-handle
  format: Rock Lambros, Ariel Fogel, and Bar Kaduri.
- A "## Triage volunteers" section follows Triage authority. It holds a table with two columns,
  Volunteer and Assigned by. Victor Hernandez (@victorm-hernandez) is listed, assigned by Rock
  Lambros. Akira Brand is added only after the invitation is accepted.
- Every sentence that gives "the project lead" a duty becomes "a project lead" or "the project
  leads", as the duty requires.
- Triage authority's first sentence becomes: anyone with the triage role or higher accepts an
  issue, by applying `status:accepted` or by setting a milestone, unless a standing triage
  label says otherwise. Leads and assigned volunteers apply the other decision labels. An issue
  accepted by someone outside the roster and the Triage volunteers table is reviewed by a
  project lead on the weekly call. Any project lead closes a roadmap milestone once its work is
  on `main`.
- "How leadership changes" says that adding or removing a project lead needs the agreement of
  the other project leads, given as approving reviews on the pull request that makes the change.
  The person being added or removed does not count. With fewer than three project leads, the
  agreement also needs one creator. A lead who resigns leaves on notice, with no agreement
  needed.
- "Why this roster and project.owasp.yaml differ" says `project.owasp.yaml` names the project
  leads first, then the creators, up to the schema's cap of five. When adding a lead would pass
  the cap, the creators decide between themselves who moves to the Origins credit, and the
  pull request names them. Origins says the creators "created ACS and are listed as OWASP
  leaders while the cap allows".
- A sentence on bypass: repository admins can bypass the rulesets on `main`, `integration`, and
  `release/*`. Nobody can force-push to or delete `main` or `integration`, because
  `protect-branch-existence` has no bypass actors by design (see #67). The health issue reports
  bypassed merges and direct pushes.

Other files:

- README.md: the sentence "Only a maintainer can move an issue to `status:accepted`" points to
  GOVERNANCE.md's Triage authority instead, and the diagram node "Maintainer triage" becomes
  "Triage".
- `landing/index.html`: "Only an issue a maintainer marks `status:accepted` enters the backlog"
  becomes "Only an accepted issue enters the backlog", linked to Triage authority.
- `project.owasp.yaml` lists five leaders: the three project leads and the two creators. Its
  comment matches the new GOVERNANCE.md rule.
- CODEOWNERS:
  - The header names the project leads.
  - The pending-invitation comment states the current state. @artmaro holds write access. The
    three lapsed Identity and Outreach invitations are not being re-sent.
  - The roster owners are the three project leads plus @GangGreenTemperTatum, @mamicidal, and
    @sclintonowasp, three of the OWASP org owners, who stay by standing decision. They own
    `/GOVERNANCE.md`, `/.github/`, a new `/project.owasp.yaml` line, and new lines for the code
    that turns the roster into trust and publishes the result: `/tools/roadmap_model.py`,
    `/tools/roadmap_sync.py`, `/tools/fetch_roadmap.py`, `/tools/build_roadmap_data.py`,
    `/tools/closing_choice.py`, `/tools/monitor_roadmap.py`, and `/tests/test_roadmap_*.py`.
    The new code lines come after the `/tools/` and `/tests/` lines, because the last matching
    pattern wins. Fred Wilmot keeps his other entries.
- A test fails when any `tools/*.py` file name is in `sys.stdlib_module_names`, because the
  roadmap tools put `tools/` first on `sys.path` and a file named `json.py` there would replace
  the standard library.

`tools/roadmap_model.py` roster parsing:

- `parse_governance` reads "Project leads" and also accepts the old "Project lead" heading, so
  the parser works on either side of the merge.
- HTML comments are stripped before any table is parsed. An unclosed `<!--` raises
  `RosterError`, because GitHub hides everything after it. `render_landing.py` strips comments
  the same way, so the published page and the trusted set agree.
- The Triage volunteers table is parsed into the trusted set. `_table_rows` gains an
  `allow_empty` parameter, used only for this table. Each Volunteer cell must be one linked
  handle with the lead tables' strict link checks. A row whose Assigned by cell names nobody in
  the lead tables is left out of the trusted set and reported by row number in the health
  issue. The check catches typos. It does not prove the lead agreed, which code-owner review
  does.
- The model exposes the project leads as their own set, which D uses.
- `roadmap_sync._sweep` loads the roster inside its `try`, so a malformed GOVERNANCE.md degrades
  the health issue instead of crashing the job.
- Tests cover both headings, a populated table, an empty table, a commented-out row, an unclosed
  comment, a malformed Volunteer cell, and an unknown assigner.

### B. OWASP skill mapping

The skill lives in `~/.claude/skills/owasp-acs-roadmap`, outside the repository.

- The written Initiative value and the row filter are separate constants. `INITIATIVE` becomes
  the dropdown value `Agentic Security Initaitive`, with a comment naming the misspelling.
- A sheet row is ACS's own when its stripped `Workstream Name` is `Agent Control Standard` and
  its Repository Link starts with `https://github.com/GenAI-Security-Project/agent-control-standard/`.
  That prefix matches the hand-entered rows, which link to `/milestones`, so they are reported
  as orphaned. A row matches a milestone only when its link fully matches
  `^https://github\.com/GenAI-Security-Project/agent-control-standard/milestone/\d+$`.
- Workstream Name is `Agent Control Standard` on every row, and Workstream Lead is the project
  leads from `roadmap.json`.
- Initiative Co-Owners is a constant, `CO_OWNERS = "John"`, read from the sheet on October 4,
  2026. The skill compares it with the stripped Co-Owners cell on the other ASI rows and prints
  `COOWNERS_DRIFT` when they differ. It still writes rows. SKILL.md tells the model to tell the
  user about the drift before the rows are pasted.
- `DUPLICATE` stops the run, so two sheet rows claiming one milestone are resolved by hand
  first.
- Every cell written to the output passes through `sanitize()`.
- Instructions that target an existing row carry the milestone number with the row number.
  SKILL.md tells the user to find the row by its Repository Link before pasting, because other
  teams insert and sort rows between the export and the paste.
- The milestone description's `Note:` lines are not copied to the sheet. D defines them.
- The first run after migration may move a row from In Progress, as hand-entered, to Planning.
  The skill's value stands.
- Tests cover other teams' ASI rows, a trailing space in Workstream Name, a hand-entered row
  linking to `/milestones`, co-owner drift, a duplicate, a row whose Workstream Name matches
  but whose link does not, and a `Note:` line. The plugin zip is rebuilt and validated.

### C. Closing-choice check

A new workflow, `.github/workflows/closing-choice.yml`, holds one job named `closing-choice`. It
is early feedback for contributors. D's verification is what stops a false claim, so C does not
have to be airtight, but it should catch the ordinary mistakes before review.

The rule reads only the pull request's title and body, never issue state, so it needs no API
call, cannot go stale when an issue is accepted later, and cannot fail on a GitHub outage.

- Trigger: `pull_request_target` with `opened`, `edited`, `synchronize`, and `reopened`, on base
  branch `integration` only. Permissions: `contents: read`. The job checks out `main`, never the
  pull request's head, with `persist-credentials: false`, and runs `tools/closing_choice.py`
  from it with `python3 -I -S`. The title and body reach the script through `env:`. A
  concurrency group per pull request number cancels runs in progress.
- Text is normalized first: `\r\n` becomes `\n`, markdown emphasis and link brackets are
  removed, and whitespace runs collapse. HTML comments and code are not removed, because GitHub
  may honor a keyword inside them.
- The issue section is the text from the line `## Which issue does this implement` to the next
  `## ` heading. A reference is `#N`, `GenAI-Security-Project/agent-control-standard#N`, or this
  repository's issue URL, case-insensitive. References to other repositories are ignored.
- The rule follows GitHub's grammar. A closing spelling applies to the one reference after it.
  A contributing spelling may introduce a comma-separated list. GitHub's closing keywords are
  `close`, `closes`, `closed`, `fix`, `fixes`, `fixed`, `resolve`, `resolves`, and `resolved`,
  with an optional colon.
- It fails when any of these holds:
  - The section is missing.
  - A reference in the section has no spelling before it.
  - The same issue is both closed and contributed to.
  - A closing keyword precedes a reference anywhere outside the section, or in the title.
  - The section holds more than 50 references.
- Exemptions:
  - The editorial checkbox, when neither title nor body holds a closing keyword.
  - A pull request opened by `dependabot[bot]`, under the same condition.
  - The sync pull request: head `main`, head repository this repository, author
    `github-actions[bot]`.
- Repository variable `CLOSING_CHOICE_SINCE` holds an ISO date. While it is unset, the job
  passes with a notice that states what it would have failed, and a missing
  `tools/closing_choice.py` passes the same way. Once the variable is set, a pull request
  created before that date is excused only from the missing-section rule, and a missing script
  or a malformed date fails the check with a message naming the cause. Unsetting the variable
  is the kill switch.
- The failure message names the rule that failed and the six spellings. It prints issue
  numbers and nothing else from the title or body.
- The template drops its prefilled `Closes #`. The section holds a comment naming the six
  spellings and saying to write one before each issue number. CONTRIBUTING.md explains the
  choice in one sentence.
- `pr-intake.yml`'s keyword-flag step stays unchanged.
- The rule is a stdlib-only module, `tools/closing_choice.py`, with no `sys.path` changes. D
  reuses its parser. Tests cover each spelling, each reference shape, a contributing list, a
  closing list where only the first reference closes, closing and contributing to one issue, a
  keyword outside the section, a keyword in the title, CRLF text, emphasis and link markup, the
  reference cap, a missing section, each exemption including a squatted sync pull request, the
  date gate, and the unmodified new template. A guard test pins the triggers, the base branch,
  the permissions, the concurrency group, and a checkout of `main` that never names the pull
  request's head.

Residuals, accepted because D verifies delivery after the merge: a required check is attached
to a commit, so a second pull request on the same commit can supply a passing result. A merger
can also edit the squash message in the merge box. Both land in D as unverified rather than as a
false delivery.

### D. Delivery verification, sweep, and monitor

#### Verification in the model

An issue counts as delivered only when the data says so. All of it comes from the landed commit
or the closing event, which nobody can edit after the fact.

- `fetch_roadmap.py` extends its issue query with the close event's `closer`:
  - for a pull request: its number, repository, merged flag, and merge commit oid and message
  - for a commit: its oid and message
  - for a person's close, there is no closer, and the event's actor is the login
- The fetch runs `closing_choice.declared_closes(message, number)` on the message in process
  and keeps only the result: whether a GitHub closing keyword precedes a reference to this issue
  anywhere in the message, and whether a contributing spelling precedes one. The whole message
  is read, not only the template section, because squash messages from before C, such as
  #174's "Closes #95.", carry their keyword in prose. The message text is discarded and never written. The node
  budget measured in phase 0 is rechecked with the larger query.
- The build checks out with `fetch-depth: 0` and asks git whether each merge commit or commit
  oid is an ancestor of `main`. Exit code 128 means the commit is not in the clone, which counts
  as not verified, never as an error that blocks the build. Oids are checked against
  `^[0-9a-f]{40}$` before they reach git.
- `classify` gains the verification rule. A close as completed by a trusted login is `done`
  when either holds:
  - The closer is a pull request in this repository, or a commit, whose message closes the issue
    and contributes to it nowhere, and whose commit is an ancestor of `main`.
  - The closer is a person who is a project lead.
- Any other close as completed by a trusted login is `unverified`, with one reason code: not on
  `main`, message does not declare a close, contributing reference, another repository, or hand
  close by a non-lead. A close by an untrusted login stays `unverified`, as today.
- Because `unverified` counts as remaining work, a milestone with any unverified issue reads In
  Progress while open and "closed with open work", In Review, once closed. A closed milestone
  never reads Published with unverified work, on the page, in `roadmap.json`, or in the sheet.
- `roadmap.json` carries the reason code, never text. `SCHEMA_VERSION` stays 1, because the
  field is additive, and `RULES_VERSION` is bumped.
- Tests cover each closer kind, each reason code, a prose "Closes #N." from before C, a message
  whose subject says "Fixes #N" and whose body says "Part of #N", a sidebar-linked close whose
  message names no keyword, a message with "Part of",
  a commit off `main`, a missing commit, a lead's hand close, a volunteer's hand close, and a
  closed milestone with one unverified issue.

#### Health issue additions

Every addition prints integers, the fixed branch names `main` and `integration`, reason codes,
and logins that match GitHub's login pattern. No fetched title, body, or message reaches the
health issue.

- Unverified closes: each unverified issue with its milestone and reason code, so a lead
  confirms by closing it again, reopens it, or fixes the missing promotion. A project lead
  confirms a volunteer's hand close by reclosing it.
- Unknown assigners in the Triage volunteers table, by row number.
- Promotion: when `git diff --quiet origin/main origin/integration` fails, the health issue says
  "Promotion pending: `integration` holds changes `main` lacks, since YYYY-MM-DD", where the
  date is the committer date of the oldest commit on `integration` that `main` lacks. It names
  an open promotion pull request by number when one exists from this repository's
  `integration`, and gives the one-line `gh pr create` command, with the title and body
  `open-promotion.yml` uses today, when none does. A squashed sync leaves the trees equal, so it
  never produces a prompt.
- Bypass report: the count of pull requests merged into `integration` or `main` in the last
  seven days whose `reviewDecision` is not `APPROVED`, with promotions and syncs counted
  separately. It lists individually:
  - a merge whose files include GOVERNANCE.md, `.github/`, `project.owasp.yaml`, or the roster
    code from A, read from the pull request files API
  - a merge from a fork whose review was not approved
  - a first-parent commit on `integration` or `main` in the window with no associated pull
    request, read from `commits/{sha}/pulls`, which is a direct push
- `open-promotion.yml` loses its `schedule` trigger and keeps `workflow_dispatch`, with a
  comment that dispatch works only if the org policy changes. Its guard test changes to match.

#### Sweep mechanics

- The sweep and dryrun jobs gain `pull-requests: read` and check out with `fetch-depth: 0`.
  Their guard tests change to match.
- Each addition is its own section. Its reads catch `SyncError`, `subprocess.SubprocessError`,
  `ValueError`, `KeyError`, and `TypeError`, and a failed section reads "Could not be read on
  this run".
- The status line gains a third value. `ok` means every section was read. `partial` lists the
  failed sections by key, exits 0, and the monitor prints a warning for it without failing.
  `degraded` still means the core snapshot failed, and still fails.
- The sweep receives the job's start time through `env:`. Reads stop eight minutes after it,
  every read's subprocess timeout is capped at the time left, and writes use 30-second timeouts,
  so the issue is written inside the job's fifteen-minute limit.
- `roadmap-sync.yml`'s `workflow_dispatch` gains a `mode` input, `dryrun` by default. `mode:
  sweep` runs the sweep job, which still requires `ROADMAP_SYNC_ENABLED`. G uses it so the
  health issue exists minutes after sync turns on.

#### Smaller changes

- `roadmap_model.DELIVERABLE_TYPES` becomes the sheet's dropdown list exactly:
  `Application/Tool`, `Cheat Sheet`, `Code Sample`, `Document`, `OSS Project`, `Other`. The
  fixture uses `OSS Project`, and a test asserts every fixture milestone parses without
  description errors. The roadmap design's "Milestone description lines" section points to the
  tuple instead of repeating the list.
- `parse_description` treats a line starting with `Note:` as a machine line. Notes go to the
  page and to `roadmap.json` as `notes`, and never into the description prose the sheet copies.
- The health issue stops reporting a missing `Workstream:` line as an OWASP problem.
- `migrate`'s dry run prints each entry's current milestone number, or `none`, next to its
  labels. Saved, that output is the undo log.

Tests use the fake GitHub and a temporary git repository with a squashed sync, a promotion merge
commit, and a direct push.

### E. Rulesets

- `protect-main` allows only merge commits. The promotion pull request's body already asks for
  one.
- `protect-integration` allows only squash merges, and the repository setting
  `allow_rebase_merge` is turned off, since no branch uses rebase.
- `protect-integration` gains `closing-choice` as a required check, in the Order's last step.
- Every required check carries `integration_id: 15368`, the GitHub Actions app, so a commit
  status or another app cannot satisfy it.
- Live ruleset edits are made with a read, modify, and write of the full ruleset JSON, with the
  read-only keys removed, so no live field is dropped.

`tools/apply_governance.py`:

- `desired_rulesets()` declares squash only on `protect-integration` from the first change. It
  adds `closing-choice` in the Order's last step, in the same change that makes the check
  required.
- `_normalize_ruleset` keeps each check's `integration_id`. `Ruleset` gains
  `require_extra_approval_for_unattributed_changes`. Both are compared and rendered, and so are
  `bypass_actors` and `conditions`.
- Both payload builders emit `integration_id`, `strict_required_status_checks_policy`, and
  `do_not_enforce_on_create`. `_protect_main_payload` starts from the live ruleset's full JSON,
  so it cannot strip code-owner review from `main`. A test pins it against the live `protect-main`
  JSON captured on October 4.
- Ruleset planning refuses to run unless the working tree is clean and `HEAD` equals the live
  tip of `integration`, read with `gh api repos/{REPO}/branches/integration`. It also refuses to
  plan the removal of a live required check, or any change to `bypass_actors`, without
  `--allow-ruleset-reduction`.
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
  suite that does not block merges. The Conformance claim template description says so in its
  prose, so the sentence reaches the page, `roadmap.json`, and the sheet.
- Every milestone description carries `Type:` and `Workstream:` lines, with `Type:` from D's
  list, and the benchmark carries `Committed: 2026-12-09`. Each also carries a `Note:` line
  saying GitHub's percentage counts every closed issue, including ones closed as not planned,
  and pointing to the health issue for verified progress.
- Before the first `--apply`, the dry run's output is saved to the scratch directory as the undo
  log.
- The migration runs with `ROADMAP_SYNC_ENABLED` off, so the event job does not race the
  migration's own writes.
- Then a project lead sets `ROADMAP_SYNC_ENABLED`, dispatches `roadmap-sync.yml` with
  `mode: sweep`, pins the health issue it creates, and sets `ROADMAP_HEALTH_ISSUE`.
  `ROADMAP_RENDER_ENABLED` and `ROADMAP_REFRESH_ENABLED` follow, and deploy-pages runs on
  `main`.
- The Day N milestones are deleted after #93 and #94 move, once Day 30 shows no open issues and
  one sweep reports `ok`.
- The skill produces per-milestone rows. Its first run reports the hand-entered ACS rows as
  orphaned, and Rock replaces them. Rows of other ASI teams are never touched.

## Order

1. Three pull requests to `integration`, in this order:
   - A, the leadership, roster, and governance text change.
   - C and E's merge-method and `apply_governance.py` changes. `CLOSING_CHOICE_SINCE` stays
     unset, so the check reports without failing.
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
- Proving the health issue was written by the sweep. Anyone with write access can overwrite it
  through a branch workflow. Checking that would add an `actions: read` grant to the monitor,
  which is its own decision.
