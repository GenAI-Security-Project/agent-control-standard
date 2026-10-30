# PR intake: one gate for work no maintainer asked for

Version 3.1, 2026-10-30. Owner: Rock Lambros. Status: design, rewritten after Rounds 2 to 5 of the premortem (`2026-10-29-pr-intake-rules-premortem.md`), amended after the plan premortem and the implementation (see Amendments). Tracking issue: issue #362.

## Intent

Maintainer attention is the scarce resource in this repository. The pull requests that
spend it without a maintainer having asked for the work pass the intake bot today, because
the bot checks one thing: does the body mention an issue carrying `status:accepted`. Any
contributor can satisfy that by copying a number from the public accepted list. The week of
2026-10-22 showed the shape: one author opened fifteen pull requests in one day, fourteen
declaring `Fixes` on accepted milestoned issues nobody had assigned and one declaring
`Part of` on an accepted umbrella. A one-line comment change to a source file (PR #354)
sits in the same queue with `Refs #92` and the editorial box ticked.

Two earlier versions of this design were measured against the live repository by the
premortem and rewritten. Version 1 keyed on the closing keyword and the editorial box.
`Part of` was a one-word bypass and the box was never what let PR #354 in. Version 2 keyed
on who holds the work but let issue authorship and any review state count as a hold. The
first turned a bulk milestone pass into thirty standing pass tokens, the second let a
months-old "changes requested" review clear a pull request forever. Version 3 keys on facts
a lead performs or has performed, keeps the bot's own writes reversible, and returns to
today's behavior whenever the switch is off.

## The gate

A pull request is reviewed when a maintainer asked for the work it contains. The bot reads
that from facts, in this order, and passes on the first that holds.

0. The author is Dependabot or the Actions bot. Out of scope: no label, no comment, no
   health row. Both are reviewed by their own workflows. Any other `type: Bot` author is
   evaluated as a non-roster author.
1. The author is on the trusted roster (`roadmap_model.trusted_logins`: project leads,
   workstream leads, triage volunteers, CODEOWNERS logins).
2. A lead has engaged this pull request. A lead is a roster login whose
   `author_association` is `OWNER`, `MEMBER`, or `COLLABORATOR`, and a lead's verdict is
   their latest `APPROVED` or `CHANGES_REQUESTED` review that is not dismissed. Any one of:
   a lead's verdict is `APPROVED`, a lead's verdict is `CHANGES_REQUESTED` within the last
   30 days (after 30 days of silence the pull request is "sent back, no response", a state the
   health issue lists), or the queue label was removed by a roster login and the pull
   request's head has not moved since (a hand clear, recorded on the data line). `COMMENTED` and
   `DISMISSED` reviews do not count: a thread reply is not a request for the work.
3. The author's record: a pull request by this author was merged in this repository with
   an `APPROVED` review from a roster login. The project already asked this person for
   work once and took it.
4. The editorial box is ticked and every changed path is on the documentation lane
   (`base_branch_guard.in_docs_lane`: `docs/topics/`, `design/`, and the root notice
   files). One definition, shared with the lane that publishes to `main`. A tick on
   `docs/spec/`, `docs/concepts/`, `specification/`, `reference-implementations/`, or any
   source path queues with the paths named.
5. The author holds a referenced accepted issue: the pull request references (any shape
   `closing_choice.parse_references` reads, closing or contributing, in title or body) an
   open issue carrying `status:accepted` to which the author is assigned. A held issue
   clears at most two open pull requests by the same author. The third queues naming the
   two. Assignment is the only hold. An accepted issue's author does not hold it by
   filing it. A lead who wants the filer to build it assigns them, which is one click at
   acceptance.
6. The standing request: the pull request references an open accepted issue carrying
   `help wanted` on which the author commented before opening the pull request. The label
   is the project's prior consent, the comment is the claim, and a lead withdraws consent
   by removing the label.

Otherwise the pull request is queued.

Drafts are not evaluated. They are re-evaluated on `ready_for_review`.

## What the bot writes

On queue: the label `status:needs-triage`. One comment. Auto-merge disabled. On clear: the
label removed and the comment edited to say so. On no change in facts: nothing. Every write
is one the bot can undo.

The comment. One per pull request. The bot finds it by two facts, never by text alone: the
comment's `user.login` equals `roadmap_model.BOT_LOGIN` exactly, and the body carries the
marker `<!-- acs-intake -->`. A legacy queue comment (a bot-authored comment beginning
"Thanks for this. It is queued rather than ignored.", or failing that one carrying
`<!-- acs-closing-keyword`) is adopted and rewritten on first contact, so an enforced pull
request never gains a second bot comment. A data line, bot-written, carries the facts the health renderer reads:
`<!-- acs-intake-data reason=<enum> issues=<n,m> since=<date> head=<sha> facts=<hash> -->`.

The comment reports every unmet route, in gate order, in the contributor's terms:

- no accepted issue referenced: "This pull request references no open accepted issue. See
  Current Priority Scope and `help wanted` for what the project has asked for."
- an accepted issue referenced and closed: "This pull request references #n, which was
  accepted and is now closed. New work on it needs a new issue."
- accepted issues referenced and not held: "This pull request references #a and #b, which
  are accepted, and neither is assigned to you." If the author has already commented on
  one of them: "You asked for #a on <date>. That claim is waiting on a lead." Otherwise:
  "To claim one, comment on it. A lead may assign it. A lead's approval of this pull
  request, or a changes-requested review, also clears the queue by the next nightly run."
- the editorial box on a path off the documentation lane: "The editorial box covers the
  documentation lane (`docs/topics/`, `design/`, and the root notice files). These paths
  are outside it: `path`, `path`. Fold the wording change into the next pull request that
  changes the file, or leave it as a comment on the issue it concerns."
- a held issue already clearing two open pull requests: "#n already clears PR #a and PR #b."

Every comment carries "This pull request is queued rather than ignored. Nothing here is
rejected." Where a closing keyword names an open milestoned issue, the merger's warning
that exists today is in the same comment. On a pull request opened before the rule landed,
the day `PR_INTAKE_LANDED` names, the comment says the rule is new and that the 30-day
clock starts today.

Paths in the comment are wrapped in code spans (which suppress autolinks), truncated at
200 characters, at most twenty of them, and the whole comment is capped at 8,000
characters.

The label. The bot owns it: set when the gate holds, removed when it stops holding, left
alone when nothing changed. A hand removal by a roster login is itself a fact (gate 2), so
the bot does not fight a lead. A hand removal by anyone else is reversed on the next
evaluation, and the comment says why.

Auto-merge. Disabled whenever the bot queues, and whenever auto-merge is on for a
non-roster author's pull request that closes an open milestoned issue, on every event,
whatever the gate decides. The
disable call is the one write whose failure is red even on an event run, because its
failure is the design's named harm. Before enforcement a lead rehearses it on a throwaway
pull request with auto-merge enabled and the tool asserts `autoMergeRequest` is null
afterwards. If the mutation needs more than `pull-requests: write`, convert-to-draft is
the fallback and the rehearsal records which path works.

## Where the gate runs

Triggers: `pull_request_target` on `opened`, `edited` (skipped only when none of body,
title, or base changed), `reopened`, `ready_for_review`, `unlabeled` (skipped unless the
label removed is `status:needs-triage`), `auto_merge_enabled`,
and `synchronize` (on which the tool re-evaluates at once only when the editorial box is
ticked. A push also lapses a hand clear, which the nightly sweep picks up).
`pull_request_review` on `submitted` and `dismissed`. It also runs on `schedule` at 03:10
UTC, before the 04:10 roadmap sweep so the health issue reports the same night's pass, and
on `workflow_dispatch` with inputs `pr_number` (optional), `mode` (`evaluate`, the default,
`dryrun`, or `retract`), and `authors` (`all`, the default, or `bots`).

Checkout. The job checks out the pull request's base ref on pull request events and
`integration` on schedule and dispatch, with `persist-credentials: false`. The job's `if`
admits pull request events only against `main`, `integration`, or `release/*`, the
ruleset-protected bases. The
pull request head never reaches the checkout. Version 2 checked out `main` and the
premortem measured the cost: promotions after other people's merges have waited 7 to 17
days, during which intake would have been silently off. This is a change from the
closing-choice check's `main` checkout, recorded for the owner.

Modes. Two repository variables arm enforcement: `PR_INTAKE_ENFORCED=true` and
`PR_INTAKE_TOOL_SHA` equal to the tool SHA, a digest over the git blob SHAs of the five
modules the gate runs, at the checked-out ref. When either is missing or mismatched the
tool runs in legacy mode: on event runs only, it queues a human author's pull request
that references no accepted issue, carries no editorial tick, and has no bot queue comment
yet (a keyword warning alone is not one), which are today's exits. On the same runs it
posts today's keyword warning as a comment of its own, with today's marker, when a closing
keyword names an open milestoned issue and no bot comment already carries that marker. It
prints what the gate would do for everything else. A legacy sweep writes nothing. Every tool change produces a new SHA, so a changed tool runs
in legacy mode until a lead dry-runs it and re-arms, and a sweep that finds enforcement
requested but the SHA mismatched is red. A third variable, `PR_INTAKE_LANDED`, holds the
day enforcement started. It changes one sentence of the comment, arms nothing, and is not
in the facts hash. Unset, no pull request counts as opened before the rule. Malformed, the
same, with one warning.

Retract. `mode=retract` removes the queue label from every open pull request whose bot
comment carries the marker (or, with `authors=bots`, from every open pull request by
Dependabot or the Actions bot), edits the comment to one line ("Retracted. This pull
request is not queued."), and prints the summary. It refuses while enforcement is armed.
This is the undo for a wrong sweep.

Event runs exit 0 on a read failure and print a notice. Nothing is written from partial
facts. Scheduled and dispatched runs are attended: every pull request is evaluated, a
failed evaluation goes into a failed list, and the run fails after the loop when the list
is non-empty or a shared listing failed, with one `::error::` line per failed pull request
(number and failure class) and a summary line that opens with the mode and the tool SHA
and counts evaluated, newly queued, queued total, cleared, unchanged, skipped (changed
during the sweep or past the budget), out of scope, errors, writes, calls, and rate limit
remaining. The same goes to the step summary, with one line per pull request in every
mode.

Pacing. Writes are paced at one per second. A `Retry-After` of up to 60 seconds is honored
once per write. A longer one fails the write, and a primary rate limit stops the write phase.
Writes happen only when the label state or the rendered comment differs from what is
there. The auto-merge call is skipped when `auto_merge` is already null. The comment edit
happens before the label change so an interrupted run leaves an explanation. Before any
write the sweep re-reads the pull request's `updated_at` and skips it, counted, when it
moved since the facts were read. All listings paginate (`--paginate --slurp`), including
files, reviews, and comments per pull request. A files listing of 3,000 entries, or shorter
than `changed_files`, is truncated and queues with that reason. A listing that fails to
arrive is an evaluation error, never a fact with a default.

Concurrency: `group: ${{ github.event.pull_request.number && format('pr-intake-{0}',
github.event.pull_request.number) || inputs.pr_number && format('pr-intake-{0}',
inputs.pr_number) || 'pr-intake-sweep' }}`, `cancel-in-progress` only on pull request
events.

Batching. On any sweep, an author with more than three newly queued pull
requests gets the full comment on the newest and a short comment on the rest ("Queued
with reason `<code>`. PR #n carries the bot's full comment.", then the auto-merge line and
the merger's warning where they apply), each still carrying its data line.

## Where the logic lives

`tools/pr_intake.py`, in the shape of `closing_choice.py`: a `Facts` record (number,
state, draft, author, author type, title, body, base, head SHA, created and updated times,
labels, changed paths with truncation flag, referenced numbers with each one's kind (issue
or pull request), state, labels, assignees, and whether the author commented on it,
reviews with state, login, association, commit, submitted time, the last removal of the
queue label and who did it, the bot comment and its data line, auto-merge state, the
author's merged-and-approved record, roster, and mode) and a pure `decide(facts) -> Decision`
returning the gate outcome, the unmet routes, the label action (`set`, `clear`, `keep`),
the comment text and data line, and the auto-merge action. `main()` collects facts through
`tools/gh_runner.py` and applies the decision.

`tools/gh_runner.py` is `fetch_roadmap._runner` lifted into a module both this tool and
`roadmap_sync.py` use: absolute `/usr/bin/gh`, a minimal environment (`PATH`, a fresh
`HOME`, `GH_TOKEN`, `GH_HOST`, `GH_PROMPT_DISABLED=1`, `GH_NO_UPDATE_NOTIFIER=1`), a
`--gh` flag for tests, and an allowlist of argv shapes, one pattern per operation (the
reads, `api -X PATCH repos/<REPO>/issues/comments/<digits> --input -`, `api -X POST
repos/<REPO>/issues/<digits>/comments --input -`, `api -X POST
repos/<REPO>/issues/<digits>/labels --input -`, `api -X DELETE
repos/<REPO>/issues/<digits>/labels/status%3Aneeds-triage`, `pr merge <digits>
--disable-auto --repo <REPO>`, and the draft fallback `pr ready <digits> --undo --repo
<REPO>`). Every body goes to stdin as JSON. `PR_NUMBER` matches
`^[0-9]{1,9}$`. `gh` stderr is never echoed. A failure prints its class. Nothing from the
pull request reaches argv or a workflow command.

References inside an HTML anchor whose target is outside this repository are dropped
before parsing, so a Dependabot changelog's `#146` is not this repository's #146.

`pr-intake.yml` becomes: the job, named, with `contents: read`, `pull-requests: write`,
`issues: read`, each line commented. Checkout as above. One step that runs
`python3 -I -S tools/pr_intake.py` with the event's number, the dispatch inputs, and the
two variables in `env`. The `zizmor` ignore comment says what `closing-choice.yml`'s
says: the job checks out a maintainer branch, never the pull request head.

`monitor_roadmap.py` gains one check: the conclusion of the last scheduled intake run. On
a change it comments on the health issue mentioning every lead, as it does for the
roadmap monitor today (decision 17), so a red nightly sweep reaches more than the one
mailbox GitHub emails.

The closing-choice check is unchanged. A code-path editorial tick is queued, not failed.
This keeps the 2026-09-09 governance decision not to make the box a red check, and the
premortem found the owner's own PR #357 would have failed the red check. It is a deviation
from the owner's 2026-10-29 request. The owner writes one line here, "Deviation accepted"
or "Overridden", before the implementing pull request opens.

## The health issue

`roadmap_sync.py` gains a section, "Queued pull requests", rendered from the bot's own data
lines (read only from comments whose `user.login` is `BOT_LOGIN` exactly), with the
invariant the report already keeps: numbers, reason codes, and days, no contributor
login, no fetched text. Grouped by reason, with one search link for the per-author view.
Under it: "Claims waiting on a lead" (an open accepted issue referenced by a queued pull
request on which that author has commented, with the claim's age), "Queued more than 30
days" (the clock starts at the first sweep for pull requests opened before the rule),
"Awaiting re-review", "Sent back, no response" (changes requested, 30 days silent), and
"Labeled without a gate record", and three counts: median age of queued pull requests
(every day count here runs from the data line's `since`, the first queue),
pull requests a lead cleared by hand that merged in the last 60 days, and non-roster pull
requests merged in the last 60 days against the 60 days before. A project lead records
the baselines in the `PR_INTAKE_BASELINES` repository variable the morning after
enforcement, and the section names the review date 60 days later. The intake sweep's last
conclusion and run link sit at the top of the section. If claims waiting rise or
non-roster merges fall against the prior 60 days, the switch goes back to legacy mode.
That is the failure condition, written now.

## Documentation

CONTRIBUTING.md, "How work gets accepted": the gate in the contributor's words, each route
one sentence, and "If a form, a template, or a bot comment disagrees with this section,
this section wins."

CONTRIBUTING.md, "What We Need": `help wanted` issues are the project's standing request.
Comment on one to claim it, then open the pull request. The comment is the claim. "You can
open a pull request against it without waiting on triage" is removed, as is the line at
73-74 that says the same.

`.github/PULL_REQUEST_TEMPLATE.md`: the editorial checkbox reads "This is an editorial
correction on the documentation lane (typo, grammar, link, formatting) with no change in
meaning, so it needs no issue", and the HTML comment above the issue section no longer says
"open the PR anyway. It will wait rather than be closed" without the claim step.

README.md: the paragraph and the mermaid flow under "How work gets accepted" gain the claim
step. `.github/ISSUE_TEMPLATE/3-reference-implementation.yml`: the line pointing at `help
wanted` says to comment first.

GOVERNANCE.md, "Triage authority": a lead or triage volunteer accepts a claim by assigning
the claimant. GitHub permits assigning a non-collaborator only after they comment. Under
"How leadership changes": a roster entry also exempts that login's pull requests from
intake and lets their approval clear another's, so it is added only for people who review
here. A GOVERNANCE/CODEOWNERS follow-up reconciles the roster with repository access
(three workstream leads hold no access today) before enforcement.

## Goals

- A non-roster pull request is reviewed when a lead asked for the work, read from a lead's
  review, a lead's hand clear, the author's merged record, an assignment, or a claim on a
  `help wanted` issue.
- The queue label is true: set and cleared by the bot from facts, never stale for longer
  than a night, listed nightly on the health issue, retractable in one dispatch.
- One bot comment per pull request, edited in place, every unmet route named.
- Off means today's behavior.
- Every promise has a test, listed below.
- Three outcome measures on the health issue with their baselines, and a written failure
  condition.

## Non-goals

- No cap on open pull requests per author (the per-issue cap of two is a different thing).
- No change to how an issue becomes accepted, to the labels, or to the milestones.
- No change to the closing-choice check.
- No automatic closing of any pull request.
- Dependabot and the Actions bot are out of the gate's scope.

## Anti-goals

- A rule that depends on a human noticing.
- Blocking a lead's own pull request, or one a lead has approved.
- A red required check on an honest editorial declaration.
- A bot comment that reads as a rejection, promises an action nobody performs, or names a
  contributor in a governance record.
- A write the bot cannot undo.

## Constraints

- `pull_request_target` with `permissions: {}` at the top. The pull request head is never
  checked out. No `${{ }}` in any `run:` in any job, and zizmor passes.
- `tools/pr_intake.py` and `tools/gh_runner.py` run under `python3 -I -S`.
- CODEOWNERS: `/.github/`, `/tools/`, `/tests/` need a project lead's approval. The
  implementing pull request carries one non-author approval.
- `monitor_roadmap.py` and the roadmap sweep need `actions: read` to list the intake
  sweep's runs. The monitor job and the roadmap sweep's two jobs gain that permission and
  no other.
- Prose follows STYLE.md.

## Tests

- `tests/test_pr_intake.py`, `decide`: one case per gate route passing. Roster login
  without a repository role does not clear by review. `COMMENTED` and `DISMISSED` do not
  clear. `CHANGES_REQUESTED` at 29 days clears and at 31 days does not. Hand clear by a
  roster login holds while the head is unchanged, by a non-roster login is reversed. The merged
  record passes. Editorial on the lane passes, off the lane queues naming the paths.
  Held issue passes, third pull request on one held issue queues naming the two. Issue
  author without assignment queues. `help wanted` with a prior comment passes, without
  one queues. Closed accepted reference gets its own reason. Several unheld references
  render as a list. A body failing two routes renders both. Drafts and bots produce no
  action. Truncated files listing queues. Legacy comment adopted (one edit, no post).
  Unchanged facts produce zero writes. Legacy mode writes only today's queue and keyword
  warning on an event run, and a legacy sweep writes nothing. A tool SHA mismatch means legacy mode. Retract removes and edits. Auto-merge
  disabled on queue and on the state case. A null review user and a `Bot` reviewer are
  skipped. A reference to a pull request number is not an issue. A changelog anchor is
  dropped.
- `tests/test_gh_runner.py`: a hostile fixture (title, body, paths, logins with `@`,
  leading `-`, `../`, newlines) produces byte-identical argv to the expected list. Any
  argv outside the allowlist raises. Bodies go to stdin.
- `tests/test_pr_intake_workflow.py`: the triggers. The `edited` guard with base. The
  checkout rule. `contents: read`. The concurrency expression. The cron and its position
  before 04:10. `${{ }}` absent from every job. The sweep evaluates 35 stubbed pull
  requests with `--paginate` on the listing. A sweep with one failed evaluation is red
  with its `::error::` line and the summary. An event run with a read failure exits 0 and
  writes nothing. The stub serves recorded real responses from `tests/fixtures/` for
  files (two pages), reviews, comments (REST login form), the pulls listing, and the
  `--slurp` shape.
- `tests/test_roadmap_sync_health.py`: the queued section renders numbers, reasons, and
  days only (a queued pull request by `outsider` leaves no login). A data line in a
  comment by anyone but the bot is ignored. The 30-day, sent-back, and claimed headings.
  The three counts.
- `tests/test_monitor_roadmap.py`: the intake conclusion check and its comment on change.
- A test ticks the template's own checkbox line and asserts `closing_choice.EDITORIAL`
  matches it, and does not match the unticked line. A guard that README's paragraph and
  the template's comment carry the claim phrase CONTRIBUTING uses.

## Rollout

1. Merge to `integration` with one non-author approval. The pull request says `Part of
   #362`, so the merge does not close the tracking issue. The new workflow runs at once on
   pull requests against `integration` (base-ref checkout) in legacy mode, which is today's
   behavior.
2. Precondition for what follows: the GOVERNANCE/CODEOWNERS reconciliation is merged, or a
   project lead writes on issue #362 why the three roster entries without repository access
   stay.
3. Dispatch `mode=dryrun` with the variables unset and read the would-queue list and the
   tool SHA it prints. Before promotion, select the `integration` ref in the dispatch form,
   because the default branch still carries the old workflow file, which has no `mode`
   input.
4. Leads clear the collateral by the gate's own facts, using that list: approve, request
   changes afresh, or assign, on every pull request a lead has already engaged (PR #24,
   PR #112, PR #113, PR #297, PR #253, PR #255, and PR #259) and on any first-time
   contributor whose work the project wants. Done when a second dry run lists none of
   those, or a project lead writes "proceed with the remainder"
   on issue #362.
5. Rehearse the auto-merge disable on a throwaway pull request.
6. Promote, so pull requests against `main` run the same workflow and the health issue and
   the monitor report on it.
7. Edit the live `help wanted` label description, retract the queue label from the bots'
   pull requests, then set `PR_INTAKE_TOOL_SHA`, `PR_INTAKE_LANDED` (today's date), and
   `PR_INTAKE_ENFORCED=true` in one sitting and dispatch the live sweep outside the 03:00
   to 04:30 UTC window.
8. The next morning, record `PR_INTAKE_BASELINES` from the health issue.
9. A project lead closes issue #362 by hand.

The checklist on issue #362 carries each step's actor and expected result. Undo at any
step: unset `PR_INTAKE_ENFORCED`, then dispatch `mode=retract`.

## Risks and how they are held

- The roster trusts login strings, three of them without repository access. Gate 2 adds
  the `author_association` check for reviews, and the reconciliation follow-up precedes
  enforcement. Gate 1 (author) still trusts the roster. Accepted, and the GOVERNANCE
  sentence says what a roster entry now grants.
- A roster that fails to parse trusts nobody. The tool prints a warning and writes nothing.
- A held issue can clear two unrelated pull requests. Accepted at two. The health issue
  shows held issues with open pull requests.
- Claims on issues have no responder today (one in four answered, measured). The comment
  no longer promises one. The health issue lists claims older than 14 days as a lead
  agenda item. Issue #145's first-response target is the real fix and stays open.
- A runner image update changes a `gh` shape. The recorded fixtures do not catch it. On
  the nightly sweep, a shared listing that fails to arrive, a per-pull read that fails, or
  a response in a shape the tool cannot read is red. A comments listing in which no entry
  has a `user` object and a `body` string is such a response, and `paths_truncated`
  catches a files listing shorter than the pull request's changed-file count.
- The base-ref checkout trusts the ruleset of the base it runs from. `main`,
  `integration`, and `release/*` are ruleset-protected. Other branches in this repository
  are not (26 when the plan premortem counted), and a pull request can target any of
  them, so the job's `if` admits only the three. Each protected base requires one
  code-owner approval, and an admin can bypass each one. Recorded for the owner.

## Amendments

These amend version 3.0. The first group comes from the plan premortem
(`2026-10-29-pr-intake-rules-premortem.md`, "Plan premortem"). The second group records
rulings made during implementation. The third records the fixes from the whole-branch
review. Where a body sentence above contradicted one of them, the sentence was changed to
match.

### From the plan premortem

Auto-merge keyed on state. The bot turns auto-merge off whenever it is on for a non-roster
author's pull request that closes an open milestoned issue, on every event including
`auto_merge_enabled`, whatever the gate decides. Version 3.0 keyed the rule on an edit
that adds a closing keyword, which needs a before-and-after body the tool never has and
misses the dangerous moment, the enable. The trade is that a non-roster pull request
closing a roadmap issue never auto-merges. The comment says so, and a lead merges it by
hand.

Hand-clear head record. A hand clear holds while the pull request's head is the one the
bot recorded on the data line when it first saw the roster unlabel. The `unlabeled`
trigger makes that first sight immediate. Version 3.0 read the last push from the
timeline, whose commit dates the pusher sets, so a clear could outlive several pushes.

Help-wanted cap. The `help wanted` route clears at most two open pull requests per author
per issue, the same cap as assignment. Uncapped, one comment on one issue cleared all
fifteen of one contributor's pull requests in the premortem's replay.

Editorial-first ordering. An editorial tick with any changed path off the documentation
lane queues as `editorial_off_lane` before the issue routes are read. Read in plain gate
order, the motivating pull request, PR #354, passed through the `help wanted` route on a
dogfooding comment.

`awaiting_rereview` and `paths_truncated`. A changes-requested review older than 30 days,
with no newer roster review, queues as `awaiting_rereview` when the author pushed or
commented after it, and as `sent_back` only when the author has been silent. A files
listing of 3,000 entries, or one shorter than the pull request's changed-file count,
queues as `paths_truncated` and never passes as editorial. Version 3.0 charged a lead's
silence to the contributor and had no reason code for a truncated listing.

Sweep budget. A sweep drops bots and drafts from the listing before reading anything,
resolves references against the shared listings instead of reading each issue, skips a
pull request whose facts have not moved since the bot last wrote, and reads the rate limit
every ten evaluations. Reading stops 150 calls short of a 600-call budget, or when fewer
than 150 calls remain in the hourly limit, so the writes for what was read still fit. The
rest are counted as skipped and the run is red. The job times out after twenty minutes.
Unbounded, the nightly sweep could spend most of the hourly limit in the roadmap sweep's
hour, and one body naming many numbers could spend it alone.

Base-ref `if`. Pull request events run the job only when the base is `main`,
`integration`, or `release/*`. The checkout trusts the base's ruleset, and those three are
the bases that have one.

Honest base-ref sentence in Risks. The Risks section now says which bases are protected
and that the others are not. The version 3.0 sentence implied every base ref was
protected.

Baselines variable. The outcome baselines live in the `PR_INTAKE_BASELINES` repository
variable, set by a project lead the morning after enforcement, and the health section
names a review date 60 days later. The counts compare 60-day windows, and hand clears are
counted from the route on the data line. The `pull_request_review` trigger serves the same
measure: approved non-roster pull requests merge within hours of approval, so a review
that cleared only at the nightly sweep would have counted the designed path as a false
queue. Version 3.0's baselines could not be read from anything the tool wrote.

Dry-run mode. `mode=dryrun` runs the enforced logic, writes nothing, prints every
decision, and prints the value that arms the tool. Legacy mode writes only on event runs,
and a legacy sweep writes nothing. The tool SHA covers the five modules the gate runs, and
a sweep that finds enforcement requested with a mismatched SHA is red, with the remedy in
its error line. In version 3.0 the rollout's dry sweep ran in legacy mode, which wrote, and
a tool change de-armed the gate with every signal green.

Retract order. Retract refuses while enforcement is armed. The undo at any step is to
unset `PR_INTAKE_ENFORCED` first, then dispatch `mode=retract`, so the gate cannot
re-queue what the retraction cleared. With `authors=bots`, retract clears the queue label
inherited by Dependabot pull requests, which carry no gate record.

`Part of #362`. The implementing pull request names the tracking issue with `Part of`, so
its merge to `integration` does not close issue #362. A project lead closes the issue by
hand once the rollout is done. A closing keyword would have closed it at the first rollout
step.

### From the implementation

Known bots. Only Dependabot and the Actions bot are out of the gate's scope, together with
drafts, in both modes. Any other `type: Bot` author, a GitHub App for instance, is
evaluated as a non-roster author. Scoping out every bot would have let any app pass a gate
that queues it today.

Facts hash. The hash that decides whether anything changed covers the pull request's
creation time, the recorded hand-clear head, and whether each reference is an issue or a
pull request. It leaves out the state the bot owns, the queue label and the bot's own
unlabel events, instead of predicting it. The hash detects a change in facts a person
performed, and the bot's writes are not such facts.

Repeat hand clears. A roster unlabel records both the head and the unlabel time on the
data line. After a push lapses a clear, a second roster unlabel newer than the recorded
time counts as a fresh clear. Without the time, a lead could clear a pull request once.

Auto-merge call budget. The auto-merge write is exempt from the call budget, because its
failure is the harm the design names. Disabling auto-merge on every queued non-roster pull
request is already in the body and is not restated here.

Reference caps. A pull request's referenced issues are read up to twenty, and claim
comments on up to five of them, and the bot comment says when a list was cut. A draft
takes no slot in the cap of two open pull requests per author per issue, which binds the
assignment and `help wanted` routes alike. Per-reference reads let one body spend the
budget, and a slot held by a draft, which the gate never evaluates, would queue a real
pull request.

Author record. The merged-and-approved record is not read for roster, bot, or draft
authors. The gate never reaches that route for them, and the read costs one call per
merged pull request.

Closing keywords. When a number appears twice with different keywords, the strongest
wins, because GitHub closes the issue on merge in that case.

Pacing. A `Retry-After` is honored up to 60 seconds, and a longer one fails the write. The
write phase stops on a primary rate limit, since that window is far longer than any wait
worth holding a job for. A queue label whose write failed is re-applied by the next
nightly sweep.

Seen. A pull request counts as seen from the bot's write time plus 120 seconds, extended to
the newest `updated_at` among the accepted issues it references. A lead's assignment after
the bot wrote is therefore a new fact, and the sweep reads the pull request again.

Expiry. A pass that rests on a review carries an expiry, and the nightly sweep
re-evaluates the pull request once it is past. Without it, an unchanged pull request would
keep a 30-day pass forever.

Fork reviews. A `pull_request_review` run on a fork's pull request holds a read-only
token, so an approval on a fork clears the label at the nightly sweep, not within the hour.
Same-repository pull requests clear on the review event.

Schedule and modes. The nightly sweep runs at 03:10 UTC, and dispatch takes `evaluate`,
`dryrun`, or `retract`, with `authors` set to `all` or `bots`, as the plan ordered. Running
before the 04:10 roadmap sweep is best effort, since scheduled runs on this repository
have started up to two hours late.

Health section. "Hand-cleared" counts only pull requests merged in the window. The median
age covers rows with a readable gate record. Bot-authored merges are left out of the
non-roster merge counts. The closed pull request listing is read newest first, page by
page, and stops once a page's oldest update is older than 120 days. Past ten pages the
whole section degrades instead of reporting a partial count. Comments are read only for
pull requests merged in the last 60 days, the only ones the counts use. A queue comment in
the earlier format is counted and listed on its own line. A baseline date far in the
future reads as not recorded, so a typo cannot stop the health write. One plan deviation:
`intake_recent` is not in the roadmap report's normalization exclusion list, because it is
not a report key and a dead entry misleads the next reader.

Monitor signature. The monitor's `evaluate` keeps its positional parameters and takes the
run reader as a trailing keyword with a default. The plan's keyword-only form would have
broken every existing caller for no behavior the task needed. This is a plan deviation.

Contributor text. The CONTRIBUTING editorial sentence names the documentation lane as
CONTRIBUTING defines it, `docs/topics/`, `design/`, and the root notice files, because the
gate admits the root files and the section's precedence sentence would otherwise bind the
narrower rule. The roster sentence names triage volunteers with the leads and code owners.
The key phrase is "assigned to you". The CODEOWNERS exemption sentence spans two comment
lines to stay inside the header's width.

Draft until the owner's line. The implementing pull request opens as a draft and is marked
ready for review once the owner writes the line in "Where the logic lives". This replaces
"before the implementing pull request opens" in that paragraph, which is left as the owner
wrote it. The live `help wanted` label description changes at rollout, not at merge,
because the label is repository state the merge does not touch.

### From the whole-branch review

Legacy keyword warning. Legacy mode posts today's keyword warning on event runs, as a
comment of its own carrying today's exact marker, `<!-- acs-closing-keyword:<numbers> -->`
with the numbers in today's string order, when no bot comment already carries that marker.
Legacy's "already commented" test counts a bot comment that opens with today's queue
sentence or carries the intake marker, and not one that carries only the keyword marker.
Adoption prefers the queue comment over the warning. The earlier legacy sentence named
the queue write alone, so between merge and arming a non-roster pull request closing a
roadmap issue got no merger warning, and a pull request carrying only the warning was
never queued. The markers the bot posted are collected as a bot-owned fact outside the
hash.

Queue clock. Every day count in the health section, the rows, the 30-day heading, and the
median, runs from the data line's `since`. The section earlier computed them from the pull
request's creation time, which contradicted the 30-day clock that starts at the first sweep
for a pull request opened before the rule, and the bot's own comment that says so.

Sweep ref. Schedule and dispatch check out `integration`, not the default branch. The dry
run that produces `PR_INTAKE_TOOL_SHA` and the sweep that enforces it must run the same
ref. The earlier text and the workflow comment said the default branch. A dispatch before
promotion selects `integration` in the form, since the default branch's workflow file is
the old one.

Landing date. `PR_INTAKE_LANDED`, a repository variable set with the SHA and the switch,
holds the day enforcement started, and the "rule is new" sentence reads it. Unset or
malformed means no pull request predates the rule, and malformed also prints one warning.
It is outside the hash and outside arming. The earlier code held a placeholder constant no
step could set.

Latest verdict. A lead's latest `APPROVED` or `CHANGES_REQUESTED` review stands and their
earlier ones drop, so an approval followed by the same lead's request for changes reads as
the request and goes stale after 30 days. A `COMMENTED` review neither grants nor takes back
a verdict, and still counts as the lead looking again for the sent-back test. The earlier
sentence, "an `APPROVED` review that is not dismissed", let such an approval pass forever.

Review expiry. Only a fresh changes request sets a review pass's expiry. An approval never
goes stale, so an approval-only pass carries none and the nightly short circuit holds on
it. The earlier expiry included approvals and re-read those pull requests every night.

Fork review runs. A `pull_request_review` run on a pull request whose head repository is
not this one decides with writes off, prints the decision and a notice that the nightly
sweep applies it, and exits 0. The earlier run tried the writes on the read-only token,
and a failed auto-merge disable turned it red.

Shape checks in Risks. The Risks bullet on a changed `gh` shape names the checks the tool
has: a failed shared listing, a failed per-pull read, or an unreadable response is red on
the nightly sweep, a comments listing with no entry in the REST shape raises rather than
reading as no bot comment, and `paths_truncated` catches a short files listing. The earlier
text named a weekly legacy-mode check for facts read empty, which no code performs, and the
sweep is nightly.

Queue label trigger. The `unlabeled` trigger runs the job only when the label removed is
`status:needs-triage`, the one removal the gate reads. Every other removal spent about
twenty calls to decide nothing new. The concurrency group is unchanged, so a run for another
label's removal still joins the pull request's group and can cancel an event run in
flight before its own job is skipped. The nightly sweep makes the cancelled run's writes.

Batched comment. The short comment on an author's other new queues names its own first
reason code and keeps the auto-merge line and the merger's keyword warning. The earlier
one-liner dropped both and assumed the newest pull request was queued for the same reason.
