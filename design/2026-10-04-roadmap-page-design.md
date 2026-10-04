# A live community roadmap, and an OWASP report on demand

Version: 1.3
Owner: ACS project lead
Date: 2026-10-04
Status: design, awaiting approval of the written spec

Three adversarial premortem rounds shaped this version. Round one removed automatic milestone
closing, guarded acceptance against deferred work, dropped the `pull_request_target` trigger,
and made roadmap failures degrade the page instead of blocking merges. Round two replaced a
post-render scan that could not see script injection, fixed a concurrency default that would
have cancelled most acceptance events, made every milestone state reachable, and moved the
OWASP report into a deterministic script. Round three found that the title guard covered one of
four rendered issue classes, that Python-Markdown parses some top-level raw HTML lines as
Markdown, that rate-limit responses were classed as permission defects, and that the model
running the OWASP skill still read text a write-role account could plant.

The weekly promotion to `main` has failed since September 24, so nothing in this design can
reach the published site until it is repaired. That repair is a separate decision.

Contributors arriving from the OWASP relaunch can see what the project accepts, but not when
any of it lands. This design publishes a roadmap page built from GitHub milestones and accepted
issues, rebuilt every night. A separate skill produces rows for OWASP's quarterly roadmap
spreadsheet on request.

## Goal

A contributor can open one page and see each deliverable the project has committed to, its
target quarter, and how much of it is done. A maintainer can say "Update the roadmap for OWASP"
and get rows ready to paste.

The upkeep this design asks for is the weekly triage pass the project already runs: setting a
milestone on accepted work, and closing a milestone when its work reaches `main`. Everything else
is automated, and everything the automation will not repair lands on one pinned issue that pass
reads. Triage itself is under strain, with the untriaged backlog doubling between September 17
and October 4. This design cannot fix that. It keeps the roadmap from adding to it.

## Decisions

| Question | Decision | Why |
| --- | --- | --- |
| Unit of the roadmap | One GitHub milestone is one deliverable | A milestone already carries a title, a due date, a description, and a set of issues. |
| Which milestones | New milestones named for what ships, replacing the Day 14/30/60/90 checkpoints | Each Day N description bundles unrelated outcomes under a title that says nothing to an outsider. |
| Target granularity | Calendar quarter, with an optional committed date where one was promised | A volunteer project cannot staff day-level dates, and the one dated commitment it made must not be hidden by rounding. |
| Freshness | Nightly rebuild of static HTML | The site renders with JavaScript disabled. |
| Page and spreadsheet | Two outputs over one rules module, `tools/roadmap_model.py` | They answer to different readers but must classify a milestone the same way. |
| OWASP procedure | A personal skill, `owasp-acs-roadmap`, driving a deterministic script, with no repository text in the model's context | The model runs in a session holding an admin credential. |
| Milestone upkeep | Setting a milestone accepts an issue, unless a standing triage decision says otherwise | The project has no capacity to apply two labels where one act will do. |
| Shipping | A maintainer closes a milestone when its work reaches `main`. Automation never closes one. | Every automated trigger for closing fired on work that had not shipped. |
| Which code runs | Every job runs the tools from `main` | The page renders from `main`, so the sync and health jobs classify against the same rules. |

## The shared rules

`tools/roadmap_model.py` holds every rule that decides what an issue or a milestone means. It is
standard library only, has no network access, and carries a `RULES_VERSION` string that changes
whenever a rule does. The renderer, the sync tool, and the OWASP script all use it.

### Milestone description lines

A milestone description may carry three machine-read lines, each on its own line. The page
strips them before showing the description.

- `Committed: 2026-12-09` names a date the project promised. It drives target-passed detection
  in place of the quarter's end, and the page shows it next to the quarter.
- `Workstream: Reference Implementation` names the owning workstream. Its value must match a row
  of the `GOVERNANCE.md` workstream table.
- `Type: Open Source tool` names the OWASP deliverable type. Its value must be one of the types
  the sheet already uses: Document, Cheat Sheet, Open Source tool, Application/Tool, Code Sample,
  Agent Skill, Other.

Creating or editing a milestone needs the Write role or higher, so these lines are written by the
11 accounts that hold it, not by outsiders.

### Issue classes

Every issue in a milestone falls into exactly one class. Pull requests are dropped first, by the
`pull_request` key. The rules are checked in order:

| Class | Rule | Counts toward progress |
| --- | --- | --- |
| Dropped | closed with `state_reason` `not_planned` or `duplicate` | no |
| Done | closed with `state_reason` `completed` | yes, as done |
| Planned | open and carrying `status:accepted` | yes, as remaining |
| Deferred | open and carrying `scope:deferred` | no, listed separately |
| Untriaged | any other open issue | no, reported |

`status:accepted` is checked before `scope:deferred`, matching the precedence the board
reconciler already uses in `desired_board_status`.

Progress reads "4 of 9 issues closed", where 9 is done plus planned. The page's introduction
says progress counts delivered issues only, because GitHub's own milestone page also counts
closed pull requests and dropped issues.

### Milestone states

Closed milestones are classified first, then open ones. The first matching row wins.

| State | Rule | Page | OWASP status |
| --- | --- | --- | --- |
| Published | closed, at least one done, no planned | Delivered section, with any dropped count shown | Published |
| Closed with open work | closed, at least one planned | Delivered section, marked "closed with open work", and reported in the health issue | In Review |
| Withdrawn | closed, no done | Withdrawn section | no row, and the script reports any existing row for removal |
| Skipped | open, no done, planned, or deferred issues | not shown | no row |
| Deferred | open, only deferred issues | card, "N deferred issues", no progress bar | Planning |
| Ongoing | open, no `due_on` | card, quarter reads "Ongoing" | Ongoing |
| Ready to publish | open, at least one done, no planned, no deferred | card, "work complete, awaiting release" | In Review |
| In progress | open, at least one done | card | In Progress |
| Planning | open, otherwise | card | Planning |

A table-driven test enumerates every combination of open or closed, dated or undated, and zero
or nonzero done, planned, deferred, and dropped counts, and asserts exactly one state each. A
second test walks every row of the Changing the roadmap table and asserts the state that
procedure produces.

### Quarters and dates

The quarter comes from the date part of `due_on`, read as a calendar date with no timezone
conversion. GitHub stores milestone dates at midnight UTC on the chosen date, as the live Day 14
milestone shows (`2026-09-24T00:00:00Z`).

An open milestone's target has passed when the current UTC date is after its `Committed:` date,
or, without one, falls in a later quarter than its `due_on`. The page reads "Q4 2026, target
passed". Whether a due date set in the GitHub UI from a non-UTC browser keeps the chosen date is
unverified, so migration step 1 tests it. A `due_on` that is not a quarter's last day is reported
in the health issue either way.

### Trusted authors

An issue author can edit their issue's title at any time, including after it closes. An author is
trusted when their `author_association` is `OWNER` or `MEMBER`. `COLLABORATOR` is not enough on
its own, because this repository has seven read-role collaborators who hold no triage authority.
Every other author is untrusted.

## The roadmap page

### Where it lives

The page publishes at `/docs/roadmap/` as a top-level "Roadmap" entry in the MkDocs nav, with a
link from the landing page's section nav next to "Specification".

`docs/roadmap.md` is committed with a fixed introduction and a replaceable region:

```html
<!--ACS:ROADMAP:START-->
<div class="acs-roadmap">
<meta name="acs-roadmap-status" content="placeholder">
<p class="acs-roadmap-note">Live roadmap data appears only in the published site.</p>
</div>
<!--ACS:ROADMAP:END-->
```

The region is always exactly one `<div class="acs-roadmap">` on its own line, holding everything
else. Python-Markdown decides line by line whether a top-level line starts a raw HTML block, and a
scratch build showed it wrapping a top-level `<meta>` or `<span>` line in `<p>` and parsing the
line's text as Markdown. A single enclosing `<div>` keeps the whole region raw, which the same
scratch build confirmed.

The render step replaces everything between the markers and fails unless each marker appears
exactly once, in order. A test asserts the committed file still holds the placeholder.

### What it shows

The fixed introduction says the roadmap shows quarterly targets set by volunteers, which move as
capacity does, and that progress counts delivered issues only. It links to Current Priority Scope
by absolute URL,
`https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CONTRIBUTING.md#current-priority-scope`,
because MkDocs strict mode rejects a link outside `docs/`.

Inside the region's `<div>`:

1. `<meta name="acs-roadmap-status" content="ok">` and
   `<meta name="acs-roadmap-generated" content="<ISO-8601 UTC>">`.
2. One card per milestone in a card state, ordered by quarter, then title, with Ongoing and
   Deferred milestones last. A card shows the title linked to the milestone, the quarter and any
   committed date, the progress count and bar, the description as plain text, and the issues by
   class, each with number, title, and state, linked to GitHub.
3. A collapsed "Delivered" section, newest close first.
4. A collapsed "Withdrawn" section.

### Untrusted titles

For every issue the page renders, in every class and state, cards and Delivered alike, whose
author is untrusted, the fetch reads the issue's events. When the events hold a `renamed` event by
the issue's author after the issue's latest `milestoned` event, and no later `renamed` event by
anyone else, the page shows "#N, title changed after it joined the roadmap" instead of the title.
A maintainer clears it by editing the title once.

The rule anchors on `milestoned`, not on `status:accepted`, because Deferred, Untriaged, and Done
issues may never carry that label. It is sticky, so reverting a title before the nightly build
does not hide the change. The fetch reads `/issues/{n}/events`, which carries renames and milestone
changes but not comments, so an author cannot slow the fetch by padding their issue with comments.

### Fetching the data

Fetching runs in its own job, so the token never shares a job with the documentation toolchain.

`deploy-pages.yml` gains a `roadmap-data` job. It runs only when the event is not
`pull_request` and `ROADMAP_RENDER_ENABLED` is `true`. It holds `contents: read` and
`issues: read`, installs nothing, and checks out with `persist-credentials: false`. Its one tool
step runs `python3 -I -S tools/fetch_roadmap.py <out.json>` with `GH_TOKEN: ${{ github.token }}`
in that step's `env:` only. The script is standard library only, imports nothing from `tools/`,
calls `/usr/bin/gh` by absolute path with an explicit minimal environment (`PATH`, a temporary
`HOME`, `GH_TOKEN`, and `GH_HOST=github.com`), and enforces its own four-minute deadline under a
five-minute step timeout. It always writes `out.json`, holding either the data or a failure record
with a class, and uploads it as an artifact.

The `build` job keeps `contents: read` and `pages: read`, and gains no token. It downloads the
artifact when the `roadmap-data` job ran, and otherwise uses the committed fixture
`tests/fixtures/roadmap-data.json`. Pull request builds therefore always render the fixture
through the real `mkdocs build` and run the structural check over it, which exercises the
renderer and the guard on every change without spending API calls on fork pull requests. A missing
or unreadable `out.json` is a data failure.

The fetch reads milestones from GraphQL, whose `issues.totalCount` on a milestone counts issues
alone. It reads issues from REST with
`gh api --paginate "repos/GenAI-Security-Project/agent-control-standard/issues?milestone=*&state=all&per_page=100"`,
and events for every rendered issue with an untrusted author.

The completeness check drops pull requests, dedupes by number, and requires, for every milestone,
that the issues fetched equal its GraphQL issue count, in both directions. A mismatch, a transport
error, an HTTP 5xx, or a rate-limit response triggers up to two refetches, 20 seconds apart.

Responses are classified from `gh api -i` headers. A 403 or 429 with `x-ratelimit-remaining: 0`,
a `retry-after` header, or "rate limit" in the message is a rate limit. Any other 401 or 403 is a
permission defect. Each class has its own exit code and failure record.

### Failure behavior

The roadmap must never stop a schema from publishing or a pull request from merging. The refresh
dispatches deploy-pages with the input `source=nightly`, and only a run carrying that input treats
roadmap trouble as fatal, since it carries nothing else.

| Failure | Pull request build | `source=nightly` dispatch | Any other build on `main` |
| --- | --- | --- | --- |
| Data failure, rate limit, timeout, or missing data after retries | not applicable, fixture rendered | build fails, so Pages keeps the last good page | region shows "Roadmap data is temporarily unavailable", status `unavailable`, build passes |
| Permission defect | not applicable | build fails | build fails |
| Any other exception in model or render | build fails, since fixture data is fixed | build fails | status `unavailable`, build passes |
| Structural check violation | build fails | build fails | region replaced by the `unavailable` placeholder, which is scanned again, and the build passes only if that scan is clean |
| Marker missing or duplicated | build fails | build fails | build fails |

A permission defect fails every publishing run because it will not clear by itself. A structural
violation on a push to `main` removes the offending content rather than blocking schemas, and the
`unavailable` status raises the roadmap monitor, so a renderer regression is loud without being a
publishing outage. On pull requests the renderer sees only fixture data, so any violation there is
a code defect and fails the build.

Fixtures cover a null description, a null due date, zero milestones, an issue with no labels, a
milestone with zero issues, and every row of the states table.

### Escaping untrusted text

- Fetched strings appear only in text nodes, never in an attribute.
- Every fetched string passes through `html.escape` with `quote=True`, and every whitespace run in
  it collapses to one space.
- Every `href` is built from the repository constant and an integer.

After `mkdocs build`, the build job runs `python3 tools/site_guards.py roadmap
_site/docs/roadmap/index.html`. It parses the region between the markers and fails on:

- anything other than one top-level `div` with class `acs-roadmap`
- any element outside `div, section, article, p, span, h2, h3, ul, li, a, details, summary,
  progress, meta`
- any attribute other than `class`, `href`, `value`, `max`, `name`, and `content`
- a `class` value outside a fixed set
- an `href` not matching
  `^https://github\.com/GenAI-Security-Project/agent-control-standard/(issues|milestone)/\d+$`
- a `meta` whose `name` is not `acs-roadmap-status` or `acs-roadmap-generated`

The existing `third_party_hosts` scanner runs over the same file as a second check. Both scanners
move from `tests/conftest.py` to `tools/site_guards.py`, standard library only, and conftest
re-exports them.

### Switches

Three repository variables control the roadmap. Each is read as the literal string `true`, and
anything else is treated as off.

| Variable | Read by | Effect when not `true` |
| --- | --- | --- |
| `ROADMAP_RENDER_ENABLED` | the `roadmap-data` job `if`, and the render step | The placeholder stays, with status `disabled` and a generated time. Use it to pull live data off the site on every deploy path at once. |
| `ROADMAP_REFRESH_ENABLED` | the refresh workflow's job `if` | The nightly dispatch is skipped. Set it before rolling Pages back to an older artifact. |
| `ROADMAP_SYNC_ENABLED` | the sync workflow's job `if`s and the roadmap monitor's job `if` | The event job, the sweep, and the roadmap monitor do not run. |

All three are created at repository level with the value `false` in rollout step 1, so an
organization-level variable of the same name cannot switch them on. The build writes a warning
annotation, and the health issue reports the value, whenever one holds anything other than `true`
or `false`.

### Incident runbook

The rollback comment in `deploy-pages.yml` gains this runbook. To pull roadmap content off the
site: set `ROADMAP_RENDER_ENABLED` to `false`, dispatch deploy-pages on `main`, and delete the
roadmap artifacts of recent runs with `gh api -X DELETE repos/{repo}/actions/artifacts/{id}`. The
site serves `cache-control: max-age=600`, so allow ten minutes after the deploy. The roadmap
artifacts carry `retention-days: 7`. To roll Pages back to an older artifact, first set
`ROADMAP_REFRESH_ENABLED` to `false`.

## Keeping it current

### Why deploy-pages cannot simply gain a schedule

Scheduled workflows run only on the default branch, which is `integration`. The deploy-pages gate
publishes only from `main`, and letting scheduled runs deploy would let the less protected branch
control production.

### The refresh workflow

`.github/workflows/roadmap-refresh.yml`:

```yaml
name: Refresh roadmap

on:
  schedule:
    # 05:15 UTC. Scheduler start delays of up to two hours were observed on this repository,
    # which the roadmap monitor's thresholds absorb.
    - cron: "15 5 * * *"

permissions: {}

jobs:
  dispatch:
    # Off unless the repository variable is exactly "true". Turn it off before rolling
    # Pages back to an older artifact, or the next nightly run redeploys main.
    if: vars.ROADMAP_REFRESH_ENABLED == 'true'
    runs-on: ubuntu-latest
    timeout-minutes: 2
    permissions:
      actions: write
    steps:
      - name: Start a nightly deploy of main
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh workflow run deploy-pages.yml --repo "$GITHUB_REPOSITORY" --ref main -f source=nightly
```

deploy-pages gains a `workflow_dispatch` input `source` with a default of `manual`, and a second
input `preview`, a boolean that forces the `roadmap-data` job to run when the gate will not
publish. `preview` lets rollout step 3 render live data on a branch without publishing it.

`actions: write` is broader than dispatch. It also covers re-running old runs, deleting runs and
logs, and cancelling runs. The refresh job offers no way to use any of that, since it checks out
nothing, runs one constant command, and lives two minutes, but the breadth is why the guard test
pins this file exactly.

### Workflow guard tests

Enumerating forbidden properties already failed five times in this repository's third-party
guard, so the guard tests pin shapes.

- `tests/test_roadmap_refresh_workflow.py` asserts the parsed YAML of `roadmap-refresh.yml`
  equals one expected dictionary exactly.
- `tests/test_roadmap_sync_workflow.py` checks `roadmap-sync.yml` against an allowlist of keys at
  every level and asserts:
  - the exact trigger set, permissions, `if`, and concurrency per job, including `queue: max`,
    which the pinned zizmor 1.30.1 does not validate and actionlint 1.7.12 rejects
  - every `env:` map equals an exact expected dictionary
  - every `run:` is free of `${{`, invokes `python3 -I -S tools/roadmap_sync.py` with `--apply`,
    and installs nothing
  - no step uses `setup-uv` or any action other than the pinned `actions/checkout` SHA, which sets
    `persist-credentials: false` and `ref: main`
- `tests/test_deploy_pages_permissions.py` asserts the exact permissions of every job in
  `deploy-pages.yml`, that `issues: read` appears only on `roadmap-data`, and that `github.token`
  appears only in that job's fetch step.
- `tests/test_monitor_roadmap_workflow.py` pins `monitor-roadmap.yml` the same way.

PyYAML loads the key `on` as the boolean `True`. Each test reads the trigger block through that
key and says why in a comment.

## Keeping milestones synced

### The one human act

Triage puts an accepted issue in its deliverable milestone. Setting a milestone needs the triage
role or higher. Three named leads have lapsed invitations and hold no access today (#144), and
several org owners hold access without being on the roster, so the health issue lists who accepted
what.

### The event job

`.github/workflows/roadmap-sync.yml` has a job named `event` that runs on `issues: milestoned`
only, when `ROADMAP_SYNC_ENABLED` is `true`. It checks out `main` and re-fetches the issue's
current milestone, labels, and state rather than trusting the event payload, which can be minutes
old once runs queue. It takes no action unless the issue is open and its milestone is still set and
open. Then it applies one rule:

| Current labels | Action |
| --- | --- |
| any of `scope:deferred`, `scope:out`, `status:blocked`, `status:needs-info`, `wontfix`, `invalid`, `duplicate` | none. The health issue reports it. |
| `status:accepted` already | remove `status:needs-triage` if present |
| otherwise | add `status:accepted`, add `scope:in-focus` when no `scope:` label is present, and remove `status:needs-triage` if present |

Adding `scope:in-focus` keeps GOVERNANCE.md's two-label minimum true for every issue the bot
accepts. Removing `status:needs-triage` is the only removal in this design, and a 404 because the
label is already gone counts as success.

The job's concurrency group is keyed by issue number, with `queue: max` and
`cancel-in-progress: false`. GitHub's default keeps only one pending run per group and cancels the
rest, which would have dropped most of the migration's acceptance events.

### The sweep job

The `sweep` job runs nightly at 04:10 UTC, when `ROADMAP_SYNC_ENABLED` is `true`, in its own
concurrency group. It changes no issue other than the health issue. It never re-applies the
acceptance rule, since a maintainer who removed `status:accepted` made a decision.

### What the automation never does

- It never closes, reopens, sets, or clears a milestone.
- It never removes a label other than `status:needs-triage`.
- It never touches a pull request.
- It never quotes fetched issue text into anything it writes.

### Structure

`tools/roadmap_sync.py` follows the split `tools/apply_governance.py` uses: pure planning functions
over an event or a snapshot, one executor through `gh`, and a dry run unless `--apply` is passed.
It and `tools/roadmap_model.py` are standard library only. The sync jobs run
`python3 -I -S tools/roadmap_sync.py`, and because `-I` removes the script's directory from the
import path, the script adds its own directory explicitly before importing `roadmap_model`. No sync
job installs packages, so no third-party code runs beside the write token.

### Security

`issues: write` and `contents: read` on the workflow's own `GITHUB_TOKEN` were reviewed and
approved. No job in this design runs with a write token on an event a fork author can trigger.
Both sync jobs check out `main` with `persist-credentials: false`, and the issue number reaches the
tool through `env:`.

## Health reporting

### The health issue

A pinned issue titled "Roadmap health" is the single place every drift lands. GOVERNANCE.md's
Triage authority section names it as the weekly call's triage agenda, and names the project lead as
the person who closes milestones.

- The sweep finds it with REST `issues?creator=github-actions[bot]&state=all`, never search, and
  selects the one whose body carries the fixed marker. A marked issue by any other author is
  ignored.
- More than one match fails the sweep. A closed match is reopened. When the listing succeeds with no
  match, the sweep creates the issue and the run summary asks for it to be pinned. When the listing
  fails, the sweep fails.
- The sweep locks the conversation on creation and again on every run.
- The body never quotes fetched titles, and logins are written in code formatting without `@`, so
  a nightly rewrite never mentions anyone.

The body opens with a machine-read status line, `<!-- acs-sweep: ok 2026-10-05T04:12:09Z run 123 -->`
or `<!-- acs-sweep: degraded <sections> ... -->`. When any read fails, the sweep still rewrites
the body, marks the failed sections "could not be read", writes `degraded`, and exits non-zero, so
an empty section is never mistaken for "nothing to report".

### Sections

| Section | Contents |
| --- | --- |
| Ready to publish | Ready-to-publish milestones, split by verification. A done issue is verified when GraphQL's `ClosedEvent.closer` is a merged pull request whose `mergeCommit` is on `main`, meaning `compare/{sha}...main` returns `ahead` or `identical`. A milestone is "on `main`" only when every done issue is verified. A done issue closed by hand, closed by an untrusted author, or closed by a pull request not yet on `main` makes the milestone "awaiting promotion or verification", with the reason per issue and days waiting. |
| Closed with open work | Closed milestones that still hold planned issues |
| Target passed | Open milestones past their committed date or quarter |
| Untriaged in a milestone | Untriaged-class issues, plus issues the event job declined because of a standing triage label |
| In focus without a milestone | Open `scope:in-focus` issues with no milestone |
| Accepted without a milestone | Open `status:accepted` issues with no milestone |
| Accepted by milestone this week | Issues the bot accepted in the last eight days, with the login that set the milestone |
| Closed by an untrusted author | Done or dropped issues in a milestone closed by an untrusted author in the last eight days |
| Title changed | Issues the page currently renders as "title changed after it joined the roadmap" |
| Off-quarter dates | Milestones whose `due_on` is not a quarter's last day |
| Missing description lines | Milestones without a valid `Workstream:` or `Type:` line |
| Switches | The current value of each roadmap variable, flagged when it is neither `true` nor `false` |
| Rules version | `RULES_VERSION` from `main` |

The "on `main`" check assumes promotions are merge commits, which every promotion so far has been.
The `main` ruleset also allows squash and rebase, and a squash promotion would leave every closing
commit off `main`'s ancestry, so every milestone would read "awaiting promotion" until checked by
hand. Restricting `main` to merge commits is a ruleset decision for the project lead.

### The roadmap monitor

A new `.github/workflows/monitor-roadmap.yml`, separate from `monitor-pages.yml` so the schema
contract's alarm never shares a red or green result with roadmap noise, runs four times a day from
`main` when `ROADMAP_SYNC_ENABLED` is `true`. It holds `contents: read` and `issues: read`, and
fails when:

- the published page's `acs-roadmap-status` is `unavailable`, or is `ok` with an
  `acs-roadmap-generated` time older than 36 hours, or has been `disabled` for more than seven days
- the health issue, selected by the same function the sweep uses, carries `degraded`, or its
  status-line time is more than 50 hours old

It reads the sweep's own timestamp rather than the issue's `updated_at`, which a comment or a label
change also moves. Failed scheduled runs notify the account that created the workflow, which is the
project lead, so the alarm reaches one person by email and everyone by the red run.

## The OWASP report skill

### Shape

The skill is a `SKILL.md` plus a bundled script, `owasp_rows.py`, standard library only. The script
fetches, classifies with a vendored copy of the rules, downloads the sheet's public CSV export
itself, matches rows, and writes the result to a TSV file. The model reads only the script's
summary, which holds milestone numbers, states, statuses, and flags such as new, updated, orphaned
at sheet row N, or missing description line. No title, description, issue text, or sheet cell enters
the model's context, so neither an outsider nor a write-role account can plant instructions for it.
The model tells the user the TSV's path and which rows changed, by milestone number.

The script uses the public REST API with no token. It reads milestones, which carry counts that
include pull requests, and every issue and pull request in them, checks the totals match, and then
drops the pull requests. That is about five requests against an anonymous limit of 60 an hour. When
it hits the limit it stops and says so. It never reads the maintainer's `gh` credentials, and
SKILL.md asks the model not to run `gh` or read the TSV itself. Claude Code's documentation says
`allowed-tools` pre-approves tools rather than restricting them, so the skill relies on keeping
untrusted text out of the context, not on a tool restriction.

The vendored rules carry a SHA-256 the script compares against the SHA-256 of `main`'s
`tools/roadmap_model.py`, fetched as text and never executed. On a mismatch the script stops and
names the commit to update from. Updating means copying the file from that reviewed commit, never
from `main` at an unknown point.

### What it produces

Rows in the column order of the "quarterly roadmap" worksheet, tab-separated, starting at the
Deliverable ID column, one per milestone whose state has an OWASP status:

| Column | Value |
| --- | --- |
| Deliverable ID | blank, matching every existing row |
| Initiative | `Agent Control Standard` |
| Work Item Title | milestone title |
| Deliverable Type | the milestone's `Type:` line |
| Initiative Co-Owners | Project lead from `GOVERNANCE.md` |
| Workstream Name | the milestone's `Workstream:` line |
| Workstream Lead | that workstream's leads from the `GOVERNANCE.md` table |
| Status | the OWASP status of the milestone's state |
| Target Quarter | the milestone's quarter, or blank when Ongoing |
| Target Publication Date | the `Committed:` date when present, otherwise blank |
| Milestone & Strategic Objective | milestone description, without the machine-read lines |
| Repository Link | milestone URL |

Rows are matched to existing ACS rows on Repository Link. Every cell has each whitespace run
containing a tab, carriage return, or newline collapsed to one space, and a cell whose first
non-space character is `=`, `+`, `-`, `@`, a tab, or a carriage return gets a leading `'`.

### Where it lives

Claude Code loads it from `~/.claude/skills/owasp-acs-roadmap/`. claude.ai on the web, the desktop
chat, and Cowork load it from a zip uploaded under Settings, Capabilities, Skills. The script needs
network access to `api.github.com`, `raw.githubusercontent.com`, and `docs.google.com`. Whether the
claude.ai sandbox allows that is unverified. If it does not, the skill says so and stops. The skill
is done only after one run in Claude Code, one attempt on claude.ai, and a paste into a copy of the
sheet checked for column alignment and the visible leading `'`.

## Rollout

The weekly promotion workflow has failed on both scheduled runs since it was added, with "GitHub
Actions is not permitted to create or approve pull requests", and `main` has not moved since
September 10. Everything here runs from `main`, so the rollout has a gate this design cannot open.

1. Create the three switches at repository level with the value `false`. Merge the implementation
   to `integration`. Nothing runs and nothing is published.
2. Promote to `main`, by the repaired workflow or by hand.
3. Dispatch deploy-pages on a branch at `main`'s head with `preview` set. The gate does not
   publish. Check the uploaded roadmap artifact for status `ok`, at least one card, and a clean
   structural check. Run `roadmap_sync.py` without `--apply` against the live repository for both
   jobs.
4. Set `ROADMAP_SYNC_ENABLED` to `true` and run the milestone migration below.
5. Set `ROADMAP_RENDER_ENABLED` and `ROADMAP_REFRESH_ENABLED` to `true`, and dispatch deploy-pages
   on `main`.

## Milestone migration

The starting set below comes from a gap analysis of the Strategic Adoption Plan v3 against open
issues and pull requests on October 4, 2026, corrected by a coverage diff against the Day N
milestones it replaces. It was agreed on October 4, 2026, as a starting point that will change.

| Milestone | Issues | Quarter |
| --- | --- | --- |
| Conformance claim template | #93, #136, #106 | Q4 2026 |
| Fail-open decision | #32, #37 | Q4 2026 |
| Reference adapters on main (Claude Code, Cursor, NAT) | #132, #134, #131 | Q4 2026 |
| Spec and docs fixes for v0.1 | #194 to #198, #146, #148, #149, #120, #121, #57, #58, #133 | Q4 2026 |
| ACS-Core conformant reference Guardian | #33, #188, #70 to #73, and the Reference Guardian bugs and conformance reports | Q4 2026 |
| Installable reference Guardian | #94, #91, #90, #127 | Q4 2026 |
| AGT interoperability benchmark | #92, #171, plus new issues for the Cursor file-read gap and the AARM mapping session | Q4 2026, `Committed: 2026-12-09` |
| Governance under OWASP | #144, #145, plus new issues for the open lead seats, domain transfer, OpenSSF Best Practices, and retiring the marketing site | Q4 2026 |
| Host adapter coverage | #170, #89, #114, #107 to #111 | Ongoing |
| Language ports | #86 to #88, #135 | Ongoing |
| v0.2.0 | every open `scope:deferred` issue, #53, #29 | Q1 2027 |

Eight open `scope:in-focus` issues are in no row: #16, #19, #31, #43, #51, #52, #67, and #74.
Placing them is a triage decision made in step 1. #178 proposes replacing the `scope:` labels this
design's rules read, so it is decided in step 1 rather than scheduled into the launch quarter.

The open lead seats are five issues: Reference Implementation, one seat. Documentation, two seats.
Testing and Validation, two seats. The Strategic Adoption Plan's "ASI governance milestones" item is
closed as not applicable, since ACS already operates as an initiative under ASI.

The migration runs in rollout step 4:

1. Run `tools/roadmap_sync.py migrate <table.json>`, a dry run. It prints each entry's type, author
   association, title, and current `scope:` and `status:` labels, refuses any pull request or closed
   issue, lists every entry the event rule would decline or accept, and lists any issue milestoned
   during the rollout gate that lacks `status:accepted`. The project lead triages each unlabeled or
   `status:needs-triage` entry, places the eight unassigned in-focus issues, and decides #144, #145,
   and #178. Set one test milestone's due date in the GitHub UI from a non-UTC browser and read
   `due_on` back.
2. File the new issues named above.
3. Create each milestone with its quarter's last day as `due_on`, a description written for an
   outside reader, `Workstream:` and `Type:` lines, and a `Committed:` line where one applies.
4. Run `tools/roadmap_sync.py migrate <table.json> --apply`. It sets each milestone and applies the
   event rule directly in one process, pacing writes at one a second and stopping with the rate-limit
   message `apply_governance.py` already uses. A second dry run must print an empty plan.
5. Move #93 and #94 out of Day 30, then close all four Day N milestones with the description
   "Superseded by the roadmap on 2026-10-04." With no done issues they land in the Withdrawn section.

`tools/apply_governance.py` declares the Day N milestones as desired state. The implementation
removes them from `desired_milestones`, drops `milestone="Day 30"` from the two seeded issues that
carry it, changes the `scope:deferred` label description from "lands after Day 90" to "lands in a
later release", and updates `tests/test_apply_governance.py`.

CONTRIBUTING.md's Current Priority Scope changes in the same pull request in two places only:
"Current window: Day 0 to Day 30" becomes a pointer to the roadmap page, and "landing after Day 90"
becomes "landing in a later release". The "Next review <date>" line stays, because
`scope-review.yml` parses it. Whether the In focus bullets should become a pointer to the open
roadmap milestones is a scope-governance decision for the project lead.

### Changing the roadmap

| Change | The one edit | What follows automatically |
| --- | --- | --- |
| Move a deliverable to another quarter | Change the milestone's due date to that quarter's last day | The page reorders it on the next nightly build. |
| Move an issue to another deliverable | Change the issue's milestone | It stays accepted. Both milestones update on the next build. |
| Drop an issue from the roadmap | Clear its milestone | It stays accepted and leaves the page. The health issue lists it until it gets a milestone or loses `status:accepted`. |
| Add a deliverable | Create a milestone | It appears once it holds a counted issue. The health issue flags missing description lines. |
| Rename or reword a deliverable | Edit the milestone's title or description | The OWASP script matches rows by milestone URL, so the existing row updates. |
| Ship a deliverable | Close the milestone once the health issue lists it as on `main` | Delivered section, Published. |
| Withdraw a deliverable | Close the milestone, leaving its unfinished issues open or closing them as not planned | With no done issues it moves to Withdrawn and the OWASP script reports its row for removal. With done issues and planned issues left open, it reads "closed with open work" and the health issue flags it. |

None of the automation stores a milestone's title, number, or quarter.

## Testing

| Test file | Covers |
| --- | --- |
| `tests/test_roadmap_model.py` | every issue class and `state_reason`, label precedence, the full states matrix, the Changing the roadmap procedures, quarter derivation at `2026-12-31T00:00:00Z`, `2027-01-01T00:00:00Z`, and `2026-10-01T00:00:00Z`, the three description lines, trusted-author rules, and target-passed detection |
| `tests/test_fetch_roadmap.py` | completeness in both directions, retries, dedupe, response classification for 401, 403, 403 with rate-limit headers, 429, and 5xx, the deadline, the failure record, and running the script as a subprocess under `python3 -I -S` |
| `tests/test_render_roadmap.py` | ordering, every section, the marker contract, the placeholder still committed, the untrusted-title rule for every class and state, every row of the failure table per event type, and the null-field fixtures |
| `tests/test_roadmap_site_build.py` | a real `mkdocs build` over a hostile fixture whose titles carry `<script>`, `onerror=`, a `javascript:` URL, Markdown emphasis, an emoji shortcode, an attribute list, a newline, and a `--8<--` line, followed by the structural check on the built page |
| `tests/test_site_guards.py` | the structural check failing on a disallowed element, attribute, class, `href`, `meta`, or a second top-level element |
| `tests/test_roadmap_sync.py` | every row of the event rule including a cleared or closed milestone, the 404-on-removal case, the absence of any action that touches a milestone, a pull request, or a label other than the three named, every health section and the degraded status line, health-issue selection by author with duplicates failing and closed matches reopened, logins written without `@`, the Ready-to-publish verification cases, and the migration check |
| `tests/test_roadmap_refresh_workflow.py`, `tests/test_roadmap_sync_workflow.py`, `tests/test_deploy_pages_permissions.py`, `tests/test_monitor_roadmap_workflow.py` | the workflow guard tests |
| `tests/test_apply_governance.py` | updated for the removed Day N milestones |

End to end, rollout step 3 must produce a previewed page with status `ok`, at least one card, and a
clean structural check, and both sync jobs must dry-run against the live repository. After step 5,
the published page must carry a fresh generated time, the health issue must exist, be pinned and
locked, and carry `ok`, and the roadmap monitor must pass once.

## Out of scope

- A per-workstream view, filtering, or search on the page
- Writing to the Google Sheet
- Burndown history or velocity
- The label migration in #178. When it lands, `tools/roadmap_model.py`, the event rule, and their
  tests change with it in the same pull request, and `RULES_VERSION` changes.
- Repairing the promotion workflow, and restricting `main` to merge commits. Both are separate
  permission decisions.
- A repository-wide guard pinning every workflow's triggers and permissions. The guard tests here
  cover the workflows this design adds or changes. A new workflow elsewhere could still grant write
  scopes, and zizmor reports that only to the Security tab. That gap predates this design.

## Residual risk

- **Promotion.** Until promotion works, nothing here reaches the site, and every renderer fix waits
  on it.
- **Triage throughput.** Milestones only stay true if the weekly pass happens.
- **Nine deliverables in one quarter.** The target-passed marker and the health issue will show the
  slip in January. Spreading the targets is a planning decision for the project lead.
- **One alarm inbox.** Scheduled-run failure email reaches the project lead alone. The red run is
  visible to everyone but noticed only by someone who looks.
- **Write-role accounts.** Eleven accounts can edit milestones and three of the roadmap variables,
  and eight admins bypass every ruleset. The design keeps milestone text out of the OWASP model's
  context, but the switches remain flippable by any of them without review.
- **Version skew.** Workflow files take effect on `integration` at merge, while the tools they run
  come from `main` at promotion. A workflow change that expects a newer tool runs against the older
  one until promotion.
- **Inactivity.** Scheduled workflows stop after 60 days without repository activity, and the
  monitor would stop with them. The repository is active daily, so this is accepted.
- **Milestoning an already-closed issue** counts it as done. This is rare and visible on the card.
- **Search index.** Two round-three reviewers confirmed that Material's search plugin re-escapes
  indexed text, so the search index does not reopen injection. A theme upgrade that changed that
  would.
