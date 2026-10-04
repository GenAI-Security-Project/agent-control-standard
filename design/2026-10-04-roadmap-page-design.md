# A live community roadmap, and an OWASP report on demand

Version: 1.2
Owner: ACS project lead
Date: 2026-10-04
Status: design, awaiting approval of the written spec

Two adversarial premortem rounds shaped this version. Round one, against version 1.0, removed
automatic milestone closing, guarded acceptance against deferred work, dropped the
`pull_request_target` trigger, and made roadmap failures degrade the page instead of blocking
merges. Round two, against version 1.1, found that the post-render scan could not see script
injection, that the default concurrency setting would cancel most acceptance events during the
migration, that the milestone states table could never reach Withdrawn, that the OWASP skill's
read-only claim was not enforceable, and that the weekly promotion to `main` has failed since
September 24, so nothing in this design can reach the published site until it is repaired.

Contributors arriving from the OWASP relaunch can see what the project accepts, but not when
any of it lands. The accepted backlog lives in labels and on an org project board, and neither
carries a date. This design publishes a roadmap page built from GitHub milestones and accepted
issues, rebuilt every night with no maintainer in the loop.

A second, separate need rides alongside it. OWASP's GenAI Security Project tracks every
initiative in a quarterly roadmap spreadsheet, and ACS has no rows there yet. Filling it is a
quarterly manual paste, so it gets a skill that produces the rows on request rather than code
in this repository's pipeline.

## Goal

A contributor can open one page and see each deliverable the project has committed to, its
target quarter, and how much of it is done, without reading a label or opening the board. A
maintainer can say "Update the roadmap for OWASP" and get rows ready to paste.

The upkeep this design asks for is the weekly triage pass the project already runs: setting a
milestone on accepted work, and closing a milestone when its work reaches `main`. Everything
else is automated, and everything the automation will not repair lands on one pinned issue
that pass reads. Triage itself is under strain, with the untriaged backlog doubling between
September 17 and October 4, and this design cannot fix that. It can only keep the roadmap from
adding to it.

## Decisions

| Question | Decision | Why |
| --- | --- | --- |
| Unit of the roadmap | One GitHub milestone is one deliverable | A milestone already carries a title, a due date, a description, and a set of issues. Nothing else in the repository has a date. |
| Which milestones | New milestones named for what ships, replacing the Day 14/30/60/90 checkpoints | Each Day N description bundles three or four unrelated outcomes under a title that says nothing to an outsider. |
| Target granularity | Calendar quarter, such as `Q4 2026`, with an optional committed date where one was promised | A day-level date promises a precision a volunteer project cannot staff. The one dated commitment the project made, the ninety-day outcome, must not be hidden by rounding to a quarter. |
| Freshness | Nightly rebuild of static HTML | The site renders with JavaScript disabled. A browser fetch would break that and share an anonymous limit of 60 requests an hour per IP. |
| Page and spreadsheet | Two outputs over one rules module, `tools/roadmap_model.py` | The page answers to contributors and the spreadsheet is a quarterly report for OWASP, but they must classify a milestone the same way. |
| Where the OWASP procedure lives | A personal skill named `owasp-acs-roadmap`, outside this repository, driving a deterministic script | OWASP reporting is an administrative chore. The script keeps outsider-written text out of the model's context. |
| Milestone upkeep | Setting a milestone accepts an issue, unless a standing triage decision says otherwise | The project has no capacity to apply two labels where one act will do. |
| Shipping | A maintainer closes a milestone when its work reaches `main`. Automation never closes one. | Closing is a claim to OWASP and the public that something shipped. Every automated trigger for it fired on work that had not shipped. |
| Which code runs | Every job runs the tools from `main` | The page renders from `main`. Running the sync and health jobs from `integration` would let the two classify the same milestone differently for a whole promotion cycle. |

## The shared rules

`tools/roadmap_model.py` holds every rule that decides what an issue or a milestone means. It
is standard library only, has no network access, and carries a `RULES_VERSION` string that
changes whenever a rule does. The renderer, the sync tool, and the OWASP script all import it.

### Milestone description lines

A milestone description may carry two machine-read lines. The page strips both before showing
the description.

- `Committed: 2026-12-09` names a date the project promised. It drives target-passed detection
  in place of the quarter's end, and the page shows it next to the quarter.
- `Workstream: Reference Implementation` names the owning workstream for the OWASP report. Its
  value must match a row of the `GOVERNANCE.md` workstream table.

### Issue classes

Every open or closed issue in a milestone falls into exactly one class. Pull requests are
dropped first, by the `pull_request` key, before any rule runs. The rules are checked in order:

| Class | Rule | Counts toward progress |
| --- | --- | --- |
| Dropped | closed with `state_reason` `not_planned` or `duplicate` | no |
| Done | closed with `state_reason` `completed` | yes, as done |
| Planned | open and carrying `status:accepted` | yes, as remaining |
| Deferred | open and carrying `scope:deferred` | no, listed separately |
| Untriaged | any other open issue | no, reported |

`status:accepted` is checked before `scope:deferred`, so an issue carrying both is Planned,
which matches the precedence the board reconciler already uses in `desired_board_status`.

Progress reads "4 of 9 issues closed", where 9 is done plus planned. The page's introduction
says progress counts delivered issues only, because GitHub's own milestone page also counts
closed pull requests and dropped issues and will show a different percentage.

### Milestone states

Closed milestones are classified first, then open ones. The first matching row wins.

| State | Rule | Page | OWASP status |
| --- | --- | --- | --- |
| Published | closed, at least one done, no planned | Delivered section, with any dropped count shown | Published |
| Closed with open work | closed, at least one planned | Delivered section, marked "closed with open work", and reported in the health issue | In Review |
| Withdrawn | closed, no done | Withdrawn section | no row, and the script tells the user to remove any existing one |
| Skipped | open, no done, planned, or deferred issues | not shown | no row |
| Deferred | open, only deferred issues | card, "N deferred issues", no progress bar | Planning |
| Ongoing | open, no `due_on` | card, quarter reads "Ongoing" | Ongoing |
| Ready to publish | open, at least one done, no planned, no deferred | card, "work complete, awaiting release" | In Review |
| In progress | open, at least one done | card | In Progress |
| Planning | open, otherwise | card | Planning |

A table-driven test enumerates every combination of open or closed, dated or undated, and zero
or nonzero done, planned, deferred, and dropped counts, and asserts exactly one state each. A
second test walks every row of the Changing the roadmap table below and asserts the state that
procedure produces, so the table is checked against the procedures and not only against itself.

### Quarters and dates

The quarter comes from the date part of `due_on`, read as a calendar date with no timezone
conversion. GitHub stores milestone dates at midnight UTC, as the live Day 14 milestone shows
(`2026-09-24T00:00:00Z`).

An open milestone's target has passed when the current UTC date is after its `Committed:` date,
or, without one, falls in a later quarter than its `due_on`. The page reads "Q4 2026, target
passed". Whether a due date set in the GitHub UI from a non-UTC browser is stored as the chosen
date is unverified, so migration step 1 sets one test milestone that way and reads it back. A
`due_on` that is not a quarter's last day is reported in the health issue either way.

## The roadmap page

### Where it lives

The page publishes at `/docs/roadmap/` as a top-level "Roadmap" entry in the MkDocs nav, with a
link from the landing page's section nav next to "Specification".

`docs/roadmap.md` is committed with a fixed introduction and a replaceable region:

```html
<!--ACS:ROADMAP:START-->
<meta name="acs-roadmap-status" content="placeholder">
<p class="acs-roadmap-local">Live roadmap data appears only in the published site.</p>
<!--ACS:ROADMAP:END-->
```

A local `mkdocs serve` shows the note. In CI, the render step replaces everything between the
markers and fails unless each marker appears exactly once, in order. A test asserts the
committed file still holds the placeholder, so live data committed by accident fails CI.

### What it shows

The fixed introduction says the roadmap shows quarterly targets set by volunteers, which move as
capacity does, and that progress counts delivered issues only. It links to Current Priority
Scope by absolute URL,
`https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CONTRIBUTING.md#current-priority-scope`,
because MkDocs strict mode rejects a link outside `docs/`. A scratch build confirmed the
relative form aborts the build.

The region holds, in order:

1. `<meta name="acs-roadmap-status" content="ok">` and
   `<meta name="acs-roadmap-generated" content="<ISO-8601 UTC>">`.
2. One card per milestone in a card state, ordered by quarter, then title, with Ongoing and
   Deferred milestones last. A card shows the title linked to the milestone, the quarter and any
   committed date, the progress count and bar, the description as plain text, and the issues by
   class, each with number, title, and state, linked to GitHub.
3. A collapsed "Delivered" section, newest close first.
4. A collapsed "Withdrawn" section, so an abandoned deliverable leaves a public record.

### Outsider-authored titles

An issue's author can edit its title at any time, and 17 of the 50 issues in the migration
table were opened by people with no repository role. A title changed after acceptance can put
any text on the project's domain under a Roadmap heading.

For each counted open issue whose `author_association` is not `OWNER`, `MEMBER`, or
`COLLABORATOR`, the renderer reads the issue timeline. When the timeline holds a `renamed` event
by the issue's author after the issue gained `status:accepted`, and no later `renamed` event by
anyone else, the card shows "#N, title changed after acceptance" instead of the title. A
maintainer clears it by editing the title once. The rule is sticky, so reverting the title
before the nightly build does not hide the change, and it needs no window or stored copy.

### Fetching the data

Fetching and rendering are separate steps, so the token never shares a process with the
documentation toolchain.

1. **Fetch roadmap data.** `python3 -I tools/fetch_roadmap.py <out.json>`, standard library
   only, run with `-I` so no installed package's startup hook sees the environment. It is the
   only step with `GH_TOKEN: ${{ github.token }}` in its `env:`, and it calls `gh`. It sets
   `timeout-minutes: 5`.
2. **Render the roadmap.** `uv run --no-dev python tools/render_roadmap.py <out.json>
   docs/roadmap.md` reads the JSON and rewrites the region. It has no token.

The fetch reads milestones from GraphQL, because GraphQL's `issues.totalCount` on a milestone
counts issues alone, which was verified against this repository. It reads issues from REST with
`gh api --paginate "repos/GenAI-Security-Project/agent-control-standard/issues?milestone=*&state=all&per_page=100"`,
and timelines for the outsider-authored issues above.

The completeness check drops pull requests, dedupes by number, and requires, for every
milestone, that the issues fetched equal its GraphQL issue count, in both directions. It also
flags any issue whose milestone is absent from the milestone list. A mismatch, a transport
error, or an HTTP 5xx triggers up to two refetches, 20 seconds apart. A failure that survives
names the milestone and the missing and extra issue numbers.

### Failure behavior

The roadmap is a contributor convenience and must never stop a schema from publishing or a
pull request from merging. A data failure therefore degrades the page, but only where degrading
costs nothing.

| Failure | Pull request build | `workflow_dispatch` (the nightly refresh) | `push` to `main` |
| --- | --- | --- | --- |
| Data failure surviving retries | warning, placeholder kept, build passes | build fails, so Pages keeps the last good page | region reads "Roadmap data is temporarily unavailable", status `unavailable`, build passes |
| HTTP 401 or 403 | warning, build passes | build fails | build fails |
| Any other exception in fetch, model, or render | warning, build passes | build fails | status `unavailable`, build passes |
| Post-render scan violation | build fails | build fails | build fails |
| Marker missing or duplicated | build fails | build fails | build fails |

A 401 or 403 is a permission defect, not an outage, so it fails every run that publishes. An
unexpected exception is classed with data failures rather than left to crash the required
`build` check, and fixtures cover a null description, a null due date, zero milestones, an
issue with no labels, and a milestone with zero issues.

A `push` to `main` degrades rather than fails because it carries schema changes that must
publish. A nightly refresh carries nothing new, so failing it costs only the day's freshness and
keeps yesterday's good page.

### Escaping untrusted text

- The renderer emits the region as one HTML block, so Markdown never parses a fetched string.
- Fetched strings appear only in text nodes, never in an attribute. An attribute holding a
  fetched string would both widen the injection surface and let an outsider fail the build,
  since the third-party guard treats a `//host` inside most attributes as a fetch.
- Every fetched string passes through `html.escape` with `quote=True`, and every run of
  whitespace in it collapses to one space, so no fetched string starts a line. A line beginning
  `--8<--` reaches the `pymdownx.snippets` preprocessor, which a scratch build showed inlining a
  repository file.
- Every `href` is built from the repository constant and an integer, never from fetched text.

After `mkdocs build`, the build job runs `tools/site_guards.py roadmap
_site/docs/roadmap/index.html`, a structural check purpose-built for this page. It parses the
region between the markers and fails on:

- any element outside `section, article, div, p, span, h2, h3, ul, li, a, details, summary,
  progress, meta`
- any attribute other than `class`, `href`, `value`, `max`, `name`, and `content`
- a `class` value outside a fixed set
- an `href` not matching
  `^https://github\.com/GenAI-Security-Project/agent-control-standard/(issues|milestone)/\d+$`
- a `meta` whose `name` is not `acs-roadmap-status` or `acs-roadmap-generated`

The existing `third_party_hosts` scanner runs over the same file as a second check. Version 1.1
named `stray_scripts` here, but that function walks a directory for `.js` files and returns
nothing for a single HTML file, and `third_party_hosts` cannot see an inline script or an event
handler at all, both of which a round-two reviewer demonstrated. The scanners move from
`tests/conftest.py` to `tools/site_guards.py`, and conftest re-exports them, so the deploy gate
no longer imports from the test tree.

### Switches

Two repository variables control the roadmap. Each is read as the literal string `true` or
`false`, and any other value is treated as the safer setting.

| Variable | Read by | Effect |
| --- | --- | --- |
| `ROADMAP_RENDER_ENABLED` | the fetch and render steps | Anything but `true` keeps the placeholder and emits status `disabled`. Use it to pull live data off the site on every deploy path at once during an incident. |
| `ROADMAP_REFRESH_ENABLED` | the refresh workflow's job `if` | Anything but `true` skips the nightly dispatch. Set it false before rolling Pages back to an older artifact, or the next night redeploys `main`. |

Both start unset, which means off. They are turned on in the rollout below, once the renderer is
on `main`. The rollback comment in `deploy-pages.yml` gains a line naming both.

## Keeping it current

### Why deploy-pages cannot simply gain a schedule

Scheduled workflows run only on the default branch, which is `integration`. The deploy-pages
gate publishes only from `main`, and letting scheduled runs deploy would let the less protected
branch control production. A separate dispatcher is the safer shape.

### The refresh workflow

`.github/workflows/roadmap-refresh.yml`:

```yaml
name: Refresh roadmap

on:
  schedule:
    # 05:15 UTC. Scheduler start delays of up to two hours were observed on this repository,
    # which the 36-hour freshness threshold absorbs.
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
      - name: Start a deploy of main
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh workflow run deploy-pages.yml --repo "$GITHUB_REPOSITORY" --ref main
```

A run started by `GITHUB_TOKEN` normally triggers no other workflow, but GitHub exempts
`workflow_dispatch`. The dispatched run executes `main`'s deploy-pages under the existing
`deploy` concurrency group.

### Workflow guard tests

Enumerating forbidden properties has already failed five times in this repository's
third-party guard, so the guard tests pin shapes instead.

- `tests/test_roadmap_refresh_workflow.py` asserts the parsed YAML of
  `roadmap-refresh.yml` equals one expected dictionary exactly. Any added key, step, `env:`,
  `container:`, `shell:`, `defaults:`, or `runs-on` change fails it.
- `tests/test_roadmap_sync_workflow.py` checks `roadmap-sync.yml` against an allowlist of keys at
  every level, the exact trigger set, the exact permissions and concurrency per job, and asserts
  every `run:` is free of `${{`, every checkout sets `persist-credentials: false` and
  `ref: main`, and every `uses:` is pinned to a 40-character commit SHA.
- `tests/test_deploy_pages_permissions.py` asserts the `build` job's permissions are exactly
  `contents: read`, `pages: read`, and `issues: read`, and that only the fetch step's `env:`
  names `GH_TOKEN`.

PyYAML loads the key `on` as the boolean `True`. Each test reads the trigger block through that
key and says why in a comment.

## Keeping milestones synced

### The one human act

Triage puts an accepted issue in its deliverable milestone. Setting a milestone needs the
repository's triage role or higher. GOVERNANCE.md intends that role for the people who make
acceptance decisions, though today three named leads have lapsed invitations and hold no access
(#144), and several org owners hold it without being on the roster. The health report lists who
accepted what, so an acceptance by anyone is visible to the weekly pass.

### The event job

`.github/workflows/roadmap-sync.yml` has a job named `event` that runs on `issues: milestoned`
only. It checks out `main`, re-fetches the issue's current labels and state rather than trusting
the event payload, which can be minutes old once runs queue, and applies one rule to an open
issue:

| Current labels | Action |
| --- | --- |
| any of `scope:deferred`, `scope:out`, `status:blocked`, `status:needs-info`, `wontfix`, `invalid`, `duplicate` | none. The health issue reports it. |
| `status:accepted` already | remove `status:needs-triage` if present |
| otherwise | add `status:accepted`, add `scope:in-focus` when no `scope:` label is present, and remove `status:needs-triage` if present |

Adding `scope:in-focus` keeps GOVERNANCE.md's two-label minimum, `scope:` plus `status:`, true
for every issue the bot accepts. Removing `status:needs-triage` is the only removal anywhere in
this design. It completes the triage the person setting the milestone just performed.

The job's concurrency group is keyed by issue number with `queue: max` and
`cancel-in-progress: false`. GitHub's default cancels every pending run in a group except the
newest, which would have dropped most of the migration's acceptance events. A per-issue group
lets different issues run in parallel and queues repeated edits to one issue.

### The sweep job

The `sweep` job runs nightly at 04:10 UTC in its own concurrency group. It changes no issue. It
reads the repository and rewrites the health issue, then exits non-zero if any of its own reads
failed, so a broken sweep produces a failed run rather than a stale report that looks current.

It never re-applies the acceptance rule. A maintainer who removes `status:accepted` from a
milestoned issue made a decision, and re-adding it nightly would overrule them.

### What the automation never does

- It never closes, reopens, sets, or clears a milestone.
- It never removes a label other than `status:needs-triage`.
- It never touches a pull request.
- It never quotes fetched issue text into anything it writes.

### Structure

`tools/roadmap_sync.py` follows the split `tools/apply_governance.py` uses: pure planning
functions over an event or a snapshot, one executor through `gh`, and `--dry-run`. Every rule is
tested against JSON fixtures with no network.

### Security

`issues: write` and `contents: read` on the workflow's own `GITHUB_TOKEN` were reviewed and
approved. No job in this design runs with a write token on an event a fork author can trigger.
Both jobs check out `main` with `persist-credentials: false`. The issue number reaches the tool
through `env:`. No `${{ }}` expression appears in a `run:` line.

## Health reporting

### The health issue

A pinned issue titled "Roadmap health", which the sweep edits in place every night, is the
single place every drift lands. It never comments, so it produces no notification noise, and its
conversation is locked to collaborators. GOVERNANCE.md's Triage authority section names it as the
weekly call's triage agenda, and names the project lead as the person who closes milestones.

The sweep selects the issue by a fixed marker in its body and by author `github-actions[bot]`.
An outsider can copy the marker into their own issue, so a marked issue by any other author is
ignored. If more than one bot-authored issue carries the marker, the sweep fails rather than
guessing. If the issue listing fails, the sweep fails rather than creating a duplicate. When no
bot-authored marked issue exists, it creates one and the run summary asks for it to be pinned.

The body starts with the time it was written and a link to the run, and every section lists
issue and milestone numbers as links without quoting fetched titles.

### Sections

| Section | Contents |
| --- | --- |
| Ready to publish | Ready-to-publish milestones, split into "on `main`" and "awaiting promotion" by checking whether each done issue's closing commit is an ancestor of `main` through the compare API, with days waiting |
| Closed with open work | Closed milestones that still hold planned issues |
| Target passed | Open milestones past their committed date or quarter |
| Untriaged in a milestone | Untriaged-class issues, plus issues the event job declined because of a standing triage label |
| In focus without a milestone | Open `scope:in-focus` issues with no milestone |
| Accepted without a milestone | Open `status:accepted` issues with no milestone |
| Accepted by milestone this week | Issues the bot accepted in the last eight days, with the login that set the milestone, read from the timeline's `milestoned` event |
| Closed by their author | Done or dropped issues in a milestone that were closed by an author without a repository role in the last eight days, since an author can close their own issue as completed and move progress |
| Title changed after acceptance | Issues the page is currently rendering as "title changed after acceptance" |
| Off-quarter dates | Milestones whose `due_on` is not a quarter's last day |
| Missing workstream | Milestones with no valid `Workstream:` line |
| Rules version | `RULES_VERSION` from `main`, so a reader can tell which rules produced the report |

### Watching the watchers

`monitor-pages.yml` already runs four times a day from `main`, independent of everything above.
It gains two checks, and its job gains `issues: read` to read the health issue:

- the published roadmap's `acs-roadmap-status` is `ok` or `disabled`, and its
  `acs-roadmap-generated` time is under 36 hours old
- the health issue was updated under 30 hours ago

Either failure fails the monitor run, which notifies by GitHub's normal failed-run path, outside
the health issue an outsider might try to interfere with. Both checks stay off until the rollout
step that enables the roadmap, so they cannot alarm on a page that does not exist yet.

## The OWASP report skill

### Shape

The skill is a `SKILL.md` plus a bundled script, `owasp_rows.py`, standard library only. The
script fetches, applies the rules, matches the sheet, and writes the rows to a TSV file. The
model reads only the script's summary: milestone numbers, titles, descriptions, states, and which
rows are new, updated, or orphaned. Milestone text can only be written by someone holding the
triage role. Issue titles, issue bodies, and sheet cells never enter the model's context.

The script reaches GitHub through the public REST API with no token, since every field it needs
is public and the whole run takes about five requests. It never reads the maintainer's `gh`
credentials, so an injection that reached the model would find no credential in the script's
path to misuse. Version 1.1 claimed `allowed-tools` made the skill read-only. Claude Code's
documentation says that field pre-approves the listed tools and restricts nothing, so this
version claims no such control. SKILL.md still states that fetched content is data, never
instructions, as a request to the model rather than a boundary.

The script carries a vendored copy of `tools/roadmap_model.py`. On each run it fetches `main`'s
copy as text, without executing it, and compares `RULES_VERSION`. On a mismatch it stops and
says the skill needs updating, so the report never classifies a milestone differently from the
page.

### What it produces

Rows in the column order of the "quarterly roadmap" worksheet, tab-separated, starting at the
Deliverable ID column, one per milestone whose state has an OWASP status:

| Column | Value |
| --- | --- |
| Deliverable ID | blank, matching every existing row |
| Initiative | `Agent Control Standard` |
| Work Item Title | milestone title |
| Deliverable Type | proposed by the model from the milestone description, confirmed with the user |
| Initiative Co-Owners | Project lead from `GOVERNANCE.md` |
| Workstream Name | the milestone's `Workstream:` line |
| Workstream Lead | that workstream's leads from the `GOVERNANCE.md` table |
| Status | the OWASP status of the milestone's state |
| Target Quarter | the milestone's quarter, or blank when Ongoing |
| Target Publication Date | the `Committed:` date when present, otherwise blank |
| Milestone & Strategic Objective | milestone description, without the machine-read lines |
| Repository Link | milestone URL |

The script matches existing ACS rows on Repository Link, since a milestone URL survives a
rename. It reports new rows, updated rows, existing rows that match no milestone, and rows for
Withdrawn milestones that should be removed. Every cell has each whitespace run containing a tab,
carriage return, or newline collapsed to one space, and a cell whose first non-space character is
`=`, `+`, `-`, `@`, a tab, or a carriage return gets a leading `'`.

### Where it lives

Claude Code loads it from `~/.claude/skills/owasp-acs-roadmap/`. claude.ai on the web, the
desktop chat, and Cowork load it from a zip uploaded under Settings, Capabilities, Skills. The
script needs network access to `api.github.com` and `raw.githubusercontent.com`. Whether the
claude.ai sandbox allows that is unverified. If it does not, the skill says so and stops rather
than falling back to a path that would put issue text in the model's context. The skill is done
only after one run in Claude Code, one attempt on claude.ai, and a paste into a copy of the sheet
checked for column alignment and the visible leading `'`.

## Rollout

The weekly promotion workflow, `open-promotion.yml`, has failed on both scheduled runs since it
was added, on September 24 and October 1, with "GitHub Actions is not permitted to create or
approve pull requests." `main` has not moved since September 10. The renderer, the switches, and
the jobs that run tools from `main` all depend on code reaching `main`, so the rollout has a gate
this design cannot open. Repairing promotion is a repository permission decision for the project
lead, made separately from this work.

1. Merge the implementation to `integration`. The event and sweep jobs fail cleanly until their
   tools exist on `main`, because they check out `main`. Nothing is published.
2. Promote to `main`, by the repaired workflow or by hand.
3. Run deploy-pages by `workflow_dispatch` on `main` with `ROADMAP_RENDER_ENABLED=true` and check
   the uploaded page. The build uploads the rendered `roadmap/index.html` as a plain artifact on
   every non-pull-request run.
4. Run the milestone migration below.
5. Set `ROADMAP_REFRESH_ENABLED=true` and enable the two monitor checks.

## Milestone migration

The starting set below comes from a gap analysis of the Strategic Adoption Plan v3 against open
issues and pull requests on October 4, 2026, corrected by a coverage diff against the Day N
milestones it replaces. It was agreed on October 4, 2026, as a starting point that will change.
Pull requests are not assigned, because the roadmap counts issues only.

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
Placing them is a triage decision made in step 1, not a title skim. #178 proposes replacing the
`scope:` labels this design's rules read, so it is decided in step 1 rather than scheduled into
the roadmap's launch quarter.

The open lead seats are five issues: Reference Implementation, one seat. Documentation, two
seats. Testing and Validation, two seats. The Strategic Adoption Plan's "ASI governance
milestones" item is closed as not applicable, since ACS already operates as an initiative under
ASI.

The migration runs once, after rollout step 3:

1. Run `tools/roadmap_sync.py migrate <table.json>`, which is a dry run by default. It prints each
   entry's type, author association, title, and current `scope:` and `status:` labels, refuses any
   pull request or closed issue, and lists every entry the event rule would decline or accept.
   The project lead triages each unlabeled or `status:needs-triage` entry, places the eight
   unassigned in-focus issues, and decides #144, #145, and #178. Set one test milestone's due date
   in the GitHub UI from a non-UTC browser and read `due_on` back.
2. File the new issues named above.
3. Create each milestone with its quarter's last day as `due_on`, a description written for an
   outside reader, a `Workstream:` line, and a `Committed:` line where one applies.
4. Run `tools/roadmap_sync.py migrate <table.json> --apply`. It sets each milestone and applies
   the event rule directly, in one process, rather than relying on a burst of events. The event
   job still fires for each and finds nothing to do. A second dry run must then print an empty
   plan.
5. Move #93 and #94 out of Day 30, then close all four Day N milestones with the description
   "Superseded by the roadmap on 2026-10-04." With no done issues they land in the Withdrawn
   section, which keeps a public record of commitments that were replaced rather than delivered.

`tools/apply_governance.py` declares the Day N milestones as desired state. The implementation
removes them from `desired_milestones`, drops `milestone="Day 30"` from the two seeded issues that
carry it, changes the `scope:deferred` label description from "lands after Day 90" to "lands in a
later release", and updates `tests/test_apply_governance.py`, which asserts the Day N dates and
that every seeded issue's milestone is declared.

CONTRIBUTING.md's Current Priority Scope changes in the same pull request in two places only:
"Current window: Day 0 to Day 30" becomes a pointer to the roadmap page, and "landing after Day
90" becomes "landing in a later release". The "Next review <date>" line stays, because
`scope-review.yml` parses it and opens the scope review reminder from it. Whether the In focus
bullets should become a pointer to the open roadmap milestones is a scope-governance decision for
the project lead. This design does not make it.

### Changing the roadmap

| Change | The one edit | What follows automatically |
| --- | --- | --- |
| Move a deliverable to another quarter | Change the milestone's due date to that quarter's last day | The page reorders it on the next nightly build. |
| Move an issue to another deliverable | Change the issue's milestone | It stays accepted. Both milestones update on the next build. |
| Drop an issue from the roadmap | Clear its milestone | It stays accepted and leaves the page. The health issue lists it until it gets a milestone or loses `status:accepted`. |
| Add a deliverable | Create a milestone | It appears once it holds a counted issue. The health issue flags a missing `Workstream:` line. |
| Rename or reword a deliverable | Edit the milestone's title or description | The OWASP script matches rows by milestone URL, so the existing row updates. |
| Ship a deliverable | Close the milestone once the health issue lists it as on `main` | Delivered section, Published. |
| Withdraw a deliverable | Close the milestone, leaving its unfinished issues open or closing them as not planned | With no done issues it moves to Withdrawn and the OWASP script says to remove its row. With done issues and planned issues left open, it reads "closed with open work" and the health issue flags it. |

None of the automation stores a milestone's title, number, or quarter. Every run reads current
state from GitHub.

## Testing

| Test file | Covers |
| --- | --- |
| `tests/test_roadmap_model.py` | every issue class and `state_reason`, label precedence including `status:accepted` with `scope:deferred`, the full states matrix, the Changing the roadmap procedures, quarter derivation at `2026-12-31T00:00:00Z`, `2027-01-01T00:00:00Z`, and `2026-10-01T00:00:00Z`, `Committed:` and `Workstream:` parsing, and target-passed detection |
| `tests/test_fetch_roadmap.py` | completeness in both directions, retries, dedupe, 401 and 403 classification, and pull request exclusion, over recorded responses |
| `tests/test_render_roadmap.py` | ordering, every section, the marker contract, the placeholder still committed, the outsider retitle rule, every row of the failure table per event type, and the null-field fixtures |
| `tests/test_site_guards.py` | the structural check failing on an unescaped `<script>`, an `onerror=` attribute, a `javascript:` href, a fetched string in an attribute, a disallowed class, and a foreign `href`, and passing on real renderer output for titles carrying each of those plus a newline and a `--8<--` line |
| `tests/test_roadmap_sync.py` | every row of the event rule, the absence of any action that touches a milestone, a pull request, or a label other than the three named, every health section, marker selection by author with duplicates failing, and the migration check refusing pull requests and closed issues |
| `tests/test_roadmap_refresh_workflow.py`, `tests/test_roadmap_sync_workflow.py`, `tests/test_deploy_pages_permissions.py` | the workflow guard tests |
| `tests/test_apply_governance.py` | updated for the removed Day N milestones |

End to end: rollout step 3 must produce an uploaded page with status `ok` and at least one card,
and the structural check must have run on it. `roadmap_sync.py --dry-run` must run against the
live repository for both jobs. After step 5, the published page must carry a fresh generated
time, the health issue must exist and be pinned, and both monitor checks must pass once.

## Out of scope

- A per-workstream view, filtering, or search on the page
- Writing to the Google Sheet
- Burndown history or velocity
- The label migration in #178. When it lands, `tools/roadmap_model.py`, the event rule, and its
  guard tests change with it in the same pull request, and `RULES_VERSION` changes.
- Repairing the promotion workflow, which is a separate permission decision.

## Residual risk

- **Promotion.** Until promotion works, nothing here reaches the site, and every later renderer
  fix waits on it.
- **Triage throughput.** Milestones only stay true if the weekly pass happens. The health issue
  makes the backlog visible but cannot shrink it.
- **Nine deliverables in one quarter.** The target-passed marker and the health issue will show
  the slip in January. Spreading the targets is a planning decision for the project lead.
- **Inactivity.** Scheduled workflows stop after 60 days without repository activity, and the
  monitor would stop with everything else. The repository is active daily, so this is accepted.
- **Milestoning an already-closed issue** counts it as done. This is rare and visible on the
  card, so it is accepted rather than reported.
