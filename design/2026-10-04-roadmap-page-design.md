# A live community roadmap, and an OWASP report on demand

Version: 1.6
Owner: ACS project lead
Date: 2026-10-04
Status: design, awaiting approval of the written spec

Four adversarial premortem rounds shaped this version. Round one removed automatic milestone
closing and the `pull_request_target` trigger. Round two replaced a post-render scan that could
not see script injection and fixed a concurrency default that would have cancelled most
acceptance events. Round three extended the title guard to every rendered issue and wrapped the
page region in one raw `<div>` after a scratch build showed Python-Markdown parsing top-level HTML
lines as Markdown.

Round four found that version 1.3's own fixes had introduced the worst defects yet. Moving the
fetch into a separate job would have silently skipped the build and deploy jobs whenever the fetch
was skipped, because of how GitHub propagates skips through `needs`, and the result would have
shown green. `author_association: MEMBER` turned out to mean organization membership, which
trusted seven read-role accounts and distrusted six leads. Version 1.4 answers by simplifying:
the fetch is a step inside the build job again, trust comes from the roster the project already
maintains, and the OWASP script reads a JSON file the build publishes instead of calling GitHub.

Round five, the last, did not converge. It found that the progress bar counts closed issues in a
repository where 2 of the last 50 merged pull requests closed one, that an author can drop their own
issue as not planned and move a milestone toward Published, and that several choices in this design
are governance decisions that belong to the project lead rather than to its implementation. Version
1.5 fixes the mechanical findings and lists the rest under Decisions for the project lead.

The weekly promotion to `main` succeeded on its scheduled runs of September 10 and 17 and has failed
since September 24, so nothing in this design can reach the published site until it is repaired.
That repair is a separate decision.

## Phase 0, decided October 4, 2026

The project lead chose decision 1 below: prove the milestone practice before building the custom
page. Phase 0 ships the parts of this design that keep milestones true and feed the OWASP report, and
defers the parts that exist only to render a page on the project's own domain.

**In phase 0:**

- `tools/roadmap_model.py`, the shared rules: trusted logins, issue classes, milestone states,
  quarters, and description lines.
- `tools/fetch_roadmap.py` and a fetch step in the `build` job of `deploy-pages.yml`.
- `tools/build_roadmap_data.py`, which writes `/roadmap/roadmap.json` into the published site at the
  site root, outside the MkDocs tree. It carries milestone fields and issue counts and numbers, and no
  issue titles, so phase 0 publishes no text an outsider wrote.
- `.github/workflows/roadmap-refresh.yml`, the nightly dispatcher, with its exact-shape guard test.
- `.github/workflows/roadmap-sync.yml` with the `event`, `sweep`, and `dryrun` jobs,
  `tools/roadmap_sync.py`, the health issue, and the migration command.
- `.github/workflows/monitor-roadmap.yml`, watching `roadmap.json` freshness and the health issue.
- The `pr-intake.yml` changes: one listing call, and the closing-keyword comment.
- `tools/apply_governance.py` losing the Day N milestones, the CONTRIBUTING.md wording changes, and a
  landing page nav link to the repository's `/milestones` page in place of a custom roadmap page.
- The `owasp-acs-roadmap` skill and its `owasp_rows.py` script, reading `/roadmap/roadmap.json`.

**Deferred to phase 1**, once milestones have stayed current through about four weekly calls: the
`/docs/roadmap/` page, its region markers and placeholder, the untrusted-title rule, the structural
check and `tools/site_guards.py`, and the page incident runbook.

**In phase 0, `ROADMAP_RENDER_ENABLED`** governs publishing `roadmap.json`. When it is not `true`, the
build writes a `roadmap.json` with status `disabled` and no milestones. The failure table applies to
`roadmap.json` alone: a data failure on a nightly dispatch fails the build when the published
`roadmap.json` already reports this commit, and every other build writes status `unavailable` and
passes.

**Not in the implementation:** running the migration against the live repository, creating
milestones or issues, setting repository variables, and pinning the health issue. Those are rollout
steps the project lead runs after deciding decisions 2 through 11, and after promotion is repaired.
The implementation carries the current defaults for decisions 3 through 8 behind constants in
`tools/roadmap_model.py`, so each can change in one place.

## Goal

A contributor can open one page and see each deliverable the project has committed to, its target
quarter, and how much of it is done. A maintainer can say "Update the roadmap for OWASP" and get
rows ready to paste.

The upkeep this design asks for is the weekly triage pass the project already runs: setting a
milestone on accepted work, and closing a milestone when its work reaches `main`. Everything else
is automated, and everything the automation will not repair lands on one pinned issue that pass
reads. Triage is under strain, with the untriaged backlog doubling between September 17 and
October 4. This design keeps the roadmap from adding to it.

## Decisions

| Question | Decision | Why |
| --- | --- | --- |
| Unit of the roadmap | One GitHub milestone is one deliverable | A milestone already carries a title, a due date, a description, and a set of issues. |
| Which milestones | New milestones named for what ships, replacing the Day 14/30/60/90 checkpoints | Each Day N description bundles unrelated outcomes under a title that says nothing to an outsider. |
| Target granularity | Calendar quarter, with an optional committed date where one was promised | A volunteer project cannot staff day-level dates, and the one dated commitment it made must not be hidden by rounding. |
| Freshness | Nightly rebuild of static HTML | The site renders with JavaScript disabled. |
| Page and spreadsheet | The build publishes `roadmap.json` next to the page, and the OWASP script reads it | One classification, computed once, cannot disagree with itself. The script needs no GitHub access, no token, and no copy of the rules. |
| OWASP procedure | A personal skill, `owasp-acs-roadmap`, driving a deterministic script, with no repository text in the model's context | The model runs in a session holding an admin credential. |
| Trust | A login is trusted when it appears in `.github/CODEOWNERS` or the `GOVERNANCE.md` roster | Both files already change together whenever leadership changes, by GOVERNANCE.md's own rule. |
| Milestone upkeep | Setting a milestone accepts an issue, unless a standing triage decision says otherwise | The project has no capacity to apply two labels where one act will do. |
| Shipping | A maintainer closes a milestone when its work reaches `main`. Automation never closes one. | Every automated trigger for closing fired on work that had not shipped. |
| Which code runs | Every job runs the tools from `main` | The page renders from `main`, so the sync and health jobs classify against the same rules. |

## The shared rules

`tools/roadmap_model.py` holds every rule that decides what an issue or a milestone means. It is
standard library only, has no network access, takes the current time as an argument rather than
reading the clock, and carries a `RULES_VERSION` string that changes whenever a rule does.

### Trusted logins

`roadmap_model.trusted_logins(repo_root)` returns every GitHub handle named in `.github/CODEOWNERS`
rule lines and in the `GOVERNANCE.md` project lead and workstream lead tables. GOVERNANCE.md requires
a leadership change to update both files in one pull request, so this list costs nothing new to
maintain. Parsing is strict, because CODEOWNERS is prose as well as patterns:

- CODEOWNERS comments are stripped line by line before any token is read. A whole-file `@handle`
  match picks up `@import` and `@font-face` from a comment, and `font-face` is a real outside account.
- Every owner token must match `^@[A-Za-z0-9-]+$`. A team or an email address fails a test that runs
  on every pull request, so the pull request that adds one fails rather than the nightly build.
- In GOVERNANCE.md, a handle counts only when the link text and the URL name the same login, so
  `[@rocklambros](https://github.com/someone-else)` fails the test.
- Logins are compared casefolded.
- `render_landing.parse_workstreams` reads only the workstream table and returns raw cells, so the
  model adds its own parser for both tables rather than reusing it.

Whether the creators named under Origins and assigned triage volunteers are trusted is a decision for
the project lead, listed below.

Version 1.3 used `author_association`. The live API showed `MEMBER` means organization membership:
all seven read-role collaborators are organization members, six leads with admin, maintain, or
write access are not, and the value changes with who is asking. Trust by roster avoids all three
problems, and it applies to an event's actor as easily as to an issue's author.

### Milestone description lines

A milestone description may carry three machine-read lines, each on its own line. The page strips
them before showing the description.

- `Committed: 2026-12-09` names a date the project promised. It drives target-passed detection in
  place of the quarter's end, and the page shows it next to the quarter.
- `Workstream: Reference Implementation` names the owning workstream. Its value must match a row of
  the `GOVERNANCE.md` workstream table, or be `Project`, which maps to the project lead table and
  covers the Governance under OWASP milestone.
- `Type: Open Source tool` names the OWASP deliverable type, one of Document, Cheat Sheet, Open
  Source tool, Application/Tool, Code Sample, Agent Skill, or Other.

Creating or editing a milestone needs the Write role or higher.

### Issue classes

Every issue in a milestone falls into exactly one class. Pull requests are excluded at fetch time.
The rules are checked in order:

| Class | Rule | Counts toward progress |
| --- | --- | --- |
| Unverified | closed, with any `state_reason`, by a login that is not trusted | yes, as remaining, marked "closed by a non-maintainer, awaiting review" |
| Dropped | closed by a trusted login with `state_reason` `not_planned` or `duplicate`, or with any `state_reason` this version does not know | no |
| Done | closed by a trusted login with `state_reason` `completed` | yes, as done |
| Planned | open and carrying `status:accepted` | yes, as remaining |
| Deferred | open and carrying `scope:deferred` | no, listed separately |
| Untriaged | any other open issue | no, reported |

The closing login comes from the issue's `ClosedEvent.actor`. A merged pull request closes its
issues with the merging maintainer as the actor, so ordinary delivery counts as Done. An outsider
who closes their own issue, whether as completed or as not planned, cannot move progress in either
direction until a trusted login reopens and recloses it. An unknown `state_reason` is reported in the
health issue.

A merge credits whatever the pull request body says it closes, and the squash message is the pull
request body, so an outsider's "Closes #132" in a typo fix would mark #132 Done under the merging
maintainer. `pr-intake.yml` therefore posts a fixed-text comment on any pull request whose body uses
a closing keyword on an issue that sits in a milestone, so the merger confirms it on purpose.

`status:accepted` is checked before `scope:deferred`, matching `desired_board_status`.

Progress reads "4 of 9 issues closed", where 9 is done plus unverified plus planned. When that
total is zero, no progress bar is rendered.

### Milestone states

Closed milestones are classified first, then open ones. The first matching row wins. "Remaining"
means unverified plus planned.

| State | Rule | Page | OWASP status |
| --- | --- | --- | --- |
| Withdrawn | closed, no done | Withdrawn section | no row, and the script reports any existing row for removal |
| Published | closed, at least one done, no remaining | Delivered section, with any dropped count shown | Published |
| Closed with open work | closed, at least one done, at least one remaining | Delivered section, marked "closed with open work", and reported in the health issue | In Review |
| Skipped | open, no done, remaining, or deferred issues | not shown | no row |
| Deferred | open, no done, no remaining, at least one deferred | card, "N deferred issues", no progress bar | Planning |
| Ongoing | open, no `due_on` | card, quarter reads "Ongoing" | Ongoing |
| Ready to publish | open, at least one done, no remaining | card, "work complete, awaiting release", with any deferred issues listed as carried forward | In Review |
| In progress | open, at least one done | card | In Progress |
| Planning | open, otherwise | card | Planning |

The table-driven test enumerates every combination of open or closed, dated or undated, and zero
or nonzero done, unverified, planned, deferred, dropped, and untriaged counts, and asserts the
expected state for each combination from a hand-written oracle, not merely that one state matched.
A second test walks every row of the Changing the roadmap table and asserts the state each procedure
produces.

### Quarters and dates

The quarter comes from the date part of `due_on`, read as a calendar date with no timezone
conversion. GitHub stores milestone dates at midnight UTC on the chosen date, as the live Day 14
milestone shows (`2026-09-24T00:00:00Z`).

An open milestone's target has passed when the given current date is after its `Committed:` date,
or, without one, falls in a later quarter than its `due_on`. The page reads "Q4 2026, target
passed". The renderer receives the current time from its caller, and the committed fixture is
rendered at a frozen time, so no test or pull request build changes result when a quarter ends.
Whether a due date set in the GitHub UI from a non-UTC browser keeps the chosen date is unverified,
so migration step 1 tests it.

## The roadmap page

### Where it lives

The page publishes at `/docs/roadmap/` as a top-level "Roadmap" entry in the MkDocs nav, with a
link from the landing page's section nav next to "Specification". The build also publishes
`/docs/roadmap/roadmap.json` for the OWASP script.

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
else. A scratch build showed Python-Markdown wrapping a top-level `<meta>` or `<span>` line in `<p>`
and parsing its text as Markdown, and showed one enclosing `<div>` keeping the whole region raw,
`<meta>` included.

The render step replaces everything between the markers and fails unless each marker appears exactly
once, in order. A test asserts the committed file still holds the placeholder.

### What it shows

The fixed introduction says the roadmap shows quarterly targets set by volunteers, which move as
capacity does, and that progress counts delivered issues only. It links to Current Priority Scope by
absolute URL,
`https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CONTRIBUTING.md#current-priority-scope`,
because MkDocs strict mode rejects a link outside `docs/`.

Inside the region's `<div>`:

1. Metadata: `acs-roadmap-status` (`ok`, `unavailable`, `disabled`, or `placeholder`),
   `acs-roadmap-generated` (ISO-8601 UTC), `acs-roadmap-commit` (the commit built),
   `acs-roadmap-run` (the run id), and `acs-roadmap-rules` (`RULES_VERSION`), so any published page
   traces back to the run, commit, and rules that produced it.
2. One card per milestone in a card state, ordered by quarter, then title, with Ongoing and Deferred
   milestones last. A card shows the title linked to the milestone, the quarter and any committed
   date, the progress count and bar, the description as plain text, and the issues by class, each
   with number, title, and state, linked to GitHub.
3. A collapsed "Delivered" section, newest close first.
4. A collapsed "Withdrawn" section.

### Untrusted titles

For every issue the page renders, in every class and state, whose author is not a trusted login, the
renderer checks two things from the fetched timeline: the issue's first `MilestonedEvent`, and its
`RenamedTitleEvent`s. When a rename by an untrusted login comes after the first milestoned event, and
no trusted login renamed it later, the page shows "#N, title changed after it joined the roadmap"
instead of the title. A maintainer clears it by editing the title. When the maintainer wants to keep
the new wording, they still need to make an edit, for example adding and removing a character in two
saves, because GitHub records no event for an unchanged title.

The rule anchors on the first milestoned event, so moving an issue to another milestone does not
clear a flag. It is sticky, so reverting a title before the nightly build does not hide the change.

### Fetching the data

The fetch is the first step of the existing `build` job in `deploy-pages.yml`, before `setup-uv` and
before any package is installed, so no third-party code has run in the job when the token is in use.

- It runs `python3 -I -S tools/fetch_roadmap.py --out roadmap-data.json`, standard library only, with
  no imports from `tools/`. It comes after the gate and checkout steps and before `setup-uv`.
- It is the only step given `GH_TOKEN: ${{ github.token }}` explicitly. The `build` job gains
  `issues: read`. `setup-uv` defaults its own `github-token` input to the job token, so the workflow
  sets that input to an empty string and pins `version`. `actions/configure-pages` receives the token
  by design, as a first-party GitHub action, which is unchanged from today.
- It calls `/usr/bin/gh`, where GitHub's Ubuntu runner images install it from the `.deb`, with an
  explicit minimal environment: `PATH`, a temporary `HOME`, `GH_TOKEN`, and `GH_HOST=github.com`. A
  `--gh` argument exists for tests only, and a guard test asserts the workflow never passes it.
- It enforces its own four-minute deadline under a five-minute step timeout, and always exits 0. It
  writes either the data or a failure record carrying a class to the output file. The render step
  reads that file, so no step outcome or job dependency carries the result and nothing can be
  silently skipped.

The fetch lists milestones, then queries each milestone's issues 50 at a time, with each issue's
first 20 labels, author, state, `stateReason`, the actor of its last `ClosedEvent`, its first
`MilestonedEvent`, and its last 20 `RenamedTitleEvent`s. Pagination follows GraphQL cursors in
Python. A single query over all milestones at page size 100 measured about 1.23 million nodes, over
GitHub's 500,000 limit, so a unit test computes the node bound of the query the code builds and fails
above 100,000. `MAX_NODE_LIMIT_EXCEEDED` is classed as a code defect. Fixtures cover a null `actor`
and a null `author`, which deleted accounts produce. GraphQL's milestone `issues.totalCount` counts issues alone, so pull requests never enter the
data. The completeness check requires, for every milestone, that the issues fetched equal that count.
A mismatch, a transport error, an HTTP 5xx, or a rate-limit response triggers up to two refetches,
20 seconds apart.

Each GraphQL page is fetched with `gh api -i` so the headers can be classified. A 403 or 429 with
`x-ratelimit-remaining: 0`, a `retry-after` header, a `RATE_LIMITED` error type, or "rate limit" in
the message is a rate limit. Any other 401 or 403 is a permission defect.

### Which data the build renders

| Event | `ROADMAP_RENDER_ENABLED` | `preview` input | Data rendered | Publishes |
| --- | --- | --- | --- | --- |
| `pull_request` | any | not applicable | the committed fixture `tests/fixtures/roadmap-data.json`, at its frozen time | no |
| any other | any | `true` | live | no, `preview` forces the publish gate off |
| any other | `true` | `false` | live | per the existing gate |
| any other | anything else | `false` | none. The placeholder with status `disabled` | per the existing gate |

Pull request builds always render the fixture through the real `mkdocs build` and run the structural
check over it, so every change exercises the renderer and the guard without spending API calls on
fork pull requests, and whatever the switch says. A `disabled` render is never a failure.

A preview run uploads the built `roadmap/index.html` and `roadmap.json` as an artifact with
`retention-days: 1`, so rollout step 3 has a rendered page to inspect. `preview` overrides the render
switch, so any account that can dispatch a workflow can render live data during an incident. That
account can already push a workflow that does the same, so the runbook says not to dispatch previews
while the switch is off rather than pretending the switch prevents it.

The `build` job exposes the gate's `publish` value as a job output. The `deploy` job's `if` becomes
`needs.build.outputs.publish == 'true'`, keeping the existing event and ref checks, so a preview run on
`main` skips deploy instead of failing it for want of an artifact. `inputs.preview` is read as a
boolean, which is null on push events.

`roadmap.json` carries a `schema_version`, `RULES_VERSION`, `status`, `generated`, `commit`, the project
lead and workstream lead names, and per milestone its number, URL, title, stripped description, the
three description lines, state, OWASP status, quarter, and counts. When the status is `disabled` or
`unavailable` it carries no milestones. A test round-trips the build's output through `owasp_rows.py`.

### Failure behavior

The roadmap must never stop a schema from publishing or a pull request from merging.

One step, `python3 tools/build_roadmap_site.py`, runs after the fetch and owns the whole sequence:
render, `mkdocs build`, the structural check, the fallback, the second check, and writing
`roadmap.json` last from the status that survived. It receives the event name, the `source` input,
and the switch value, and exits non-zero only where the table below says the build fails. Plain
workflow steps cannot express "if this check fails, rebuild and check again" without `if:` chains
that would collide with the guard test's exact pins.

| Failure | Pull request build | `source=nightly` dispatch | Any other build |
| --- | --- | --- | --- |
| Data failure, rate limit, timeout, permission defect, or unexpected exception in fetch, model, or render | not applicable, fixture rendered | build fails when the published `roadmap.json` reports this commit, so Pages keeps the last good page. Otherwise it degrades, like any other build. | status `unavailable`, region reads "Roadmap data is temporarily unavailable", build passes |
| Unexpected exception rendering the fixture | build fails, a code defect | not applicable | not applicable |
| Structural check violation | build fails | build fails | `docs/roadmap.md` is reset to an `unavailable` placeholder, `mkdocs build` runs again so the search index is rebuilt too, the check runs again, `roadmap.json` is written with status `unavailable` and no milestones, and the build passes only if that check is clean |
| Marker missing or duplicated, in source or in built output | build fails | build fails | build fails |

The nightly dispatch fails only when the site already serves this commit. The driver reads `commit`
from the published `roadmap.json`, at the Pages base URL from `configure-pages` with the constant
already in `deploy-pages.yml` as the fallback, with a ten-second timeout, `Cache-Control: no-cache`,
and redirects followed. A 404, a timeout, an unreadable body, or a missing field all mean "not the same
commit", so the build degrades rather than failing closed on the first deploy or during an outage that
also broke the page read. If an earlier push deploy failed and the site is behind, the nightly
carries a schema change too, and it degrades so the schema still publishes. Version 1.3 failed every
publishing run on a permission defect, which contradicted the rule that the roadmap never blocks a
schema. Every non-nightly build now degrades instead, and the roadmap monitor reports
`unavailable`.

Fixtures cover a null description, a null due date, zero milestones, an issue with no labels, a
milestone with zero issues, an unknown `state_reason`, and every row of the states table.

### Escaping untrusted text

- Fetched strings appear only in text nodes, never in an attribute.
- Every fetched string passes through `html.escape` with `quote=True`, and every whitespace run in it
  collapses to one space.
- Every `href` is built from the repository constant and an integer.

After `mkdocs build`, the build job runs `python3 tools/site_guards.py roadmap
_site/docs/roadmap/index.html`. It parses the region between the markers and fails on:

- the region missing from built output, which catches a defect that swallowed the end marker
- anything other than one top-level `div` with class `acs-roadmap`
- any element outside `div, section, article, p, span, h2, h3, ul, li, a, details, summary, progress,
  meta`
- any attribute other than `class`, `href`, `value`, `max`, `name`, and `content`
- a `class` value outside a fixed set
- an `href` not matching
  `^https://github\.com/GenAI-Security-Project/agent-control-standard/(issues|milestone)/\d+$`
- a `meta` whose `name` is not one of the five listed above

The existing `third_party_hosts` scanner runs over the same file as a second check. Both scanners
move from `tests/conftest.py` to `tools/site_guards.py`, standard library only, and conftest
re-exports them.

### Switches

Three repository variables control the roadmap. Each is read as the literal string `true`, and
anything else is off.

| Variable | Read by | Effect when not `true` |
| --- | --- | --- |
| `ROADMAP_RENDER_ENABLED` | the build job's fetch and render steps | No fetch. The placeholder renders with status `disabled`. Pulls live data off the site on every deploy path at once. |
| `ROADMAP_REFRESH_ENABLED` | the refresh workflow's job `if` | The nightly dispatch is skipped. Turn it off before rolling Pages back to an older artifact. |
| `ROADMAP_SYNC_ENABLED` | the sync workflow's job `if`s | The event job and the sweep do not run. |

All three are created at repository level with the value `false` in rollout step 1, so an
organization-level variable of the same name cannot switch them on. The build writes a warning
annotation, and the health issue reports the value, whenever one holds anything other than `true` or
`false`.

### Incident runbook

The rollback comment in `deploy-pages.yml` gains this runbook. To pull roadmap content off the site:

1. Set `ROADMAP_REFRESH_ENABLED` and `ROADMAP_RENDER_ENABLED` to `false`.
2. Dispatch deploy-pages on `main` and confirm the `deploy` job itself ran and succeeded, not only the
   workflow.
3. Delete the `github-pages` artifacts and preview artifacts of every run since the content first
   appeared, with `gh api -X DELETE repos/{repo}/actions/artifacts/{id}`. Re-running any of those
   runs' deploy jobs would republish the content.
4. Allow ten minutes for the site's `cache-control: max-age=600` to expire.

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

deploy-pages gains two `workflow_dispatch` inputs: `source`, defaulting to `manual`, and `preview`, a
boolean defaulting to `false`.

`actions: write` is broader than dispatch. It also covers re-running old runs, deleting runs and logs,
and cancelling runs. The refresh job offers no way to use any of that, since it checks out nothing,
runs one constant command, and lives two minutes, and the guard test pins this file exactly.

### Workflow guard tests

Enumerating forbidden properties already failed five times in this repository's third-party guard,
so the guard tests pin shapes.

- `tests/test_roadmap_refresh_workflow.py` asserts the parsed YAML of `roadmap-refresh.yml` equals one
  expected dictionary exactly.
- `tests/test_roadmap_sync_workflow.py` checks `roadmap-sync.yml` against an allowlist of keys at every
  level and asserts:
  - the exact trigger set, permissions, `if`, and concurrency per job, including `queue: max`, which
    the pinned zizmor 1.30.1 does not validate and actionlint 1.7.12 rejects
  - every `env:` map equals an exact expected dictionary
  - every `run:` is free of `${{`, invokes `python3 -I -S tools/roadmap_sync.py`, passes `--apply`, and
    installs nothing
  - no step uses `setup-uv` or any action other than the pinned `actions/checkout` SHA, which sets
    `persist-credentials: false` and `ref: main`
- `tests/test_deploy_pages_workflow.py` asserts every job's exact `permissions`, `needs`, and `if` in
  `deploy-pages.yml`, that the fetch step comes before `setup-uv`, that `github.token` appears only in
  that step, and that no step passes `--gh`. It pins `needs` and `if` because skip propagation through
  `needs` is the defect round four found.
- `tests/test_monitor_roadmap_workflow.py` pins `monitor-roadmap.yml` the same way.

PyYAML loads the key `on` as the boolean `True`. Each test reads the trigger block through that key and
says why in a comment.

## Keeping milestones synced

### The one human act

Triage puts an accepted issue in its deliverable milestone. Setting a milestone needs the triage role
or higher. Three named leads have lapsed invitations and hold no access today (#144), and several org
owners hold access without being on the roster, so the health issue lists who accepted what.

### The event job

`.github/workflows/roadmap-sync.yml` has a job named `event` that runs on `issues: milestoned` only,
when `ROADMAP_SYNC_ENABLED` is `true`. It checks out `main` and re-fetches the issue's current
milestone, labels, and state rather than trusting the event payload. It takes no action unless the
issue is open and its milestone is still set and open. Then it applies one rule:

| Current labels | Action |
| --- | --- |
| any of `scope:deferred`, `scope:out`, `status:blocked`, `status:needs-info`, `wontfix`, `invalid`, `duplicate` | none. The health issue reports it, except `scope:deferred`, which is how deferred work joins a deferred milestone. |
| `status:accepted` already | remove `status:needs-triage` if present |
| otherwise | add `status:accepted`, add `scope:in-focus` when no `scope:` label is present, and remove `status:needs-triage` if present |

Adding `scope:in-focus` keeps GOVERNANCE.md's two-label minimum true for every issue the bot accepts.
Removing `status:needs-triage` is the only removal in this design, and a 404 because the label is
already gone counts as success.

The job's concurrency group is keyed by issue number, with `queue: max` and
`cancel-in-progress: false`. GitHub's default keeps only one pending run per group and cancels the
rest, which would have dropped most of the migration's acceptance events.

### The sweep job

The `sweep` job runs nightly at 04:10 UTC, when `ROADMAP_SYNC_ENABLED` is `true`, in its own
concurrency group. It changes no issue other than the health issue, and never re-applies the
acceptance rule, since a maintainer who removed `status:accepted` made a decision.

### What the automation never does

- It never closes, reopens, sets, or clears a milestone.
- It never removes a label other than `status:needs-triage`.
- It never touches a pull request.
- It never quotes fetched issue text into anything it writes.

### Structure

`tools/roadmap_sync.py` follows the split `tools/apply_governance.py` uses: pure planning functions
over an event or a snapshot, one executor through `gh`, and a dry run unless `--apply` is passed. It
and `tools/roadmap_model.py` are standard library only. The sync jobs run
`python3 -I -S tools/roadmap_sync.py`, and because `-I` removes the script's directory from the import
path, the script adds its own directory explicitly before importing `roadmap_model`. No sync job
installs packages, so no third-party code runs beside the write token.

### Security

`issues: write` and `contents: read` on the sync workflow's `GITHUB_TOKEN`, and `issues: read` on the
build job, were reviewed and approved. No job in this design runs with a write token on an event a fork
author can trigger. Both sync jobs check out `main` with `persist-credentials: false`, and the issue
number reaches the tool through `env:`.

One further grant is needed and is **not yet approved**: `pull-requests: read` on the sweep job. The
"on `main`" check below reads each closing pull request's merge commit, and a token without
pull-request permission cannot read pull requests. Until it is approved, the sweep lists Ready to
publish milestones without the on-`main` split and says to verify by hand.

`pr-intake.yml` changes in two places. Today it calls `gh issue view` once for every `#N` in a pull
request body, re-run on every edit, against the shared `GITHUB_TOKEN` budget of 1,000 requests an hour
per repository that the roadmap fetch and sync also draw on. It instead makes one call listing
`status:accepted` issues and intersects the references with that list, so its cost no longer depends on
the body. It also posts the closing-keyword comment described under Issue classes.

## Health reporting

### The health issue

A pinned issue titled "Roadmap health" is the single place every drift lands. GOVERNANCE.md's Triage
authority section names it as the weekly call's triage agenda, and names the project lead as the person
who closes milestones.

- The repository variable `ROADMAP_HEALTH_ISSUE` holds its number once it exists. The sweep uses that
  issue, after checking its author is `github-actions[bot]` and its body carries the fixed marker. A
  marked issue anywhere else is ignored, so a second marked issue cannot jam the sweep.
- When the variable is unset, the sweep lists with REST `issues?creator=github-actions[bot]&state=all`
  and selects the marked issue. Exactly one match is used, a closed match is reopened, more than one
  fails the sweep, and no match after a successful listing creates the issue. The run summary then asks
  for the variable to be set and the issue pinned. A test asserts the creator filter's exact spelling,
  since a wrong value returns an empty list with status 200.
- The sweep locks the conversation on creation and again on every run.
- The body never quotes fetched titles. Logins appear only for maintainer actions, such as who set a
  milestone, in code formatting without `@`. Contributors are never named.

The body opens with a machine-read status line in a fixed format:
`<!-- acs-sweep: <ok|degraded> <ISO-8601 UTC> run <run id> [failed sections] -->`. When any read fails,
the sweep still rewrites the body, marks the failed sections "could not be read", writes `degraded`,
and exits non-zero.

### Sections

| Section | Contents |
| --- | --- |
| Ready to publish | Ready-to-publish milestones. Without `pull-requests: read`, they are listed with "verify on `main` by hand". With `pull-requests: read`, each is split by verification: a done issue is verified when its `ClosedEvent.closer` is a merged pull request whose `mergeCommit` is on `main`, meaning `compare/{sha}...main` returns `ahead` or `identical`. A milestone is "on `main`" only when every done issue is verified, and otherwise "awaiting promotion or verification" with the reason per issue and days waiting. |
| Closed with open work | Closed milestones that still hold remaining issues |
| Target passed | Open milestones past their committed date or quarter |
| Untriaged in a milestone | Untriaged-class issues, plus issues the event job declined because of a standing triage label other than `scope:deferred` |
| Awaiting maintainer confirmation | Unverified-class issues, by number only |
| Closed with open work and nothing done | Closed milestones with no done issues but remaining issues, which render as Withdrawn |
| In focus without a milestone | Open `scope:in-focus` issues with no milestone |
| Accepted without a milestone | Open `status:accepted` issues with no milestone |
| Accepted by milestone this week | Issues the bot accepted in the last eight days, with the login that set the milestone |
| Title changed | Issues the page currently renders as "title changed after it joined the roadmap" |
| Unknown close reasons | Issues whose `state_reason` this version does not know |
| Off-quarter dates | Milestones whose `due_on` is not a quarter's last day |
| Missing description lines | Milestones without a valid `Workstream:` or `Type:` line |
| Switches | The current value of each roadmap variable, flagged when it is neither `true` nor `false` |
| Rules version | `RULES_VERSION` from `main` |

The "on `main`" check assumes promotions are merge commits, which every promotion so far has been. A
squash promotion would leave every closing commit off `main`'s ancestry. Restricting `main` to merge
commits is a ruleset decision for the project lead.

### The roadmap monitor

A new `.github/workflows/monitor-roadmap.yml`, separate from `monitor-pages.yml` so the schema
contract's alarm never shares a result with roadmap noise, runs four times a day from `main`. It holds
`contents: read` and `issues: read`. Each check runs only while the switch it watches is on, so
turning sync off does not silence the page check.

- While `ROADMAP_RENDER_ENABLED` is `true`, it fails when the published page returns anything but 200,
  lacks the status meta, carries a status other than `ok`, or carries an `ok` with a generated time
  older than 36 hours.
- While `ROADMAP_SYNC_ENABLED` is `true`, it fails when `ROADMAP_HEALTH_ISSUE` is unset or not an
  integer, when that issue's author is not `github-actions[bot]` or its body lacks the marker, or when
  its status line is missing, says `degraded`, carries a time more than 50 hours old, or carries a
  time in the future.

It reads the sweep's own status line rather than the issue's `updated_at`, which a comment or a label
change also moves. Failed scheduled runs notify the account that last changed the workflow's cron line
or re-enabled the workflow, so the project lead merges this file and the refresh workflow personally.

## The OWASP report skill

### Shape

The skill is a `SKILL.md` plus a bundled script, `owasp_rows.py`, standard library only. The script
downloads two public files, `roadmap.json` from the published site and the sheet's CSV export, builds
the rows, matches them against the sheet, and writes a TSV file. It needs no GitHub access and no
token, holds no copy of the rules, and reads the classification the page itself used.

The model reads only the script's summary: milestone numbers, states, statuses, and flags such as new,
updated, orphaned at sheet row N, duplicate match at rows N and M, or missing description line. No
title, description, issue text, or sheet cell enters the model's context, so neither an outsider nor a
write-role account can plant instructions for it. SKILL.md asks the model not to run `gh` or read the
TSV itself, and to tell the user the TSV's path and which rows changed, by milestone number. Claude
Code's documentation says `allowed-tools` pre-approves tools rather than restricting them, so the skill
relies on keeping untrusted text out of the context.

The script refuses a `roadmap.json` whose `generated` time is more than 48 hours old, whose status is
not `ok`, or whose `schema_version` it does not know, and a CSV response whose `Content-Type` is not
`text/csv`, which catches a sign-in page served with status 200. Its `main` is wrapped in a catch-all
that prints only a fixed error code and sends any traceback to a file, because a Python traceback
prints the offending value and the model reads standard error. Every summary field is checked against
an integer or enum allowlist before it is printed. A test feeds a hostile title and a hostile sheet
cell and asserts neither appears in standard output or standard error.

### What it produces

Rows in the column order of the "quarterly roadmap" worksheet, tab-separated, starting at the
Deliverable ID column, one per milestone whose state has an OWASP status:

| Column | Value |
| --- | --- |
| Deliverable ID | blank, matching every existing row |
| Initiative | `Agent Control Standard` |
| Work Item Title | milestone title |
| Deliverable Type | the milestone's `Type:` line |
| Initiative Co-Owners | Project lead from `GOVERNANCE.md`, carried in `roadmap.json` |
| Workstream Name | the milestone's `Workstream:` line |
| Workstream Lead | that workstream's leads, carried in `roadmap.json` |
| Status | the OWASP status of the milestone's state |
| Target Quarter | the milestone's quarter, or blank when Ongoing |
| Target Publication Date | the `Committed:` date when present, otherwise blank |
| Milestone & Strategic Objective | milestone description, without the machine-read lines |
| Repository Link | milestone URL |

Rows are matched to existing ACS rows on Repository Link, and more than one existing row with the same
link is reported rather than guessed. Every cell has each whitespace run containing a tab, carriage
return, or newline collapsed to one space, and a cell whose first non-space character is `=`, `+`,
`-`, `@`, a tab, or a carriage return gets a leading `'`.

### Where it lives

Claude Code loads it from `~/.claude/skills/owasp-acs-roadmap/`. claude.ai on the web, the desktop
chat, and Cowork load it from a zip uploaded under Settings, Capabilities, Skills. The script needs
network access to the project's GitHub Pages host and `docs.google.com`. Whether the claude.ai sandbox
allows that is unverified. If it does not, the skill says so and stops. The skill is done only after one
run in Claude Code, one attempt on claude.ai, and a paste into a copy of the sheet checked for column
alignment and the visible leading `'`. `owasp_rows.py` ships with its own tests, run against a recorded
`roadmap.json` and a recorded CSV.

## Rollout

The weekly promotion workflow has failed on its scheduled runs of September 24 and October 1, with
"GitHub Actions is not permitted to create or approve pull requests", and `main` has not moved since
September 10. Everything here runs from `main`, so the rollout has a gate this design cannot open.

1. Create the three switches at repository level with the value `false`. Merge the implementation to
   `integration`. Nothing runs and nothing is published.
2. Promote to `main`, by the repaired workflow or by hand. Confirm the push deploy's `deploy` job ran.
3. Dispatch deploy-pages on `main` with `preview` set. The gate does not publish and the deploy job is
   skipped. Check the uploaded page for status `ok`, at least one card, and a clean structural check,
   and confirm `ClosedEvent.actor` resolved under the build token. Dispatch the sync workflow's `dryrun`
   job and read both plans.
4. Set `ROADMAP_SYNC_ENABLED` to `true` and run the milestone migration below. Once the sweep creates
   the health issue, confirm the `creator=github-actions[bot]` listing returns it, then set
   `ROADMAP_HEALTH_ISSUE` and pin it.
5. Set `ROADMAP_RENDER_ENABLED` and `ROADMAP_REFRESH_ENABLED` to `true`, and dispatch deploy-pages on
   `main`.

The sync workflow gains a third job, `dryrun`, triggered only by `workflow_dispatch`, holding only
`issues: read` and `contents: read`, and running whatever the switches say, since it cannot write. It
runs the sweep planner and, given an issue number as a dispatch input passed through `env:`, the event
planner, and prints both plans. The guard test pins it as the one `run:` without `--apply`.

## Milestone migration

The starting set below comes from a gap analysis of the Strategic Adoption Plan v3 against open issues
and pull requests on October 4, 2026, corrected by a coverage diff against the Day N milestones it
replaces. It was agreed on October 4, 2026, as a starting point that will change.

| Milestone | Issues | Open pull requests | Quarter |
| --- | --- | --- | --- |
| Conformance claim template | #93, #136, #106 | PR #168 (closes #93), PR #24 (closes #136) | Q4 2026 |
| Fail-open decision | #32, #37 | none | Q4 2026 |
| Reference adapters on main (Claude Code, Cursor, NAT) | #132, #134, #131 | PR #21 (closes #132), PR #22 (closes #134) | Q4 2026 |
| Spec and docs fixes for v0.1 | #194 to #198, #146, #148, #149, #120, #121, #57, #58, #133 | PR #63 (closes #57, #58), PR #20 (closes #133) | Q4 2026 |
| ACS-Core conformant reference Guardian | #33, #188, #70 to #73, and the Reference Guardian bugs and conformance reports | PR #193 (for #188, no closing reference) | Q4 2026 |
| Installable reference Guardian | #94, #91, #90, #127 | PR #112 (closes #90), PR #126 (closes #127) | Q4 2026 |
| AGT interoperability benchmark | #92, #171, plus new issues for the Cursor file-read gap and the AARM mapping session | PR #113 (for #92, no closing reference) | Q4 2026, `Committed: 2026-12-09` |
| Governance under OWASP | #144, #145, plus new issues for the open lead seats, domain transfer, OpenSSF Best Practices, and retiring the marketing site | none | Q4 2026 |
| Host adapter coverage | #170, #89, #114, #107 to #111 | PR #162 (closes #170) | Ongoing |
| Language ports | #86 to #88, #135 | PR #183 (closes #86), PR #169 (closes #87), PR #187 (Rust, no closing reference), PR #78 (for #135, no closing reference) | Ongoing |
| v0.2.0 | every open `scope:deferred` issue, #53, #29 | none | Q1 2027 |

Eight open `scope:in-focus` issues are in no row: #16, #19, #31, #43, #51, #52, #67, and #74. Placing
them is a triage decision made in step 1. #178 proposes replacing the `scope:` labels this design's
rules read, so it is decided in step 1 rather than scheduled into the launch quarter.

The open lead seats are five issues: Reference Implementation, one seat. Documentation, two seats.
Testing and Validation, two seats. The Strategic Adoption Plan's "ASI governance milestones" item is
closed as not applicable, since ACS already operates as an initiative under ASI.

The migration runs in rollout step 4:

1. Run `tools/roadmap_sync.py migrate <table.json>`, a dry run. It prints each entry's type, author,
   title, and current `scope:` and `status:` labels, refuses any pull request or closed issue, lists
   every entry the event rule would decline or accept, lists any issue milestoned during the rollout
   gate that lacks `status:accepted`, and lists open table entries referenced by a merged pull request
   as possibly delivered, so the project lead can close what already shipped before the page counts
   it as zero. The project lead triages each unlabeled or
   `status:needs-triage` entry, places the eight unassigned in-focus issues, and decides #144, #145, and
   #178. Set one test milestone's due date in the GitHub UI from a non-UTC browser and read `due_on`
   back.
2. File the new issues named above.
3. Create each milestone with its quarter's last day as `due_on`, a description written for an outside
   reader, `Workstream:` and `Type:` lines, and a `Committed:` line where one applies.
4. Run `tools/roadmap_sync.py migrate <table.json> --apply`. It sets each milestone and applies the
   event rule directly in one process, pacing writes at one a second and stopping with the rate-limit
   message `apply_governance.py` already uses. A second dry run must print an empty plan.
5. Move #93 and #94 out of Day 30, then close all four Day N milestones with the description
   "Superseded by the roadmap on 2026-10-04." With no done issues they land in the Withdrawn section.

`tools/apply_governance.py` declares the Day N milestones as desired state. The implementation removes
them from `desired_milestones`, drops `milestone="Day 30"` from the two seeded issues that carry it,
changes the `scope:deferred` label description from "lands after Day 90" to "lands in a later
release", and updates `tests/test_apply_governance.py`.

CONTRIBUTING.md's Current Priority Scope changes in the same pull request in two places only: "Current
window: Day 0 to Day 30" becomes a pointer to the roadmap page, and "landing after Day 90" becomes
"landing in a later release". The "Next review <date>" line stays, because `scope-review.yml` parses
it. Whether the In focus bullets should become a pointer to the open roadmap milestones is a
scope-governance decision for the project lead.

### Changing the roadmap

| Change | The one edit | What follows automatically |
| --- | --- | --- |
| Move a deliverable to another quarter | Change the milestone's due date to that quarter's last day | The page reorders it on the next nightly build. |
| Move an issue to another deliverable | Change the issue's milestone | It stays accepted. Both milestones update on the next build. |
| Drop an issue from the roadmap | Clear its milestone | It stays accepted and leaves the page. The health issue lists it until it gets a milestone or loses `status:accepted`. |
| Add a deliverable | Create a milestone | It appears once it holds a counted issue. The health issue flags missing description lines. |
| Rename or reword a deliverable | Edit the milestone's title or description | The OWASP script matches rows by milestone URL, so the existing row updates. |
| Ship a deliverable | Close the milestone once the health issue lists it as on `main`, or after checking by hand while `pull-requests: read` is pending | Delivered section, Published. |
| Withdraw a deliverable that delivered nothing | Close the milestone | Withdrawn section. The OWASP script reports its row for removal. |
| Close a deliverable that delivered part of its work | Close the milestone, leaving the rest open or closing it as not planned | With remaining work left open it reads "closed with open work" and the health issue flags it. With the rest closed as not planned it reads Published, with the dropped count shown. |

None of the automation stores a milestone's title, number, or quarter.

## Testing

| Test file | Covers |
| --- | --- |
| `tests/test_roadmap_model.py` | every issue class including unverified and unknown `state_reason`, label precedence, the full states matrix against an oracle, the Changing the roadmap procedures, quarter derivation at `2026-12-31T00:00:00Z`, `2027-01-01T00:00:00Z`, and `2026-10-01T00:00:00Z`, the three description lines, trusted logins from CODEOWNERS and GOVERNANCE.md, and target-passed detection at injected times |
| `tests/test_fetch_roadmap.py` | GraphQL cursor pagination, completeness, retries, response classification for 401, 403, 403 with rate-limit headers, 429, `RATE_LIMITED`, and 5xx, the deadline, the always-exit-0 failure record, and running the script as a subprocess under `python3 -I -S` with a `--gh` stub |
| `tests/test_render_roadmap.py` | ordering, every section, every meta, the marker contract, the placeholder still committed, the untrusted-title rule for every class and state including after a re-milestone, the render decision table for every event, switch, and preview combination, every row of the failure table, the nightly commit comparison, and the null-field fixtures |
| `tests/test_roadmap_site_build.py` | a real `mkdocs build` over a hostile fixture whose titles carry `<script>`, `onerror=`, a `javascript:` URL, Markdown emphasis, an emoji shortcode, an attribute list, a newline, and a `--8<--` line, then the structural check on the built page, and the violation fallback rebuilding the site and leaving none of the hostile text in `search/search_index.json` |
| `tests/test_site_guards.py` | the structural check failing on a disallowed element, attribute, class, `href`, `meta`, a second top-level element, or a missing region |
| `tests/test_roadmap_sync.py` | every row of the event rule including a cleared or closed milestone, the 404-on-removal case, the absence of any action that touches a milestone, a pull request, or a label other than the three named, every health section and the status line format, health-issue selection by variable and by listing, including duplicates, closed matches, and the creator filter's spelling, logins written without `@`, the Ready-to-publish verification cases with and without pull request access, and the migration check |
| `tests/test_roadmap_monitor.py` | every monitor condition, including a future status-line time and each switch combination |
| `tests/test_roadmap_refresh_workflow.py`, `tests/test_roadmap_sync_workflow.py`, `tests/test_deploy_pages_workflow.py`, `tests/test_monitor_roadmap_workflow.py` | the workflow guard tests |
| `tests/test_apply_governance.py` | updated for the removed Day N milestones |
| `tests/test_pr_intake_workflow.py` | the single listing call and the closing-keyword comment |

End to end, rollout step 3 must produce a previewed page with status `ok`, at least one card, and a clean
structural check, and the sweep's dry run must succeed under the real token. After step 5, the published
page must carry a fresh generated time and this commit, `roadmap.json` must load in `owasp_rows.py`, the
health issue must exist, be pinned and locked, and carry `ok`, and the roadmap monitor must pass once.

## Decisions for the project lead

The premortem's fifth round found that several choices in this design are governance decisions. The
implementation should not settle them by default. Each is listed with the design's current default.

| # | Decision | Current default | Why it is yours |
| --- | --- | --- | --- |
| 1 | Build the custom page now, or run a phase 0 first: migrate milestones, run the sync job and the health issue, link the landing nav to GitHub's own `/milestones` page, and build the page only once milestones have stayed current for several weekly calls | Build the page now | GitHub's milestone page already shows title, due date, description, and percent complete, with no code and no injection surface. The September 9 design also made milestones the weekly burndown, and today 2 of 18 accepted issues carry one. |
| 2 | Adopt "Closes #N" in pull requests for accepted work, enforced by `pr-intake.yml` | Not adopted | 2 of the last 50 merged pull requests closed an issue, and only 4 issues have ever closed. Without the convention every card launches near "0 of N" while work merges. |
| 3 | Whether setting a milestone is an acceptance decision, and whether only a trusted login's milestone counts | Any triage-role milestone accepts, and adds `scope:in-focus` | GOVERNANCE.md gives acceptance to workstream leads and the project lead. The triage role is wider, and includes org owners who are not leads. |
| 4 | Who is trusted: CODEOWNERS and the lead tables only, or also the creators under Origins and assigned triage volunteers | Lead tables and CODEOWNERS only | The creators and the current triage volunteer would otherwise show as non-maintainers on the page. |
| 5 | The OWASP Co-Owners column: the project lead, or the three leaders in `project.owasp.yaml` | The project lead | It is a credit decision shown to OWASP, and `project.owasp.yaml` already names three. |
| 6 | The Day N milestones: close them into a public Withdrawn section, or delete them | Close into Withdrawn | Withdrawn keeps a record, but a first public view showing the ninety-day plan "withdrawn" reads as an abandoned plan. |
| 7 | Whether #178 was accepted on September 24 | Undecided | A comment on #178 records acceptance "per our meeting today". If adopted, the `scope:` labels this design reads change, and it should land first. |
| 8 | Realistic quarters: keep eight deliverables in Q4 2026, or keep only the serial-chain items there | Eight in Q4 2026 | Most cards would read "target passed" in January, in public and in the OWASP report. |
| 9 | Approve `pull-requests: read` on the sweep job | Not approved | It is a token scope change. Without it, Ready to publish says to verify on `main` by hand. |
| 10 | Who closes milestones, and where monitor failures go | The project lead, by email | One person already owns promotion, which has failed since September 24. Allowing any lead to close after the weekly call, and routing monitor failures to an issue, would need an `issues: write` grant on the monitor. |
| 11 | Repair promotion, restrict `main` to merge commits, and require the project lead's review on `.github/CODEOWNERS` and `GOVERNANCE.md` | None changed | Each is a repository permission or ruleset change, and the last two also protect the trust roster. |

## Out of scope

- A per-workstream view, filtering, or search on the page
- Writing to the Google Sheet
- Burndown history or velocity
- The label migration in #178. When it lands, `tools/roadmap_model.py`, the event rule, and their tests
  change with it in the same pull request, and `RULES_VERSION` changes.
- Repairing the promotion workflow, and restricting `main` to merge commits. Both are separate
  permission decisions.
- A repository-wide guard pinning every workflow's triggers and permissions. The guard tests here cover
  the workflows this design adds or changes. That gap predates this design.

## Residual risk

- **Promotion.** Until promotion works, nothing here reaches the site, and every renderer fix waits on
  it.
- **Triage throughput.** Milestones only stay true if the weekly pass happens.
- **Eight deliverables in one quarter.** The target-passed marker and the health issue will show the slip
  in January.
- **One alarm inbox.** Scheduled-run failure email reaches whoever last changed the cron line. A failed
  nightly deploy is started by `github-actions[bot]` and emails no one, so the first signal is the
  monitor's 36-hour freshness check, about two nights after the first failure.
- **Shared job.** The fetch token lives in the same job as the documentation build, which runs later. A
  later step with root on the runner could read it from the runner's memory. The token is read-only, for
  public data, and expires with the job, so this is accepted in exchange for removing the job-skip
  failure class that a separate job introduced.
- **Write-role accounts.** Eleven accounts can edit milestones and set the roadmap variables, and eight
  admins bypass every ruleset. One of them could forge the health issue's status line. Their writes are
  visible in the issue's and the repository's audit history.
- **Health issue on the board.** Project 9's auto-add puts the health issue on the triage board once. A
  maintainer archives that card when it appears.
- **Version skew.** Workflow files take effect on `integration` at merge, while the tools they run come
  from `main` at promotion.
- **Inactivity.** Scheduled workflows stop after 60 days without repository activity.
- **Milestoning an already-closed issue** counts it as done when a trusted login closed it.
- **Search index.** Material's search plugin re-escapes indexed text, so the search index does not reopen
  injection. A theme upgrade that changed that would.
