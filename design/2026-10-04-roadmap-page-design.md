# A live community roadmap, and an OWASP report on demand

Version: 1.0
Owner: ACS project lead
Date: 2026-10-04
Status: design, awaiting review

Contributors arriving from the OWASP relaunch can see what the project accepts, but not
when any of it lands. The accepted backlog lives in labels and on an org project board,
and neither carries a date. This design publishes a roadmap page built from GitHub
milestones and accepted issues, rebuilt every night with no maintainer in the loop.

A second, separate need rides alongside it. OWASP's GenAI Security Project tracks every
initiative in a quarterly roadmap spreadsheet, and ACS has no rows there yet. Filling it is
a quarterly manual paste, so it gets a skill that produces the rows on request rather than
code in this repository.

The two outputs read the same GitHub milestones and share nothing else. The page is
designed for contributors. The spreadsheet only defines the shape of the skill's output.

## Goal

A contributor can open one page and see each deliverable the project has committed to, its
due date, and how much of it is done, without reading a label or opening the board. A
maintainer can say "Update the roadmap for OWASP" in any Claude surface and get rows ready
to paste.

## Decisions

| Question | Decision | Why |
| --- | --- | --- |
| Unit of the roadmap | One GitHub milestone is one deliverable | A milestone already carries a title, a due date, a description, and a set of issues. Nothing else in the repository has a date. |
| Which milestones | New milestones named for what ships, replacing the Day 14/30/60/90 checkpoints | Each Day N description bundles three or four unrelated outcomes under a title that says nothing to an outsider. |
| Freshness | Nightly rebuild of static HTML | The site renders with JavaScript disabled. A browser fetch would break that and share an anonymous limit of 60 requests an hour per IP. |
| Page and spreadsheet | Decoupled | The page answers to contributors. The spreadsheet is a quarterly report for OWASP. |
| Where the OWASP procedure lives | A personal skill named `owasp-acs-roadmap`, outside this repository | OWASP reporting is an administrative chore, not part of the standard, and nothing in CI depends on it. |
| Milestone upkeep | Automated on the event, with a nightly sweep under it. Setting a milestone is the only human act. | The project has no capacity to keep milestones current by hand, so any rule that depends on a person remembering it will drift. |

## The roadmap page

### Where it lives

The page publishes at `/docs/roadmap/` as a top-level "Roadmap" entry in the MkDocs nav,
with a link from the landing page's section nav next to "Specification".

`docs/roadmap.md` is committed with a fixed introduction and one placeholder,
`<!--ACS:ROADMAP-->`. A new `tools/render_roadmap.py` replaces the placeholder in the CI
workspace before `mkdocs build` runs. This is the pattern `tools/render_landing.py` already
uses, so the build has one way of injecting repository state, not two.

A local `mkdocs serve` leaves the placeholder alone. The page then shows a one-line note
that live roadmap data appears only in the published build, so local previews never need a
token or network access.

### What it shows

The fixed introduction says when the page was generated and links to
[Current Priority Scope](../CONTRIBUTING.md#current-priority-scope). That section declares
itself the only place scope is stated, so the page links to it and never restates it.

Below the introduction, each open milestone renders as a card, ordered by due date with
undated milestones last. A card carries:

- the milestone title, linked to the milestone on GitHub
- the due date, or "No date set"
- a progress bar and a count, such as "4 of 9 done"
- the milestone description as plain text
- the counted issues, each with its number, title, and open or closed state, linked to GitHub

Closed milestones move to a "Delivered" section below the open ones, collapsed by default
and ordered by close date, newest first.

### Which issues count

An issue in a milestone counts toward its card when it is closed, or when it is open and
carries `status:accepted`. `status:accepted` survives the planned label migration, so this
rule does not wait on it.

An open issue in a milestone without `status:accepted` stays off the page, and the build
prints a warning naming it. A milestone should only hold accepted work, so this is a triage
mistake worth surfacing rather than hiding.

A milestone with no counted issues is skipped. Once the Day N milestones are closed and
emptied, they drop off the page with no special case.

Pull requests are excluded. The issues API returns them alongside issues, and the renderer
drops any entry carrying a `pull_request` key.

### Fetching the data

`render_roadmap.py` shells out to `gh`, which every GitHub-hosted runner carries and which
`tools/apply_governance.py` already uses. It makes two paginated calls:

```text
gh api --paginate "repos/GenAI-Security-Project/agent-control-standard/milestones?state=all&per_page=100"
gh api --paginate "repos/GenAI-Security-Project/agent-control-standard/issues?milestone=*&state=all&per_page=100"
```

Pagination returns every page, so the danger is a silently partial result, not a capped
one. The renderer checks completeness against GitHub's own counts. For every milestone,
the issues and pull requests it fetched must equal that milestone's `open_issues` plus
`closed_issues`. Any mismatch fails the build with the milestone named.

### Structure

The module follows the split `tools/apply_governance.py` uses, so the logic runs under test
with no network and no token.

| Function | Network | Does |
| --- | --- | --- |
| `fetch_roadmap_data()` | yes | Runs the two `gh` calls and returns raw JSON |
| `check_complete(milestones, items)` | no | Fails on any count mismatch |
| `build_roadmap(milestones, items)` | no | Returns ordered `Deliverable` records and the list of warnings |
| `render_roadmap(deliverables, generated_on)` | no | Returns the HTML that replaces the placeholder |
| `main()` | calls the above | Rewrites `docs/roadmap.md` in place |

### Escaping untrusted text

An issue's author can edit its title after a maintainer accepts it, and MkDocs passes raw
HTML through to the page. An issue title is therefore attacker-controlled text that lands
on the project's own domain.

The renderer emits the card markup as an HTML block, so Markdown never parses any string
from GitHub. Every title, description, and label passes through `html.escape` with
`quote=True`. Every link is built from the repository constant and an integer issue or
milestone number, never from a URL found in fetched text.

The cards use only local markup and the site's own stylesheet. They load no avatar, badge,
or image from GitHub, so the built page passes the third-party fetch guard in
`tests/conftest.py`.

### Failure behavior

A failed fetch, a nonzero `gh` exit, or a completeness mismatch fails the build. GitHub
Pages keeps serving the last successful deploy, so the worst case is a roadmap that is a day
stale, never a broken or empty page.

Pull request builds run the renderer too. That exercises the fetch path on every change,
at the cost of a pull request build failing during a GitHub API outage.

## Keeping it current

### Why deploy-pages cannot simply gain a schedule

Scheduled workflows run only on the default branch, which is `integration`. The
deploy-pages gate publishes only from `main`. A `schedule:` trigger added to deploy-pages
would build every night and publish nothing.

Letting scheduled runs deploy would mean allowing the `github-pages` environment to accept
deploys from `integration`. A scheduled run executes the workflow file as it exists on
`integration`, so that would let the less protected branch control production. This design
rejects it.

### The refresh workflow

A new `.github/workflows/roadmap-refresh.yml` runs nightly and starts a deploy-pages run on
`main`:

```yaml
name: Refresh roadmap

on:
  schedule:
    # 05:15 UTC, after the 04:40 board reconcile, so the roadmap reflects any Status
    # the board correction changed overnight.
    - cron: "15 5 * * *"

permissions: {}

jobs:
  dispatch:
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
`workflow_dispatch` from that rule, which is what makes this work. The dispatched run
executes `main`'s copy of deploy-pages under the existing `deploy` concurrency group, so it
queues behind any deploy already in flight.

### Permission changes

This design makes two permission changes. Both were reviewed and approved during design.

**`issues: read` on the deploy-pages `build` job.** The renderer needs to read milestones
and issues. The data is already public, so the grant exposes nothing new. Anonymous access
would avoid the grant but shares 60 requests an hour per runner IP and would fail nightly
builds at random. The real risk from issue data is its content, which the escaping section
handles.

**`actions: write` on the refresh job.** A token holding it can dispatch, re-run, or cancel
any workflow, disable workflows, and delete run logs and artifacts. Exploiting that requires
code execution inside the job, so the job is built to offer none:

- It checks out nothing and uses no third-party action. No repository code runs while the
  token is live.
- Its only trigger is `schedule`, so no event payload reaches it. The workflow name and ref
  are constants, and no `${{ }}` expression appears in the shell. The token reaches `gh`
  through `env:`, the pattern every other workflow here follows.
- The workflow defaults to `permissions: {}`, the job takes only `actions: write`, and a
  two-minute timeout bounds how long the token lives.
- The dispatch target is `main`'s deploy-pages, which the main ruleset already protects.
  Misused, the dispatch produces one extra deploy of reviewed code, and a deploy is
  idempotent.

The residual risk is an edit to `roadmap-refresh.yml` itself that misuses the grant. Landing
that edit takes a `/.github/` code-owner review on the default branch, which is the same
control that already stops any workflow from requesting `actions: write`. The file adds no
path that does not already exist.

### The guard test

This is the one workflow in the repository whose safety depends entirely on staying
trivial, and zizmor does not flag a widened trigger or an added step as a policy violation.
`tests/test_roadmap_refresh_workflow.py` pins its shape. It asserts that:

- the only trigger is `schedule`
- the top-level `permissions` is empty
- there is exactly one job, and its `permissions` is exactly `{actions: write}`
- no step carries `uses:`
- the job has exactly one step, whose `run` is the fixed `gh workflow run` command
- `timeout-minutes` is set and no greater than 5

PyYAML loads the key `on` as the boolean `True`. The test reads the trigger block through
that key and says why in a comment, so the next reader does not "fix" it.

## Keeping milestones synced

Milestones are the single source of truth. The page, the board, and the OWASP rows all
derive from them, so a milestone that drifts makes all three wrong at once. Nobody on the
project has time to keep milestones current by hand, which makes this a hard requirement
rather than a convenience.

### The one human act

Triage puts an accepted issue in its deliverable milestone. Everything after that is
automated. Triage may also apply `status:accepted` by hand, and the automation fills in
whichever half is missing. Two manual steps drift apart within a week at this staffing, so
the design never depends on both happening.

### The sync workflow

A new `.github/workflows/roadmap-sync.yml` reacts to events as they happen:

| Event | Action |
| --- | --- |
| `issues: milestoned` | Add `status:accepted` if the issue is open and lacks it |
| `issues: labeled` with `status:accepted`, no milestone | Write a job-summary warning naming the issue. The deliverable is a human call, so the workflow never guesses one. |
| `issues: closed` | Close the issue's milestone if it now has no open issues or pull requests |
| `issues: reopened` | Reopen the issue's milestone if it is closed |
| `pull_request_target: opened, edited` | Give the pull request the milestone of the issue it closes, when the pull request has none and exactly one milestone is found |

A closed milestone renders as Published on the page and in the OWASP rows, so closing it is
how a deliverable ships.

The workflow only adds a label, sets a milestone, closes a milestone, or reopens one. It
never removes a label and never clears a milestone. When a maintainer pulls an issue out of
a milestone on purpose, the automation leaves that decision alone. This is the same
add-only property that makes the board reconciler safe to run unattended.

### The nightly sweep

Events get missed. Changes made by `GITHUB_TOKEN` trigger no workflow, bulk edits can drop
events, and an Actions outage loses whatever fired during it. The same workflow therefore
also runs on a nightly `schedule` and applies every rule above to the whole repository.

This is the two-layer pattern the board already uses: the event path keeps things current
in seconds, and the sweep repairs anything the event path missed. A date passing fires no
event, so overdue milestones are reported only by the sweep's summary and by the roadmap
page, which marks them when it renders.

### Structure

`tools/roadmap_sync.py` follows the split `tools/apply_governance.py` uses. Pure planning
functions take an event or a repository snapshot and return a list of `Action` records.
One executor runs them through `gh`. A `--dry-run` flag prints the plan without running it.
Every rule is tested against JSON fixtures, with no network.

### Security

`issues: write` and `pull-requests: write` on the workflow's own `GITHUB_TOKEN` were
reviewed and approved during design. Labels and milestones are repository resources, so
the org project App's grant does not change.

A fork pull request's token cannot write, so the pull request rule needs
`pull_request_target`. That trigger runs with a write token in the context of the base
repository, so the job follows the pattern `pr-intake.yml` already uses:

- It checks out the base branch's tools only, never the pull request's head.
- The pull request number comes from the event payload through `env:`. The linked issues
  come from GitHub's `closingIssuesReferences` field, never from parsing the pull request
  body.
- No `${{ }}` expression appears in a `run:` line.
- Each job declares only the permissions its trigger needs.

A guard test pins the workflow's shape the way the refresh workflow's test does. It asserts
the exact trigger set, the exact permissions per job, and that no step checks out a pull
request ref.

The board card for a newly accepted issue moves on the nightly board reconcile, not
instantly, because a label added by `GITHUB_TOKEN` triggers no other workflow. Whether the
project's built-in workflows also ignore token-made changes is unverified.

## The OWASP report skill

### What it produces

The skill reads the same milestones the page reads and prints rows in the column order of
the "quarterly roadmap" worksheet, tab-separated so they paste straight into the sheet,
starting at the Deliverable ID column.

| Column | Value |
| --- | --- |
| Deliverable ID | blank, matching every existing row |
| Initiative | `Agent Control Standard` |
| Work Item Title | milestone title |
| Deliverable Type | proposed from the milestone's content, confirmed with the user before printing |
| Initiative Co-Owners | Project lead from `GOVERNANCE.md` |
| Workstream Name | the workstream the milestone's `area:` labels point to, confirmed with the user |
| Workstream Lead | that workstream's leads from the `GOVERNANCE.md` table |
| Status | rule below |
| Target Quarter | calendar quarter of `due_on`, written as `Q4 2026` |
| Target Publication Date | `due_on` as `YYYY-MM-DD` |
| Milestone & Strategic Objective | milestone description |
| Repository Link | milestone URL |

Status uses the sheet's existing vocabulary, applied as the first rule that matches:

1. Milestone closed: Published
2. No due date: Ongoing
3. Every counted issue closed, milestone still open: In Review
4. Any counted issue closed: In Progress
5. Otherwise: Planning

The skill also reads the sheet's public CSV export, finds the existing ACS rows, and says
which printed rows are new and which update an existing row. Any cell that starts with `=`,
`+`, `-`, or `@` gets a leading `'`, so a title cannot run as a formula once pasted.

### Where it lives

One `SKILL.md` serves every surface, installed two ways:

- Claude Code, in the terminal and the desktop app's Code tab, loads it from
  `~/.claude/skills/owasp-acs-roadmap/`.
- claude.ai on the web, the desktop chat, and Cowork load it from a zip uploaded under
  Settings, Capabilities, Skills. One upload covers all three.

The skill reads GitHub in this order and reports which path it used: `gh` when present, the
GitHub connector when connected, then the public REST API without a token. Whether the
claude.ai sandbox can reach `api.github.com` is unverified, so the skill is not done until
it has run once on the web.

## Milestone migration

The starting set below comes from a gap analysis of the Strategic Adoption Plan v3 against
open issues and pull requests on October 4, 2026. It is proposed, not agreed. Issue
assignments were made from titles, and the dates from November onward are estimates.

| Milestone | Issues and pull requests | Due |
| --- | --- | --- |
| Conformance claim template | #93, PR #168, #136, PR #24 | 2026-10-09 |
| Fail-open decision | #32, #37 | 2026-10-23 |
| Reference adapters on main (Claude Code, Cursor, NAT) | #132, PR #21, #134, PR #22, #131, PR #20 | 2026-10-30 |
| Spec v0.1 errata | #194 to #198, #146, #148, #149, #120, #121, #57, #58, PR #63 | 2026-11-06 |
| ACS-Core conformant reference Guardian | the Reference Guardian bugs and conformance reports, #188, PR #193, #71 to #73 | 2026-11-20 |
| Installable reference Guardian | #94, #91, #90, PR #112, #127, PR #126 | 2026-12-04 |
| AGT interoperability benchmark | #92, PR #113, #171 | 2026-12-04 |
| Governance under OWASP | open lead seats, domain transfer, OpenSSF Best Practices, marketing site retirement, #144, #145, #178 | 2026-12-04 |
| Host adapter coverage | #162, #170, #89, #114, #107 to #111 | none |
| Language ports | #86 to #88, #135, PRs #183, #78, #169, #187 | none |
| v0.2.0 | every `scope:deferred` issue, #53, #29 | 2027-03-09 |

The governance work has no issues today, so it is invisible to the page until it does.
Filing it means one issue for each open lead seat (Reference Implementation, one seat.
Documentation, two seats. Testing and Validation, two seats), one each for the domain
transfer, OpenSSF Best Practices registration, and retiring the marketing site
repository. The Strategic Adoption Plan's "ASI governance milestones" item is closed as
not applicable, since ACS already operates as an initiative under ASI.

The migration runs once, in this order:

1. Agree the set above, then create each milestone with a due date and a description
   written for an outside reader.
2. File the governance issues.
3. Put each issue in its milestone. The sync workflow applies `status:accepted` as each
   one lands, so this step also accepts any issue triage has not yet labeled.
4. Close the four Day N milestones once they are empty.

`tools/apply_governance.py` declares the Day N milestones as desired state, and it creates
or updates any milestone it declares. Left alone, it would rewrite the Day N descriptions
every time someone runs it. The implementation removes them from `desired_milestones`. The
deliverable milestones are not added there, because the roadmap should change when triage
changes, not when a pull request to the governance tool merges.

## Testing

| Test file | Covers |
| --- | --- |
| `tests/test_render_roadmap.py` | ordering, the counted-issue rule, pull request exclusion, empty-milestone skipping, the warning for unaccepted issues, completeness mismatch, and escaping, using JSON fixtures with no network |
| `tests/test_render_roadmap.py` | an issue title carrying `<script>`, an `onerror=` attribute, a Markdown link, and a `javascript:` URL, each rendered inert |
| `tests/test_roadmap_refresh_workflow.py` | the refresh workflow guard test |
| `tests/test_roadmap_sync.py` | every sync rule against event and snapshot fixtures, including the add-only property: no planned action removes a label or clears a milestone |
| `tests/test_roadmap_sync_workflow.py` | the sync workflow guard test |
| existing `tests/test_site_config.py` and `tests/conftest.py` guards | the built page fetches nothing from a third party |

The skill is tested by running it, once in Claude Code and once on claude.ai, against live
milestones and comparing the output with the sheet's existing rows.

## Out of scope

- A per-workstream view, filtering, or search on the page
- Writing to the Google Sheet. The output is pasted by hand.
- Burndown history or velocity. The page shows current state only.
- The label migration. This design depends only on `status:accepted`, which both taxonomies
  keep.

## Open questions

1. Is the proposed milestone set in Milestone migration right, including its dates?
2. Do the project's built-in board workflows react to a label that `GITHUB_TOKEN` applies?
   If they do not, a newly accepted issue reaches the Accepted column on the nightly board
   reconcile rather than at once. Verified during implementation.
