# One navigation for the landing page and the documentation

Version 3.0, 2026-10-29. Owner: Rock Lambros. Status: design, rewritten after Rounds 2 to 5 of the premortem (see `2026-10-29-site-navigation-premortem.md`). Tracking issue #361, accepted.

## Intent

A reader who clicks from the homepage into the FAQ sees a different left pane. The
homepage sidebar lists the homepage's own sections with two links into the docs. The docs
sidebar is the MkDocs Material tree with one link back home. Rock's decision on
2026-10-29: one pane, carrying both the homepage sections and the docs tree, consistent on
every page of the site.

The site is one GitHub Pages origin with two builds: `landing/index.html`, rendered by
`tools/render_landing.py` into `_site/`, and the MkDocs site built into `_site/docs/`. The
design keeps both builds and gives them one navigation source.

## Goals

- Same entries, same order, same grouping on the landing page and on every docs page,
  including the page GitHub serves for a missing URL.
- One source of truth read by both builds, and a test that fails the build when the two
  panes differ in entries, order, grouping, or which group is open on a given page.
- A red test on a documentation pull request is repairable from the file the author
  already edited, and every assertion's failure message says what to edit.
- At phone width, the same entries in the same order behind a menu button on both
  surfaces. Each surface keeps its own breakpoint and its own drawer mechanics.
- Accessible: one primary navigation landmark per page labeled "Navigation", one
  `aria-current="page"` on an `<a>` per in-nav page, keyboard operable, no state conveyed by
  color alone. The landing footer's "Project documents" nav and Material's table-of-contents
  nav are separate landmarks and stay.
- The landing page keeps its design, its no-third-party rule, its vendored font, and its
  no-inline-handler rule, and gains a content security policy. Every guard in
  `tests/test_landing_page.py` keeps passing.
- The landing pane fits its column: at most 20 rows with Home open, and the theme toggle
  reachable without scrolling the column at 1366x768.

## Non-goals

- Moving the landing page into MkDocs, or changing any URL.
- Redesigning the landing page body, the hero, or the diagram.
- Changing the docs tree's information architecture (no Overview rows removed, no pages
  moved). The one change is the order of top-level entries.
- Search on the landing page. Scroll-spy on the landing page.
- Making the two surfaces share a breakpoint or a drawer implementation.
- A content security policy on the docs. Material needs inline scripts.

## Anti-goals

- Two hand-maintained copies of the navigation, in any file, including the override.
- A third-party resource, a CDN script, or an inline event handler on the landing page.
- A navigation that renders only with JavaScript.
- A theme override that fails silently when mkdocs-material is bumped, or that fails
  loudly with no written way to repair it, or whose repair only one person has performed.
- A comparison test that is loosened on day one because the design did not say what to
  compare, or that goes red on a theme bump that changed no behavior.
- A control named for its intent and never checked against the platform. Version 2.0
  named a Dependabot reviewer. GitHub retired that key on 2025-05-20.

## Decisions, with their inputs

- The pane carries both: the homepage sections and the docs tree. Rock, 2026-10-29.
- FAQ sits at the top level of the pane on both surfaces. Rock, 2026-10-29, choice A on the
  mockup. Rock's July comment on PR #20 gave two reasons a readable FAQ above Conformance
  Profiles was a problem: it restated normative content, and it is the page a procurement
  reader quotes. The non-normative banner at the top of `docs/topics/faq.md` answers the
  first, and a guard test holds the page to it (the banner line present, no capitalized
  RFC 2119 keyword). The second is accepted: the relaunch sends readers to the FAQ first,
  and this placement says so. The three passages that still restate ACS-Core (lines 91,
  170, and 213 today) get a link-not-copy pass as a follow-up issue for the Documentation
  lead, opened with the pull request. The one capitalized `SHOULD` on line 170 is fixed in
  this change so the guard can land.
- "Read the specification" keeps landing on the docs front page, `/docs/`. Rock,
  2026-10-29, choice C on the mockup, which showed that page's pane row labeled
  "Trustworthy Agents", the page's own title. The call to action keeps its wording and its
  target. This is a decision, not a residual: the highest-intent click lands on a page whose
  pane row is not called Specification, and the owner accepted that on the mockup. Reversing
  it is one line in `landing/index.html`.
- Roadmap sits under External resources because it leaves the site. Shown on the mockup
  Rock approved on 2026-10-29. It was placed at row 3 of the landing list on 2026-10-04.
- `navigation.indexes` is not enabled. The premortem showed it buys one grammar on paper and
  delivers two (Identity's Overview is not an index file), adds a second `aria-current`
  site, a stylesheet dependency, and a docs IA change with no owner. The docs tree keeps
  its Overview rows. My call, 2026-10-29.
- The landing keeps its 1024px breakpoint. A reader never has both surfaces open at two
  widths. Only a test does. My call, 2026-10-29.
- The ruleset, not a sentence in this document, is the control on who merges. The
  `protect-integration` ruleset already requires one code-owner approval and lets repository
  admins bypass it, and the merge record shows the bypass is the practice. The owner decides
  between removing `RepositoryRole 5` from the ruleset's bypass actors and keeping it. A
  permission change is its own decision and is not bundled into this work. This design
  assumes the bypass stays and makes the non-author approver's review the closure criterion
  of issue #361: the pull request body records the approver and the review's commit.
- mkdocs-material reaches end of life on 2027-05-05 (9.8.0 release notes, 2026-10-24). The
  design binds to the 9.x partials, keeps the override Jinja inside the subset MiniJinja
  shares with Jinja2 (filters only, no Python method calls), and confirms before merge that
  both overrides render under Zensical's classic variant in a scratch build. My call,
  2026-10-29.
- Pages outside the docs nav are declared by directory prefix in `mkdocs.yml`, not by a
  list in a test file, so a documentation pull request repairs itself in the file it
  already edits. My call, 2026-10-29.
- Issue #361 moves to a Documentation milestone (description `Workstream: Documentation`,
  matching the GOVERNANCE workstream row), created for this work and issue #267, because
  the public roadmap page and the health check read the milestone's workstream, and today
  they report the issue as Spec work. The OWASP roadmap rows carry the project name, not
  the workstream. Whether the public site belongs on CONTRIBUTING's in-focus list, or the issue drops
  `scope:in-focus`, is the owner's call and is listed for him.
- The claim-rule question belongs to the intake design.

## The pane

Both surfaces show this, in this order. A group is a toggle. It is open only when the
reader is inside it, with one exception: Home is open on the landing page.

1. **Home** → `./` on the landing (the landing root, because the landing
   test forbids `href="/"`), and the landing root on the docs. A group whose label is also a link. Children,
   in page order: The problem (`#problem`), The solution (`#solution`), How it works
   (`#architecture`), Why now (`#why-now`), Built with the community (`#built-with`), Spec
   status (`#status`), Workstreams (`#workstreams`), Contribute (`#contribute`). Built with
   the community has a section and no link today. It gets one.
2. **Trustworthy Agents** → `/docs/`.
3. **ACS** → `/docs/acs/`.
4. **FAQ** → `/docs/topics/faq/`.
5. **Topics**, a group: Core concepts, ACS in Action.
6. **Concepts**, a group: Overview, Agents, Identity (a group: Overview, Identity for
   Agents, Standards), Session Lifecycle, Intent, Capability, Skill, Provenance, Trust Basis.
7. **Specification**, a group: Conformance Profiles, Conformance Claim Template, Instrument
   (a group: Overview, Supported Hooks, ACS specification, Instrument MCP, Instrument A2A),
   Trace (a group: Overview, Supported Events, Trace with OpenTelemetry, Trace with OCSF,
   OCSF Implementation Examples), Inspect (a group: Overview, AgBOM with CycloneDX, AgBOM
   with SPDX, AgBOM with SWID).
8. **About** → `/docs/about/`.
9. **External resources**, a section row that is not a link and never collapses, with its
   three links always visible beneath it: GitHub (the repository), Roadmap (the milestones
   page), Slack (`owasp.slack.com`).

Row counts: 12 rows with every group closed (the same as today's 12 links). 20 on the
landing page with Home open. 53 fully expanded, as 12 closed rows plus Home's 8 plus
Topics 2, Concepts 9, Identity 3, Specification 5, Instrument 5, Trace 5, Inspect 4. The
20 and the 12 are asserted as ceilings on the rendered landing pane. The message on that
assertion says to re-run the fold check and raise the ceiling in the same pull request.

The landing page keeps exactly one theme toggle, at the bottom of the pane, at every width.
On a phone it is reached by opening the menu. The docs keep Material's toggle in the header.
The docs nav's "ACS home" entry goes away. Home replaces it.

Seven pages under `docs/spec/instrument/a2a/hooks/` are outside the docs nav and reachable
from the A2A page. They are not added to the pane. `mkdocs.yml` declares that directory
under `extra.acs_nav.out_of_nav_prefixes`. On those pages the pane is the same and nothing
is active.

## Source of truth

`mkdocs.yml`. The `nav:` key stays the docs tree, reordered as above, with every entry a
`title: path` or `title: [children]` mapping. One namespaced key, `extra.acs_nav`, carries
what the docs tree does not know, with a comment above it naming both readers,
`tools/render_landing.py` and `overrides/partials/nav.html`:

```yaml
extra:
  acs_nav:
    landing_sections:
      - { title: The problem, anchor: problem }
      - ...
    external_resources:
      - { title: GitHub, url: https://github.com/GenAI-Security-Project/agent-control-standard }
      - { title: Roadmap, url: https://github.com/GenAI-Security-Project/agent-control-standard/milestones }
      - { title: Slack, url: https://owasp.slack.com }
    out_of_nav_prefixes:
      - spec/instrument/a2a/hooks/
```

The section titles in `landing_sections` are the pane labels, written here on purpose.
They are not the sections' `<h2>` text ("Agents are shipping fast. Controls are not" is the
heading behind "The problem"). The anchors are checked against the landing page's
`section[id]` elements, in document order, by test.

Three constraints hold on the file by test, because two renderers read it and one of them
(Material's) does not escape: every `nav` title and every `acs_nav` title matches
`[^<>&]+`. Every anchor matches `^[A-Za-z][A-Za-z0-9_-]*$`. Every URL starts with
`https://`. The file's YAML tags are allowlisted: `!ENV` on `site_url` only, the three
existing `!!python/name:` values, nothing else, and `!relative` absent. The loader both
consumers use executes tags, and the allowlist records that in a test.

## Renderers

### The landing page

`tools/render_landing.py` reads `mkdocs.yml` through `mkdocs.utils.yaml.yaml_load` with no
config object. It treats `use_directory_urls` as true when absent, as mkdocs does, and
derives each page URL by mkdocs's rule (`foo.md` to `foo/`, `README.md` and `index.md` to
their directory, nested directories kept, `urllib.parse.quote` applied), relative to the
landing root as `docs/<url>`. A nav value with a scheme must be `https://` and renders as a
plain external row with that URL. A value without a scheme that does not end in `.md`, a
bare-string entry, or a group with no title raises `RenderError` naming the entry, so a
drift failure on a routine docs PR reads as a one-line instruction.

Every value read from `mkdocs.yml` is untrusted text, the rule `render_landing.py` already
states for GOVERNANCE.md: titles pass through `html.escape(value, quote=True)`, anchors
must match the anchor pattern, URLs must start with `https://` after the renderer's own
`_NOISE` stripping, and a value that fails raises `RenderError` naming the entry. The
renderer fails closed. It never drops a link.

The pane renders into a new placeholder, `<!--ACS:NAV-->`. A second new placeholder,
`<!--ACS:CSP-->`, renders a `<meta http-equiv="Content-Security-Policy">` whose value is
`default-src 'none'; script-src 'sha256-<inline script>'; style-src 'self'
'sha256-<starburst style>'; img-src 'self'; font-src 'self'; base-uri 'none';
form-action 'none'`, with both hashes computed from the rendered bodies. The landing page
has one inline script and one inline style (the starburst's), no `style` attributes, and
no `data:` URIs today, and a test holds all three so the hashes stay complete. A meta
policy ignores `frame-ancestors` and reporting, so this is injection containment and
nothing more. Both placeholders join `REQUIRED_PLACEHOLDERS`.

The rendered markup is one `<nav aria-label="Navigation">` containing a nested list. Groups
are `li > details > summary` so they collapse and expand without JavaScript. The Home
group's summary holds the Home link, and the group is `open`. Every other group is closed.
The Home link carries `aria-current="page"`. External resources is
`<li class="nav-section">` whose first child is a heading and whose second child is the
list of three links. It is not a `details`. No pane link carries `target` or `rel`.

The sidebar's hand-written markup in `landing/index.html` is replaced by the placeholder.
The wordmark stays above it and the theme toggle below it. The `<aside>` becomes a plain
container, and a skip link to `main` goes first in the focus order. `.sidebar` keeps
`height: 100vh` and `overflow-y: auto`, asserted by test, so the toggle stays reachable
when the column is taller than the viewport.

### The docs

`overrides/partials/nav.html` overrides Material's primary navigation partial: it keeps the
drawer title and the source block, then emits the Home group by looping
`config.extra.acs_nav.landing_sections` in the theme's own `md-nav__container` markup (the
`input` id `__nav_home`, the `label[for]` with `id="__nav_home_label"` and `tabindex="0"`,
the nested `nav[aria-labelledby="__nav_home_label"]`, so Material's sidebar script finds
every element it binds), then the stock loop over `nav.items`, then External resources by
looping `config.extra.acs_nav.external_resources` in Material's section markup (`input`
id `__nav_ext`, `label[for]` with `id="__nav_ext_label"` and `tabindex=""`, the nested
`nav[aria-labelledby]`). Every emitted value carries `| e`. The theme environment has
autoescape off. A test asserts the override source contains no literal `#problem` and no
`owasp.slack.com`, so the lists cannot be copied into it.

The landing root is `{{ (base_url ~ '/..') | replace('//..', '/..') }}`. On pages
`base_url` is `.` or `../..` with no trailing slash, so the result is `./..` or `../../..`.
On `404.html` it is the absolute docs path with a trailing slash, and the `replace` removes
the doubled separator. `replace` is a filter both Jinja2 and MiniJinja ship. A Python
method call such as `rstrip` is not. A header comment in the override records that
reasoning and the re-derivation command below.

`overrides/partials/nav-item.html` is overridden to add `aria-current="page"` on the active
page's `<a>` (the leaf branch), never on a `<label>`. With `navigation.indexes` off that is
the only site.

Each override is kept as three files: `<name>.html.upstream`, a byte copy of the installed
partial, then `<name>.html`, the override, and `<name>.html.diff`, the unified diff from
upstream to override. Two tests hold them. The first asserts the installed partial equals the upstream
copy, and on failure prints the delta from the committed upstream to the installed file
with the instruction to read that delta, then run `uv run python
tools/rederive_overrides.py`. The second asserts
`difflib.unified_diff(upstream, override, fromfile, tofile, n=3)` equals the stored diff,
pure Python and deterministic. `tools/rederive_overrides.py` prints the upstream delta,
copies the installed partials to `.upstream`, applies each stored diff to a temporary copy
with `git apply --check` and then `git apply` (zero fuzz, so a context change refuses, which
is the signal to edit by hand), writes the override, and re-records the diff. The bump
never lands on Dependabot's branch, which is force-pushed on every upstream release: the
owner opens a hand pull request that bumps `uv.lock` and the overrides together and closes
the Dependabot one. `overrides/README.md` says all of this, names the Documentation lead
as the owner of the bump, and records who rehearsed the re-derivation and when. The
non-author approver rehearses it during review against a scratch edit of an upstream copy,
and the pull request records the commands and the result.

`.github/dependabot.yml` gains no reviewer (the key is retired) and loses the `python`
label its docs-toolchain group names, which does not exist on the repository and makes
Dependabot post an error on every bump. A test asserts the file has no `reviewers` key.

`theme.features` is unchanged.

### Active state

Docs: Material marks the active page with `md-nav__link--active` and checks its ancestors'
toggles. The override adds `aria-current`. `docs/stylesheets/extra.css` sets the active link
to weight 600. Landing: the Home link carries `aria-current` and the same weight. Neither
surface marks state by color alone.

### The page for a missing URL

GitHub Pages serves only a root-level `404.html`. The one MkDocs builds sits at
`/docs/404.html` and is never served as a 404, so today a reader on a missing URL gets
GitHub's default page with no navigation. The deploy's build step copies
`_site/docs/404.html` to `_site/404.html` after the docs build. With `site_url` set,
MkDocs renders the 404 with an absolute base, so its assets and its pane resolve from the
root. A workflow test pins that step after the docs build.

### Phones

The landing page keeps its layout breakpoint at 1024px. Below it the sidebar leaves the
grid and a header strip appears with the wordmark and a real `<button>` with
`aria-expanded` and `aria-controls` that opens the pane as an off-canvas panel. The pane
keeps its contents, theme toggle included. Escape closes the panel and returns focus to the
button. The script lives in the landing's existing inline `<script>` block next to the theme
toggle, attaches listeners (no `onclick` attributes), and loads no resource. Without
JavaScript the pane renders as a static block below the header strip.

Material's drawer below `76.234375em` is a drill-in panel that opens inside the active
group. The landing's is an expand-collapse tree. Both show the same entries in the same
order. That is the phone goal, and nothing more is claimed.

## Tests

### The walkers

`tools/site_nav.py` holds the two walkers, shared by the test and the live verifier. A row
is `(depth, label, url, is_group, is_section)`. `url` is the resolved href or `None`.

Docs walk. The pane is the element with `aria-label="Navigation"`. Rows are the
`li.md-nav__item` elements under each `ul.md-nav__list`, with every `nav.md-nav--secondary`
subtree pruned. Per row, the candidates are the `li`'s direct children plus the children
of a direct-child `div.md-nav__container`, skipping `label[for="__toc"]`. The pick is the
first `a.md-nav__link`, else the first `label.md-nav__link[for]`. Zero candidates or a row
with both raise, naming the row. `is_group` is the class `md-nav__item--nested`.
`is_section` is the class `md-nav__item--section`. Depth is the count of enclosing `ul`
inside the pane. Label is the whitespace-collapsed concatenation of the picked element's
text nodes.

Landing walk. The pane is the element with `aria-label="Navigation"`. Rows are each `li`
of each `ul`. The pick is the summary's `a` if the row has a `details`, else the summary
itself (its text is the label), else the row's direct `a`, else the row's heading.
`is_group` is a direct `details` child. `is_section` is the class `nav-section`. Depth and
label as on the docs.

Resolution bases: docs pages resolve against `rel="canonical"`. `404.html` resolves against
`DOCS_BASE + "404.html"`, which makes the fixture's `GITHUB_PAGES_URL` load-bearing for
that page and is said in a comment. The landing resolves against the landing root
(`DOCS_BASE` with the trailing `docs/` removed).

### The samples

Chosen by state from the pane at test time, never by path, so a renamed page cannot break
a fixture: the landing page, the docs front page, the first depth-1 leaf, the first leaf
under a top-level group, the first leaf under a nested group, the root `404.html`, and the
first built page under each out-of-nav prefix. Those are the six static states of the
pane above the breakpoint. No in-nav page lacks a table of contents today, so the walk's
link-only branch runs on no sample, and the test says so.

### The assertions

Each assertion's failure message names the file to edit. `tests/test_site_nav.py`:

1. The landing sequence equals every sampled docs sequence.
2. Per sampled page above the breakpoint, the set of open groups equals the ancestors of
   the `aria-current` row (plus Home on the landing). Docs read `md-nav__toggle[checked]`,
   assert no `md-toggle--indeterminate` anywhere in the pane, and assert each nested `nav`'s
   `aria-expanded` equals its group's membership in the open set. On the docs this
   assertion's job is the hand-emitted groups and theme drift, since Material derives
   `checked` from the same ancestry. On `404.html` and out-of-nav pages the open set is
   empty.
3. Exactly one `aria-current="page"` per in-nav page, on an `<a>`, which is the element the
   walk picked for its row, resolving to the page's canonical URL (the landing root on the
   landing). Zero on `404.html` and out-of-nav pages.
4. Every docs URL in the pane has an `index.html` in the build. Every built `index.html`
   (`404.html` excluded) is in the pane or under an out-of-nav prefix, and each prefix
   matches at least one built page. The message names the page, says to add a titled `nav`
   entry in `mkdocs.yml` or, for a page reachable only from its parent, to extend
   `out_of_nav_prefixes` in `mkdocs.yml` with a comment, and says the change targets
   `integration`.
5. The Home children equal the landing's `section[id]` list in document order. External
   resources hosts are a subset of `{github.com, owasp.slack.com}`, the GitHub URL starts
   with the literal repository URL, every pane URL is `https`, no pane link carries `target`
   or `rel`, and the hero's call-to-action hosts are a subset of the pane's.
6. Every `label.md-nav__link[for]` in the built pane has an `input` with that id and an
   element with `aria-labelledby` equal to the label's id. All ids are unique. `__nav_home`
   and `__nav_ext` collide with nothing Material emits.
7. Both overrides: upstream equality and diff equality, as above.
8. The override source contains no literal `#problem` and no `owasp.slack.com`.
9. The theme stylesheet, split by a brace walker into `(media header, selector,
   declaration set)` after `conftest._strip_css_comments`: inside the
   `min-width:76.25em` block, the `.md-nav__item--section>.md-nav` rule's declarations
   include `display:block` and `visibility:visible`. The
   `.md-nav__item--section>.md-nav__link:not(.md-nav__container)` rule includes
   `pointer-events:none`. The section rule's index is greater than the index of the
   `.md-nav__toggle~.md-nav` collapse rule in that block (equal specificity, so order
   decides). The two top-level `.md-nav__container` rules exist. Never a substring: the
   9.8.0 wheel reorders the declarations of the first rule with no behavior change.
10. `mkdocs.yml`: every `nav` entry is a titled mapping, and the title, anchor, and URL
    patterns and the tag allowlist hold.
11. The rendered landing pane has at most 20 rows with Home open and 12 with every group
    closed, and `.sidebar` keeps `height: 100vh` and `overflow-y: auto`.
12. On every built docs page and the landing: no `on*` attribute, and no `href` or `src`
    whose value, after the landing test's `_NOISE` stripping, starts with `javascript:`,
    `data:`, or `vbscript:`.
13. `docs/topics/faq.md` carries the non-normative line and no capitalized RFC 2119
    keyword.

`tests/test_landing_page.py` gains: the policy's two hashes recomputed from the page and
no other script or style element or `style` attribute present. The script and style
bodies of the rendered page equal those of the template (`_element_bodies`). The scheme
check strips `_NOISE` and covers `data:` and `vbscript:`.

`tests/test_render_landing.py` gains nav escaping cases mirroring the governance ones
(attribute breakout in a URL, `javascript:` and `data:` URLs, raw HTML in a title, a bad
anchor), and a case that `render()` succeeds with no `_site/docs` present.

`tests/test_deploy_pages_workflow.py` gains: the docs build step precedes the render step,
the 404 copy step follows the docs build, the render step has no `env`, and no step after
"Install uv" references `secrets.` or `github.token`. A test asserts `dependabot.yml` has
no `reviewers` key. `tests/test_site_config.py` scans built `*.js` for `https?://` hosts
against the reviewed allowlist, so a bump that adds a network destination fails for a
stated reason.

Existing tests change where they depend on the old markup: `test_landing_page.py`'s
split-based test is restated on the tuple. `test_render_landing.py` builds `FULL_TEMPLATE`
from `REQUIRED_PLACEHOLDERS`. `test_docs_theme.py`'s theme-styles test gains
`.md-nav__container`, `.md-nav__toggle`, `.md-nav__item--section`. The guards for no
third-party resources, no inline handlers, the vendored font, and contrast are unchanged.

### Fixtures

The docs build helper moves into `tests/_docs_build.py`. `tests/conftest.py` exposes
`built_docs` from it as a session-scoped fixture in two lines and gains, in its docstring,
the rule the project keeps privately today: never accept a change to this file on a green
suite, inject a third-party host and watch the suite fail. `test_docs_theme.py` uses the
shared fixture. `test_site_config.py` keeps its own build with its own `GITHUB_PAGES_URL`.
Two builds per run, as today. The conftest change is its own commit inside the pull
request, and the pull request body records the output of
`uv run pytest tests/test_third_party_guard.py`.

### The live check

`tools/verify_site_nav.py` fetches `/`, `/docs/`, and `/docs/does-not-exist-<run id>/`
from the published site, walks each with `tools/site_nav.py`, and asserts the three
sequences are equal and the third response carries the pane (the site's 404, not
GitHub's). The deploy's verify step runs it after the schema check, and
`monitor-pages.yml` runs it every six hours. Three GETs.

### Before merge, recorded in the pull request

- A screenshot of the sidebar column at 1366x768 showing the theme toggle without
  scrolling the column.
- A browser console on the rendered landing page with no policy violation.
- The suite green on a scratch relock to mkdocs-material 9.8.0, the bump that arrives
  first.
- Both overrides rendering under Zensical's classic variant in a scratch build.
- The approver's re-derivation rehearsal: the commands and the result.
- The third-party guard test's output.

## Supporting changes

- CLAUDE.md, Hosting: `mkdocs.yml` is a landing build input whose values are escaped as
  untrusted text, next to the sentence that says the same of GOVERNANCE.md.
- `mkdocs.yml`: a comment above `extra.acs_nav` naming both readers. The "ACS home" entry
  and its comment are removed, and the relative-link reasoning moves to the override's
  header comment.
- `overrides/README.md`: what each override changes, the re-derivation command, the rule
  against repairing on Dependabot's branch, the owner, the rehearsal record, the Zensical
  check.
- `.github/dependabot.yml`: the `python` label removed. No reviewer.
- `.github/CODEOWNERS`, in this change: `@Lrd0036` on `/landing/`, `/mkdocs.yml`,
  `/overrides/`, and `/docs/stylesheets/`, and the header comment that still calls his
  entries inert corrected, since his write access is live. The pull request already
  touches `/.github/`, so the approval set does not grow.
- GOVERNANCE.md: one sentence that the Documentation lead owns the docs toolchain bump and
  the override re-derivation.
- CONTRIBUTING.md, Development Process: a new page needs a titled `nav` entry in
  `mkdocs.yml`, so a page-adding pull request targets `integration`. A page outside `nav`
  and outside the declared prefixes fails the build.
- `docs/topics/faq.md`: the one capitalized `SHOULD` on line 170 lowercased. A follow-up
  issue for the link-not-copy pass on the three restating passages, opened with the pull
  request and offered to the Documentation lead.
- `.github/workflows/deploy-pages.yml`: the 404 copy step. The verify step calls
  `verify_site_nav.py`. `.github/workflows/monitor-pages.yml`: the same call.
- A Documentation milestone. Issues #361 and #267 moved into it.

## Constraints

- mkdocs-material 9.7.7 as pinned by `uv.lock`. The upstream copies come from that
  version. End of life 2027-05-05.
- The override Jinja uses filters only, never a Python method call, so it renders under
  MiniJinja.
- `landing/`, `mkdocs.yml`, `overrides/`, and `docs/stylesheets/` are privilege surfaces in
  CODEOWNERS. The change goes to `integration`, and the approver's review is recorded on
  the pull request. It publishes on promotion.
- No URL changes. No change to `publish_schemas.py` or the schema paths.
- STYLE.md for prose. The landing page has a no-em-dash test, which is one reason the
  renderer never reads page headings.
- The deploy job runs `render_landing.py` after `mkdocs build`, in the same checkout, so the
  renderer may read `mkdocs.yml` and may not read the built docs. A test pins the order and
  another runs the renderer with no built docs present.
- The nav assertions run in the suite that gates every publication, schemas included, so
  every message names its repair.
- The implementing pull request closes issue #361.

## Rollback

Two paths, fastest first.

1. Re-run the deploy job of the last good workflow run from the Actions tab. Minutes.
   Artifact retention is 30 days. It restores everything as of that run and carries no fix
   merged since.
2. Revert the squash commit on `integration`, run the suite on the reverted tree, and
   promote. The revert conflicts on `mkdocs.yml` if any docs pull request changed `nav`
   since, and on `tests/conftest.py` if anything touched it since, so expect a hand merge.
   The change adds no data outside the repository.

## Left to the builder

- The exact HTML and CSS of the drawer and the landing group markup.
- The internals of the brace walker and the two walkers, within the rules above.
- Fixture choices beyond the stated scope and the stated build count.

## Risks

- The partial overrides track generated upstream files. The upstream copy makes a bump
  loud and shows the delta. The re-derivation tool makes it one command. The rehearsal
  gives it a second pair of hands. A compromised theme release is held by the lock hash,
  the seven-day cooldown, and the instruction to read the delta, and by nothing else.
- The hand-emitted Home and External resources groups depend on the theme's class names
  and script contract. The theme-styles test, the id-contract assertion, and the stylesheet
  rule assertions cover them, and the 9.8.0 scratch relock proves the assertions survive a
  bump that changes nothing.
- The landing sidebar grows from 12 rows to 20 by default. The row ceiling holds the pane's
  cost. The sidebar guard keeps the toggle reachable. The skip link holds the keyboard cost.
- The policy is a meta tag with no reporting. A violation is visible only in a browser
  console, which is why the console check is recorded before merge.
- `render_landing.py` gains an import of mkdocs. It is already installed wherever the
  renderer runs.
- The theme's end of life is six months out. The Zensical scratch build reduces the
  migration's cost. It does not schedule the migration.
- The approver record is a practice while the admin bypass stands. The owner holds the
  decision that would make it a rule.

## Amendments from the plan premortem and implementation

Each line names what changed from the text above and why. Where a line and the text above
disagree, the line holds.

- The docs walk is a precedence: inside a row and its direct `div.md-nav__container`, one
  `a.md-nav__link` wins and labels are ignored, a row with no link takes its one toggle
  label, and any other count raises, because the Home row the override emits holds both
  its link and its toggle and the earlier "a row with both raises" rule failed on it.
- `is_group` on the docs is `md-nav__item--nested` without `md-nav__item--section`, and the
  section row's class list is fixed verbatim as `md-nav__item md-nav__item--section
  md-nav__item--nested`, because Material marks a section nested too and the two surfaces
  would otherwise disagree on the External resources row.
- The hand-emitted Home and External resources rows carry `aria-expanded` on their nested
  `nav` and a `md-nav__title` label, because Material's own groups carry both, the expanded
  state check reads `aria-expanded`, and the phone drawer shows the title label.
- The upstream copies and diffs live in the dot directory `overrides/.upstream/partials/`,
  not beside the overrides, because MkDocs skips dot directories and the bookkeeping files
  must stay out of the published tree.
- The re-derivation tool adopts an upstream delta only when run again with
  `--accept-delta` and the sha256 of the delta it printed, and `--record` is the first-use
  mode, because one unattended run must never adopt a theme change nobody read.
- The host rule covers every pane row with a host, not three: each must be `https`, have
  `netloc` equal to `hostname`, contain no backslash, and name a reviewed host unless it is
  a site page, because the earlier test checked three rows of 53 and a backslash
  parsed differently in Python than in a browser.
- The live check is its own deploy step and its own `monitor-pages.yml` job, never sharing
  a result with the schema check, and it retries a row mismatch for thirteen minutes,
  because the Pages CDN caches for ten minutes and no request header clears it.
- Rollback starts by setting `ROADMAP_REFRESH_ENABLED` to `false`, because the nightly
  refresh redeploys main and would undo a re-run of an older deploy.
- The milestone sentence in Decisions is corrected: the public roadmap page and the health
  check read the milestone's workstream, and the OWASP roadmap rows carry the project name.
- The four CODEOWNERS lines that add the Documentation lead widen who can approve those
  paths, so they are a permission change for the owner to confirm, and `/pyproject.toml`
  and `/uv.lock` stay unchanged pending his call.
- `ancestor_labels` treats a section as an ancestor, and a section is always open, because
  skipping it handed a section's children to the group that closed before it.
- The shared title, anchor, and URL patterns are anchored with `\A` and `\Z`, because `^`
  and `$` let a trailing newline through.
- `--record` never re-baselines an upstream copy that differs from the installed partial,
  because recording over a changed copy would adopt an unread delta without the gate.
- The 404 sample resolves at a deep missing address, and every pane link on it is absolute
  or path-absolute, because GitHub Pages serves that page at whatever address missed and a
  relative link breaks below the docs root.
- In the live check a 200 page without the pane landmark gets the full retry window, and
  only the nonce'd 404 fails fast, because a 200 without the pane can be the edge's stale
  copy while the nonce means no cache holds the 404.
- The built-script host allowlist is keyed by bundle name with the content hash stripped,
  because the hash changes on every theme release and a key on it would fail every bump.
- Only `REPAIR["ceiling"]` may name `tests/test_site_nav.py` as the file to edit, because
  the ceiling lives in that module, so its repair edits it.
