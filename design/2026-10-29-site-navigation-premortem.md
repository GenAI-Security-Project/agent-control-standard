# Adversarial premortem: one navigation for the landing page and the docs

Artifact: `design/2026-10-29-site-navigation-design.md` v1.1 (Round 1), then v2.0 (Rounds 2 to 5). Date: 2026-10-29. Adversarial premortem. Each perspective read the artifacts, the installed mkdocs-material 9.7.7 partials and stylesheet, and a scratch build of the docs independently.

## Round 1. Problem framing and inputs (against v1.1)

Perspectives spawned: Data Scientist (lead), ML Engineer, Governance / Risk. Skipped: Red Teamer and Security Architect (no adversarial or trust-boundary surface at the framing layer, and they attack Round 3), MLOps / SRE (leads Round 4).

Premortem narrative. Six months out, the drift test passes on every build and the two panes differ anyway: the comparison was loosened on day one because the docs pane carried the page's table of contents and a duplicate active row, and the loosened version compares sets. Four index pages render with no `aria-current`. The 404 page's Home link goes to the docs front page. A Dependabot bump of mkdocs-material has been red for six weeks because nobody wrote down how to re-derive the two override copies, and the maintainer who could is the only person who has ever touched `landing/`, `overrides/` or the renderer. A contributor's docs PR that added an untitled page turned the build red with a message about the landing page. The homepage shows a hamburger on an iPad in landscape.

Findings, surviving at Plausible or above.

1. The pane the test walks is not the pane the design describes. Material renders the table of contents inside the primary nav's active item (for the phone drawer) and emits the active page twice (a `label` and an `a`) and every group title twice (link plus drawer title).
   - Impact: High. The comparison fails on every docs page, and the cheap repairs (compare sets, drop fragment hrefs) hide real drift and silently empty the Home group.
   - Confidence: Very likely (built HTML, two perspectives independently).
   - Evidence anchor: installed `nav-item.html` lines 142-162 (`label for="__toc"`, `a`, then `include "partials/toc.html"` in one `li`). Design v1.1 "skipping the secondary (table of contents) sidebar".
   - Failure mode: either the build never goes green or the test stops pinning order and children.
   - Blind spot: "secondary sidebar" and "table of contents" were treated as one thing. Material renders the TOC twice.
   - Opportunity cost: the only enforcement of the design's central promise.

2. `aria-current` has two insertion sites in `nav-item.html` once `navigation.indexes` is on (the index-group container link at line 114 and the leaf link at line 156), plus a `label` twin that carries the same class. The sample ("one Concepts page") can miss the index branch entirely.
   - Impact: High for the accessibility goal. The four index pages would ship with zero or two `aria-current`.
   - Confidence: Likely (scratch build with indexes on, read by two perspectives).
   - Evidence anchor: design v1.1 "overridden only to add `aria-current="page"` to the active link" (singular). Built `concepts/index.html` with indexes on.
   - Failure mode: the "smallest edit" instruction invites editing one site. CI stays green.
   - Blind spot: one template site assumed. The feature adds a second.

3. The digest test measures upstream, not the override. A copy that drifts from "upstream plus the smallest edit" passes. A theme bump that changes the partial fails on a Dependabot PR the project merges 1 time in 18, with no re-derivation procedure written down. 2 of 17 consecutive Material bumps changed `nav.html` or `nav-item.html`. The repository's own bump from 9.6.14 to 9.7.7 crossed both.
   - Impact: High. Either the docs toolchain freezes at 9.7.7 or the test gets deleted to land a bump (the conftest docstring's own prediction).
   - Confidence: Likely (PyPI release history and the Dependabot merge record, measured).
   - Evidence anchor: design v1.1 "a test compares the installed partials' digests with the ones recorded next to the overrides". `overrides/partials/source.html` follows the opposite rule.
   - Failure mode: the stated risk control does not control the stated risk.
   - Blind spot: "loud" was equated with "noticed".

4. The External resources section depends on four stylesheet rules scoped to `min-width:76.25em` that a class-substring test cannot see, and the digest test does not cover the stylesheet.
   - Impact: Medium. The one group that must never collapse can collapse on a theme bump with no red test.
   - Confidence: Plausible.
   - Evidence anchor: `main.*.min.css` `.md-nav__item--section>.md-nav{display:block;...}` under the media block. `test_docs_theme.py` lines 109-123 test `klass in css`.
   - Blind spot: class existence treated as behavior.

5. `base_url ~ "/.."` is right on pages and wrong on `404.html`, where `base_url` is the absolute path with a trailing slash, so the Home link resolves to the docs front page (or to `https://..` under a local build). `404.html` is not sampled.
   - Impact: Medium. The one page that exists to recover lost readers (the population the domain cutover creates) has a wrong Home link.
   - Confidence: Likely (probed with `urljoin`).
   - Evidence anchor: `mkdocs/commands/build.py` line 74. Design v1.1 "The landing root is `base_url` followed by `/..`".

6. `mkdocs.utils.yaml.yaml_load` without a config object is not mkdocs's loader: it lacks the `!relative` constructor, which is the documented idiom for `pymdownx.snippets` (already enabled). A one-line config edit that `mkdocs build --strict` accepts would kill the landing render step. `use_directory_urls` is absent from `mkdocs.yml`, so a renderer keyed on `cfg.get(...)` emits `.html` URLs.
   - Impact: Medium. A blocked deploy at an unpredictable date, with an error naming neither the landing nor the nav.
   - Confidence: Plausible.
   - Evidence anchor: `mkdocs/utils/yaml.py` lines 122-123. Probe output `could not determine a constructor for the tag '!relative'`.

7. A nav entry without a title is valid mkdocs. Material derives the title from the page (front matter, first H1, file name) and the renderer, which reads only the YAML, cannot. The H1s already differ from the nav titles (`# Inspect — AgBOM` versus "Inspect", `# Frequently Asked Questions` versus "FAQ"), and teaching the renderer to read H1s would put an em dash on the landing page.
   - Impact: Medium. A confusing red build on the first page-adding PR after merge.
   - Confidence: Plausible (every entry is titled today, while bare entries are the idiomatic form).
   - Evidence anchor: `mkdocs/structure/pages.py` title resolution order. Design v1.1 "reads `mkdocs.yml` through `mkdocs.utils.yaml.yaml_load`".

8. "Consistent" is defined twice and the tuple implements the weaker one: open state (Home open on the landing, every other group closed), the always-shown property of External resources, and the "same breakpoint" claim are unmeasured. Topics, Specification and External resources are indistinguishable in `(depth, label, url, is_group)`.
   - Impact: Medium. The two behaviors the owner decided on can regress with a green build.
   - Confidence: Very likely (textual, since the tuple has no slot).
   - Evidence anchor: design v1.1 "Open and closed state is excluded from the comparison because it depends on where the reader is" versus "the same open groups behind a menu button".
   - Blind spot: "depends on where the reader is" was read as "not testable". It is computable from the `aria-current` ancestors.

9. "Same breakpoint" serves the comparison, not a reader. Moving the landing from 1024px to Material's 1220px puts an 11-inch iPad in landscape and a 1366-wide laptop at 125 percent zoom into the drawer on the homepage, for a property no reader perceives (nobody has both surfaces open at two widths). Material's drawer is also a drill-in panel, not an expand-collapse tree, so "same open groups" cannot hold at phone width whatever the breakpoint, and the breakpoint is a pair (`76.25em` / `76.234375em`), not a number.
   - Impact: Medium. Lost hero real estate on tablets, and a goal nobody can verify.
   - Confidence: Likely (the 2026-09-05 design chose 1024px for the hero grid on purpose, and the CSS pair is unambiguous).
   - Evidence anchor: design v1.1 "moves to Material's, `76.25em`". `acs.css` line 280 `@media (max-width: 1024px)`. `.hero { grid-template-columns: 1fr 1fr }`.

10. Seven built pages (`spec/instrument/a2a/hooks/*`) are outside `nav`, reachable from the A2A page, and render with no active entry. The sample and the URL check are both pane-to-build only.
    - Impact: Medium. "Consistent on every page" is false on 7 of 40 pages and the test cannot see it.
    - Confidence: Very likely (build output, INFO level, `--strict` passes).

11. The row counts do not follow from the pane: 12 rows with every group closed (same as today), 20 on the landing with Home open, 49 fully expanded. "About thirty" and "about forty-five" describe no state. The skip-link rationale and the `navigation.sections` rejection rest on them.
    - Impact: Low, but the document would be cited as evidence.
    - Confidence: Very likely (arithmetic).

12. Material's index rule is "the first index-named child at any position", not "the first child is an index page". The design's paraphrase would make a contributor's reordered nav group fail the comparison in a file they cannot edit.
    - Impact: Medium (lands on an outside contributor's docs PR).
    - Confidence: Plausible.
    - Evidence anchor: installed `nav-item.html` lines 67-74. `mkdocs/structure/files.py` line 369.

13. The three coupled surfaces have one maintainer: 14 of 17 commits in 90 days on `mkdocs.yml`, `landing/`, `overrides/`, `render_landing.py` and `docs/stylesheets/` are Rock's, nobody else has touched four of the five, CODEOWNERS omits the Documentation lead on all of them, and the "project lead's approval" the design cites has been admin bypass in practice (PR #357 today, zero reviews).
    - Impact: High. Bus factor one on the front door, and the accountability control the design names never fires.
    - Confidence: Very likely (measured).
    - Cross-attack: the counterargument that this is the project's existing state, not a cost the design adds, was weighed. The design adds eight coupled artifacts to that state and cites the approval as its control, so the finding stands as a requirement on the implementing PR (one non-author approval) and a GOVERNANCE/CODEOWNERS follow-up.

14. The homepage cost is asserted from a miscount, cannot be measured (no analytics by decision), and has no rollback section where the 2026-09-05 design had one. On today's stylesheet, 20 rows plus chrome run about 900px, so on a 768 to 800px tall viewport the theme toggle and the External resources sit below the fold of the sticky column.
    - Impact: High. The front door, weeks before the domain cutover.
    - Confidence: Likely.

15. Three decisions are recorded as outputs without their inputs, or made by the document without an owner: FAQ at top level reverses the owner's own written reasoning on PR #20 (the FAQ "wins" over Conformance Profiles by sitting higher). The Overview rows are removed under four groups by an unnamed "Accepted" while the Identity exception means two grammars remain. Roadmap is demoted from row 3 (placed by the owner on 2026-10-04) to row 11 under a heading. "Read the specification" keeps landing on a page titled Trustworthy Agents while the pane has a Specification group three rows down, so the naming principle the design applies to the pane is withheld from the highest-intent click.
    - Impact: Medium.
    - Confidence: Likely (all quoted from the record).

16. The work has no accepted issue and no workstream, and the intake design being written the same day makes its own surfaces ineligible for the editorial lane the owner used on them this morning. The first use of the new intake rules would be the project lead routing around them.
    - Impact: Medium.
    - Confidence: Likely (`gh issue list` for navigation, sidebar, left pane returns nothing).

17. Supporting documentation is missing: the CLAUDE.md hosting sentence does not say `mkdocs.yml` is now a landing build input. The removed "ACS home" comment takes the absolute-versus-relative reasoning with it. Nothing in `mkdocs.yml` or the override says the renderer reads `extra`.
    - Impact: Low.
    - Confidence: Likely.

18. Material's sidebar script binds every `label[tabindex]` and throws a `ReferenceError` on a hand-emitted group whose `input` id and `aria-labelledby` contract is incomplete. The hand id must also not collide with `__nav_1`.
    - Impact: Low (console error, stale `aria-expanded`).
    - Confidence: Plausible.

19. Day-one breakage the design understates: `test_render_landing.FULL_TEMPLATE` hand-lists placeholders and raises on the new one. `render()` gains an input, so `main()` and `test_landing_page.py` change. The design counts three split-based tests where there is one, and the rule that test encodes (docs links are not external resources) needs restating in tuple terms. The landing root for URL resolution is unstated and must be `DOCS_BASE` minus `docs/`.
    - Impact: Low.
    - Confidence: Very likely (mechanical).

Cross-attack log.
- ML Engineer's counterargument to finding 1 (it cannot ship, the first `pytest` run fails, a builder prunes by class in minutes) was accepted for impact on the shipped artifact and rejected for impact on the test: the design must specify the walk so the patch is not improvised. Held at High for the test, Low for readers.
- Data Scientist and ML Engineer reached finding 2 from different sites (the sample set and the template). The band was raised to Likely on genuinely different evidence.
- Governance's bus-factor finding was challenged as describing the project rather than the design. Held because the design cites the approval as its control.
- The Data Scientist's "define open state from the `aria-current` ancestors" turned finding 8 from a defect into a specification. The ML Engineer's drill-in observation (finding 9) means the open-state assertion applies above the breakpoint only.
- The ML Engineer's `navigation.indexes` findings (2, 12) and the Governance finding on the Overview rows (15) were weighed together: the feature buys one grammar on paper, delivers two grammars in fact, adds a second `aria-current` site, a stylesheet dependency, and a docs IA change with no owner. v2.0 drops it.

Stop signal: not reached. Findings 1, 2, 3, 13, 14 are High at Likely or above and change the design. The design was rewritten as v2.0 before Round 2.

## What v2.0 changed in response

- `navigation.indexes` is dropped. The docs tree keeps its Overview rows and its one grammar (every group is a toggle and every page is a row), the override adds `aria-current` at one site, and no docs IA change ships with this work (findings 2, 12, 15).
- The pane walk is specified: `li.md-nav__item` children of `ul.md-nav__list`, first `a.md-nav__link` or `label.md-nav__link[for]` per item, `label.md-nav__title` ignored, every `md-nav--secondary` subtree pruned, never filtered by href shape (finding 1).
- The tuple gains `is_section`. Open state is asserted per sampled page as the ancestors of the `aria-current` entry (plus Home on the landing), above the breakpoint only. The sample is chosen by state and includes `404.html` and one out-of-nav page (findings 5, 8, 10).
- Overrides are kept as upstream copy plus a unified diff, and the test asserts `patch(installed, diff) == override`. The re-derivation steps are in `overrides/README.md`. The docs-toolchain Dependabot group gets a reviewer (finding 3).
- External resources keeps Material's section markup and the test asserts the two stylesheet rules inside the `min-width` block, not the class name (finding 4).
- The landing root in the override is `base_url.rstrip('/') ~ '/..'` (finding 5). The renderer keeps `yaml_load`, defaults `use_directory_urls` to true, raises on an untitled or non-mapping nav entry, and a test forbids `!relative` in `mkdocs.yml` with a comment naming the renderer (findings 6, 7).
- The landing keeps its 1024px breakpoint. The phone goal is same entries and order behind a menu button, nothing about breakpoints or open groups (finding 9).
- Row counts corrected (12 closed, 20 with Home open, 49 expanded). A rollback section and a manual fold check at 1366x768 and 1440x900 are added (findings 11, 14).
- The implementing PR requires one non-author approval. A GOVERNANCE/CODEOWNERS follow-up names a second maintainer for the nav surfaces (finding 13).
- Decisions are recorded with their inputs: FAQ at top level with the PR #20 reasoning and the non-normative banner it relies on. Roadmap under External resources as shown in the mockup the owner approved. The "Read the specification" label collision recorded as residual risk for the owner (finding 15).
- An accepted issue is opened for the work and the PR closes it (finding 16). Supporting changes are listed: CLAUDE.md, a comment above `extra.acs_nav`, a header comment in the override (finding 17). The Home group's script contract is asserted (finding 18). `FULL_TEMPLATE` is built from `REQUIRED_PLACEHOLDERS` (finding 19).

## Round 2. Measurement and build correctness (against v2.0)

Perspectives spawned: Data Scientist (lead), ML Engineer. Rounds 2 to 5 were run as one batch against v2.0, each perspective assigned its round's layer, because v2.0 was a whole-design rewrite and the layers were independent. Each perspective built the docs from the pinned theme and applied the written walk to the built HTML.

Premortem narrative. Six months out, the comparison test has an exception for the Home row, a second exception for the active row, and a hand-wrapped heading on the landing that makes the External resources row appear. Nobody remembers which of the three was the design and which was the repair. The first theme bump went red on a stylesheet substring that had changed order and nothing else, and the expected string was pasted over. A reader on a mistyped URL still sees GitHub's default page.

Findings, surviving at Plausible or above.

1. The written docs walk picks the table-of-contents label on every in-nav page. The active row emits `label.md-nav__link--active[for="__toc"]` before its `<a>`, outside the pruned secondary nav, so "the first `a` or `label[for]`" is the label and the active row's URL is `None` on all seven docs samples. Read a-first instead, the seven group rows become their first child. Neither reading is correct.
   - Impact: High for the test. Confidence: Very likely (applied to seven built pages under both readings by two perspectives).
   - Resolution in v3: a precedence over the row's direct children plus a `md-nav__container`'s children, skipping `label[for="__toc"]`, first `a.md-nav__link` else first `label.md-nav__link[for]`, exactly one pick or raise, and the `aria-current` element must be the picked element.

2. The landing's External resources is an `<h2>`, which the landing walk cannot see, so the landing has 40 rows against 41 and the `is_section` assertion has no landing element. `is_group` and `is_section` have no derivation on either surface, and the Home group, the one group with a link in its header, is where "label means group" breaks.
   - Impact: High. Confidence: Very likely (textual, both perspectives).
   - Resolution in v3: `li.nav-section` with a heading and a list on the landing. `is_group` from `md-nav__item--nested` or a direct `details`. `is_section` from `md-nav__item--section` or `nav-section`. The landing pick is the summary's `a`, else the summary, else the `a`, else the heading.

3. `404.html` has no canonical URL, no active row, and sits in neither branch of the `aria-current` count, so the sample added for Round 1 finding 5 is the one the test can assert nothing on.
   - Impact: Medium. Confidence: Very likely (built file).
   - Resolution in v3: the 404 resolves against `DOCS_BASE + "404.html"`, expects zero `aria-current` and an empty open set, is excluded from the `index.html` walk, and the fixture's `GITHUB_PAGES_URL` is recorded as load-bearing.

4. "Open" is read from `md-nav__toggle[checked]`, one of three openers Material's stylesheet consumes. `navigation.expand` would open every group with the assertion green.
   - Impact: Medium. Confidence: Likely (latent today).
   - Resolution in v3: no `md-toggle--indeterminate` in the pane. `aria-expanded` on each nested `nav` equals the open set. The assertion's job on the docs is stated as the hand-emitted groups and theme drift.

5. Label extraction is unspecified, Material renders titles raw and the renderer escapes, so a title with an entity splits the panes with no visible cause.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: label is the whitespace-collapsed text nodes of the picked element. Every title matches `[^<>&]+` by test.

6. The expanded row count is 53, not 49, computed two ways.
   - Impact: Low. Confidence: Very likely.
   - Resolution in v3: 53, with the arithmetic shown.

7. The sample set carries a duplicate justified by a dropped feature. The out-of-nav allowlist is seven names in a test file with no owner, no derivation, no message, and no check that its entries exist, in a directory a contributor who can add a page cannot edit.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: samples chosen by state from the pane at test time. `extra.acs_nav.out_of_nav_prefixes` in `mkdocs.yml`. Each prefix must match a built page. The failure message names the page, the two fixes, and the lane.

8. The design writes `Home → /` and the landing test forbids `href="/"`. `target` and `rel` are invisible to the tuple.
   - Impact: Low. Confidence: Likely.
   - Resolution in v3: `./`. No pane link carries `target` or `rel`.

9. The stylesheet assertion is a substring over one 140 KB line with ten `min-width:76.25em` blocks, no parser is in the venv, and the section's behavior also depends on its rule sitting after the collapse rule at equal specificity.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: a brace walker yielding `(media, selector, declaration set)`. Membership on declarations. The section rule's index greater than the collapse rule's. The two `.md-nav__container` rules asserted too.

10. `patch(installed, diff) == override` names no applier. The standard library has none. BSD and GNU `patch` and `git apply` differ on fuzz and offset.
    - Impact: Medium. Confidence: Likely (probed on this machine).
    - Resolution in v3: an upstream copy in the repository. `difflib.unified_diff` equality in the test. `git apply --check` with zero fuzz in the re-derivation tool.

11. The override is told to emit the Home children and the three external links by hand, which is the second copy the anti-goals forbid.
    - Impact: Medium. Confidence: Likely.
    - Resolution in v3: the override loops `config.extra.acs_nav`. A test forbids the literals in its source.

12. A URL-valued `nav` entry passes the "titled mapping" test and the renderer's rule has no branch for it. A file name with a space diverges from mkdocs's quoting.
    - Impact: Low. Confidence: Likely.
    - Resolution in v3: `https://` values render as external rows. Other non-`.md` values raise. `urllib.parse.quote` applied.

13. The script-contract scan is on `label[tabindex][for]`, which misses a section label emitted without `tabindex` and covers the one with it.
    - Impact: Low. Confidence: Likely.
    - Resolution in v3: scan `label.md-nav__link[for]`.

Confirmed sound, no change: the `base_url` expression on pages and on `404.html` (replaced in v3 for a Round 4 reason, not this one). `yaml_load` with no config and the `!relative` guard at the pinned mkdocs.

Cross-attack log.
- The ML Engineer's counterargument to finding 1 (the first run is red and the builder scopes the selector in minutes) was rejected on its own evidence: under the a-first reading the first run is green, so nothing prompts the repair. Held at High for the test.
- The Data Scientist's `h2` finding and the ML Engineer's row-count finding were the same defect reached from the walk rule and the markup. Merged, band raised to Very likely.
- The Data Scientist's cascade-order finding (9) was weighed against the ML Engineer's "ten blocks, no parser" finding and the Round 4 measurement that 9.8.0 reorders the declarations: the three together set the brace walker as the only implementation that survives a bump.
- The ML Engineer's `difflib` proposal was adopted over GNU `patch` because it needs no tool on either machine and because Round 4 measured the tools disagreeing.

## Round 3. Trust boundaries and supply chain (against v2.0)

Perspectives spawned: Security Architect (lead). Red Teamer skipped: the artifact has no reader-supplied input at runtime. The contributor-input boundary is the Security Architect's layer, and the skip is logged here.

Premortem narrative. Six months out, a page-adding pull request carried a nav title with markup. The reviewer read it for wording, as the renderer's own docstring predicts for GOVERNANCE.md, and it merged under the one-approval rule with every test green. The landing page sent no policy, so the markup ran. The docs rendered the same title raw on forty pages.

Findings, surviving at Plausible or above.

1. The renderer's new input has no escaping rule, and the existing landing guards cannot see a payload that carries no `https://` and no `on*` attribute. Four of eleven commits to `mkdocs.yml` in 180 days were not the owner's, and every page-adding docs pull request edits `nav:`.
   - Impact: High. Confidence: Likely.
   - Resolution in v3: `html.escape` on every value. Anchor and URL patterns. `RenderError` naming the entry, fail closed. Nav escaping cases in `test_render_landing.py`. The rendered page's script and style bodies must equal the template's.

2. The override renders `extra.acs_nav` in a Jinja environment with autoescape off, and Material already renders `nav:` titles raw.
   - Impact: High on the docs surface. Confidence: Very likely for the mechanism (built HTML). Likely that a builder omits `| e`.
   - Resolution in v3: `| e` on every emitted value. A built-page scan for `on*` attributes and `javascript:`, `data:`, `vbscript:` URLs, which covers Material's raw titles for the first time.

3. The diff test detects drift, not malice, and the written remedy copies whatever upstream shipped into repository-owned code without reading it.
   - Impact: Medium. Confidence: Plausible (the lock hash and the cooldown hold the supply chain, and the gap is the unread delta).
   - Resolution in v3: the upstream copy in the repository. The failure message prints the upstream delta and says to read it first. Built JavaScript scanned for network hosts against the allowlist.

4. The Dependabot `reviewers` key was retired on 2025-05-20. CODEOWNERS already requests the same seven people on every bump and the record shows zero reviews.
   - Impact: Medium. Confidence: Very likely (publisher's changelog).
   - Resolution in v3: dropped. A test forbids the key. The CODEOWNERS edit lands in this change.

5. The restated landing test drops the literal-host assertions, so a lookalike Slack host is a URL diff with every test green.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: external hosts a subset of the two literals. The GitHub URL starts with the repository URL. `https` only. Hero hosts a subset of the pane's.

6. The landing page sends no policy, and it is the one page where a hash-based policy is cheap: one inline script, one inline style, no `style` attributes, no `data:` URIs.
   - Impact: Medium as a control. Confidence: Likely.
   - Resolution in v3: `<!--ACS:CSP-->` filled by `render()` with hashes of the rendered bodies. A test recomputes them and holds the three preconditions.

7. The `javascript:` guard checks by prefix without stripping the tab and newline the URL parser strips.
   - Impact: Low alone, Medium beside an unescaped attribute. Confidence: Likely.
   - Resolution in v3: `_NOISE` stripping before the check. `data:` and `vbscript:` added. The renderer's own `https://` rule is the control.

8. `!ENV` is a channel from the build environment into the published page through the loader both consumers share.
   - Impact: Low today. Confidence: Plausible (the mechanism is certain, but exposure needs a workflow edit).
   - Resolution in v3: a tag allowlist on `mkdocs.yml`.

9. The deploy's build-then-render order and the render step's empty environment are design constraints with no test.
   - Impact: Low. Confidence: Likely.
   - Resolution in v3: workflow tests for the order, the empty `env`, and no token reference after "Install uv".

Cross-attack log.
- The Security Architect's own strongest counterargument to finding 1 (`hooks:` in `mkdocs.yml` already runs Python in the build) was weighed and rejected on detection probability: `hooks:` is a key CODEOWNERS names as the thing to look for, and a nav title is the line every page-adding pull request edits and is reviewed for wording.
- The policy (finding 6) was tested against Round 1's "no third-party, no inline handler" guards and against Round 4's maintenance lens: it adds one placeholder and one test, and a hash policy breaks only when the inline bodies change, which the renderer controls. Adopted, with a pre-merge console check because a meta policy reports nowhere.
- The JavaScript host scan was weighed against the conftest hotspot (Round 5 finding 9) and placed in `test_site_config.py`, which already scans built output, rather than in `conftest.py`.

## Round 4. Build, deploy, maintenance, and recovery (against v2.0)

Perspectives spawned: MLOps / SRE (lead). The perspective downloaded the 9.8.0 wheel, diffed the partials and the stylesheet, relocked a scratch tree, and measured the deploy chain and the merge record.

Premortem narrative. Six months out, the docs toolchain is still 9.7.7. The first bump went red on a reordered declaration. The second changed nothing in the partials and was superseded four times while the maintainer re-derived on its branch. A red promotion merged by bypass stopped the schema deploy for a week. A reader on a missing URL got GitHub's page with no navigation, as today.

Findings, surviving at Plausible or above.

1. The bump's named owner is a retired key, and the replacement mechanism measures zero reviews on this repository's two docs-toolchain pull requests. One of eighteen Dependabot pull requests has ever merged. The `docs-toolchain` group names a label that does not exist, and Dependabot posts an error about it on every bump.
   - Impact: High. Confidence: Very likely (changelog plus measured record).
   - Resolution in v3: `tools/rederive_overrides.py`. The Documentation lead named as owner in GOVERNANCE. CODEOWNERS in this change. The label removed.

2. The drift test gates every publication, schemas and the nightly roadmap refresh included, and the path by which a red reaches `main` is the admin bypass used on three merges the day the design was written.
   - Impact: High. Confidence: Likely.
   - Resolution in v3: a repair sentence on every assertion. The artifact re-run written as rollback step 1. The test's inputs in `mkdocs.yml`. CODEOWNERS in this change.

3. mkdocs-material 9.8.0 is on PyPI, leaves both partials byte-identical, reorders the declarations of one asserted rule, and arrives through Dependabot about 2026-11-02.
   - Impact: Medium-High. Confidence: Very likely for the change (measured on the wheel). Likely for the red.
   - Resolution in v3: declaration-set membership, never a substring. The suite run on a 9.8.0 scratch relock before merge.

4. `patch` is three programs that disagree on fuzz and offset across the Mac and the runner.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: `git apply --check` then `git apply`, zero fuzz, in the tool and the README.

5. GitHub Pages serves only a root `404.html`. The built one at `/docs/404.html` is never served as a 404, so the page the design samples for lost readers is not the page lost readers get, and nothing observes served HTML.
   - Impact: High for the 404 claim, Medium for drift. Confidence: Very likely (measured on the live site).
   - Resolution in v3: the build copies `_site/docs/404.html` to `_site/404.html`. The test samples the root file. `tools/verify_site_nav.py` compares three served pages after deploy and every six hours.

6. Rollback as written is revert plus a manual promotion on a cadence measured at 4 to 25 days, and omits the artifact re-run the deploy workflow already documents.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: both paths, fastest first, with the conflict note.

7. The fold check measures the hero, which sits in a different grid column from the pane and cannot move. The pane's own overflow, where Round 1 placed the cost, is unmeasured and never re-checked.
   - Impact: Medium. Confidence: Very likely (stylesheet).
   - Resolution in v3: a row ceiling asserted on the rendered pane. `.sidebar` keeps `height: 100vh` and `overflow-y: auto` by test. The pre-merge screenshot is of the sidebar column.

8. A contributor docs pull request has three red modes, two of which need an edit under `/tests/`, and outside authors wrote four of four new docs pages in ninety days.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: samples by state. Prefixes in `mkdocs.yml`. A repair sentence per assertion. The CONTRIBUTING sentence from Round 5.

9. Repairing on Dependabot's branch races the next release. The branch is force-pushed or superseded within a week.
   - Impact: Medium. Confidence: Likely (measured on PR #85 and PR #301).
   - Resolution in v3: never on Dependabot's branch. A hand pull request bumps `uv.lock` and the overrides together.

10. The theme reaches end of life on 2027-05-05 and the design's constraints do not say so. The override uses a Python method call MiniJinja cannot run.
    - Impact: Medium now, High at the horizon. Confidence: Very likely (release notes).
    - Resolution in v3: the date in Decisions, Constraints, and Risks. `replace` filter in place of `rstrip`. A Zensical scratch build before merge.

11. The `built_docs` move into `conftest.py` costs under a second and is safe. The file's role as the guard and the unstated fixture scope are the residual.
    - Impact: Low. Confidence: Very likely (measured).
    - Resolution in v3: session scope. The helper in `tests/_docs_build.py`. Two builds per run stated. The injection rule in the docstring.

12. The build-then-render order is pinned by nothing, and the renderer's "may not read the built docs" rule has no test.
    - Impact: Low. Confidence: Likely.
    - Resolution in v3: the workflow order test and a render-without-docs test.

Cross-attack log.
- Findings 1 and Round 3 finding 4 and Round 5 finding 3 are one defect from three lenses (platform, supply chain, ownership). Merged in the remediation plan, with the Round 5 rehearsal as the part none of the others supplied.
- Finding 5 was challenged on scope (a live verifier is new machinery for one page): held, because the design's goal sentence promises the pane on every page and the served 404 is the page it is false on, and because the verifier reuses the test's walker and costs three GETs.
- Finding 7 and Round 5 finding 2 reached the same column from the stylesheet and from the risk ledger. Merged, band Very likely.
- Finding 10's MiniJinja point was tested against Round 2's confirmation that the `rstrip` expression is correct: both hold, which is why v3 keeps the semantics and changes the filter.

## Round 5. Governance, reader outcome, and second-order effects (against v2.0)

Perspectives spawned: Governance / Risk (lead). The perspective read the rulesets, the merge record since 2026-09-10, the milestone roster, the roadmap parser, and the July and September comments on PR #20.

Premortem narrative. Six months out, every nav-surface merge was the owner merging his own work under the bypass, as before, with a sentence in a design document saying otherwise. The OWASP quarterly rows reported the pane as a Spec document. The FAQ sat at row 4 on every page and a vendor quoted its line 170 to a buyer after the hook level moved. The CODEOWNERS follow-up never got an issue.

Findings, surviving at Plausible or above.

1. "One non-author approval, not an admin bypass" is self-restraint. The ruleset already requires the approval and already lets admins bypass it, and ten of eleven merges touching the nav surfaces since 2026-09-10 carry zero reviews.
   - Impact: High. Confidence: Very likely (ruleset and record).
   - Resolution in v3: the ruleset is named as the control. The bypass decision goes to the owner as its own permission decision. The design assumes it stands and records the approver's review on the pull request as issue #361's closure criterion.

2. The fold check measures the wrong column and has no repeat trigger. Merged into Round 4 finding 7.

3. The red bump has one person who has ever re-derived an override, and the design's new owner is a retired key.
   - Impact: High. Confidence: Very likely for the key. Likely for the consequence.
   - Resolution in v3: the approver rehearses the re-derivation during review. The README records who and when. The failure message prints the command.

4. The CODEOWNERS follow-up has no issue, owner, or date. Its stated precondition (the Documentation lead's write access) was already true. The implementing pull request already pays the `/.github/` approval.
   - Impact: Medium. Confidence: Very likely.
   - Resolution in v3: the four CODEOWNERS lines and the header comment land in this change.

5. The pane-to-build assertion turns every page-adding docs pull request into a two-file, lead-gated change with a red check as first contact, and CONTRIBUTING does not say so.
   - Impact: Medium to High. Confidence: Likely.
   - Resolution in v3: the CONTRIBUTING sentence. The specified failure message. The prefixes in `mkdocs.yml`, which stay lead-owned by CODEOWNERS and by intent.

6. The "Read the specification" collision is recorded, not decided.
   - Impact: Medium. Confidence: Very likely.
   - Resolution in v3: decided, with its input (choice C on a mockup that showed the row label), and the one-line reversal named for the owner.

7. The non-normative banner answers one of the July comment's two legs. A depth-1 FAQ on every page strengthens the other, and line 170 carries a capitalized `SHOULD` that the project's own review principles forbid in non-normative prose, with no guard.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: the decision text names both legs and accepts the second. The guard test. The one-word fix. A follow-up issue for the link-not-copy pass.

8. Issue #361 sits in a Spec milestone, and the roadmap tooling reads the milestone's workstream, not the label, so OWASP sees Spec work. `scope:in-focus` asserts a link the in-focus list does not contain.
   - Impact: Medium for the report. Confidence: Very likely (parser read).
   - Resolution in v3: a Documentation milestone. #361 and #267 moved. The scope label left to the owner.

9. The `conftest.py` move lands in the file the project's own record says never to accept on a green suite, under a rule that lives in the owner's private memory.
   - Impact: Low to Medium. Confidence: Likely.
   - Resolution in v3: session scope in its own commit. The rule in the module docstring. The guard test's output in the pull request body. The conflict note in Rollback.

10. Rollback omits the artifact re-run. Merged into Round 4 finding 6.

Cross-attack log.
- Finding 1 was challenged as describing the project rather than the design, the same challenge Round 1 made to finding 13: held again, because the design cited the approval as its control. v3 stops citing it and names the ruleset, and the design's own memory rules (permission changes are their own decision, and no design depends on an org owner) shape the resolution.
- Finding 6 was weighed against the non-goal that the hero is out of scope. The resolution keeps the hero untouched and converts the residual into a decision, which is what the finding asked for.
- Finding 7's "readable page wins" leg was tested against the owner's placement choice: a disclaimer cannot change what readers cite, and the owner chose the placement knowing it, so v3 records acceptance rather than claiming the banner closes the comment.
- Finding 8's milestone fix was checked against the roadmap parser: `parse_description` accepts any workstream named in the GOVERNANCE table, and Documentation is one, so a new milestone needs no tooling change.

## Dropped ledger

- Round 2, the sample-set redundancy on its own: Low with no defect. The samples-by-state rule absorbs it.
- Round 2, the `base_url` expression and the loader: confirmations, not findings.
- Round 3, `!ENV` as a present exposure: Unlikely while the render step has no secret. The one-test allowlist was adopted for its cost, not its band.
- Round 4, the fixture's build cost: none measured.
- Round 5, "the owner will comply on this one PR": accepted as true for one merge and rejected as a control.

Tail risk, parked. A compromised mkdocs-material release reaching readers through a routine bump: Critical, Remote under the lock hash, the seven-day cooldown, the upstream delta printed by the test, and the JavaScript host scan. The trigger that would raise it: a release whose bundle digest changes with no corresponding source commit upstream, or a cooldown shorter than the project's own review latency.

## Convergence statement

Rounds 2 through 4 each produced High findings that changed the design: the walk, the landing section markup, escaping on both surfaces, the retired reviewer key, the served 404, the stylesheet assertion. Round 5's High findings were governance (the bypass, the single re-deriver) and resolve into a recorded decision for the owner plus a rehearsal, not a change to the pane or the renderer. No Round 5 finding reopened a Round 2 to 4 resolution. The survivors that remain open are the owner's three calls, each recorded with its input and its one-line reversal. Stop signal reached after Round 5.

## Prioritized remediation plan

Ordered by expected cost reduction per unit of effort. All are in v3.0.

1. Specify the docs walk as a precedence and the landing section as a row, with structural `is_group` and `is_section` (Round 2, findings 1 to 3). No implementation cost. Prevents the day-one loosening the anti-goals name.
2. Escape and validate every `mkdocs.yml` value in the renderer, `| e` in the override, a built-page attribute and scheme scan (Round 3, findings 1, 2, 7). One function call the file already has, plus two tests.
3. Drop the retired reviewer, land the CODEOWNERS lines now, keep the upstream copy, re-derive with `git apply` through one tool, rehearse it with the approver, never on Dependabot's branch (Round 3 findings 3, 4 and Round 4 findings 1, 4, 9 and Round 5 findings 3, 4). One tool, one README, four CODEOWNERS lines.
4. Copy the built 404 to the root, sample it, and verify three served pages after deploy and every six hours (Round 4, finding 5). One workflow line and one small script sharing the walker.
5. Replace the stylesheet substring with a brace walker over declaration sets and an order assertion, and run it on a 9.8.0 scratch relock before merge (Round 2, finding 9 and Round 4, finding 3). Thirty lines.
6. Put the test's inputs in `mkdocs.yml`, choose samples by state, write a repair sentence on every assertion, and say the lane rule in CONTRIBUTING (Round 2, finding 7 and Round 4, findings 2, 8 and Round 5, finding 5).
7. Assert the row ceiling and the sidebar overflow, and screenshot the sidebar column (Round 4, finding 7 and Round 5, finding 2).
8. Add the landing policy with hashes and a console check (Round 3, finding 6).
9. Guard the FAQ, fix the one word, open the follow-up (Round 5, finding 7).
10. Record the governance decisions with their inputs: the ruleset as the control and the bypass question to the owner, the CTA decision, the Documentation milestone (Round 5, findings 1, 6, 8).
11. Rewrite Rollback, session-scope the fixture with the rule in its docstring, pin the workflow order, allowlist the YAML tags, record the end-of-life date and the Zensical check (Round 3, findings 8, 9 and Round 4, findings 6, 10 to 12 and Round 5, finding 9).

## Residual risk

- The admin bypass stands until the owner decides otherwise. The approver record on the pull request is a practice, and issue #209 will keep counting merges without review after the fact.
- The theme has six months of security-only maintenance left. The Zensical scratch build lowers the migration's cost and schedules nothing.
- The policy is a meta tag: no reporting, no `frame-ancestors`. A violation after merge is visible only to a reader with a console open.
- The live verifier samples three URLs every six hours. Drift on a deeper page between deploys is caught by the next deploy's build, not by the monitor.
- The fold check is a screenshot taken once. The row ceiling makes it recur when the pane grows and not otherwise.
- One person has written the renderer. The rehearsal gives a second person the override procedure, not the renderer.
- The out-of-nav prefixes and the samples now live in `mkdocs.yml`, which stays lead-owned. A contributor can repair the file they edited. They still need a lead's approval to land it.

## Plan premortem (against `design/plans/2026-10-29-site-navigation.md` v1.0)

Perspectives spawned, one batch, each attacking the plan as an executable artifact handed task by task to fresh implementers: Data Scientist, ML Engineer, Security Architect, MLOps / SRE, Governance / Risk. Red Teamer skipped: the site has no reader input at runtime, and the contributor-input boundary is the Security Architect's layer. Each read the plan, the spec, this report, the code the plan modifies, the installed theme, the 9.8.0 wheel, and the live site and repository. Two built the docs and applied the plan's walk rules to the output. Fifty-nine findings came back. After merging duplicates, thirty-four survived at Plausible or above. All are resolved in plan v2.0.

Premortem narrative. Six months out, the walker raised on the Home row of every docs page and was repaired by whoever hit it first. The first theme bump went red on a selector list the test had not foreseen. The live verifier was red from its first run, because the designed 404 was a retryable error to it, and was muted. A rollback by artifact re-run was undone by the nightly redeploy at 05:15. The milestone created to fix roadmap attribution failed the roadmap parser every night. The approval that was supposed to close issue #361 was dismissed by the push that recorded it.

Findings, merged, with the plan's resolution.

1. The docs walk's "a row with both raises" fires on the Home row the override emits in `md-nav__container` form (Data Scientist, ML Engineer). High, Very likely. v2.0 Task 1: one or more `a` wins, labels ignored. The container row is a verbatim fixture.
2. Material's section `li` is also `md-nav__item--nested`, the class that hides the drawer title at desktop, so `is_group` differs across surfaces or the pane shows a duplicate heading (Data Scientist, ML Engineer). High, Very likely. v2.0: `is_group` is `--nested` and not `--section`. The section row's class list is verbatim. The title-hiding rule is asserted.
3. The 9.8.0 stylesheet merges the `pointer-events:none` rule into a two-member selector list, so an exact-selector lookup fails on the bump while a hand-written fixture passes (Data Scientist). High, Very likely. v2.0: `_css_rules` splits selector lists on top-level commas. The fixture is the real block text from the wheel.
4. The section-label contract test fails on every page with a table of contents, and the obvious repair exempts the case it exists for (Data Scientist). High, Very likely. v2.0 excludes `__toc` by name and requires the two hand ids to appear exactly once.
5. `ancestor_labels` as worded collects every earlier group at a smaller depth, and the day-one repair is a subset assertion that passes with nothing open (Data Scientist). High, Likely. v2.0 states the algorithm and forbids subset.
6. Task 3's signature change breaks every existing `render` caller and the real template lacks both placeholders until Task 4, so "Expected: PASS" cannot be reached without a default that lets the pane or the policy be absent (ML Engineer). Critical for the plan, Very likely. v2.0 moves the two placeholder insertions and the fixture updates into Task 3.
7. The body-equality test is false by construction because the starburst's style is a render input (Data Scientist, ML Engineer, Security Architect). High, Very likely. v2.0 asserts `starburst + template`.
8. The sample rule picked a landing anchor as the first depth-2 row and the front page twice (Data Scientist). Medium, Very likely. v2.0 filters by the docs root and asserts distinctness.
9. Task 1's fixtures could not be copied from a built page for the container and section shapes (Data Scientist, ML Engineer). Medium, Very likely. v2.0 transcribes both rows as the contract.
10. The live verifier compared two CDN-cached pages against one never-cached page on a 60-second budget, treated the designed 404 as a retryable error, passed when `/docs/` was not served, and was appended to the schema alarm step (SRE, Security Architect, Data Scientist). High, Likely. v2.0: `HTTPError` returns its body, statuses 200, 200, 404 and the landmark are required, retries are 13 at 60 seconds on a row mismatch, the nonce carries the attempt, the check is its own step and its own monitor job, and the diff goes to the step summary.
11. Rollback path 1 is undone by the nightly roadmap redeploy and leaves the monitor red until promotion (SRE). High, Very likely. v2.0 Task 9 writes the variable step and the expectation into CLAUDE.md and the pull request.
12. The approval sequence pushed after the approval the ruleset dismisses on push, and named a reviewer who is not a code owner on most touched lines (Governance). High, Very likely. v2.0 Task 10 rehearses and pushes before any approval, names whose approval satisfies the ruleset, and records the approving head.
13. The milestone description failed both parsers (Governance). High, Very likely. v2.0 gives the exact two-line form and a verification.
14. The FAQ follow-up issue had no status label, milestone, or assignee, so no surface would show it, and the intake bot would queue the lead's pull request (Governance). High, Very likely. v2.0 gives the exact command with `status:accepted` and the milestone, assignment after consent.
15. The GOVERNANCE sentence assigned a duty to the Documentation lead with no step that asks him, in lines an open pull request rewrites (Governance, SRE). Medium, Likely. v2.0 Task 9 Step 0 asks on issue #361 and lands the sentence after the reply, placed outside PR #292's hunk.
16. The CONTRIBUTING lane paragraph still sent page-adding pull requests to `main`, where the pane test does not run until promotion (Governance). Medium, Likely. v2.0 adds the exception sentence and the clause in the message.
17. Failure messages were promised and never written. The FAQ guard's literals were unspecified and its regex scanned fenced diagrams (Governance). Medium, Likely. v2.0 Task 7 carries the `REPAIR` table and a meta-test.
18. The host allowlist covered three rows of 53 and compared `repo_url` to itself. The host parser disagreed with the browser on a backslash (Security Architect). Medium, Likely. v2.0 asserts every row with a netloc against the two literals and `REPO_URL`, requires `netloc == hostname`, and rejects `\`, `@`, and a second `:`.
19. The re-derivation tool had no first-use mode, adopted an unread upstream delta in one run, and left the file naming `git apply` depends on unstated. The published tree would carry the bookkeeping files (ML Engineer, Security Architect, SRE). Medium, Likely. v2.0: `--record`, `--accept-delta <hash>`, the dot directory, the tofile naming with `cwd`, the verbatim bump sequence.
20. The CODEOWNERS widening made a non-lead a sufficient sole approver on a build-job code-execution surface with no deterministic guard (Security Architect). Medium, Likely. v2.0 keeps the spec's four lines, adds the build-surface pin test in Task 2, and lists the widening as a permission change for the owner.
21. Dependabot names two missing labels on two ecosystem entries, not one on a group (Security Architect, SRE, ML Engineer). Low, Very likely. v2.0 names both lines.
22. Smaller: the CODEOWNERS header edit breaks a pinned literal. `tests/test_docs_links.py` does not exist. The `page` fixture is invisible across modules. `TITLE` and `ANCHOR` were defined twice. The landing-sections test could not fail at Task 2. The row ceiling had no counting rule. The hand navs lacked `aria-expanded`. The 404 test measured the fixture, not the page. The build-count grep could not see a build. The Zensical and Playwright checks were not runnable as written. The CSP meta's position and the SVG style's entity decoding were unstated. The renderer's body extractor could diverge from the test's. Zizmor was pinned at a version CI does not run. The JS host scan would fail on licence links and sleep on an activated component. The PR body's issue heading was described, not given. The three owner questions were parked where the merge erases them. The design records' `git add` could sweep in the intake files. CLAUDE.md's file list still called `mkdocs.yml` docs configuration. All adopted in v2.0 as proposed.

Cross-attack log.
- The container row: the Data Scientist's "a over label" and the ML Engineer's "two `a` or two labels raise" were the same rule from two sides. Merged, with the fixture as the contract both tasks build to.
- The CODEOWNERS widening: the SRE wanted the Documentation lead on `/pyproject.toml` and `/uv.lock` too so the bump requests him. The Security Architect wanted no widening without a guard. The spec's four lines stand with the pin test, and the lock files stay with the leads pending the owner's call, which is the spec's own rule on permission changes.
- The verifier's 404: the Security Architect and the SRE found the `HTTPError` subclass trap independently (one by reading, one by measuring the live site), and the Data Scientist found the opposite failure (a cached root 404 satisfying the docs check). The three fixes compose: status, landmark, and rows.
- The live verifier's placement: the SRE's rule (never share a result with the schema alarm) came from the repository's own workflow comment. Held over the plan's "same call".
- Consent before duty: the Governance finding on the GOVERNANCE sentence was weighed against the spec's Round 5 resolution (the follow-up has no owner). Asking first is the resolution, not a reversal.

Dropped ledger.
- Security Architect, the policy as a control that also governs the docs: out of scope by spec. The docs need inline scripts.
- SRE, the build-count cost: none measured. The verification command was corrected and the claim kept.
- Governance, the owner questions blocking the merge: they do not. The merge needs the approval, and the questions have venues now.

Convergence statement. The five perspectives agreed on the walker's two defects, the verifier's HTTP semantics, and the override tooling from different evidence, and the Governance lens alone found the approval sequence and the milestone parser failure, which no code reading could have produced. No finding reopened a spec-level resolution except by amendment, and the amendments are listed in Task 10. Stop signal reached for the plan.
