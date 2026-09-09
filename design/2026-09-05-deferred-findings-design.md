# Closing the deferred findings from the Pages branch

Version: 3.1
Owner: ACS project lead
Date: 2026-09-05
Status: implemented on branch fix/deferred-findings

Three adversarial premortem rounds have run against this work. The first refuted version
1.0, which had closed a finding as "already correct" while a draft schema in a directory
named `Proposals` published to the live normative namespace. The second refuted the two
fixes the next plan led with: a six-name denylist and a regex widened by two attributes.
Six perspectives reproduced bypasses of both, by execution rather than argument, so this
design replaced them with checks that fail closed on constructs nobody enumerated.

The third round attacked those replacements. The identity check held against every
directory-name attack, and the inverted guard held against all twenty markup constructs it
was built for. Three defects survived elsewhere: a symlink under `specification/` published
any file on the runner, two paths differing only by case diverged between a Mac and the CI
runner, and the new exempt list let a form and a speculative anchor through. Version 3.1
closes those and corrects two claims version 3.0 made about the deploy workflow and the
size of its own payload set.

## Goal

Close the findings carried from the Pages branch reviews, plus the findings both
premortems raised against the plans to close them.

The site is live and serving 44 schemas that external tools fetch. Nothing here changes
what it publishes. Every change either removes a way the tooling can fail silently,
replaces a guard that keeps proving incomplete, or corrects a document that is false.

## What changed from version 2.0

| Was | Now |
|---|---|
| `NON_NORMATIVE` widened to six case-folded names | **Replaced.** A schema's `$id` must match its location. No name list |
| The guard widened by two attributes and a tag list | **Inverted.** Every attribute is a fetch unless it sits on a short exempt list |
| "Writing the bytes read during validation closes the window" | **False as written.** `load_schemas` read text, the loop read bytes again |
| Finding 18 tabled as Fix, delivered as tracking | **Fixed.** Verification derives its URI list from the tree |
| Finding 20 tracked by a public GitHub issue | **Recorded in-repo.** A plan is the wrong place for a disclosure decision |
| Three self-assessments claiming completeness | **Corrected.** Each overstated what it had done |

## The defect that reopened, and why widening did not close it

Version 2.0 case-folded the comparison, which closes `Proposals`, `PROPOSALS`, `proposal`,
and `drafts`. Measured against the widened check, all of these still publish a draft to
the normative namespace:

| Directory | Result under version 2.0 |
|---|---|
| `sandbox/`, `staging/`, `rc/`, `unreleased/`, `incubator/` | publishes |
| `_drafts/`, `draft-v2/`, `drafty/` | publishes |
| `ｐｒｏｐｏｓａｌｓ/` (fullwidth) | publishes |
| `dra‍ft/` (zero-width joiner) | publishes |
| `prоposаls/` (Cyrillic homoglyphs) | publishes |

The last three matter more than the synonyms. They render identically to a blocked name in
a diff, so the human review that might catch `sandbox/` cannot catch them at all.
`str.casefold` folds case. It applies no compatibility normalization and has no concept of
a confusable. A check normalized on one axis is not a normalized check.

Three perspectives reached this independently. Version 1.0 argued about match depth,
version 2.0 argued about the name list, and both were the wrong axis. The right axis is
that a denylist cannot enumerate its own complement.

### The replacement

Exactly one schema in the tree has an `$id` tail that differs from its path under
`specification/`. Moving `specification/ACS/acs_schema.json` to `specification/v0.1.0/`
makes the two identical for all 44, which turns the question into an identity test:

```python
if tail != path.relative_to(source).as_posix():
    raise SchemaError(f"{path}: $id declares {tail!r} but the file sits at {on_disk!r}")
```

A draft cannot claim the normative namespace under any directory name, because it would
have to declare an `$id` naming that directory, and `SAFE_TAIL` already requires a
`v<digits>` first segment. A draft declaring its own honest location is refused by
`SAFE_TAIL`. A draft lying about its location is refused by the identity check. The
directory name stops being load-bearing, so no list exists to forget to extend.

Measured: 44 schemas publish unchanged, and 26 draft-directory names are refused,
including every Unicode variant above.

No published URI changes. One source file moves.

## Findings and disposition

| # | Where | Disposition |
|---|---|---|
| 1 | `publish_schemas.py` partial output | Fix, with the rationale corrected. See C1 |
| 2 | `NON_NORMATIVE` matching | **Fix as a class.** Identity check, see above |
| 3 | percent-decode redundancy | Close, with corrected reasoning and a drift test |
| 4 | `render_landing.py` error boundary | Fix |
| 5 | `render_landing.py` double load | Fix, with a shared version helper mandated |
| 6 | `verify_published.py` exception handling | Fix |
| 7 | `verify_published.py` final sleep | Fix |
| 8 | workflow artifact on dispatch | Fix, from one source rather than two copies |
| 9 | `javascript:` test strength | Fix |
| 10 | guard attribute and file coverage | **Fix as a class.** Inverted, see C4 |
| 11 | offender diagnostics | Fix |
| 12 | starburst font fallback | Fix |
| 13 | `CLAUDE.md` ambiguous sentence | Fix |
| 14 | `LICENSING.md` section placement | Fix |
| 15 | `SECURITY.md` duplicate row | Fix |
| 16 | `SECURITY.md` says "once Pages is enabled" on a live site | Fix |
| 17 | `CLAUDE.md` absent from the restricted CODEOWNERS tier | Fix |
| 18 | Post-deploy verification covers 2 of 44 URIs | **Fix.** Derived from the tree |
| 19 | `verify_published.py` has no test file at all | Fix |
| 20 | `schema.lock` deferred twice with no durable tracking | Record in-repo |
| 21 | Guard misses `<base>`, inline script, SVG, meta refresh, `image-set`, tab-in-scheme | **New.** Fix as a class |
| 22 | `VENDORED_SEGMENT` is a substring test, not a prefix test | **New.** Fix |
| 23 | Validation reads text, the write reads bytes again | **New.** Fix |
| 24 | `test_main_reports_a_copy_failure` never reaches the copy | **New.** Fix |
| 25 | Version-selection test uses a single-version fixture | **New.** Fix |
| 26 | `_schema_facts` names one version and counts every version | **New.** Fix |
| 27 | `_schema_facts` duplicates the body of `_versions` | **New.** Fix |
| 28 | `design/` falls to the wide CODEOWNERS default | **New.** Fix |
| 29 | `main` has no required status checks | **New.** Fix, outside the code |
| 30 | Three self-assessments overstate their own completeness | **New.** Fix |
| 31 | Rollback docs do not separate a failed verify from a failed deploy | **New.** Fix |
| 32 | The monitor has no alerting path | **New.** Record, see out of scope |
| 33 | A symlink under `specification/` publishes any file on the runner | **Round 2.** Fix |
| 34 | Two paths differing only by case collapse on a case-insensitive filesystem | **Round 2.** Fix |
| 35 | The exempt list lets `form action` and a speculative `rel` through | **Round 2.** Fix |
| 36 | `paths_from` tails do not carry the `schema/` segment the workflows expect | **Round 2.** Fix |
| 37 | Neither verification job sets a timeout | **Round 2.** Fix |
| 38 | Static scanning cannot see a URL computed at runtime | **Round 2.** Record, see out of scope |

## One finding still closes

**Finding 3, the percent-decode check.** `SAFE_TAIL` admits `%` in no character class, so
any percent-encoded input is rejected by the pattern regardless of the decode comparison.
Version 1.0 defended keeping the check by claiming "no single layer is load-bearing." That
is false: for this input class exactly one layer is load-bearing, and it is `SAFE_TAIL`.

The check stays for a different and correct reason. It turns a percent-encoded traversal
attempt into a distinctly labelled error, `$id must not be percent-encoded`, rather than a
generic pattern failure. That distinction tells an operator reading a CI log that someone
tried something, rather than that someone made a typo. Intent signal in a build log is
worth three lines of code.

## C1: validate everything, then write

`publish()` runs in three phases:

1. For every schema, resolve `rel`, `sid`, and the contained destination. Detect duplicate
   `$id`. Build the `$id` map.
2. Run `verify_refs`.
3. Create directories and write the bytes validation read.

No `mkdir` happens before phase 3. On failure the output directory does not exist at all,
so the test asserts absence rather than emptiness.

**The correction.** Version 2.0's commit message claimed phase 3 "writes the bytes phase 1
validated." It did not. `load_schemas` called `read_text` to parse, discarded the text, and
the phase 1 loop called `read_bytes` separately. A mutation harness confirmed the gap by
writing content to the output that no validation had seen.

`load_schemas` now returns the raw bytes alongside each parsed document, so one read serves
both. The claim becomes true rather than aspirational. This matters less for the narrow
race than for the record. A design document asserting a property its code lacks is how
version 1.0's false claims survived four reviews.

Round 2 found two more ways the read betrays the path checks above it.

**A symlink.** `specification/v0.1.0/config.json` can be a symlink to any file on the
runner. Every path check passes, because they all examine the symlink's own name, and the
read follows it. Reproduced: a self-consistent JSON file elsewhere in the checkout was
copied verbatim into the published output. The diff under `specification/` looks like an
ordinary three-line schema addition, distinguished only by a file mode a reviewer has to
notice. Paths now resolve before they are read, and a resolved path outside the source tree
is refused. This defect predates the restructure, and the module docstring has claimed
"every path derived from it is validated and contained" the whole time. The read was not
contained.

**A case collision.** Two schemas whose publish paths differ only by case are two files on
the Linux runner and one file on a maintainer's Mac. Both publish in CI while the local
checkout that a human verifies shows one. That defeats the byte-level diff this design
leans on, by making the local side of the comparison quietly wrong. Publishing now refuses
a pair that collides under case folding, so an ambiguous tree fails rather than deploying
a shape nobody reviewed.

## C4: invert the guard

The no-third-party guard had been found incomplete five times before this work, and was
corrected five more times during it, each round prompted by a review reproducing a defect
the previous round introduced or missed. Every fix before the rewrite added names to an
enumeration of things that fetch. The
enumeration is the defect. Nine payloads defeat the version 2.0 pattern, each reproduced:

| Construct | Why the enumeration cannot see it |
|---|---|
| `<base href>` | Rewrites resolution for the whole page, so every other URL carries no host |
| Inline `<script>` body | The scan reads attributes. A script body is text |
| `<use href>`, `<image href>` | SVG tags absent from the tag list |
| `<meta http-equiv="refresh">` | Navigates with no interaction, and lives in `content` |
| `image-set("https://…")` | Not `url(`, so the stylesheet pattern misses it |
| `src="ht<TAB>tps://…"` | The URL parser strips tab and newline before resolving. The regex does not |
| Second fetch attribute on one tag | `finditer` is non-overlapping, so the tag anchor is already consumed |
| `<a ping>` | Never enumerated |

So the guard stops enumerating what fetches and enumerates what does not. It parses the
markup with `html.parser`, walks every attribute on every element, and treats each as a
fetch unless the pair sits on a short exempt list: anchor and area `href`, the four `cite`
attributes, form and button `action` and `formaction`, and any `xmlns`. Inline `<script>`
and `<style>` bodies are scanned for absolute URLs. Tab and newline are stripped before
matching. A `<base>` element's href is folded into the same result, so a base pointing off
site is reported like any other fetch and one pointing at our own host is not.

An attribute nobody anticipated is now a failure rather than a silent pass. That is the
property every previous version lacked.

Round 2 attacked the exempt list, which is where inverting the guard moves the trust
boundary. Two entries were wrong. `form action` was exempted on the theory that submission
needs a click, and a script calling `submit()` fires the request on load with no URL in the
script text. An anchor `href` was exempted unconditionally, and `rel="prefetch"` or
`rel="preconnect"` makes one fetch without a click. Both are now handled: form action is
off the list, and an anchor loses its exemption when it carries a speculative `rel`. The
site's own anchors carry only `noopener` and `edit`, and no form on the site declares an
`action`, so neither correction costs a false positive.

Stylesheets get their own scanner rather than sharing the attribute pattern. Run over
minified theme CSS, the attribute pattern reported `fontawesome.com` from a licence banner
and `www.w3.org` from an inlined `data:` SVG, neither of which is a request. CSS reaches
the network only through `url()`, `image-set()`, and `@import`, so that set can be
enumerated safely, unlike the HTML one. Comments are stripped and `data:` values skipped.

Base handling folds into `third_party_hosts` rather than sitting beside it. Coverage a
call site has to opt into is how this guard reached five incomplete versions.

Measured against the real built site: 38 pages, zero third-party hosts, zero `<base>`
elements, and 36 vendored scripts with none stray. The payload set ends at 33 markup
constructs caught and 14 non-fetching cases quiet, plus 7 stylesheet fetches caught and 4
ignored. Markup following an unclosed or self-closed `<script>` is not among the quiet
cases. It belongs to that script and a browser runs it, so two tests pin it as caught.

**What this cannot do.** The script scan matches literal URLs. A URL assembled at runtime,
from `atob()`, from concatenation, or read back out of an exempted attribute, is invisible
to it. No static scanner closes that, and saying so here is better than implying the scan
proves more than it does. Closing it needs a content security policy, which is a hosting
change rather than a test.

The `xmlns` exemption is load-bearing for a real reason. The built site carries 407
`xmlns="http://www.w3.org/2000/svg"` declarations. A namespace URI names a vocabulary and
no browser resolves it. Verified that the exemption cannot smuggle a fetch, because a
`<use href>` on the same element is still caught.

**The script check compares digests.** The substring form accepted any path containing
`assets/javascripts/`. A prefix fixed that and still could not tell the theme's own file
from one edited in place, because mkdocs copies `docs/assets/` into the same directory. It
now hashes every script in the built site against the installed package's own files.

## C3: the publish pipeline

**`render_landing.py`.** Move `out.mkdir`, the `index.html` write, and `shutil.copytree`
inside the error boundary. `_schema_facts` calls `_versions` rather than restating its
body, and both share `_version_key`. The schema count is taken within the version being
reported, because naming `v0.2.0` while counting every schema in the repository states a
number that is wrong about the version printed beside it.

Two tests are rewritten because they pass for the wrong reason. The copy-failure test's
fixture omitted four required placeholders, so `render` raised before reaching the copy at
all, and the test passed identically against the pre-fix code. The version-selection test
used a single-version fixture, so a deliberately broken comparison still passed it.

**`verify_published.py`.** Widen the retry clause to `UnicodeDecodeError`. Guard that the
parsed body is a mapping before reading `$id`. Skip the sleep after the final attempt.

**Verification covers all 44 URIs.** Both workflows check out the repository, so both can
derive the expected URI list from `specification/` using the code that already computes it.
Two hardcoded paths in two files becomes one derivation with nothing to drift.

A correction to version 2.0's reasoning here. It justified the non-object guard by
imagining an edge serving an error page during propagation. Measured against the live site,
a Pages 404 serves HTML, which raises `JSONDecodeError` and is retried. The guard is still
right, because a parsed non-object cannot be fixed by waiting, but the scenario given for
it was not the real one.

**`deploy-pages.yml`.** Configure Pages and the artifact upload gain the branch half of the
condition the `deploy` job already carries, so a dispatch from a feature branch stops
building an artifact that was never publishable.

A correction to the reasoning version 3.0 gave for this. It described a compound condition
copied onto two steps and framed the change as deduplication. The two build steps carry
only `github.event_name != 'pull_request'`, and the compound form appears once, on the
deploy job. So this is a deliberate behavior change rather than a cleanup, which is what
finding 8 asked for in the first place. The framing was wrong, not the work.

Both verification jobs also gain a timeout. Checking 44 URIs at six attempts and ten
seconds apiece can run past half an hour during a real outage, and neither job sets a limit
today, so a failing run holds a runner against a six-hour default.

## C5: documents, ownership, and tracking

**`SECURITY.md`.** Merge the two overlapping in-scope rows, and remove "once Pages is
enabled" from the row describing a live site. The plan carries the exact replacement row,
because a prose instruction to "merge two rows" admits several readings and no test in the
suite distinguishes them.

**`CLAUDE.md`.** Give "The landing page links both" an explicit subject. Record the moved
schema path and the identity rule.

**`.github/CODEOWNERS`.** Add `/CLAUDE.md`, `/STYLE.md`, and `/design/` to the restricted
tier. Version 2.0's commit message claimed `CLAUDE.md` "was the one root document absent
from the restricted owner list." Seven others are equally absent, `STYLE.md` among them,
which `CLAUDE.md` itself makes binding on every text edit in the repository. The design
directory holds the documents arguing the threat model for a live publishing pipeline and
currently needs no restricted-tier review at all.

**`LICENSING.md`.** Move the provenance section after the scope table it explains.

**`landing/assets/starburst.svg`.** Declare `font-family` once on the root element and
remove the fifteen per-element declarations.

**Record the `schema.lock` follow-up here.** Version 2.0 specified `gh issue create` inside
a plan meant for unattended execution, gated by one sentence of prose. Two perspectives
objected on the same grounds, and `SECURITY.md` routes tooling flaws to private reporting
rather than public issues. The record belongs somewhere reviewed, reversible, and inside
the repository. Opening an issue stays the project lead's call to make separately.

**Required status checks on `main`.** The `protect-main` ruleset requires one approval and
code-owner review, and requires no passing check. A pull request can merge with `test` and
`build` red onto the branch that deploys to the live site with no human in the loop. This
is a repository settings change rather than a code change, approved separately by the
project lead.

## Testing

Every code change gets a test that fails before the fix. Four carry more weight.

**The identity check is tested by its complement.** Not the six names a list would have
held, but 26 directory names including Unicode variants, plus both ways a draft can declare
an `$id`. The previous test could only ever confirm the names already in the list.

**The guard is verified by watching it fail.** Inject a third-party host through each of
the nine constructs the enumeration missed, confirm each fails, then revert and confirm the
suite returns to green. A guard with this history is not verified by reading it.

**Two rewritten tests are checked against the pre-fix code.** A test that passes before the
fix it is named for is worse than no test, because it reports coverage that does not exist.
Both run against the old implementation to confirm they fail there.

**`tests/test_verify_published.py` is a new file.** The module has no coverage today.

## Verification

The full suite, a clean rebuild of all three surfaces, a byte-level diff of the published
schema tree before and after, and a live re-check of the published site to confirm nothing
regressed for consumers already fetching those URIs.

The published tree diff is the one that matters. Everything else here can be wrong and
recoverable. A change to what 44 live URIs serve is not.

## Out of scope, with reasons

**`specification/schema.lock`.** Implementation is a separate change with release-process
implications. Published schemas stay mutable in place with no hash record, so a loosened
constraint under a released spec version reaches consumers silently.

**Alerting on a failed monitor run.** The monitor produces a red Actions run and nothing
else. The earlier claim that a regression "surfaces within that window" is true only in the
sense that a computer knows. Routing that to a human is a notification-settings decision
for the project lead.

**A URL the page computes at runtime.** The script scan matches literal URLs, so a fetch
assembled from `atob()`, from string concatenation, or from a value read back out of an
exempted attribute passes it. No static scanner closes that class. A content security policy
would, and that is a hosting change with its own design. Recorded rather than implied away,
because the guard's own history is of each version sounding more complete than it was.

**The review process itself.** Three audited pull requests touching restricted paths merged
with an administrative bypass and no recorded review. Combined with finding 29, nothing
mechanical currently gates a merge to a branch that deploys on merge. Recorded because two
premortems found it, not because this change addresses it.

## Residual gaps in the third-party guard

Recorded because the guard's history is of each version sounding more complete than it was.
None of these is reachable on the site as it stands, measured across all 38 built artifacts.

**Backslash protocol-relative forms.** The URL parser treats `src="/\evil.tld/x"` and
`src="\\evil.tld/x"` as protocol relative for special schemes. The attribute pattern matches
only two forward slashes.

**A bare protocol-relative URL in script text.** `fetch("//evil.tld/x")` is missed on
purpose, because two slashes open a JavaScript comment far more often than a URL, and a
false positive here is what gets a guard switched off. Markup a script writes is covered,
because an attribute name disambiguates it.

**A URL the page computes at runtime.** `atob()`, string concatenation, or a value read back
out of an exempted attribute defeats any static scan. Closing this needs a content security
policy, which is a hosting change with its own design.

**`<svg:style>` in HTML.** Handled differently from `<style>`, and a browser does not apply
it as CSS in an HTML document, so it is a divergence rather than exposure.

**One claim in this document cannot be verified from history.** The guard shipped in a
squashed commit, so "found incomplete five times before this work" rests on the docstring
that recorded it rather than on five separate commits. The five corrections made during
this work are each their own commit and are verifiable.

**Scaffolding that invites the mistake the identity rule rejects.** `specification/AG-BOM/`
and `specification/Observability/` hold no schemas. A file added there fails the build
loudly and early, which is the designed behavior, but `CONTRIBUTING.md` does not warn a
contributor before they structure work there.

## Tracked follow-up: specification/schema.lock

Deferred three times now. Published schemas are mutable in place with no hash record, so a
constraint loosened under a released spec version reaches every consumer resolving that
`$id` with no way to detect the change against a copy fetched earlier.

The work is a manifest of every published path and its hash, written at build time and
checked at deploy time. It carries release-process implications this change does not, which
is why it stays out of scope rather than being folded in.

This record replaces the public tracking issue an earlier plan specified. Opening one is
the project lead's decision to make separately, and `SECURITY.md` routes tooling flaws to
private reporting.
