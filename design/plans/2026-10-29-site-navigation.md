# Site Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

Version 2.0, 2026-10-29, rewritten after the plan premortem (five perspectives, with findings and resolutions in `design/2026-10-29-site-navigation-premortem.md`, "Plan premortem").

**Goal:** One left pane, read from `mkdocs.yml`, rendered on the landing page by `tools/render_landing.py` and on every docs page by two theme partial overrides, held equal by a test that names its repair and by a live check of the published site.

**Architecture:** `tools/site_nav.py` walks either surface's pane into rows and is shared by the test and the live verifier. The renderer gains a nav section, escaping and validation, and a hash-based content security policy. The overrides are kept as upstream copy plus recorded diff under a dot directory MkDocs does not publish, re-derived by one tool that refuses to adopt an unread upstream delta. The deploy copies the built 404 to the site root so GitHub serves it, and a separate step and a separate monitor job verify the served pane.

**Tech Stack:** Python 3 standard library (plus `mkdocs.utils.yaml` in the renderer only), MkDocs Material 9.7.7 partials, hand-written HTML and CSS, pytest.

**Spec:** `design/2026-10-29-site-navigation-design.md` v3.0, with the amendments the plan premortem made (listed in the premortem's "Plan premortem" section and applied to the spec in Task 10). Tracking issue #361.

## Global Constraints

- mkdocs-material 9.7.7 as pinned by `uv.lock`. No new dependency. Parsing uses `html.parser` and hand-written walkers. `tools/site_nav.py` and `tools/verify_site_nav.py` import the standard library only: the deploy and monitor jobs run them on the bare interpreter with no virtual environment.
- The override Jinja uses filters only, never a Python method call: `{{ (base_url ~ '/..') | replace('//..', '/..') }}`, `| e` on every emitted value.
- The landing page never carries `href="/"`, an `on*` attribute, a third-party resource, or an em dash. All of `tests/test_landing_page.py` passes at the end of every task.
- Every value read from `mkdocs.yml` is escaped with `html.escape(value, quote=True)`. Titles match `TITLE`, anchors `ANCHOR`, external URLs `EXTERNAL_URL`, page paths `DOC_PATH`, all defined once in `tools/site_nav.py`. A failure raises `RenderError` naming the entry and the file to edit.
- Every new assertion's failure message comes from the `REPAIR` table in `tests/test_site_nav.py`, names the file to edit, and names `integration` when the fix is a build-side change.
- The docs are built at most twice per suite run: the session fixture in `tests/conftest.py` and `test_site_config.py`'s own. The `tests/conftest.py` change is its own commit, two lines plus the docstring. No other task touches that file.
- Prose follows STYLE.md: no em dashes, no semicolons, American English.
- Commits are signed off (`git commit -s`). Branch `feat/361-site-nav` from `origin/integration`.
- File names as tracked: `tests/test_doc_links.py`. zizmor runs as CI does: `uv run --locked --only-group zizmor zizmor <files>`. Dependabot `labels` live on ecosystem entries, not groups.

## Review Focus

1. A `nav` title such as `Trace & Inspect` or a title carrying `<code>`. Expected: `RenderError` naming the entry, never a split pane. Pinned in Task 3.
2. The Home row on the docs, which carries both an `a.md-nav__link` and a `label.md-nav__link[for]` inside `md-nav__container`. Expected: one row labeled Home with the link's URL and `is_group` true. Pinned in Task 1.
3. The real 9.8.0 stylesheet, where `.md-nav__item--section>.md-nav` reads `{display:block;visibility:visible;opacity:1}` and the `pointer-events:none` rule's selector is a two-member list with `.md-nav--lifted>...`. Expected: the stylesheet assertion passes. Pinned in Task 7.
4. An `out_of_nav_prefixes` entry matching no built page. Expected: failure naming the prefix and `mkdocs.yml`. Pinned in Task 7.
5. A docs build without `GITHUB_PAGES_URL`, where the 404's base is `/`. Expected: the 404 sample fails on the page's recorded base and its Home URL, naming the variable. Pinned in Task 7.

---

### Task 1: The walkers and the shared patterns

**Files:**
- Create: `tools/site_nav.py`
- Test: `tests/test_site_nav_walk.py`

**Interfaces:**
- Produces: `Row = tuple[int, str, str | None, bool, bool]` as `(depth, label, url, is_group, is_section)`. `class WalkError(ValueError)`. `walk_docs(markup: str, base: str) -> list[Row]`. `walk_landing(markup: str, base: str) -> list[Row]`. `docs_open_labels(markup) -> frozenset[str]` (labels of rows whose `md-nav__toggle` input is `checked`). `landing_open_labels(markup) -> frozenset[str]` (labels of `details[open]` rows). `aria_current_links(markup) -> list[tuple[str, str]]` as `(tag, href)`. `ancestor_labels(rows, index) -> list[str]`. `docs_expanded_mismatch(markup) -> list[str]`. `TITLE = re.compile(r"^[^<>&]+$")`. `ANCHOR = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")`. `EXTERNAL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:|^/")` (a value is external when it matches). `EXTERNAL_URL = re.compile(r"^https://(github\.com|owasp\.slack\.com)(/|$)")`. `DOC_PATH = re.compile(r"^(?!/)(?!.*(^|/)\.\.(/|$))[A-Za-z0-9_./-]+\.md$")`. `REPO_URL = "https://github.com/GenAI-Security-Project/agent-control-standard"`.
- Docs walk: the pane is the element with `aria-label="Navigation"`. Rows are `li.md-nav__item` under `ul.md-nav__list` with `nav.md-nav--secondary` subtrees pruned. Per row the candidates are the direct children plus the children of a direct-child `div.md-nav__container`, skipping any `label` whose `for` is `__toc`. Collect the `a.md-nav__link` candidates and the `label.md-nav__link[for]` candidates. If one or more `a` exist the pick is the first `a` and the labels are ignored (the `md-nav__container` shape). If no `a` exists the pick is the first `label`. Two or more `a`, or zero `a` and two or more `label`, or zero of both, raise `WalkError` naming the row's depth and text. `is_group` is class `md-nav__item--nested` and not class `md-nav__item--section`. `is_section` is class `md-nav__item--section`.
- Landing walk: rows are every `li` of every `ul` in the pane. The pick is the `summary`'s `a` if the row has a direct `details`, else the `summary`, else the row's direct `a`, else the row's direct heading. `is_group` is a direct `details` child. `is_section` is class `nav-section`.
- Depth is the count of enclosing `ul` elements inside the pane. Label is the whitespace-collapsed join of the picked element's text nodes. URL is `urllib.parse.urljoin(base, href)` or `None`.
- `ancestor_labels(rows, index)`: set `limit` to the row's depth, walk backward, take a row when `is_group` and `depth < limit`, then set `limit` to that depth, and stop after taking a row at depth 1. `docs_expanded_mismatch` reports a group whose nested `nav` lacks `aria-expanded`, carries a value other than `true` or `false`, or disagrees with the toggle's `checked`, plus `"indeterminate"` when any `md-toggle--indeterminate` exists.
- The two hand-emitted rows, as byte-for-byte fixtures in this task's test module and the contract Task 5 emits (`PATH` is `__nav_home` or `__nav_ext`, `TITLE` the label):

```html
<li class="md-nav__item md-nav__item--nested">
  <input class="md-nav__toggle md-toggle" type="checkbox" id="PATH">
  <div class="md-nav__link md-nav__container">
    <a href="LANDING_ROOT" class="md-nav__link">
      <span class="md-ellipsis">Home</span>
    </a>
    <label class="md-nav__link" for="PATH" id="PATH_label" tabindex="0">
      <span class="md-nav__icon md-icon"></span>
    </label>
  </div>
  <nav class="md-nav" data-md-level="1" aria-labelledby="PATH_label" aria-expanded="false">
    <label class="md-nav__title" for="PATH">
      <span class="md-nav__icon md-icon"></span>
      Home
    </label>
    <ul class="md-nav__list" data-md-scrollfix>
      <li class="md-nav__item"><a href="LANDING_ROOT#problem" class="md-nav__link"><span class="md-ellipsis">The problem</span></a></li>
    </ul>
  </nav>
</li>
```

```html
<li class="md-nav__item md-nav__item--section md-nav__item--nested">
  <input class="md-nav__toggle md-toggle" type="checkbox" id="__nav_ext">
  <label class="md-nav__link" for="__nav_ext" id="__nav_ext_label" tabindex="">
    <span class="md-ellipsis">External resources</span>
    <span class="md-nav__icon md-icon"></span>
  </label>
  <nav class="md-nav" data-md-level="1" aria-labelledby="__nav_ext_label" aria-expanded="false">
    <label class="md-nav__title" for="__nav_ext">
      <span class="md-nav__icon md-icon"></span>
      External resources
    </label>
    <ul class="md-nav__list" data-md-scrollfix>
      <li class="md-nav__item"><a href="https://github.com/GenAI-Security-Project/agent-control-standard" class="md-nav__link"><span class="md-ellipsis">GitHub</span></a></li>
    </ul>
  </nav>
</li>
```

- [ ] **Step 1: Write the failing tests.** The active-leaf and nested-group fixtures are copied from the built front page and `concepts/identity/index.html`. The container and section fixtures are the two blocks above.

```python
def test_docs_walk_skips_the_toc_label_and_picks_the_link(): ...
def test_docs_walk_container_row_picks_the_link_not_the_toggle_label(): ...   # Review Focus 2
def test_docs_walk_keeps_group_labels_not_first_children(): ...
def test_docs_walk_section_row_is_section_not_group(): ...
def test_docs_walk_raises_on_a_row_with_no_pick_and_on_two_links(): ...
def test_landing_walk_home_summary_link_is_one_group_row(): ...
def test_landing_walk_section_row_from_heading(): ...
def test_depth_counts_enclosing_lists_on_both_surfaces(): ...
def test_label_collapses_whitespace_and_ellipsis_span(): ...
def test_ancestors_skip_earlier_sibling_groups(): ...                          # a closed sibling group precedes the open path
def test_open_labels_and_ancestors_agree_on_a_nested_page(): ...
def test_expanded_mismatch_reports_indeterminate_and_a_missing_attribute(): ...
def test_patterns_accept_the_pane_and_reject_markup_and_lookalike_hosts(): ...
def test_module_imports_on_the_bare_interpreter(): ...                           # python -I -S -c "import site_nav" from tools/
```

- [ ] **Step 2: Run `uv run pytest tests/test_site_nav_walk.py -v`. Expected: FAIL, module not found.**
- [ ] **Step 3: Implement `tools/site_nav.py`.**
- [ ] **Step 4: Run the tests. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Add the pane walkers and patterns shared by the nav test, the renderer, and the live check"`

### Task 2: The source of truth

**Files:**
- Modify: `mkdocs.yml` (`nav:` reordered. "ACS home" entry and its comment removed. `extra.acs_nav` added with its comment naming both readers)
- Test: `tests/test_site_nav.py` (config assertions only in this task)

**Interfaces:**
- `mkdocs.yml` `nav:` in the spec's order: Trustworthy Agents, ACS, FAQ (moved out of Topics), Topics, Concepts, Specification, About. `extra.acs_nav` with `landing_sections` (eight `{title, anchor}` entries in page order), `external_resources` (GitHub, Roadmap, Slack), `out_of_nav_prefixes: [spec/instrument/a2a/hooks/]`.
- Produces in the test module: `MKDOCS = REPO / "mkdocs.yml"`. `load_mkdocs() -> dict` via `mkdocs.utils.yaml.yaml_load(MKDOCS.open())`. `nav_entries(nav) -> Iterator[tuple[str, object]]` (recursive, raising on a non-mapping). Patterns imported from `tools/site_nav.py`.

- [ ] **Step 1: Write the failing tests**: `test_every_nav_entry_is_a_titled_mapping`. `test_titles_anchors_paths_and_urls_match_their_patterns` (a leaf value is external iff `EXTERNAL` matches. External values match `EXTERNAL_URL`. Others match `DOC_PATH`. Every `acs_nav` URL matches `EXTERNAL_URL`). `test_repo_url_and_the_three_resources_are_the_literals` (`repo_url == REPO_URL`, GitHub `== REPO_URL`, Roadmap `== REPO_URL + "/milestones"`, Slack `== "https://owasp.slack.com"`). `test_yaml_tags_are_allowlisted` (raw text scan: `!ENV` only on the `site_url` line, `!!python/name:` on exactly the three existing values, no other `!` tag, `!relative` absent, with a comment naming the renderer and the mkdocs pin). `test_landing_sections_anchors_match_the_landing_sections_in_order` (compare with `section[id]` in `landing/index.html`, all eight of which exist today). `test_out_of_nav_prefixes_are_declared_and_end_with_a_slash`. `test_mkdocs_build_surface_is_pinned` (`"hooks" not in cfg`, `cfg["plugins"] == ["search"]`, `cfg["extra_javascript"] == ["assets/javascripts/mermaid.min.js", "assets/javascripts/mermaid-init.js"]`, `cfg["extra_css"] == ["stylesheets/extra.css"]`, `cfg["theme"]["name"] == "material"`, `cfg["theme"]["custom_dir"] == "overrides"`, message: "mkdocs.yml runs code in the build job through these keys. Change them in a pull request a project lead approves and update this test in the same commit.").
- [ ] **Step 2: Run `uv run pytest tests/test_site_nav.py -v`. Expected: FAIL.**
- [ ] **Step 3: Edit `mkdocs.yml`.** Run `uv run mkdocs build --strict`.
- [ ] **Step 4: Run the tests. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Make mkdocs.yml the one source of the site navigation"`

### Task 3: The renderer

**Files:**
- Modify: `tools/render_landing.py`. `landing/index.html` (only two edits: `<!--ACS:CSP-->` on the line after `<meta charset="utf-8">`, and lines 18 to 36, the `<nav aria-label="Sections">` block and the External resources `<div>`, replaced by `<!--ACS:NAV-->`). `tests/test_landing_page.py` (the `page` fixture passes `read_nav_config(REPO / "mkdocs.yml")` as the sixth argument. `test_the_specification_is_not_listed_as_an_external_resource` restated on `walk_landing` rows: no External resources child under the docs root)
- Test: `tests/test_render_landing.py` (`FULL_TEMPLATE = "".join(REQUIRED_PLACEHOLDERS) + "<script>var x=1;</script>"`. A module constant `STARBURST = "<svg><style>a{}</style></svg>"` passed wherever `"<svg/>"` or `"<svg id='sb'/>"` is passed today and written at line 151. `NAV = read_nav_config(REPO / "mkdocs.yml")` on every `render(` call)

**Interfaces:**
- Produces: `@dataclass(frozen=True) class NavConfig: nav: tuple; landing_sections: tuple[dict, ...]; external_resources: tuple[dict, ...]; out_of_nav_prefixes: tuple[str, ...]; repo_url: str`. `read_nav_config(path: Path) -> NavConfig` (through `mkdocs.utils.yaml.yaml_load`, no config object, `use_directory_urls` defaulting to true). `page_url(path: str) -> str` (mkdocs's rule: `README.md` and `index.md` to their directory, `foo.md` to `foo/`, nested directories kept, `urllib.parse.quote` applied). `render_nav(config: NavConfig) -> str`. `_inline_bodies(page: str) -> list[tuple[str, str]]` (a copy of `conftest._element_bodies`'s raw-text rule: the body is every byte between the end of the start tag and the start of the end tag, no stripping). `render_csp(page: str) -> str` (the `<meta http-equiv="Content-Security-Policy" content="...">` with `default-src 'none'; script-src 'sha256-…'; style-src 'self' 'sha256-…'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'`, hashes as `base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest())` of the page's one `<script>` and one `<style>` body, raising `RenderError` when the count of either is not one or when a style body contains `&` or `<`, since an SVG style is foreign content the browser decodes before hashing). `render(template, source, governance, contributing, starburst, nav: NavConfig) -> str` filling `<!--ACS:NAV-->` and, last, `<!--ACS:CSP-->`. Both tokens in `REQUIRED_PLACEHOLDERS`. `main` reads `repo / "mkdocs.yml"`. Patterns imported from `site_nav`.
- Markup from `render_nav`: `<nav id="site-nav" aria-label="Navigation"><ul>…</ul></nav>`. Home: `<li><details open><summary><a href="./" aria-current="page">Home</a></summary><ul>` of eight `<li><a href="#anchor">title</a></li>` `</ul></details></li>`. A leaf: `<li><a href="docs/<url>">title</a></li>`. A group: `<li><details><summary>title</summary><ul>…</ul></details></li>`. External resources: `<li class="nav-section"><h2>External resources</h2><ul>` three links `</ul></li>`. No `target`, no `rel`.
- Validation, each failure a `RenderError` whose text names the entry, the pattern, and "Edit `mkdocs.yml` on a branch from `integration`": a `nav` value is external when `EXTERNAL` matches and must then match `EXTERNAL_URL` after `[\t\r\n]` stripping, and must not contain `\`, `@`, or a `:` after the scheme. A non-external value must match `DOC_PATH`. A bare-string entry or an untitled group raises. Every title must match `TITLE`, every anchor `ANCHOR`, every `acs_nav` URL `EXTERNAL_URL`. Every value passes through `html.escape(value, quote=True)`.

- [ ] **Step 1: Write the failing tests**: `test_page_url_matches_mkdocs_rule` (parametrized: `README.md→./`, `concepts/README.md→concepts/`, `topics/faq.md→topics/faq/`, `spec/trace/OCSF/implementation_examples.md` keeps case, a name with a space is quoted). `test_render_nav_emits_the_pane_in_order` (row labels through `site_nav.walk_landing`). `test_title_with_markup_raises_naming_the_entry` (Review Focus 1). `test_bad_anchor_raises`. `test_url_with_javascript_scheme_or_newline_raises`. `test_url_with_backslash_or_userinfo_raises`. `test_external_url_outside_the_two_hosts_raises`. `test_attribute_breakout_in_an_external_url_is_rejected`. `test_bare_string_entry_raises`. `test_csp_hashes_the_one_script_and_one_style`. `test_csp_raises_on_two_scripts`. `test_csp_raises_on_an_entity_in_the_style_body`. `test_render_succeeds_with_no_built_docs_present`. `test_inline_bodies_match_conftests_rule_on_the_real_page`.
- [ ] **Step 2: Run `uv run pytest tests/test_render_landing.py tests/test_landing_page.py -v`. Expected: FAIL.**
- [ ] **Step 3: Implement**, and make the two template edits and the two test-module edits named under Files.
- [ ] **Step 4: Run `uv run pytest tests/test_render_landing.py tests/test_landing_page.py tests/test_site_nav.py -q`. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Render the shared navigation and a hashed content security policy on the landing page"`

### Task 4: The landing page's styles, drawer, and guards

**Files:**
- Modify: `landing/index.html` (a skip link first in `body`, a header strip with the menu `<button>`, and the drawer script in the existing inline `<script>`), `landing/assets/acs.css` (pane styles for `details`/`summary`, `.nav-section`, `aria-current` weight 600, the strip and off-canvas panel below 1024px, `.sidebar` keeping `height: 100vh` and `overflow-y: auto`)
- Test: `tests/test_landing_page.py`

**Interfaces:**
- The strip: `<header class="topbar"><a class="wordmark" href=".">…</a><button id="menu-toggle" type="button" aria-expanded="false" aria-controls="site-nav">Menu</button></header>`, shown only below 1024px. The script toggles `aria-expanded` and a `nav-open` class on `body`, closes on Escape and returns focus to the button, and attaches listeners with `addEventListener`.
- A row is visible when every group among its ancestors (by `ancestor_labels`) is open, where open means `details[open]` for a group and always for a section.

- [ ] **Step 1: Write the failing tests**: `test_the_pane_is_the_only_primary_navigation`. `test_csp_meta_precedes_every_link_and_script`. `test_csp_hashes_match_the_page_and_nothing_else_is_inline` (recompute with `conftest._element_bodies`. `render_landing._inline_bodies(page) == conftest._element_bodies(page)`. No `style=` attribute. No `data:` URI). `test_rendered_element_bodies_equal_the_starburst_plus_the_template` (`_element_bodies(page) == _element_bodies(starburst) + _element_bodies(template)`. The style body comes from the inlined diagram, the script body from the template, in document order). `test_no_inline_event_handlers` extended to strip `_NOISE` and cover `data:` and `vbscript:`. `test_menu_button_contract`. `test_pane_row_ceilings` (visible count with the page's open set at most 20 and with an empty open set at most 12. Message from `REPAIR["ceiling"]`). `test_sidebar_keeps_its_own_scroll`. `test_no_pane_link_has_target_or_rel`.
- [ ] **Step 2: Run `uv run pytest tests/test_landing_page.py -v`. Expected: FAIL.**
- [ ] **Step 3: Edit the template and the stylesheet.**
- [ ] **Step 4: Run `uv run pytest tests/test_landing_page.py tests/test_render_landing.py tests/test_site_nav.py -q`. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Style the rendered pane, add the phone drawer, and guard the landing policy"`

### Task 5: The theme overrides

**Files:**
- Create: `overrides/.upstream/partials/nav.html`, `overrides/.upstream/partials/nav.html.diff`, `overrides/.upstream/partials/nav-item.html`, `overrides/.upstream/partials/nav-item.html.diff` (the dot directory matches MkDocs's `.*` exclusion, so none of it is published), `overrides/partials/nav.html`, `overrides/partials/nav-item.html`, `overrides/README.md`, `tools/rederive_overrides.py`
- Modify: `docs/stylesheets/extra.css` (`.md-nav__link[aria-current="page"] { font-weight: 600; }`)
- Test: `tests/test_overrides.py`, `tests/test_docs_theme.py` (theme-styles test gains `.md-nav__container`, `.md-nav__toggle`, `.md-nav__item--section`)

**Interfaces:**
- `tools/rederive_overrides.py`: `PARTIALS = ("nav.html", "nav-item.html")`. `UPSTREAM = Path("overrides/.upstream/partials")`. `installed_partial(name) -> Path` (under `material/templates/partials/`). `record_diff(upstream: str, override: str, name: str) -> str` as `"".join(difflib.unified_diff(upstream.splitlines(True), override.splitlines(True), fromfile=f"{name}.upstream", tofile=name, n=3))`. `apply_diff(upstream: Path, diff: Path, out: Path) -> None` copies `upstream` to `<tmpdir>/<tofile name>` (the `+++` line of the diff), runs `git apply --check <diff>` then `git apply <diff>` with `cwd=<tmpdir>`, never `--unsafe-paths`, moves the result to `out`, and raises `SystemExit` with git's message on refusal. `main(argv) -> int` with two modes. `--record`: copy each installed partial to `UPSTREAM/<name>` and write `UPSTREAM/<name>.diff` from that copy and the current override, no apply (first use, and after a hand edit). Default, the bump flow: print `material.__version__`. Compute `delta = record_diff(committed_upstream, installed, name)`. When every delta is empty exit 1 with "installed partials equal the upstream copies; relock first". When a delta is nonempty and `--accept-delta <sha256 hex of the printed deltas>` is absent or wrong, print the deltas and return 2 without writing. When accepted, write `UPSTREAM/<name>.delta`, copy the installed partial to `UPSTREAM/<name>`, apply the stored diff, write the override, re-record the diff, and print the three steps.
- The overrides emit the two rows byte-for-byte as Task 1's fixtures, looping `config.extra.acs_nav.landing_sections` and `.external_resources` with `| e` on every value, `LANDING_ROOT` as `{{ (base_url ~ '/..') | replace('//..', '/..') }}`, `aria-current="page"` never on a docs page. `nav-item.html` adds `aria-current="page"` to the leaf branch's `<a>` when `nav_item == page`. The header comment carries the reasoning and the `--record` command.
- `overrides/README.md` carries verbatim: what each override changes. The bump sequence `git switch -c chore/mkdocs-material-<ver> origin/integration`, `uv lock --upgrade-package mkdocs-material==<ver>`, `uv run python tools/rederive_overrides.py` (read the delta it prints), `uv run python tools/rederive_overrides.py --accept-delta <hex>`, `uv run pytest -q`, `gh pr create --base integration`, then close Dependabot's pull request with a comment naming the hand one. "never on Dependabot's branch". The owner (the Documentation lead opens the bump, a project lead approves it). A "rehearsed by" line left for the approver. The Zensical check with its caveat.

- [ ] **Step 1: Write the failing tests**: `test_upstream_copies_equal_the_installed_partials` (message prints the delta and both commands). `test_recorded_diffs_equal_difflib_of_upstream_and_override`. `test_override_rows_equal_the_task_1_fixtures` (render both partials through a scratch mkdocs build and compare the two `li` blocks after whitespace collapse). `test_override_source_has_no_nav_literals` (no `#problem`, `owasp.slack.com`, `Roadmap`). `test_override_jinja_uses_no_python_method_call`. `test_rederive_record_writes_the_copies_and_diffs(tmp_path)`. `test_rederive_reproduces_the_override(tmp_path)` (the tool is given a path outside the repository). `test_rederive_refuses_a_context_change(tmp_path)` (a line inside a hunk's context edited, not inserted above). `test_rederive_refuses_an_unaccepted_delta_and_writes_nothing(tmp_path)`. `test_rederive_exits_one_when_nothing_changed(tmp_path)`. The extended theme-styles test.
- [ ] **Step 2: Run `uv run pytest tests/test_overrides.py tests/test_docs_theme.py -v`. Expected: FAIL.**
- [ ] **Step 3: Write the overrides, run the tool with `--record`, write the README.**
- [ ] **Step 4: Run `uv run mkdocs build --strict` and the tests. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Emit the shared navigation on the docs through recorded partial overrides"`

### Task 6: The shared docs build and landing render

**Files:**
- Create: `tests/_docs_build.py`
- Modify: `tests/conftest.py` (two lines plus the docstring rule), `tests/test_docs_theme.py` (drop its fixture, import `DOCS_BASE`), `tests/test_landing_page.py` (its `page` fixture returns `_docs_build.render_landing_page()`)

**Interfaces:**
- `tests/_docs_build.py`: `DOCS_BASE = "https://example.org/agent-control-standard/docs/"`. `build_docs(out: Path, base: str = DOCS_BASE) -> Path` (the body of today's fixture, failing with the build output). `render_landing_page() -> str` (the body of today's `page` fixture: `render()` with `read_nav_config(REPO / "mkdocs.yml")`).
- `tests/conftest.py`: `@pytest.fixture(scope="session") def built_docs(tmp_path_factory): return _docs_build.build_docs(tmp_path_factory.mktemp("docs"))`. The docstring gains: "Never accept a change to this file on a green suite. Inject a third-party host into a fixture and watch `tests/test_third_party_guard.py` fail first."

- [ ] **Step 1: Move the fixture and the render helper.**
- [ ] **Step 2: Run `uv run pytest tests/test_docs_theme.py tests/test_third_party_guard.py tests/test_render_landing.py tests/test_landing_page.py --setup-show -q 2>&1 | grep -c 'SETUP    S built_docs'`. Expected: `1`.**
- [ ] **Step 3: Commit, alone** `git commit -s -m "Share one session-scoped docs build across the theme and navigation tests"` with the body "Each build measured at under a second; the suite stays about 22 seconds locally and 8 seconds in CI's Run the guards."

### Task 7: The pane comparison

**Files:**
- Modify: `tests/test_site_nav.py`
- Modify: `docs/topics/faq.md` (line 170: `SHOULD-implement` to `should-implement`, the only capitalized keyword today)

**Interfaces:**
- Fixtures in this module: `@pytest.fixture(scope="module") def page(): return _docs_build.render_landing_page()`. `landing_rows(page)` via `walk_landing(page, LANDING_ROOT)` where `LANDING_ROOT = DOCS_BASE[: -len("docs/")]`. `samples(built_docs, landing_rows) -> dict[str, Path]` chosen by state: `front` is the first row whose `url == DOCS_BASE`. `leaf_depth_1` the first row with depth 1, `is_group` false, `url` starting with `DOCS_BASE` and not equal to it. `leaf_under_group` the first row with depth 2, `is_group` false, `url` starting with `DOCS_BASE`. `leaf_under_nested_group` the same at depth 3. `not_found` is `built_docs / "404.html"`. One `out_of_nav_<i>` per prefix (the first `index.html` under it). The fixture asserts the chosen paths are pairwise distinct and each exists, failing with the row it chose.
- `_css_rules(css: str) -> list[tuple[str, str, frozenset[str]]]` as `(media header or "", member selector, declarations)` by a brace walker over `conftest._strip_css_comments(css)` that splits every selector list on top-level commas, one tuple per member selector. Lookups match a member selector exactly, never a substring.
- `RFC2119 = re.compile(r"\b(MUST|MUST NOT|REQUIRED|SHALL|SHALL NOT|SHOULD|SHOULD NOT|RECOMMENDED|MAY|OPTIONAL)\b")` applied after fenced code blocks are removed.
- `REPAIR: dict[str, str]`, every value containing `mkdocs.yml` or `docs/topics/faq.md` or `overrides/partials/nav.html`, and every build-side one containing `integration`, pinned by a meta-test:
  - `page_not_in_nav`: "`{page}` is built but not in the pane. Add a titled `nav` entry for it in `mkdocs.yml`, or, if it is reachable only from its parent, add its directory to `extra.acs_nav.out_of_nav_prefixes` in `mkdocs.yml` with a comment. A pull request that adds a page targets `integration`."
  - `prefix_matches_nothing`: "`{prefix}` in `extra.acs_nav.out_of_nav_prefixes` matches no built page. Remove it from `mkdocs.yml`."
  - `rows_differ`: "The landing pane and `{page}` show different rows. Both read `mkdocs.yml`. The diff below says where. If the docs side is wrong, the override is `overrides/partials/nav.html`."
  - `faq_keyword`: "`docs/topics/faq.md` line {n} carries `{word}`. The FAQ is non-normative: lowercase the word, or move the requirement to a normative page (SPEC_REVIEW_PRINCIPLES.md principle 5)."
  - `faq_banner`: "`docs/topics/faq.md` must keep its non-normative sentence, quoted in this test from today's line 5, in its first ten lines."
  - `ceiling`: "The landing pane shows {n} rows. Re-run the fold check at 1366x768 and raise the ceiling in `tests/test_site_nav.py` in the same pull request."
  - `label_contract`: "`overrides/partials/nav.html`: label `{id}` needs an `input` with its `for`, an `id`, and a `nav[aria-labelledby]`, or Material's sidebar script throws."

- [ ] **Step 1: Write the failing tests**:

```python
def test_landing_and_every_sampled_docs_page_show_the_same_rows(...)       # REPAIR["rows_differ"] with a unified diff of the two row lists
def test_open_groups_are_the_ancestors_of_the_current_row(...)           # set equality, never subset; docs: checked set, no indeterminate, aria-expanded agrees; 404 and out-of-nav: empty
def test_exactly_one_aria_current_on_the_picked_link(...)                 # zero on 404 and out-of-nav
def test_every_pane_docs_url_is_built_and_every_built_page_is_in_the_pane_or_declared(...)  # 404 excluded; each prefix matches >= 1 (Review Focus 4)
def test_home_children_equal_the_landing_sections_in_order(...)
def test_every_pane_host_is_reviewed(...)                                 # every row with a netloc: scheme https, netloc == hostname, no backslash, hostname in the two literals unless under DOCS_BASE or LANDING_ROOT; hero CTA hosts a subset
def test_every_section_label_has_its_input_and_nav(...)                  # label.md-nav__link[for] with for != "__toc": input exists, label has an id, aria-labelledby matches; __nav_home_label and __nav_ext_label each the id of exactly one label
def test_section_rules_hold_inside_the_wide_media_block(...)             # declaration sets; the section display rule's index greater than the collapse rule's; .md-nav__container rules; .md-nav__item--nested>.md-nav>.md-nav__title has display:none; also run on the real block text of the 9.8.0 wheel pasted as a fixture (Review Focus 3)
def test_404_sample_resolves_against_the_pinned_base(...)                # the 404's #__config JSON base == urlparse(DOCS_BASE).path and its Home row URL == LANDING_ROOT (Review Focus 5)
def test_built_pages_carry_no_handler_or_script_scheme(...)              # on*, javascript:, data:, vbscript: after NOISE strip, every page
def test_built_site_carries_no_override_bookkeeping(...)                 # no built path under partials/, none ending .upstream, .diff, or .delta
def test_faq_is_non_normative_by_banner_and_vocabulary(...)
def test_every_repair_message_names_its_file(...)
```

- [ ] **Step 2: Run `uv run pytest tests/test_site_nav.py -v`. Expected: FAIL.**
- [ ] **Step 3: Implement the fixtures, the brace walker, the `REPAIR` table, and the one-word FAQ fix.**
- [ ] **Step 4: Run `uv run pytest -q`. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Hold the landing and docs panes equal, with each failure naming its repair"`

### Task 8: The deploy, the served 404, and the live check

**Files:**
- Create: `tools/verify_site_nav.py`, `tests/test_verify_site_nav.py`, `tests/test_monitor_pages_workflow.py`, `tests/test_dependabot_config.py`
- Modify: `.github/workflows/deploy-pages.yml` (after "Build the documentation site": `- name: Copy the 404 page to the site root` with `run: cp _site/docs/404.html _site/404.html`. After "Verify the published schemas", a separate step `- name: Verify the published navigation` with `timeout-minutes: 15`, `env: PAGE_URL: ${{ steps.deployment.outputs.page_url }}`, `run: python3 tools/verify_site_nav.py "$PAGE_URL"`), `.github/workflows/monitor-pages.yml` (a second job `navigation` with its own `timeout-minutes: 15`, `ref: main`, and the same call, so each check has its own conclusion), `.github/dependabot.yml` (delete `- "python"` at line 49 under the `uv` entry's `labels` and `- "github-actions"` at line 33 under the `github-actions` entry's `labels`. Both are absent from the repository, per Dependabot's comments on PR #328 and PR #303)
- Test: `tests/test_deploy_pages_workflow.py`, `tests/test_site_config.py`

**Interfaces:**
- `tools/verify_site_nav.py`, standard library only, with the measured Pages headers in its docstring (`cache-control: max-age=600`. Request `Cache-Control: no-cache`, `Pragma`, and a query string were all measured as `HIT` on 2026-10-29, so only time clears the edge): `fetch_text(url: str) -> tuple[int, str]` calling `urllib.request.urlopen(Request(url, headers={"User-Agent": "acs-verify-site-nav"}), timeout=20)`, catching `urllib.error.HTTPError as error` and returning `(error.code, error.read(5_000_000).decode("utf-8", "replace"))`, letting any other `URLError` propagate. `check(base: str, nonce: str) -> list[str]` normalizing `base = base.rstrip("/") + "/"`, fetching `base`, `base + "docs/"`, and `base + f"docs/does-not-exist-{nonce}/"`, requiring statuses 200, 200, 404 and the pane landmark on all three (a 404 without it is GitHub's page), walking the first with `walk_landing` and the others with `walk_docs`, and returning problems naming the URL and status, then the row diff. `main(argv) -> int` with nonce `f"{GITHUB_RUN_ID}-{GITHUB_RUN_ATTEMPT}"` or `int(time.time())`, retrying only a row mismatch or a non-HTTP `URLError` or a 5xx, 13 attempts at 60 seconds, failing a missing landmark after the second attempt, and writing the row lists' `difflib.unified_diff` to `$GITHUB_STEP_SUMMARY` on failure.
- Tests: `test_docs_build_precedes_the_404_copy_and_the_render`. `test_render_step_has_no_env`. `test_no_step_after_uv_install_references_a_token`. `test_navigation_verify_is_its_own_step_with_a_timeout_and_no_continue_on_error`. `test_monitor_pages_has_two_jobs_each_checking_out_main`. `test_dependabot_has_no_retired_reviewers_key`. `test_dependabot_labels_exist` (the union of every `labels` list in the file is a subset of `{"dependencies"}`, with the comment "verified against `gh label list` on 2026-10-29. `python:uv` exists and is unused"). `test_built_javascript_names_only_reviewed_hosts(built_site)` (per-file allowlist. Hosts match `^[a-z0-9.-]+$`. Template-literal matches counted separately as `RUNTIME_HOSTS = {"bundle.d7400e89.min.js": 1}`. Pattern `\b(?:https?|wss?)://`. The docstring says literal hosts only). `test_built_pages_use_only_recorded_md_components(built_site)` (the set of `data-md-component` values across built HTML equals the recorded seventeen, message: "a theme partial started binding a new bundle component. Read what the bundle does with it before recording it here. `overrides/partials/source.html` exists because `source` fetches api.github.com."). `test_fetch_text_returns_the_body_of_a_404(monkeypatch)` (constructing `HTTPError(url, 404, "Not Found", email.message.Message(), io.BytesIO(b"<nav aria-label=\"Navigation\"></nav>"))`). `test_check_reports_a_github_default_404(monkeypatch)`. `test_check_reports_a_404_on_the_docs_front(monkeypatch)`. `test_check_reports_a_row_mismatch(monkeypatch)`. `test_verifier_runs_on_the_bare_interpreter` (`[sys.executable, "-I", "-S", "tools/verify_site_nav.py"]` exits 2 with usage).

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them. Expected: FAIL.**
- [ ] **Step 3: Implement the script and edit the three workflow and config files.** Run `uv run --locked --only-group zizmor zizmor .github/workflows/deploy-pages.yml .github/workflows/monitor-pages.yml`.
- [ ] **Step 4: Run `uv run pytest -q`. Expected: PASS, and zizmor clean.**
- [ ] **Step 5: Commit** `git commit -s -m "Serve the docs 404 from the site root and verify the published pane in its own step"`

### Task 9: The words around it

**Files:**
- Modify: `CLAUDE.md` (Hosting: `mkdocs.yml` is a landing build input whose values are escaped as untrusted text. Line 82 becomes "`mkdocs.yml`: documentation site configuration and the navigation source for both the docs and the landing page. Its values render into the landing page as untrusted text". A Rollback paragraph: "Before re-running an older deploy: `gh variable set ROADMAP_REFRESH_ENABLED --body false`, or the 05:15 UTC nightly redeploys main. Expect the navigation job in `monitor-pages.yml` to stay red until the revert reaches main, since it checks out main's verifier against the rolled-back site. Re-enable the variable once the revert deploys. A red navigation verify after a green Deploy to Pages means the site is live and the edge may be stale. Re-run once, then read the step summary."), `CONTRIBUTING.md` (Development Process: a new page needs a titled `nav` entry in `mkdocs.yml`, so a page-adding pull request targets `integration`. A page outside `nav` and outside the declared prefixes fails the build. In the lane paragraph at lines 131 to 135, after the `docs/topics/` list: "A pull request that adds a page is the exception: it also adds a `nav` entry to `mkdocs.yml`, so it targets `integration`."), `GOVERNANCE.md` (as its own paragraph with a blank line after the `| Spec |` row and before `## Triage authority`: "The Documentation lead owns the re-derivation of the two theme overrides and opens the docs toolchain bump pull request, which a project lead approves, as `overrides/README.md` describes."), `.github/CODEOWNERS` (`@Lrd0036` added to `/landing/`, `/mkdocs.yml`, `/overrides/`, `/docs/stylesheets/`. Line 11 keeps `@artmaro holds write access.` byte-for-byte and the rest of lines 11 to 12 becomes `@Lrd0036 accepted write access and his entries are live.`. Lines 13 to 15 unchanged)
- Test: `tests/test_render_landing.py::test_parse_workstreams_handles_the_real_file`, `tests/test_doc_links.py` (scans GOVERNANCE.md, so the new sentence uses backticks and no link), `tests/test_governance_files.py`

- [ ] **Step 0: Ask before assigning.** Post one comment on issue #361 asking Lance Dye whether he takes the override re-derivation and the bump pull request, and whether issue #267 moves to the Documentation milestone. The GOVERNANCE sentence lands only after his reply, linked in the pull request body. Until then the task edits the other three files.
- [ ] **Step 1: Read the open hunks first**: `gh api repos/GenAI-Security-Project/agent-control-standard/pulls/292/files --jq '.[] | select(.filename=="GOVERNANCE.md" or .filename==".github/CODEOWNERS") | .patch'` and the same for PR #162 on `CONTRIBUTING.md`. Place every edit outside those hunks.
- [ ] **Step 2: Edit the four files.**
- [ ] **Step 3: Run `uv run pytest -q` and `uv run mkdocs build --strict`. Expected: PASS.**
- [ ] **Step 4: Commit** `git commit -s -m "Say who owns the navigation surfaces and how a new page reaches the pane"`

### Task 10: Pre-merge checks, repository state, and the pull request

**Files:**
- Modify: `design/2026-10-29-site-navigation-design.md` (the plan premortem's spec amendments: the walk precedence with the container rule, the section row's class list and the `is_group` definition, the `aria-expanded` and title label on the hand-emitted rows, the dot-directory storage, the delta acceptance gate, the host grammar over every row, the separate verify step and monitor job with the cache behavior, the rollback variable, the milestone sentence corrected to "the public roadmap page and the health check read the milestone's workstream. The OWASP rows carry the project name", the CODEOWNERS widening named as a permission change for the owner)
- Add to the branch by explicit `git add` of the three files only: `design/2026-10-29-site-navigation-design.md`, `design/2026-10-29-site-navigation-premortem.md`, `design/plans/2026-10-29-site-navigation.md`. Then `git status --short design/` must still show the three intake-rules files untracked
- Create: `claudedocs/pr361-body.md` (not committed), started from `.github/pull_request_template.md` verbatim

- [ ] **Step 1: The scratch checks, outputs saved under the scratchpad and quoted in the pull request body.** (a) `cp -r` the checkout to a scratch directory, `uv lock --upgrade-package mkdocs-material==9.8.0`, `uv sync --locked`, `uv run pytest tests/test_site_nav.py tests/test_overrides.py -q`. Expected: the nav tests pass and the override tests fail with the upstream-equality message (the 9.8.0 partials are identical, so the message says "relock first"). (b) In another copy add `  variant: classic` under `theme:`, run `uvx --from zensical==0.0.73 zensical build`, confirm the built front page contains `__nav_home` and `__nav_ext` and that `site_nav.walk_docs` on it equals the landing walk. Record the version and the caveat that Zensical overrides replace Zensical's own partials, so the check proves the template renders, not that it is the right partial. (c) `uv run --no-dev python tools/render_landing.py landing /tmp/nav/_site`, `python3 -m http.server 8123 --bind 127.0.0.1 --directory /tmp/nav/_site`, open `http://127.0.0.1:8123/` at 1366x768 with the Playwright MCP (`file://` is refused), screenshot the sidebar column with the theme toggle visible, and assert no console message contains `Content Security Policy` or `Refused to` (a favicon 404 is not a violation). (d) `python3 tools/verify_site_nav.py https://genai-security-project.github.io/agent-control-standard/` once against the live site. Expected before merge: it reports GitHub's default 404. (e) `uv run pytest tests/test_third_party_guard.py -q`.
- [ ] **Step 2: Repository state.** Create the milestone: `gh api repos/GenAI-Security-Project/agent-control-standard/milestones -f title="Documentation" -f description=$'Site, docs toolchain, and documentation work.\n\nType: Other\nWorkstream: Documentation' -f due_on=2026-12-31T12:00:00Z`. Verify with `gh api repos/GenAI-Security-Project/agent-control-standard/milestones --jq '.[] | select(.title=="Documentation") | .description'` and with `parse_description(text, {"Documentation"}).errors == ()`. Move with `gh issue edit 361 --repo GenAI-Security-Project/agent-control-standard --milestone Documentation` (and 267 after Lance's reply). Open the FAQ follow-up: `gh issue create --repo GenAI-Security-Project/agent-control-standard --title "[Docs] FAQ: link to ACS-Core where it restates it (three passages)" --label type:docs --label workstream:docs --label status:accepted --milestone Documentation --body-file <path>`, the body naming the three passages by heading ("Is ACS another agent framework?", "What if my framework does not have a particular hook surface?", "What happens when the Guardian fails?"), assigned to Lance only after his reply. Post the scope question as one sentence on issue #265 (does the public site join the in-focus list, or does #361 drop `scope:in-focus`). Open `[Governance] Decide whether RepositoryRole 5 stays a bypass actor on protect-integration` with labels `type:proposal`, `status:needs-triage`, milestone "Governance under OWASP", the body naming the ruleset id and the #209 bypass count.
- [ ] **Step 3: Commit the design records** `git commit -s -m "Record the site navigation design, its premortem, and its plan"`.
- [ ] **Step 4: Before any approval.** Lance (or the approving lead) rehearses the re-derivation against a scratch edit of an upstream copy. The author pushes the "rehearsed by" line to `overrides/README.md`. Every review thread is resolved. The ruleset dismisses approvals on push, so no commit follows the approval.
- [ ] **Step 5: Open the pull request** against `integration` from the template verbatim: What changed (three sentences). Under `## Which issue does this implement` write `Closes #361` and nothing else that closes, and no closing word anywhere else in the body (the follow-up issue and the design text included). Base `integration` ticked. Types Documentation, Tooling or CI, Governance. The Specification changes section deleted. "I tested this" with the suite, the build, zizmor, and the five scratch checks with their outputs. A Security subsection (escaping, the policy, the token test, the delta gate). A "Permission changes" subsection naming the four CODEOWNERS lines as a widening for the owner to confirm, and `/pyproject.toml` and `/uv.lock` as unchanged pending his call. A "Before merge" subsection linking issue #265 and the bypass issue, and carrying the rollback sentences from Task 9. Reviewers `bar-capsule` (a code owner on every touched line) and `Lrd0036` (a code owner on his four lines after this change). The approval that satisfies `protect-integration` is `bar-capsule`'s or `afogel`'s. Lance's review and rehearsal are recorded in the body, not the merge condition. After approval, add `approved by <login> on <head SHA>` to the body and merge with the squash button. A merge while the approval shows as dismissed is a bypass. Do not.

---

## Self-review

Spec coverage: pane and row rules with the container precedence and the section class list (Tasks 1, 3, 5). Source of truth, its grammar, the build-surface pin (Task 2). Renderer, escaping, policy, and the template edits that keep every caller green (Task 3). Landing styles, drawer, ceilings, sidebar guard, body parity (Task 4). Overrides, dot-directory storage, the recording and bump modes with the delta gate, README, active weight (Task 5). The shared build and render helpers (Task 6). Samples by state, every assertion with its `REPAIR` message, the real 9.8.0 fixture, the FAQ guard and fix (Task 7). The served 404, the verifier with real HTTP semantics and cache patience, its own step and job, dependabot, the JS and component scans (Task 8). CLAUDE.md with rollback, CONTRIBUTING with the lane exception, GOVERNANCE after consent, CODEOWNERS with the pinned header (Task 9). Milestone, follow-up, the owner questions filed where they will be seen, the scratch checks as runnable commands, the approval sequence that survives the ruleset (Task 10).

Type consistency: `Row`, the walkers, the open-set helpers, and the patterns from Task 1 are what Tasks 2, 3, 4, 7, and 8 use. `NavConfig`, `read_nav_config`, and `_inline_bodies` from Task 3 are what Tasks 4, 6, and 7 use. `DOCS_BASE` and `render_landing_page` from Task 6 are what Task 7 resolves against. `REPAIR` from Task 7 is what Task 4's ceiling test quotes.

Review Focus: 1 in Task 3, 2 in Task 1, 3 to 5 in Task 7.

Proportion: signatures, markup contracts, message literals, and test names. The two fixture blocks are transcribed because they are the contract two tasks must agree on byte-for-byte.
