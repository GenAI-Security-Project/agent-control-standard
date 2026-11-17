# Theme overrides

MkDocs Material renders any template in this directory in place of its own. Four partials are overridden here.

- `partials/source.html` drops the theme's GitHub API fetch from the header repository link. It is written for this project and tracks no upstream file.
- `partials/header.html` is Material's partial with the logo and the site title both linking to the landing page, which is what the landing page's own header does. The target is derived from `base_url`, so it holds on the custom domain and on the project subpath.
- `partials/nav.html` is Material's partial with two rows added to the left pane and the drawer logo pointed at the landing page. Home links back to the landing page and opens to its sections. External resources lists the project's outside links. Both rows read `extra.acs_nav` in `mkdocs.yml`, the same block the landing page renderer reads, so the two panes show the same rows.
- `partials/nav-item.html` is Material's partial with one change. The current page's link carries `aria-current="page"`, which `docs/stylesheets/extra.css` sets in weight 600 to match the landing page.

## How the three Material overrides stay reproducible

Each Material override is an installed partial plus a small change. `.upstream/partials/` holds a byte copy of the installed partial and the unified diff from that copy to the override. MkDocs skips dot directories, so none of these files is published.

`tools/rederive_overrides.py` keeps the three in step. After a hand edit of an override, record the change. `--record` only re-records the diff from the committed copy and never re-baselines the upstream copy. It refuses when the installed partial differs from the committed copy, because that is a bump and goes through the bump flow below.

```bash
uv run python tools/rederive_overrides.py --record
```

The test suite fails when an override and its recorded diff disagree, and when the installed partials differ from the committed copies.

## Bumping mkdocs-material

When Dependabot's checks are green, the partials did not change and its pull request merges as is. The hand flow below is for a red `test_upstream_copies_equal_the_installed_partials`. Do that bump by hand on its own branch, never on Dependabot's branch, because Dependabot's pull request changes the lock file only.

1. `git switch -c chore/mkdocs-material-<ver> origin/integration`
2. `uv lock --upgrade-package mkdocs-material==<ver>`
3. `uv run python tools/rederive_overrides.py` and read the delta it prints. That is everything upstream changed in the three partials.
4. `uv run python tools/rederive_overrides.py --accept-delta <hex>`
5. `uv run pytest -q`
6. `gh pr create --base integration`
7. Close Dependabot's pull request with a comment naming the hand one.

Step 4 writes nothing unless the hex is the sha256 of the delta printed in step 3. It saves the delta beside each copy as `<name>.delta`, copies the installed partial over the committed copy, replays the recorded diff with `git apply`, and records the diff again. When upstream edits a line the diff carries as context, `git apply` refuses and nothing is written. Port the change to the new partial by hand, then run `--record`.

The Documentation lead opens the bump pull request. A project lead approves it.

Rehearsed by:

## Checking the overrides under Zensical

Zensical is the planned successor to Material and renders these templates with MiniJinja, which is why the overrides use Jinja filters only and never a Python method call. To check that they still render, work in a scratch copy of the checkout, add `variant: classic` under `theme:` in `mkdocs.yml`, and run:

```bash
uvx --from zensical==0.0.73 zensical build
```

The built front page should contain `__nav_home` and `__nav_ext`. The check has a limit. Zensical overrides replace Zensical's own partials, not Material's, so a pass proves the template renders, not that it is the right partial for Zensical.
