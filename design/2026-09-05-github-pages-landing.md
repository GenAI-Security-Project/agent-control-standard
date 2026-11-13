# GitHub Pages landing page and schema hosting

Version: 1.0
Owner: ACS project lead
Date: 2026-09-05
Status: approved design, not yet implemented

## Goal

Publish three things from this repository to GitHub Pages, rebuilt on every merge to `main`:

1. A landing page that matches the visual design of agentcontrolstandard.org.
2. The existing MkDocs specification site.
3. The JSON schemas, served at the URIs their `$id` values already declare.

Item 3 closes a known gap. Every schema in `specification/` declares an `$id` under
`https://genai-security-project.github.io/agent-control-standard/schema/<spec-version>/`.
Pages has never been enabled, so all 44 of those URIs return 404. Enabling Pages is the
precondition for fixing it.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Site scope | Landing page, docs, and schemas | The eventual domain redirect makes this the public front door. A front door needs somewhere to lead. |
| Build approach | Hand-authored HTML plus MkDocs, assembled by one workflow | Exact design fidelity with no new dependency tree. See "Approaches rejected". |
| Landing page content | Mirror the live site, plus repo-native sections | Continuity for visitors after the redirect, and the page can show live spec data the marketing site cannot. |
| Analytics | None | Material emits a Google tag with an empty ID when no key is set, leaking referrer and client IP for no benefit. Removed rather than configured. |
| Contact address | `rock.lambros@owasp.org` on the page | Amends the no-email policy in `CLAUDE.md` with a named exception. |
| Custom domain | Not yet | `agentcontrolstandard.org` redirects here in a later, separate change. |

## Architecture

One workflow assembles three independent parts into a single Pages artifact.

```
_site/
  index.html              landing page, hand-authored, generated content injected
  assets/                 stylesheet, fonts, starburst SVG, favicon
  docs/                   mkdocs build output
  schema/v0.1.0/          44 schemas, placed at the paths their $id values declare
```

Each part builds independently. A failure in any part fails the whole deploy, which is
deliberate: a half-published site is worse than a stale one.

### Approaches rejected

**MkDocs theme override for the landing page.** One build system, but Material's chrome,
CSS reset, and typography fight a full-bleed custom hero. Design fidelity is the reason
this work exists, so the approach trades away the thing being bought.

**Port the Next.js source.** Pixel-identical by construction, but it adds a Node toolchain
and a second dependency tree to a Python repository, widens supply-chain surface against
QC.1, and the source is not available. Reconstructing it from minified chunks costs more
than writing the page.

## Schema publishing

The publish path for each schema derives from that schema's own `$id`. Nothing hardcodes
directory names.

```
tools/publish_schemas.py

BASE = "https://genai-security-project.github.io/agent-control-standard/schema/"

1. Read every *.json under specification/.
2. Require an $id inside BASE. Fail the build on a missing or out-of-namespace $id.
3. Write the file to the path its $id declares.
4. Resolve every relative $ref against its enclosing $id.
   Fail the build if the target was not published.
```

Step 4 asserts closure. The package either resolves completely or the build stops.

This design fixes the root cause of a failure that hardcoded paths would reintroduce. The
on-disk layout does not match the URI layout: `specification/ACS/acs_schema.json` declares
`$id` of `.../schema/v0.1.0/acs_schema.json`. Deriving the target from `$id` handles that
without a special case, and a future `specification/v0.2.0/` publishes with no workflow
edit.

Current tree verified: 44 JSON files, 44 in-namespace `$id` values, and no `$ref` resolves
outside the `/schema/` base.

`$id` is versioned by spec version, not release version. `version.txt` reads `0.1.1` while
the spec version is `v0.1.0`. The two are separate concepts. `sync_version.py` leaves `$id`
alone by design, and this workflow does the same.

## Landing page

### Design tokens

Values taken from the live site's stylesheet, not approximated.

| Token | Light | Dark |
|---|---|---|
| page / surface | `#ffffff` / `#f4f5f7` | `#0a0a0a` / `#161616` |
| text / soft / muted | `#121212` / `#5f636d` / `#6b7079` | `#ffffff` / `#9ca3af` / `#6b7280` |
| brand | `#111111` | `#1b4f72` |
| accent navy / teal | `#1b4f72` / `#17a2b8` | `#2e86c1` / `#1abc9c` |
| border / border strong | `#e5e7eb` / `#d0d5dd` | `#2a2a2a` / `#373737` |
| footer | `#111111` | `#0a0a0a` |

Tier accents carry to the three-tier section: `#0f7b3f`, `#1b4f72`, `#6b46c1`.

Typography is Inter for text and JetBrains Mono for code, each with a full system fallback
stack. Both themes ship, with a toggle that persists the reader's choice and falls back to
`prefers-color-scheme`.

### The starburst

The hero diagram reuses the live site's SVG: a hexagonal ACS control panel at center, six
dashed spokes radiating to circular nodes labeled LLM agent, Tool call, Output guard, Sub
agent, Memory store, and Code exec. Particles travel the spokes. Orbit rings expand on an
eight second cycle.

Two changes. Node fills and strokes bind to theme tokens so the diagram works in dark mode.
All motion sits behind a `prefers-reduced-motion` guard, with a static fallback that keeps
every node, spoke, and label legible.

### Structure

```
Sidebar nav        wordmark, section links, external resources, theme toggle
Hero               "The runtime control plane for AI agents." plus starburst
The problem        agents ship fast, controls do not
The solution       Instrument, Trace, Inspect
How it works       three-tier control model
Why now            EU AI Act, NIST AI RMF
Built with         OWASP ASI, AIVSS, OpenTelemetry, CycloneDX, SPDX, MCP, A2A
Spec status        current spec version and schema index, generated at build time
Workstreams        generated from GOVERNANCE.md
Contribute         Slack, GitHub Discussions, contact address
Footer             Apache 2.0, vendor neutral, OWASP GenAI Security Project
```

Spec status and Workstreams are new sections that the marketing site cannot serve. Both
generate from repository state so they cannot drift.

Every specification link points at `docs/` on this site. No link references `aos.owasp.org`.

### Contact

- Slack: `owasp.slack.com`, channel `#team-genai-asi-acs-general`
- GitHub Discussions
- General contact: `rock.lambros@owasp.org`

Security reports continue to route through GitHub private vulnerability reporting. Code of
Conduct enforcement continues to route to the OWASP process, so a report about a maintainer
never lands with the maintainers. The `CLAUDE.md` Contact channels section gets amended in
the same commit to record the exception.

### Accessibility and layout

Links use relative paths. Root-relative paths break because a project Pages site serves from
`/agent-control-standard/`, not `/`.

The sidebar collapses to a top bar below 1024px. The starburst scales and moves below the
hero copy on narrow screens. Semantic landmarks throughout, visible focus rings using the
source `--acs-focus-ring` value, and the page works with JavaScript disabled apart from the
theme toggle.

## Pipeline

```
build   (push to main, pull_request, workflow_dispatch)
  1. uv sync --locked
  2. mkdocs build --strict -> _site/docs/
  3. render landing page, injecting spec version and workstreams -> _site/
  4. python tools/publish_schemas.py -> _site/schema/
  5. upload-pages-artifact                       (push only)

deploy  (push to main only)
  needs: build
  6. deploy-pages
  7. smoke test: /schema/v0.1.0/acs_schema.json returns 200
```

Permissions are `contents: read`, `pages: write`, `id-token: write`. Concurrency group
`pages` with `cancel-in-progress: false`, so a running deploy never gets cancelled into a
partial state. Actions are SHA-pinned, matching the two existing workflows.

Pull requests build without deploying. A broken build surfaces before merge rather than
after, which matters because merge to `main` publishes with no human in the loop.

The trigger is `pull_request`, never `pull_request_target`. Fork pull requests get a
read-only token and no access to repository secrets.

`--strict` turns a broken navigation reference into a failed build. Step 7 asserts that the
gap this project set out to close did close.

### Supporting changes

| File | Change |
|---|---|
| `mkdocs.yml` | Remove the `extra.analytics` block. No env value suppresses the Google tag, so the block itself has to go. |
| `.gitignore` | Add `_site/`, so a local build leaves no untracked output. |
| `CLAUDE.md` | Amend Contact channels to record the address exception. Add a Hosting section describing what this repository now publishes. |

The workflow sets `GITHUB_PAGES_URL` for the MkDocs build, because `mkdocs.yml` reads
`site_url` from that variable. An unset value produces a site with no canonical URL.

Generated page content injects at build time, not in the browser. A small script fills
named placeholders in the HTML template from `specification/` and `GOVERNANCE.md`. The
published page is static, so it needs no client-side fetch and renders with JavaScript
disabled.

## Risks accepted

**A docs failure blocks schema publishing.** One artifact means one deploy. A broken prose
link fails the build that also republishes schemas. Accepted because Pages keeps serving the
last successful deployment, so published schema URIs continue to resolve. Only new schema
changes wait, behind a visible red build on `main`. Splitting into two deploy targets adds
real complexity for a low-severity risk.

**The landing page is hand-maintained markup.** Volatile content generates from repository
state, but prose does not. A page that changes a few times a year is the cheaper side of
this trade.

## Domain cutover

Pointing `agentcontrolstandard.org` at this site later adds a `CNAME` file. GitHub then
issues a 301 from `genai-security-project.github.io/agent-control-standard/*` to the custom
domain.

Schema resolution survives, because JSON Schema tooling follows redirects. The `$id` URIs
stop being the address that answers directly and become the address that redirects. The
recorded reason for choosing a project-controlled base was that schema identity survives a
domain or hosting change, and a redirect honors that.

Do not rebase `$id` onto the marketing domain during the cutover.

## Out of scope

- Enabling the custom domain.
- Changes to the separate repository that builds the current agentcontrolstandard.org.
  Stale links there, including the `aos.owasp.org` specification link, live in that
  repository and resolve when the redirect lands.
- Seven A2A hook pages under `docs/spec/instrument/a2a/hooks/` are absent from the MkDocs
  navigation. They publish as orphans reachable only by direct URL. Tracked separately.

## Rollback

A build failure needs no rollback. Pages keeps serving the last successful deployment.

A successful deploy of wrong content does. In order of speed:

1. Re-run the deploy job of the last good workflow run from the Actions tab. Artifact
   retention is 30 days, so this stays available for a month.
2. `git revert` the offending commit, then merge. This takes a full pipeline run.

Both are available to anyone with write access. The scheduled monitor in
`.github/workflows/monitor-pages.yml` checks every six hours that the schema endpoints
still serve their own `$id`, so a silent regression surfaces within that window rather
than waiting for a consumer to report it.

A failed verification step is not a failed deploy. `actions/deploy-pages` runs before the
check, so a red run with a green deploy job means the site is live and the check could not
confirm it inside its retry window. Read the step log before reverting anything. Reverting
a good deploy because a check was unlucky costs more than waiting for the next run.

## Status

The site went live on 2026-09-05. The first deploy succeeded, and all 44 schema URIs were
confirmed serving their own `$id`. The `github-pages` environment is restricted to
protected branches, which is the second layer behind the workflow's own branch check.
