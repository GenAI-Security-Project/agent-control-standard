# Maintain the AgBOM Viewer

Use Node.js 22 or later. Run the commands below from the repository root. To inspect your own BOMs, see [Inspect Local BOMs](../../docs/spec/inspect/agbom_viewer_local.md).

## Rebuild the public viewer data

Edit the mapping data and viewer configuration in `tools/agbom-viewer/`. The shared viewer assets and indexed examples live in `docs/spec/inspect/agbom-viewer/`.

After changing the mapping data, field reference, viewer configuration, or indexed examples, regenerate `docs/spec/inspect/agbom-viewer/viewer-data.js` and include it with the input changes.

```sh
node tools/agbom-viewer/build.mjs
```

## Run the CI checks locally

```sh
node tools/agbom-viewer/build.mjs --check
node --test tests/agbom_viewer/evidence.test.mjs tests/agbom_viewer/server.test.mjs
```

## Run the browser tests

Install the locked Playwright package with npm, then use it to download its matching headless Chromium.

```sh
npm ci --prefix tests/agbom_viewer
npm --prefix tests/agbom_viewer exec -- playwright install chromium --only-shell
node --test tests/agbom_viewer/browser.test.mjs
```

The optional Museum browser test runs when `VIEWER_MUSEUM_PACK` points to a local Museum fixture pack.
