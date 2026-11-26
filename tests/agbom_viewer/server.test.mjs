import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { repoRoot, root as viewerRoot } from '../../tools/agbom-viewer/build.mjs';
import { discover } from '../../tools/agbom-viewer/inventory.mjs';
import { createViewerServer, docsPath } from '../../tools/agbom-viewer/serve.mjs';

async function start(t, options) {
  const server = await createViewerServer(options);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => {
    server.closeAllConnections();
    return new Promise((done) => server.close(done));
  });
  return 'http://127.0.0.1:' + server.address().port;
}

async function temporaryInventory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'agbom-inventory-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test('the viewer command reports an occupied port and exits with an error', async (t) => {
  const blocker = createServer();
  try {
    blocker.listen(4173, '127.0.0.1');
    await once(blocker, 'listening');
  } catch (error) {
    if (error.code !== 'EADDRINUSE') throw error;
    t.skip('Another process already owns 127.0.0.1:4173.');
    return;
  }
  t.after(() => new Promise((done) => blocker.close(done)));

  await assert.rejects(
    promisify(execFile)(process.execPath, [join(viewerRoot, 'serve.mjs')], { timeout: 5000 }),
    (error) => {
      assert.equal(error.code, 1);
      assert.equal(error.stdout, '');
      assert.match(error.stderr, /127\.0\.0\.1:4173 is already in use/);
      assert.match(error.stderr, /Stop the process using port 4173 and rerun this command/);
      return true;
    },
  );
});

test('the local server serves the read-only inventory workflow over loopback', async (t) => {
  const origin = await start(t, { roots: [['inventory', join(repoRoot, 'tests', 'agbom_viewer', 'fixtures')]] });
  const page = await fetch(origin);
  assert.match(await page.text(), /Local BOMs/);
  const endpoint = origin + '/api/agbom';
  const response = await fetch(endpoint);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const { inventories } = await response.json();
  assert.ok(inventories.some(({ acsFile, cdxText }) => acsFile === 'inventory/startup.acs.json' && cdxText));
  const head = await fetch(endpoint, { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  const write = await fetch(endpoint, { method: 'POST' });
  assert.equal(write.status, 405);
  assert.equal(write.headers.get('allow'), 'GET, HEAD');
  assert.equal((await fetch(origin + '/inventory/startup.acs.json')).status, 404);
  const forbiddenHost = await new Promise((resolve, reject) => {
    request(endpoint, { headers: { Host: 'example.org' } }, (response) => {
      response.resume();
      resolve(response.statusCode);
    }).on('error', reject).end();
  });
  assert.equal(forbiddenHost, 403);
});

test('the local server applies one file count limit across inventory subfolders', async (t) => {
  const dir = await temporaryInventory(t);
  const nested = join(dir, 'captures');
  await mkdir(nested);
  const snapshot = '{"agbom_version":"0.1.0"}';
  await Promise.all(Array.from({ length: 98 }, (_, i) => writeFile(join(nested, `capture-${i}.json`), snapshot)));
  await writeFile(join(nested, 'malformed.json'), '{');
  await writeFile(join(dir, 'last.json'), snapshot);

  const origin = await start(t, { roots: [['inventory', dir]] });
  const endpoint = origin + '/api/agbom';
  const atLimit = await (await fetch(endpoint)).json();
  assert.equal(atLimit.inventories.length, 99);
  assert.ok(atLimit.inventories.some(({ acsFile }) => acsFile === 'inventory/last.json'));
  assert.equal(atLimit.limitReached, false);

  await writeFile(join(dir, 'overflow.json'), snapshot);
  const overLimit = await (await fetch(endpoint)).json();
  assert.deepEqual(overLimit.inventories, atLimit.inventories);
  assert.equal(overLimit.limitReached, true);
  assert.ok(overLimit.notices.some((notice) => /limit reached \(100 JSON files per refresh\)/.test(notice)));
});

test('the local server skips oversized files and accepts a file at the byte limit', async (t) => {
  const dir = await temporaryInventory(t);
  const maxBytes = 1024 * 1024;
  await writeFile(join(dir, 'a-oversized.json'), '{"agbom_version":"0.1.0","name":"é"}'.padEnd(maxBytes));
  await writeFile(join(dir, 'b-at-limit.json'), '{"agbom_version":"0.1.0"}'.padEnd(maxBytes));

  const origin = await start(t, { roots: [['inventory', dir]] });
  const { inventories, notices, limitReached } = await (await fetch(origin + '/api/agbom')).json();
  assert.deepEqual(inventories.map(({ acsFile }) => acsFile), ['inventory/b-at-limit.json']);
  assert.equal(Buffer.byteLength(inventories[0].acsText), maxBytes);
  assert.equal(limitReached, true);
  assert.ok(notices.some((notice) => /inventory\/a-oversized\.json.*exceeds the 1 MiB per-file limit/.test(notice)));
});

test('pairs a .agbom.json snapshot with its CycloneDX export', async () => {
  const fixtures = join(viewerRoot, 'data', 'examples', 'developer-support');
  const { inventories } = await discover([['inventory', fixtures]]);
  const exportPath = 'inventory/session-start.cdx.json';
  const matches = inventories.filter(({ cdxFile }) => cdxFile === exportPath);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].acsFile, 'inventory/session-start.agbom.json');
  assert.ok(matches[0].cdxText);
});

test('the public preview serves only public viewer files', async (t) => {
  const origin = await start(t, { mode: 'public' });
  const viewer = origin + docsPath;
  const page = await fetch(viewer);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Sample AgBOM/);
  for (const path of ['/api/agbom', docsPath + 'api/agbom', docsPath + 'local.js', docsPath + 'local-evidence.mjs',
    docsPath + 'examples/museum-kiosk.cdx.json']) {
    assert.equal((await fetch(origin + path)).status, 404, path);
  }
});
