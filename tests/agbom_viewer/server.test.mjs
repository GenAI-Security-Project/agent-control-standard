import assert from 'node:assert/strict';
import { once } from 'node:events';
import { request } from 'node:http';
import { join } from 'node:path';
import { test } from 'node:test';
import { repoRoot } from '../../tools/agbom-viewer/build.mjs';
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
