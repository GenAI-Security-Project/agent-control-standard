import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { test } from 'node:test';
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

async function inventoryRoot(t, files) {
  const base = resolve(tmpdir());
  const directory = await mkdtemp(join(base, 'agbom-viewer-test-'));
  t.after(() => {
    assert.match(relative(base, directory), /^agbom-viewer-test-[a-z0-9]+$/i);
    return rm(directory, { recursive: true, force: true });
  });
  await Promise.all(Object.entries(files).map(([name, value]) => writeFile(join(directory, name), JSON.stringify(value))));
  return [['inventory', directory]];
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

test('pairs a .agbom.json snapshot with its CycloneDX export', async () => {
  const fixtures = join(viewerRoot, 'data', 'examples', 'developer-support');
  const { inventories } = await discover([['inventory', fixtures]]);
  const exportPath = 'inventory/session-start.cdx.json';
  const matches = inventories.filter(({ cdxFile }) => cdxFile === exportPath);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].acsFile, 'inventory/session-start.agbom.json');
  assert.ok(matches[0].cdxText);
});

test('detects supported AIBOM layouts and reports a CycloneDX 1.6 ACS export as unsupported', async (t) => {
  const base = { bomFormat: 'CycloneDX', specVersion: '1.6' };
  const model = { type: 'machine-learning-model', name: 'Example model', version: '1' };
  const agent = { type: 'application', name: 'Example agent' };
  const agbom = {
    ...base, metadata: { component: agent },
    components: [{ ...model, properties: [{ name: 'acs:provenance:origin', value: 'system' }] }],
  };
  const roots = await inventoryRoot(t, {
    'metadata.json': { ...base, metadata: { component: model } },
    'nested.aibom.json': { ...base, components: [{ type: 'application', components: [model] }] },
    'top-level.json': { ...base, specVersion: '1.7', metadata: { component: agent }, components: [model] },
    'draft.aibom.json': { ...base, specVersion: '2.0-dev', inventories: [{ components: [model] }] },
    'legacy.cdx.json': agbom,
    'mixed.cdx.json': { ...base, metadata: { component: agent }, components: [model, { type: 'application', name: 'Example tool' }] },
  });
  const origin = await start(t, { roots });
  const { aiboms, inventories, notices } = await (await fetch(origin + '/api/agbom')).json();
  assert.deepEqual(aiboms.map(({ file }) => file).sort(), [
    'inventory/draft.aibom.json', 'inventory/metadata.json', 'inventory/nested.aibom.json', 'inventory/top-level.json',
  ]);
  assert.deepEqual(inventories, []);
  assert.deepEqual(notices, [
    'inventory/legacy.cdx.json · Unsupported standalone CycloneDX 1.6 document.',
    'inventory/mixed.cdx.json · Unsupported standalone CycloneDX 1.6 document.',
  ]);
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
