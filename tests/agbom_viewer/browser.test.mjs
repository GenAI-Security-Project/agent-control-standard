import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { publicDir, root } from '../../tools/agbom-viewer/build.mjs';
import { createViewerServer, docsPath } from '../../tools/agbom-viewer/serve.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.VIEWER_PLAYWRIGHT ?? 'playwright');
let browser;

before(async () => {
  browser = await chromium.launch({ executablePath: process.env.VIEWER_BROWSER });
});
after(async () => browser?.close());

async function httpViewer(t, options) {
  const server = await createViewerServer(options);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); return new Promise((done) => server.close(done)); });
  return 'http://127.0.0.1:' + server.address().port;
}

async function monitoredPage(t, options) {
  const page = await browser.newPage(options);
  page.setDefaultTimeout(7000);
  const errors = [];
  const requests = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (msg) => { if (msg.type() === 'error') errors.push(msg.text()); });
  page.on('request', (request) => requests.push(request.url()));
  t.after(async () => {
    await page.context().close();
    assert.deepEqual(errors, []);
  });
  return { page, requests };
}

const downloadPath = 'examples/sample-cyclonedx.json';
const bodyText = (page, selector) => page.locator(selector).innerText();

test('public sample at the nested ACS path, with mobile keyboard review and exact download', async (t) => {
  const origin = await httpViewer(t, { mode: 'public' });
  const { page, requests } = await monitoredPage(t, { viewport: { width: 390, height: 844 }, reducedMotion: 'reduce' });
  await page.goto(origin + docsPath);
  assert.equal(await bodyText(page, '#sample-title'), 'Sample AgBOM');
  assert.equal(await bodyText(page, 'h1'), 'AgBOM Viewer');
  assert.equal(await bodyText(page, '.brand'), 'OWASP ACS - AgBOM Viewer');
  assert.match(await bodyText(page, '#sample-json'), /"specVersion": "2\.0-dev"/);
  assert.equal(await page.getByRole('link', { name: 'Local BOMs', exact: true }).count(), 0);
  assert.equal(await page.locator('#your-inventories').count(), 0);
  for (const path of ['/api/agbom', docsPath + 'api/agbom', docsPath + 'local.js']) {
    assert.equal((await page.request.get(origin + path)).status(), 404);
  }
  assert.equal(await page.locator('#agbom').count(), 0);
  assert.equal(await page.getByText('Model AIBOM reference', { exact: true }).count(), 0);
  assert.equal(await page.locator('#agbom-json table').count(), 0);
  assert.equal(await page.getByRole('link', { name: 'Review full mapping' }).getAttribute('href'), '#cyclonedx-mapping/all');
  assert.deepEqual(await page.evaluate(async () => {
    await document.fonts.ready;
    return [...document.fonts].map((font) => font.status);
  }), ['loaded']);
  await page.keyboard.press('Tab');
  assert.equal(await page.locator(':focus').textContent(), 'Skip to viewer');
  await page.getByRole('button', { name: 'Light mode' }).press('Enter');
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
  await page.getByRole('link', { name: 'CycloneDX mapping', exact: true }).press('Enter');
  assert.equal(await page.locator(':focus').textContent(), 'CycloneDX mapping');
  assert.equal(await page.locator('#question option:checked').textContent(), 'All mapping rules');
  assert.ok(await page.locator('#evidence .path').first().isVisible());
  await page.getByRole('checkbox', { name: 'Show JSON paths' }).uncheck();
  await page.locator('#evidence .rule-link a').first().click();
  assert.ok(await page.locator('details.rule-card[open]').isVisible());
  assert.equal(await page.locator('.rule-card').count(), 54);
  await page.getByRole('link', { name: 'Field reference', exact: true }).click();
  await page.getByText('CycloneDX document fields', { exact: false }).first().click();
  assert.match(await bodyText(page, '#reference-content'), /serialNumber\s+string\s+Optional/);
  const components = page.locator('#reference-content details').filter({ has: page.locator('summary', { hasText: /^Components/ }) });
  await components.locator('summary').click();
  const region = components.getByRole('region', { name: 'Components' });
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 844 });
    const layout = await region.evaluate((region) => {
      const rows = [...region.querySelectorAll('tbody tr')];
      const long = rows.find((row) => row.cells[3].innerText.length > 400);
      const multiple = rows.find((row) => row.cells[4].querySelectorAll('a').length > 1);
      const links = [...multiple.cells[4].querySelectorAll('a')];
      const fits = links.every((link) => {
        const range = document.createRange();
        range.selectNodeContents(link);
        const glyphs = [...range.getClientRects()];
        const cell = multiple.cells[4].getBoundingClientRect();
        return glyphs.length === 1 && glyphs[0].right <= cell.right;
      });
      const ruleHeader = region.querySelector('thead th:last-child');
      const range = document.createRange();
      range.selectNodeContents(ruleHeader);
      region.scrollLeft = region.scrollWidth;
      return {
        fits,
        oneLineHeader: range.getClientRects().length === 1,
        descriptionWraps: long.cells[3].getBoundingClientRect().height > 60,
        scrolls: region.scrollLeft > 0,
      };
    });
    assert.deepEqual(layout, { fits: true, oneLineHeader: true, descriptionWraps: true, scrolls: width === 390 });
  }
  const rule = components.getByRole('link', { name: 'View Rule AG-030', exact: true });
  await rule.click();
  assert.match(await bodyText(page, '#AG-030'), /Rule detail/);
  assert.match(await bodyText(page, '#AG-030'), /Description/);
  await page.getByRole('link', { name: 'CycloneDX mapping', exact: true }).click();
  assert.equal(await page.locator('#evidence .path').first().isVisible(), false);
  await page.getByRole('checkbox', { name: 'Show JSON paths' }).check();
  const unresolved = await page.locator('.rule-card').evaluateAll((cards) => cards.map(({id}) => id).filter((id) =>
    ![...document.querySelectorAll('#evidence tr')].some((row) =>
      row.querySelector('a[href="#' + id + '"]') && row.querySelectorAll('td code.literal, td code.inline-code').length >= 2)));
  assert.deepEqual(unresolved, [], 'each rule has positive evidence in the primary example');
  const reference = page.locator('#evidence tr').filter({ hasText: 'Referenced model AIBOM' });
  assert.match(await reference.innerText(), /sample-model\.aibom\.json/);
  assert.match(await reference.innerText(), /No dedicated ACS model field/);
  assert.equal(await reference.getByRole('link', { name: /View Rule/ }).count(), 0);
  await reference.getByRole('button', { name: 'Open AIBOM JSON' }).click();
  assert.match(await bodyText(page, '#aibom-json'), /"specVersion": "1\.7"/);
  await page.getByRole('button', { name: 'Close' }).click();
  const focus = page.locator('#focus-filter');
  for (const kind of ['document', 'model', 'mcp_server', 'a2a_peer', 'tool', 'skill', 'knowledge_source', 'memory_store', 'agent_capability']) {
    await focus.selectOption(kind);
    assert.ok(await page.locator('#evidence tbody tr').count(), kind + ' has matching fields');
  }
  await focus.selectOption('a2a_peer');
  await page.locator('#group-filter').selectOption('Evidence questions');
  assert.match(await bodyText(page, '#evidence'), /Agent card ref/);
  assert.match(await bodyText(page, '#evidence'), /Protocol version/);
  await page.locator('#coverage-filter').selectOption('ACS convention');
  assert.deepEqual([...new Set(await page.locator('#evidence .badge').allTextContents())], ['ACS convention']);
  await page.locator('#coverage-filter').selectOption('');
  await focus.selectOption('document');
  await page.locator('#group-filter').selectOption('Document and agent');
  await focus.selectOption('model');
  assert.equal(await page.locator('#group-filter').inputValue(), '');
  assert.match(await reference.innerText(), /externalReferences\[0\]\.url/);
  await page.locator('#question').selectOption({ label: 'Which AIBOM file describes this model revision?' });
  assert.equal(await page.locator('#evidence tbody tr').count(), 1);
  assert.match(await reference.innerText(), /sample-model\.aibom\.json/);
  await page.getByRole('button', { name: 'All mapping rules' }).click();
  for (const id of ['focus-filter', 'group-filter', 'coverage-filter', 'question']) {
    assert.equal(await page.locator('#' + id).inputValue(), '');
  }
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390);
  await page.getByRole('link', { name: 'Sample AgBOM', exact: true }).click();
  await page.locator('#sample-component').selectOption('model-1');
  await page.getByRole('button', { name: 'Expected types in JSON' }).click();
  assert.match(await bodyText(page, '#sample-mode-note'), /Reading guide/);
  assert.match(await bodyText(page, '#sample-json'), /<URI for the model AIBOM>/);
  await page.getByRole('link', { name: 'Review this component’s mapping' }).click();
  assert.equal(await page.locator('#focus-filter').inputValue(), 'model');
  const context = page.locator('#evidence tr').filter({ has: page.getByRole('link', { name: 'View Rule AG-029', exact: true }) });
  assert.match(await context.locator('td').nth(0).innerText(), /model_fields\.context_window\s+integer\s+64000/);
  assert.match(await context.locator('td').nth(1).innerText(), /Property acs:model:context_window\s+string containing an integer\s+"64000"/);
  const files = await bodyText(page, '#cyclonedx-mapping');
  assert.match(files, /ACS source\s+examples\/sample-agbom-v0.1.0.json/);
  assert.match(files, /CycloneDX sample\s+examples\/sample-cyclonedx.json/);
  for (const filename of ['sample-agbom-v0.1.0.json', 'sample-cyclonedx.json']) assert.equal(files.split(filename).length - 1, 1);
  assert.ok((await page.locator('#evidence .path').allTextContents()).every((path) => path.startsWith('$')));
  await page.getByRole('link', { name: 'Sample AgBOM', exact: true }).click();
  await page.locator('#sample-component').selectOption('all');
  await page.getByRole('link', { name: 'Review full mapping' }).click();
  assert.equal(await page.locator('#focus-filter').inputValue(), '');
  assert.equal(await page.locator('#question').inputValue(), '');
  await page.getByRole('link', { name: 'Sample AgBOM', exact: true }).click();
  await page.locator('#sample-component').selectOption('model-1');
  const waiting = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download full CycloneDX 2.0-dev AgBOM JSON' }).click();
  const download = await waiting;
  assert.equal(download.suggestedFilename(), 'sample-cyclonedx.json');
  assert.deepEqual(await readFile(await download.path()), await readFile(join(publicDir, downloadPath)));
  assert.ok(requests.every((url) => url.startsWith(origin + docsPath) && !url.includes('/api/agbom')), requests.join('\n'));
});

test('file URL works offline with the local font and sample download', async (t) => {
  const { page, requests } = await monitoredPage(t, { offline: true });
  await page.goto(pathToFileURL(join(publicDir, 'index.html')).href);
  assert.equal(await bodyText(page, '#sample-title'), 'Sample AgBOM');
  assert.deepEqual(await page.evaluate(async () => {
    await document.fonts.ready;
    return [...document.fonts].map((font) => font.status);
  }), ['loaded']);
  const waiting = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download full CycloneDX 2.0-dev AgBOM JSON' }).click();
  assert.deepEqual(await readFile(await (await waiting).path()), await readFile(join(publicDir, downloadPath)));
  await page.getByRole('link', { name: 'Explore Use Cases' }).click();
  assert.match(await bodyText(page, '#case-context'), /finance assistant/);
  assert.match(await bodyText(page, '.stage-artifacts'), /example-ledger-agent_startup\.cdx\.json/);
  const source = page.locator('.stage-artifacts details').filter({ hasText: 'View ACS source inventory' });
  assert.equal(await source.getAttribute('open'), null);
  assert.equal(await source.locator('.artifact-filename').isVisible(), false);
  await source.locator('summary').click();
  assert.match(await source.innerText(), /example-ledger-agent_startup\.acs\.json/);
  const reference = page.locator('.stage-evidence tr').filter({ hasText: 'Referenced model AIBOM' });
  assert.match(await reference.innerText(), /example-ledger-model\.aibom\.json/);
  assert.match(await reference.innerText(), /urn:cdx:.*\/1/);
  assert.match(await reference.innerText(), /Document ID .*BOM revision 1/);
  assert.equal(await page.locator('#investigation-focus-filter option[value="a2a_peer"]').textContent(), 'A2A peer (absent)');
  await page.locator('#investigation-focus-filter').selectOption('model');
  assert.match(await reference.innerText(), /example-ledger-model\.aibom\.json/);
  await page.locator('#investigation-question').selectOption({ label: 'Which AIBOM file describes this model revision?' });
  assert.equal(await page.locator('.stage-evidence tbody tr').count(), 1);
  await reference.getByRole('button', { name: 'Open AIBOM JSON' }).click();
  assert.equal(await bodyText(page, '#aibom-title'), 'example-ledger-model.aibom.json');
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'After tool discovery' }).click();
  await page.locator('#scenario-baseline').selectOption('ledger-startup');
  const comparison = page.getByRole('table', { name: 'Stage comparison' });
  assert.match(await comparison.innerText(), /Baseline · Startup/);
  assert.match(await comparison.innerText(), /Selected stage · After tool discovery/);
  const added = comparison.getByRole('row', { name: /Component added.*Search/ });
  assert.match(await added.locator('td').nth(0).innerText(), /Absent/);
  assert.match(await added.locator('td').nth(1).innerText(), /Search tool/);
  assert.doesNotMatch(await added.locator('td').nth(1).innerText(), /search-tool/);
  await added.getByText('Technical details', { exact: true }).click();
  assert.match(await added.locator('td').nth(1).innerText(), /search-tool/);
  const edge = comparison.getByRole('row', { name: /Relationship added.*Ledger MCP server exposes Search/ });
  assert.match(await edge.locator('td').nth(0).innerText(), /Absent/);
  assert.match(await edge.locator('td').nth(1).innerText(), /Ledger MCP server exposes Search/);
  assert.doesNotMatch(await edge.locator('td').nth(1).innerText(), /acs:exposes-tool|search-tool|ledger-mcp-server/);
  await edge.getByText('Technical details', { exact: true }).click();
  assert.match(await edge.locator('td').nth(1).innerText(), /ledger-mcp-server → acs:exposes-tool → search-tool/);
  assert.match(await bodyText(page, '.stage-artifacts'), /example-ledger-agent_after-discovery\.cdx\.json/);
  assert.ok((await page.locator('.stage-evidence .path').allTextContents()).every((path) => path.startsWith('$')));
  await page.getByRole('button', { name: /Startup/ }).click();
  await page.locator('#scenario-baseline').selectOption('ledger-after-discovery');
  assert.match(await comparison.innerText(), /Baseline · After tool discovery/);
  const removed = comparison.getByRole('row', { name: /Component removed.*Search/ });
  assert.match(await removed.locator('td').nth(0).innerText(), /Search/);
  assert.match(await removed.locator('td').nth(1).innerText(), /Absent/);
  const removedEdge = comparison.getByRole('row', { name: /Relationship removed.*Ledger MCP server exposes Search/ });
  assert.match(await removedEdge.locator('td').nth(0).innerText(), /Ledger MCP server exposes Search/);
  assert.match(await removedEdge.locator('td').nth(1).innerText(), /Absent/);
  await page.locator('#scenario-baseline').selectOption('');
  assert.equal(await comparison.count(), 0);
  assert.ok(await page.getByRole('heading', { name: 'Investigate this stage · Startup' }).isVisible());
  assert.ok(requests.every((url) => url.startsWith('file:') && !url.includes('/api/agbom')));
});

test('local captures, comparison, pairing, partial data, events and original AIBOMs', async (t) => {
  const base = resolve(tmpdir());
  const fixture = await mkdtemp(join(base, 'agbom-viewer-test-'));
  t.after(async () => {
    assert.match(relative(base, fixture), /^agbom-viewer-test-[a-z0-9]+$/i);
    await rm(fixture, { recursive: true, force: true });
  });
  const scenario = join(root, 'data', 'examples', 'developer-support');
  const initial = JSON.parse(await readFile(join(scenario, 'session-start.agbom.json'), 'utf8'));
  const latest = JSON.parse(await readFile(join(scenario, 'after-discovery.agbom.json'), 'utf8'));
  const payload = '<img src="https://example.invalid/inert.png" onerror="alert(1)">';
  initial.agent.name = payload;
  initial.agbom_version = '0.0.9';
  latest.components.reverse();
  latest.components.find(({id}) => id === 'support-triage-model').version = 'next-revision';
  const save = async (name, obj) => writeFile(join(fixture, name), JSON.stringify(obj));
  for (const folder of ['early', 'later', 'partial']) await mkdir(join(fixture, folder));
  await save('early/my-agent.json', initial);
  await save('later/my-agent.json', latest);
  await save('partial/my-agent.acs.json', { agbom_version: '0.1.0', agent: { agent_id: 'partial' }, components: [
    { id: 'ambiguous', type: 'model', name: '', model_fields: { context_window: 0, args: { flag: false, value: null } } },
    { id: 'ambiguous', type: 'model', name: 'Incomplete' },
  ] });
  const sourceBefore = await readFile(join(fixture, 'later/my-agent.json'));
  await writeFile(join(fixture, 'partial/my-agent.cdx.json'), '{ malformed');
  await save('unassociated.event.json', JSON.parse(await readFile(join(scenario, 'discovery-diff.event.json'), 'utf8')));
  const origin = await httpViewer(t, { roots: [['inventory', fixture]] });
  const { page, requests } = await monitoredPage(t);
  await page.goto(origin);
  const local = page.getByRole('link', { name: 'Local BOMs', exact: true });
  assert.equal(await local.getAttribute('href'), '#your-inventories');
  await local.click();
  assert.ok(await page.getByRole('heading', { name: 'Local BOMs', exact: true }).isVisible());
  assert.ok(await page.getByText(
    'Open an ACS inventory, a CycloneDX AgBOM, or a model AIBOM from the local inventory folder.',
    { exact: true },
  ).isVisible());
  await page.locator('#agbom').waitFor();
  assert.equal(await page.locator('#agbom option').count(), 3);
  assert.equal(await page.getByRole('heading', { name: 'Snapshot history' }).count(), 0);
  await page.locator('#manual-baseline').selectOption('inventory/early/my-agent.json');
  await page.locator('#manual-target').selectOption('inventory/later/my-agent.json');
  assert.match(await bodyText(page, '#personal-comparison'), /next-revision/);
  assert.match(await bodyText(page, '#personal-comparison'), /Added components \(2\)/);
  assert.match(await bodyText(page, '#personal-comparison'), /Changed typed relationships \(1\)/);
  await page.locator('#manual-baseline').selectOption('inventory/later/my-agent.json');
  await page.locator('#manual-target').selectOption('inventory/early/my-agent.json');
  assert.match(await bodyText(page, '#personal-comparison'), /Removed components \(2\)/);
  await page.locator('#personal-events > details > summary').click();
  assert.match(await bodyText(page, '#personal-events'), /No associated baseline/);
  await page.locator('#agbom').selectOption('inventory/early/my-agent.json');
  assert.match(await bodyText(page, '#personal-artifacts'), /AgBOM schema\s+0\.0\.9/);
  assert.equal(await page.getByRole('link', { name: 'Download sample AgBOM JSON' }).isVisible(), false);
  assert.match(await bodyText(page, '#personal-artifacts .inventory-summary'), /<img src=/);
  assert.equal(await page.locator('img').count(), 0);
  assert.match(await bodyText(page, '#personal-artifacts'), /No CycloneDX export supplied/);
  const goodCdx = { specFormat: 'CycloneDX', specVersion: '2.0', inventories: [{ subject: { refId: latest.agent.agent_id }, components: [] }],
    properties: [{ name: 'acs:generated_at', value: 'different' }] };
  await save('later/my-agent.cdx.json', goodCdx);
  await save('capture-index.json', { series: [{ id: 'explicit', label: 'Manual test series', captures: [
    { file: 'early/my-agent.json', label: 'One' }, { file: 'later/my-agent.json', label: 'Two' }
  ] }] });
  await local.click();
  await page.getByRole('button', { name: 'Refresh local inventory' }).click();
  await page.getByRole('heading', { name: 'Snapshot history' }).waitFor();
  await page.locator('#agbom').selectOption('inventory/later/my-agent.json');
  assert.match(await bodyText(page, '#personal-artifacts'), /Pairing mismatch \(snapshot time\)/);
  goodCdx.properties[0].value = latest.generated_at;
  await save('later/my-agent.cdx.json', goodCdx);
  await local.click();
  const updated = page.waitForResponse((response) => response.url().endsWith('/api/agbom'));
  await page.getByRole('button', { name: 'Refresh local inventory' }).click();
  await updated;
  await page.locator('#personal-artifacts').getByText('View CycloneDX JSON').waitFor();
  await page.locator('#personal-artifacts').getByText('View CycloneDX JSON').click();
  assert.match(await bodyText(page, '#personal-artifacts'), /inventory\/later\/my-agent.cdx.json/);
  await page.locator('#agbom').selectOption('inventory/partial/my-agent.acs.json');
  assert.match(await bodyText(page, '#personal-artifacts'), /Expected a valid CycloneDX 2.0 draft export/);
  await page.locator('#inventory-notices summary').click();
  assert.match(await bodyText(page, '#inventory-notices'), /\.provider is required and missing/);
  assert.match(await bodyText(page, '#inventory-notices'), /Ambiguous component ID/);
  await page.getByRole('link', { name: 'Explore Use Cases' }).click();
  await page.locator('#use-case-choice').selectOption('developer');
  assert.match(await bodyText(page, '.stage-artifacts'), /session-start\.cdx\.json/);
  const modelRow = page.locator('.stage-evidence tr').filter({ hasText: 'Referenced model AIBOM' });
  assert.match(await modelRow.innerText(), /Qwen_Qwen2\.5-0\.5B-Instruct_aibom_1_7\.json/);
  assert.match(await modelRow.innerText(), /Filename from model-associations\.json/);
  assert.match(await bodyText(page, '#scenario-content'), /7ae55760/);
  assert.match(await bodyText(page, '#scenario-content'), /Agent-selectable triage model/);
  await page.getByRole('button', { name: 'After tool discovery' }).click();
  assert.match(await bodyText(page, '#scenario-content'), /2e1fd397/);
  assert.match(await bodyText(page, '#scenario-content'), /Tool backend · Review a code change tool/);
  assert.match(await bodyText(page, '#scenario-content'), /Matching recorded identifier and revision/);
  assert.doesNotMatch(await bodyText(page, '#scenario-content'), /17955505\d+/);
  await page.locator('#scenario-baseline').selectOption('data/examples/developer-support/session-start.agbom.json');
  assert.equal(await page.locator('#scenario-content .timeline [aria-pressed="true"]').count(), 2);
  assert.match(await bodyText(page, '#scenario-content'), /Calculated from CycloneDX artifacts/);
  await page.getByText('Reported by ACS change event · Component diff', { exact: true }).click();
  assert.match(await bodyText(page, '#scenario-content'), /Reported component changes agree with/);
  assert.match(await bodyText(page, '#scenario-content'), /mcp-review-list-tools/);
  await page.getByText('Reported by ACS change event · Full snapshot', { exact: true }).click();
  assert.match(await bodyText(page, '#scenario-content'), /Embedded snapshot matches/);
  await page.getByText('agbom/snapshot · Session-start snapshot', { exact: true }).click();
  assert.match(await bodyText(page, '#scenario-content'), /session_start/);
  await save('standalone.cdx.json', { specFormat: 'CycloneDX', specVersion: '2.0-dev', inventories: [
    { subject: { refId: 'independent', name: 'Independent CycloneDX' }, components: [
      { refId: 'model', type: 'machine-learning-model', name: 'Imported model', version: '7ae55760',
        externalReferences: [{ type: 'bom', url: 'https://example.invalid/unknown.json' }] },
      { refId: 'external-server', type: 'service', name: 'Example API', properties: [{name: 'acs:kind', value: 'mcp_server'}] },
      { refId: 'remote-tool-id', type: 'application', name: 'Imported operation', properties: [{name: 'acs:kind', value: 'tool'}] },
    ] },
    { subject: { refId: 'second', name: 'Independent second inventory' }, components: [] },
  ], blueprints: [{relationships: [{ref: 'external-server', custom: [
    {type: 'acs:exposes-tool', targets: ['remote-tool-id', 'missing-tool-id']},
  ]}]}] });
  const localAibom = 'Qwen_Qwen2.5-0.5B-Instruct_aibom_1_7.json';
  await save('imported.aibom.json', JSON.parse(await readFile(join(scenario, 'aiboms', localAibom), 'utf8')));
  await local.click();
  await page.getByRole('button', { name: 'Refresh local inventory' }).click();
  await page.getByRole('option', { name: /Independent second inventory/ }).waitFor({ state: 'attached' });
  assert.equal(await page.locator('#agbom option').count(), 6);
  await page.locator('#agbom').selectOption('inventory/standalone.cdx.json#inventory-0');
  await page.locator('#personal-focus-filter').selectOption('model');
  const unresolvable = page.locator('#personal-evidence tr').filter({ hasText: 'Referenced model AIBOM' });
  assert.match(await unresolvable.innerText(), /https:\/\/example\.invalid\/unknown\.json/);
  assert.match(await unresolvable.innerText(), /AIBOM file unavailable/);
  assert.match(await unresolvable.innerText(), /externalReferences\[0\]\.url/);
  await page.locator('#personal-focus-filter').selectOption('mcp_server');
  const tools = page.locator('#personal-evidence tr').filter({ has: page.getByRole('link', { name: 'View Rule AG-046', exact: true }) });
  assert.match(await tools.innerText(), /Imported operation tool/);
  assert.match(await tools.innerText(), /Unresolved component reference · missing-tool-id/);
  assert.doesNotMatch(await tools.innerText(), /remote-tool-id/);
  await tools.getByText('Technical details', { exact: true }).click();
  assert.match(await tools.innerText(), /\["remote-tool-id", "missing-tool-id"\]/);
  await page.locator('#agbom').selectOption('inventory/imported.aibom.json');
  assert.match(await bodyText(page, '#personal-artifacts'), /CycloneDX 1\.7/);
  assert.match(await bodyText(page, '#personal-artifacts'), /Model revision 7ae55760/);
  assert.deepEqual(await readFile(join(fixture, 'later/my-agent.json')), sourceBefore);
  assert.ok(requests.every((url) => url.startsWith(origin)), requests.join('\n'));
});

const museumPack = process.env.VIEWER_MUSEUM_PACK;
test('Museum captures, kiosk, model AIBOMs and snapshot changes', { skip: !museumPack }, async (t) => {
  const prefix = 'inventory/museum-collections-test';
  const origin = await httpViewer(t, { roots: [[prefix, resolve(museumPack)]] });
  const { page, requests } = await monitoredPage(t);
  await page.goto(origin);
  await page.getByRole('link', { name: 'Local BOMs', exact: true }).click();
  await page.locator('#agbom').waitFor();
  const refreshed = page.waitForResponse((response) => response.url().endsWith('/api/agbom'));
  await page.getByRole('button', { name: 'Refresh local inventory' }).click();
  assert.equal((await refreshed).status(), 200);

  const selector = page.getByLabel('Select a BOM');
  assert.equal(await selector.locator('option').count(), 6);
  const capture = (folder) => prefix + '/' + folder + '/museum-collections.acs.json';
  for (const [folder, label] of [
    ['01-startup', 'Startup'], ['02-after-discovery', 'After discovery'], ['03-public-hours', 'Public-hours profile'],
  ]) {
    await page.locator('#personal-history').getByRole('button', { name: new RegExp('^' + label + '( · Selected)?$') }).click();
    assert.equal(await selector.inputValue(), capture(folder));
    assert.match(await bodyText(page, '#personal-artifacts'), /CycloneDX AgBOM · 2\.0-dev/);
    assert.match(await bodyText(page, '#personal-artifacts'), /Museum Collections Assistant/);
  }
  await selector.selectOption(prefix + '/museum-kiosk.cdx.json#inventory-0');
  assert.match(await bodyText(page, '#personal-artifacts'), /Standalone CycloneDX inventory · Museum Kiosk Assistant/);
  for (const version of ['1.0', '1.1']) {
    await selector.selectOption(prefix + '/models/gallery-text-' + version + '.aibom.json');
    assert.ok((await bodyText(page, '#personal-artifacts')).includes('Model revision ' + version));
  }
  await page.locator('#manual-baseline').selectOption(capture('01-startup'));
  await page.locator('#manual-target').selectOption(capture('02-after-discovery'));
  const comparison = await bodyText(page, '#personal-comparison');
  assert.match(comparison, /Added components \(2\)/);
  assert.match(comparison, /Check exhibit status/);
  assert.match(comparison, /Visitor Services Assistant/);
  await page.locator('#manual-baseline').selectOption(capture('02-after-discovery'));
  await page.locator('#manual-target').selectOption(capture('03-public-hours'));
  assert.match(await bodyText(page, '#personal-comparison'), /Removed components \(1\)[\s\S]*Check exhibit status/);
  assert.ok(requests.every((url) => url.startsWith(origin)), requests.join('\n'));
});
