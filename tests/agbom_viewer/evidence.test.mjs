import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';
import vm from 'node:vm';
import { buildPublicData, publicDir, root } from '../../tools/agbom-viewer/build.mjs';
import { compareSnapshots, corroborateDiff, inspectModelIdentity, modelEntries, reportedEvent, sameBomReference } from '../../tools/agbom-viewer/src/local-evidence.mjs';

const text = (path) => readFile(join(root, path), 'utf8');
const json = async (path) => JSON.parse(await text(path));
const publicText = (path) => readFile(join(publicDir, path), 'utf8');
const example = async (path) => JSON.parse(await publicText('examples/' + path));
const fixture = async (name) => JSON.parse(await readFile(new URL('fixtures/' + name, import.meta.url), 'utf8'));
const scenario = 'data/examples/developer-support/';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

async function mappingRules(csv) {
  const src = await publicText('viewer.js');
  return vm.runInNewContext(src.slice(0, src.indexOf('const questions')) + '\nrules',
    { agbomViewerData: { csv } });
}

test('54 unique links survive reordering the CSV', async () => {
  const csv = await text('data/mapping.csv');
  const rules = await mappingRules(csv);
  const [header, ...rows] = csv.trimEnd().split(/\r?\n/);
  const reversed = await mappingRules([header, ...rows.reverse()].join('\n'));
  assert.equal(new Set(rules.map(({id}) => id)).size, 54);
  assert.ok(rules.every(({id}) => /^AG-\d{3}$/.test(id)));
  assert.equal(rules.find(({id}) => id === 'AG-030').field, 'args');
  assert.equal(rules.map(({id}) => id).join(' '), reversed.map(({id}) => id).reverse().join(' '));
});

test('primary and minimal fixtures preserve identities, hashes, kinds, lineage and directed edges', async () => {
  const rules = await mappingRules(await text('data/mapping.csv'));
  const examples = await example('index.json');
  const pairs = [
    ...examples.map(({acs, cdx}) => [example, acs, acs, cdx]),
    ...['minimal', 'all-kinds', 'startup', 'runtime'].map((name) => [fixture, name, name + '.acs.json', name + '.cdx.json']),
  ];
  for (const [load, label, a, c] of pairs) {
    const acs = await load(a);
    const cdx = await load(c);
    const [{subject, components}] = cdx.inventories;
    assert.equal(subject.refId, acs.agent.agent_id);
    const nameFallback = subject.properties?.some(({name,value}) => name === 'acs:name-is-id' && value === 'true');
    if (acs.agent.name === undefined) assert.equal(nameFallback, true);
    else assert.equal(subject.name, acs.agent.name);
    assert.equal(components.length, acs.components.length);
    const {agbom_hash, ...rest} = acs;
    if (agbom_hash) {
      assert.equal(hash(canonical(rest)), agbom_hash, label);
      assert.equal(cdx.properties.find(({name}) => name === 'acs:agbom_hash').value, agbom_hash);
    }
    const ids = new Map(acs.components.map((component) => [component.id, component]));
    assert.equal(ids.size, acs.components.length);
    const nodes = new Set(acs.components.map((component) => component.registration_provenance?.provenance_id).filter(Boolean));
    for (const component of acs.components) {
      const mapped = components.find(({refId}) => refId === component.id);
      assert.ok(mapped);
      assert.equal(mapped.version, component.version);
      assert.equal(mapped.type === 'machine-learning-model' ? 'model' : mapped.properties.find(({name}) => name === 'acs:kind').value, component.type);
      const parents = component.registration_provenance?.derived_from;
      if (parents) {
        assert.ok(parents.every((id) => nodes.has(id)));
        assert.deepEqual(JSON.parse(mapped.properties.find(({name}) => name === 'acs:provenance:derived_from').value), parents);
      }
      for (const rule of rules.filter(({kind, edge}) => kind === component.type && edge)) {
        const targets = rule.path.reduce((value, field) => value?.[field], component);
        const edges = (cdx.blueprints ?? []).flatMap(({relationships}) => relationships)
          .filter(({ref}) => ref === component.id).flatMap(({custom}) => custom).filter(({type}) => type === rule.edge);
        if (targets?.length) {
          const targetKind = { tools: 'tool', mcp_servers: 'mcp_server', a2a_peers: 'a2a_peer', models: 'model', composed_skills: 'skill' }[rule.field];
          assert.ok(targets.every((id) => ids.get(id)?.type === targetKind));
          assert.deepEqual(edges.flatMap((edge) => edge.targets), targets);
        } else {
          assert.equal(edges.length, 0);
          if (targets) assert.ok(mapped.properties.some(({name,value}) => name === rule.edge.replace('acs:', 'acs:empty:') && value === 'true'));
        }
      }
    }
  }
});

test('comparison uses stable IDs and typed relationships and preserves value distinctions', async () => {
  const relationshipRules = await mappingRules(await text('data/mapping.csv'));
  const make = (components) => ({ agent: { agent_id: 'agent' }, components });
  const model = { id: 'model', type: 'model', version: '1', args: { ordered: [true, false], missing: '' } };
  const server = { id: 'server', type: 'mcp_server', mcp_server_fields: { tools: ['a', 'b'] } };
  const reordered = { ...server, mcp_server_fields: { tools: ['b', 'a'] } };
  const reorder = compareSnapshots(make([model, server]), make([reordered, model]), relationshipRules);
  for (const changes of Object.values(reorder)) assert.equal(changes.length, 0);
  const other = { ...model, version: '2', args: { ordered: [false, true], missing: null, value: 0 } };
  const result = compareSnapshots(make([model, { id: 'server', type: 'mcp_server' }]),
    make([other, { ...server, mcp_server_fields: { tools: [] } }, {id:'tool', type:'tool'}]), relationshipRules);
  assert.equal(result.added[0].value.id, 'tool');
  assert.equal(result.changed.find(({path}) => path.join('.') === 'version').after, '2');
  assert.deepEqual(result.changed.find(({path}) => path.join('.') === 'args.ordered').after, [false, true]);
  assert.equal(result.changed.find(({path}) => path.join('.') === 'args.missing').before, '');
  assert.equal(result.changed.find(({path}) => path.join('.') === 'args.missing').after, null);
  assert.equal(result.changed.find(({path}) => path.join('.') === 'args.value').after, 0);
  assert.equal(result.relationships[0].before, undefined);
  assert.deepEqual(result.relationships[0].after, []);
  const duplicate = compareSnapshots(make([model, model]), make([other]), relationshipRules);
  assert.match(duplicate.issues[0], /Ambiguous component ID/);
  assert.equal(duplicate.changed.length, 0);
});

test('adding or removing a relationship block counts only its changed fields and relationships', async () => {
  const rules = await mappingRules(await text('data/mapping.csv'));
  const capability = { id: 'capability', type: 'agent_capability' };
  const snapshot = (component) => ({ agent: { agent_id: 'agent' }, components: [component] });
  const absent = snapshot(capability);
  const present = snapshot({ ...capability, agent_capability_fields: { description: 'Reports', tools: ['report'], a2a_peers: [] } });
  const summarize = (changes) => changes.map(({ path, edge, before, after }) => [path.join('.'), edge, before, after]);
  const added = compareSnapshots(absent, present, rules);
  assert.deepEqual(summarize(added.changed), [['agent_capability_fields.description', undefined, undefined, 'Reports']]);
  assert.deepEqual(summarize(added.relationships), [
    ['agent_capability_fields.tools', 'acs:uses-tool', undefined, ['report']],
    ['agent_capability_fields.a2a_peers', 'acs:uses-peer', undefined, []],
  ]);
  const removed = compareSnapshots(present, absent, rules);
  const reverse = (changes) => summarize(changes).map(([path, edge, before, after]) => [path, edge, after, before]);
  assert.deepEqual(summarize(removed.changed), reverse(added.changed));
  assert.deepEqual(summarize(removed.relationships), reverse(added.relationships));
});

test('CycloneDX stage diff compares stable references, typed edges and order-insensitive fields', async () => {
  const src = await publicText('use-cases.js');
  const comparison = src.slice(0, src.indexOf('function control'));
  const compareCycloneDx = vm.runInThisContext('(() => {\n' + comparison + '\nreturn compareCycloneDx;\n})()');
  const startup = await example('example-ledger-agent_startup.cdx.json');
  const discovery = await example('example-ledger-agent_after-discovery.cdx.json');
  const forward = compareCycloneDx(startup, discovery);
  assert.deepEqual(forward.issues, []);
  assert.deepEqual(forward.rows.map(({kind}) => kind).sort(), ['Component added', 'Relationship added']);
  const added = forward.rows.find(({kind}) => kind === 'Component added');
  const edge = forward.rows.find(({kind}) => kind === 'Relationship added');
  assert.equal(added.before, undefined);
  assert.equal(added.after.name, 'Search');
  assert.equal(added.after.refId, 'search-tool');
  assert.deepEqual(edge.after, { source: 'ledger-mcp-server', type: 'acs:exposes-tool', target: 'search-tool' });
  assert.deepEqual(startup.inventories[0].components.map(({refId}) => refId), ['m', 'ledger-mcp-server', 'balance-tool']);
  assert.deepEqual(discovery.inventories[0].components.slice(0, 3).map(({refId}) => refId),
    startup.inventories[0].components.map(({refId}) => refId));
  const reverse = compareCycloneDx(discovery, startup);
  assert.deepEqual(reverse.rows.map(({kind}) => kind).sort(), ['Component removed', 'Relationship removed']);
  const reorder = structuredClone(discovery);
  reorder.inventories[0].components.reverse();
  for (const component of reorder.inventories[0].components) component.properties?.reverse();
  reorder.blueprints[0].relationships[0].custom[0].targets.reverse();
  assert.deepEqual(compareCycloneDx(discovery, reorder).rows, []);
  const model = reorder.inventories[0].components.find(({type}) => type === 'machine-learning-model');
  model.version = '2';
  assert.deepEqual(compareCycloneDx(discovery, reorder).rows,
    [{ kind: 'Component field changed', id: model.refId, field: 'version', before: '1', after: '2' }]);
});

test('public model references identify the bundled sample file and resolve the Ledger document revision', async () => {
  const modelReference = (bom) => bom.inventories[0].components.find(({type}) => type === 'machine-learning-model')
    .externalReferences.find(({type}) => type === 'bom').url;
  const sample = await example('sample-cyclonedx.json');
  assert.equal(sample.specVersion, '2.0-dev');
  assert.equal(modelReference(sample), 'sample-model.aibom.json');
  const attachment = await example('example-ledger-model.aibom.json');
  for (const stage of ['startup', 'after-discovery']) {
    const ledger = await example('example-ledger-agent_' + stage + '.cdx.json');
    assert.equal(ledger.specVersion, '2.0-dev');
    assert.equal(modelReference(ledger), 'urn:cdx:' + attachment.serialNumber.slice(9) + '/' + attachment.version);
  }
});

test('sample event payloads match their recorded captures only with corroborating evidence', async () => {
  const start = await json(scenario + 'session-start.agbom.json');
  const later = await json(scenario + 'after-discovery.agbom.json');
  for (const capture of [start, later]) {
    const { agbom_hash, ...contents } = capture;
    assert.equal(hash(canonical(contents)), agbom_hash);
  }
  assert.deepEqual(reportedEvent(await json(scenario + 'session-start.event.json')).snapshot, start);
  const full = reportedEvent(await json(scenario + 'discovery-full.event.json'));
  const increment = reportedEvent(await json(scenario + 'discovery-diff.event.json'));
  const ledgerEvent = reportedEvent(await fixture('change-event.acs.json'));
  assert.deepEqual(ledgerEvent.snapshot, await fixture('runtime.acs.json'));
  assert.deepEqual(full.snapshot, later);
  assert.ok(corroborateDiff(increment.diff, start, later));
  assert.equal(corroborateDiff(increment.diff, undefined, later), false);
  assert.equal(corroborateDiff(increment.diff, later, start), false);
  assert.equal(reportedEvent({full_snapshot: later, diff: increment.diff}).type, 'Unrecognized ACS event payload');
});

test('original model evidence preserves precision and shows missing, conflicting and weak evidence', async () => {
  const { associations } = await json(scenario + 'model-associations.json');
  for (const record of associations) {
    const capture = await json(scenario + record.inventory);
    const model = capture.components.find(({id}) => id === record.modelId);
    const aibom = await json(scenario + record.aibom);
    const matching = inspectModelIdentity(model, {record, aibom});
    assert.equal(matching.status, 'Matching recorded identifier and revision');
    assert.equal(matching.entry.version, model.version);
    assert.notEqual(matching.entry.version, aibom.metadata.component.version);
    assert.equal(matching.upstreamCommits[0].revision.length, 40);
    assert.ok(matching.upstreamCommits[0].revision.startsWith(model.version));
    assert.equal(inspectModelIdentity({...model, version:'different'}, {record, aibom}).status, 'Mismatch');
    assert.equal(inspectModelIdentity(model, {record}).status, 'AIBOM reference supplied but unavailable');
    assert.equal(inspectModelIdentity(model, {record:{}}).status, 'No AIBOM supplied');
    const weak = { ...aibom, components: [{type: 'machine-learning-model', name: model.name, version: model.version}] };
    assert.equal(inspectModelIdentity(model, {record: {...record, aibomComponentRef: undefined}, aibom: weak}).status, 'Insufficient evidence');
  }
});

test('metadata model evidence matches hexadecimal revisions and preserves case-sensitive identifiers', () => {
  const identifier = 'Example/Model';
  const version = 'AbC1234';
  const fullCommit = version.toUpperCase() + '0'.repeat(33);
  const entry = {
    type: 'machine-learning-model', name: 'Metadata model', version,
    'bom-ref': 'pkg:huggingface/' + identifier + '@' + version.toLowerCase(),
    purl: 'pkg:huggingface/' + identifier + '@' + version.toUpperCase(),
    externalReferences: [{ url: 'https://huggingface.co/' + identifier + '/commit/' + fullCommit }],
  };
  const aibom = { metadata: { component: entry } };
  const record = { aibom: 'model.json', aibomComponentRef: entry['bom-ref'], revision: version.toLowerCase() };
  const model = { name: identifier, version: version.toUpperCase() };
  assert.deepEqual(modelEntries(aibom), [{ entry, path: ['metadata', 'component'] }]);
  const outcome = inspectModelIdentity(model, { record, aibom });
  assert.equal(outcome.status, 'Matching recorded identifier and revision');
  assert.equal(outcome.entry.version, version);
  assert.equal(outcome.upstreamCommits[0].revision, fullCommit);
  assert.deepEqual(outcome.upstreamCommits[0].path, ['metadata', 'component', 'externalReferences', 0, 'url']);
  assert.equal(inspectModelIdentity({ ...model, version: 'AbC1235' }, { record, aibom }).status, 'Mismatch');
  assert.equal(inspectModelIdentity({ ...model, name: identifier.toLowerCase() }, { record, aibom }).status, 'Mismatch');
  assert.equal(inspectModelIdentity(model, { record: { ...record, revision: 'release-A' }, aibom }).status, 'Mismatch');
  assert.equal(inspectModelIdentity({ ...model, version: 'Release-A' }, {
    record: { aibom: 'model.json', revision: 'release-a' },
    aibom: { metadata: { component: { type: 'machine-learning-model', version: 'release-a', purl: 'pkg:huggingface/' + identifier } } },
  }).status, 'Mismatch');
});

test('BOM references fold only the hexadecimal UUID', () => {
  const uuid = 'abcdef01-2345-6789-abcd-ef0123456789';
  const document = 'urn:cdx:' + uuid + '/1';
  const upperUuid = 'urn:cdx:' + uuid.toUpperCase();
  assert.ok(sameBomReference(document, upperUuid + '/1'));
  assert.ok(sameBomReference(document + '#Model-A', upperUuid + '/1#Model-A'));
  assert.equal(sameBomReference(document + '#Model-A', upperUuid + '/1#model-a'), false);
  assert.equal(sameBomReference(document, upperUuid + '/1#Model-A'), false);
  assert.equal(sameBomReference(document, upperUuid + '/2'), false);
  assert.equal(sameBomReference('Model-A', 'model-a'), false);
});

test('the checked-in bundle matches its inputs and only uses indexed public examples', async () => {
  const baseline = await buildPublicData();
  const renamed = await buildPublicData({ publicationLabel: 'Published with ACS v9.8.7' });
  const index = await example('index.json');
  assert.deepEqual([...baseline.examples.keys()].sort(), [
    'examples/index.json',
    ...new Set(index.flatMap(({acs,cdx,aiboms}) => [acs,cdx,...aiboms].filter(Boolean).map((name) => 'examples/' + name))),
  ].sort());
  const decode = (script) => {
    const context = vm.createContext({});
    vm.runInContext(script, context);
    return JSON.parse(JSON.stringify(context.agbomViewerData));
  };
  const original = decode(baseline.script);
  const alternate = decode(renamed.script);
  assert.equal(alternate.config.publicationLabel, 'Published with ACS v9.8.7');
  alternate.config.publicationLabel = original.config.publicationLabel;
  assert.deepEqual(alternate, original);
  assert.deepEqual(baseline.examples, renamed.examples);
  const checkedIn = await publicText('viewer-data.js');
  assert.equal(checkedIn.replaceAll('\r\n', '\n'), baseline.script);
  assert.doesNotMatch(checkedIn, /developer-support|museum-collections|Qwen|planning|\/api\/agbom/);
});
