import { compareSnapshots, corroborateDiff, reportedEvent, sameValue, inspectModelIdentity, modelEntries, sameBomReference } from './local-evidence.mjs';

const relationshipRules = rules.filter(({edge}) => edge);
let loading = false;
const personal = new Map();
const histories = new Map();
let historyId = '';
const selector = byId('agbom');
const personalMapping = createMappingControls('personal-', byId('personal-evidence'));
byId('personal-filters').append(personalMapping.root);

function captureLabel(current) {
  if (!current.acs) return current.label + ' · ' + current.cdxFile;
  return [current.acs.agent?.name, current.acs.agent?.agent_id, current.acs.generated_at, current.acsFile]
    .filter((value) => typeof value === 'string' && value).join(' · ');
}

function fileHeading(current, label) {
  return element('div', 'snapshot-name', element('strong', '', label), element('span', '', current.label),
    element('code', '', current.acsFile),
    element('span', 'muted', dataText(current.acs.generated_at)),
    element('span', 'muted', 'Agent ID · ' + dataText(current.acs.agent?.agent_id)));
}

function evidencePair(before, after, change) {
  const cells = element('div', 'change-pair');
  for (const [snapshot, entry, value] of [[before, change.beforeEntry, change.before], [after, change.afterEntry, change.after]]) {
    const cell = element('div');
    const path = [...(entry?.path ?? []), ...change.path];
    const hit = locate(snapshot.acs, path);
    const evidence = { ...hit, value };
    if (change.edge) {
      const parent = locate(snapshot.acs, path.slice(0, -1));
      cell.append(element('span', 'muted', 'Parent block '), element('code', 'path', parent.path));
      if (parent.value !== undefined && (parent.value === null || typeof parent.value !== 'object' || Array.isArray(parent.value))) {
        addValue(cell, { value: parent.value });
      }
      addValue(cell, { ...referencedValues(evidence, snapshot.acsComponents, 'id'), relationship: change.edge });
    } else {
      addValue(cell, evidence);
    }
    cells.append(cell);
  }
  const subject = change.afterEntry?.value;
  return element('div', 'relationship-change',
    element('strong', '', [subject ? componentReference(subject) : null, change.edge ? titles[change.path.at(-1)] ?? change.path.join('.') : change.path.join('.')].filter(Boolean).join(' · ')), cells);
}

function comparisonPanel(baseline, comparison) {
  const result = compareSnapshots(baseline.acs, comparison.acs, relationshipRules);
  const block = element('div', 'comparison-results',
    element('h3', '', 'Calculated from snapshots'),
    element('div', 'change-pair', fileHeading(baseline, 'Baseline'), fileHeading(comparison, 'Comparison')));
  if (result.issues.length) block.append(element('ul', 'local-evidence', ...result.issues.map((issue) => element('li', '', issue))));
  const membership = (kind, entries, current) => {
    const list = element('ul', 'local-evidence');
    for (const { value, path } of entries) {
      list.append(element('li', '', componentLabel(value),
        technicalDetails(element('code', '', dataText(value.id) + ' · ' + locate(current.acs, path).path))));
    }
    return element('section', '', element('h4', '', kind + ' (' + entries.length + ')'), list);
  };
  block.append(membership('Added components', result.added, comparison),
    membership('Removed components', result.removed, baseline));
  for (const [label, entries] of [['Changed component fields', result.changed], ['Changed typed relationships', result.relationships],
    ['Document metadata and agent fields', result.document]]) {
    block.append(element('h4', '', label + ' (' + entries.length + ')'),
      ...entries.map((change) => evidencePair(baseline, comparison, change)));
  }
  return block;
}

function manualComparison() {
  const panel = byId('personal-comparison');
  const captures = [...personal].filter(([, current]) => current.acs);
  if (captures.length < 2) {
    panel.replaceChildren(element('p', 'muted explanation', 'Add two ACS inventories to compare snapshots.'));
    return;
  }
  const oldBaseline = byId('manual-baseline')?.value;
  const oldTarget = byId('manual-target')?.value;
  const values = captures.map(([id, current]) => [id, captureLabel(current)]);
  const baseline = values.some(([id]) => id === oldBaseline) ? oldBaseline : values[0][0];
  const target = values.some(([id]) => id === oldTarget) ? oldTarget : values[1][0];
  const result = element('div');
  const render = () => {
    const before = personal.get(byId('manual-baseline').value);
    const after = personal.get(byId('manual-target').value);
    result.replaceChildren(...(before === after ? [element('p', 'muted', 'Select two distinct captures.')] :
      [comparisonPanel(before, after)]));
  };
  panel.replaceChildren(element('section', 'panel local-panel', element('h3', '', 'Selected comparison'),
    element('p', 'muted', 'The chosen files determine which capture is the baseline. Lifecycle context comes from an explicit history or event association.'),
    element('div', 'change-controls',
      control('Baseline', 'manual-baseline', values, baseline, render),
      control('Comparison', 'manual-target', values, target, render)), result));
  render();
}

function personalHistory() {
  const panel = byId('personal-history');
  if (!histories.size) return panel.replaceChildren();
  const history = histories.get(historyId) ?? histories.values().next().value;
  historyId = history.id;
  const active = history.captures.some(({id}) => id === selector.value) ? selector.value : undefined;
  panel.replaceChildren(element('section', 'panel local-panel', element('h3', '', 'Snapshot history'),
    control('Capture series', 'history-series', [...histories].map(([id, entry]) => [id, entry.label]), history.id, (id) => {
      historyId = id;
      personalHistory();
      byId('history-series').focus();
    }),
    element('p', 'muted', element('code', '', history.file + ' · ' + history.location)),
    timeline(history.captures.map(({id,label}) => ({ id, label: label ?? captureLabel(personal.get(id)) })), active,
      undefined, (id) => { selector.value = id; selectPersonal(); personalHistory(); })));
}

function eventEvidence(event, captures) {
  const {type, snapshot: inventory, diff, field} = reportedEvent(event.payload);
  const baseline = captures?.get(event.baseline);
  const target = captures?.get(event.capture);
  const title = type === 'agbom/changed' ? 'Reported by ACS change event' : type;
  const card = element('details', 'panel local-panel event-card', element('summary', '', title + ' · ' + (event.label ?? event.file)));
  const evidence = element('div');
  card.append(element('p', 'muted', event.synthetic ? 'Synthetic sample evidence' : 'Imported ACS event evidence', ' · ',
    element('code', '', event.file)), element('p', '', type), evidence);
  for (const key of ['trigger', 'reason', 'trigger_step_id']) {
    if (Object.hasOwn(event.payload, key)) addValue(evidence, { ...locate(event.payload, [key]), note: key });
  }
  if (inventory) {
    const matches = target && sameValue(inventory, target.acs);
    evidence.append(element('p', '', matches ? 'Embedded snapshot matches ' + target.acsFile :
      target ? 'Embedded snapshot differs from ' + target.acsFile : 'Embedded snapshot recorded by the event.'));
    addValue(evidence, locate(event.payload, [field]));
  }
  if (diff) {
    const matches = corroborateDiff(diff, baseline?.acs, target?.acs);
    evidence.append(element('p', '', matches ?
      'Reported component changes agree with ' + baseline.acsFile + ' and ' + target.acsFile + '.' :
      baseline && target ? 'The selected capture evidence does not corroborate the reported diff.' :
        'No associated baseline and resulting snapshot are available. The event supplies reported changes.'));
    for (const operation of ['added', 'removed', 'changed']) {
      evidence.append(element('h4', '', operation[0].toUpperCase() + operation.slice(1)));
      addValue(evidence, locate(event.payload, ['diff', operation]));
    }
  }
  if (!field) addValue(evidence, locate(event.payload, []));
  return card;
}

function modelAssociationCard(current, component, association, cdxRefs) {
  const {record, location, aibom} = association;
  const outcome = inspectModelIdentity(component.value, association);
  const card = element('div', 'association-evidence',
    element('p', 'muted', 'Local inventory association'),
    element('p', '', record.recordType ?? 'User-supplied association'),
    element('strong', '', outcome.status));
  if (outcome.detail) card.append(element('p', '', outcome.detail));
  const consumer = current.acsComponents.filter(({value}) => value.id === record.consumerId);
  const actor = record.consumerId && record.consumerId === current.acs?.agent?.agent_id ?
    {value: current.acs.agent.name ?? record.consumerId, path: '$.agent.agent_id'} :
    consumer.length === 1 ? {value: componentReference(consumer[0].value), path: consumer[0].path + '.id'} : undefined;
  const sourceFields = ['consumerId', 'relationship', 'modelId', 'identifier', 'revision', 'aibom', 'aibomComponentRef'];
  const evidence = element('details', '', element('summary', '', 'View identity and association evidence'));
  for (const field of sourceFields) addValue(evidence, { value: record[field], path: location + '.' + field, note: field });
  const description = record.relationship ?? 'Consumer relationship unspecified';
  card.append(element('p', '', description, ' · ', actor?.value ?? (record.consumerId ? componentReference(undefined, record.consumerId) : 'Consumer not recorded')));
  if (actor) card.append(element('code', 'aibom-source path', actor.path));
  const aibomLink = /^urn:uuid:[a-f0-9-]{36}$/i.test(aibom?.serialNumber) && Number.isInteger(aibom.version) ?
    'urn:cdx:' + aibom.serialNumber.slice(9) + '/' + aibom.version : undefined;
  if (aibom) {
    card.append(element('p', '', 'AIBOM document · CycloneDX ' + aibom.specVersion + ' · BOM revision ' + (aibom.version ?? 'Not supplied')));
    if (cdxRefs.length && aibomLink) {
      const links = cdxRefs.filter(({value}) => typeof value === 'string' && value.startsWith('urn:cdx:'));
      if (links.length) card.append(element('p', '', links.some(({value}) => sameBomReference(value, aibomLink)) ?
        'The CycloneDX BOM-Link matches this document UUID and BOM revision.' : 'CycloneDX BOM-Link differs from this document UUID or BOM revision.'));
    }
    for (const field of ['specVersion', 'serialNumber', 'version']) addValue(evidence, { ...locate(aibom, [field]), note: 'Document ' + field });
    if (aibomLink) evidence.append(element('p', '', 'Document BOM-Link ', element('code', '', aibomLink)));
  }
  if (outcome.entry) {
    const revision = outcome.entry.version ?? 'Not supplied';
    card.append(element('p', '', 'Recorded model revision · AgBOM ', element('code', '', component.value.version ?? 'Not supplied'),
      ' · AIBOM ', element('code', '', revision)));
    if (outcome.identifier) card.append(element('p', '', 'Model repository · ', element('code', '', outcome.identifier), outcome.source ? ' · ' + outcome.source : ''));
    for (const field of ['name', 'purl', 'bom-ref', 'refId', 'version'].filter((field) => Object.hasOwn(outcome.entry, field) || field === 'version')) {
      addValue(evidence, { ...locate(aibom, [...outcome.path, field]), note: 'Model ' + field });
    }
    for (const commit of outcome.upstreamCommits) {
      addValue(evidence, { ...locate(aibom, commit.path), note: 'Recorded upstream repository commit · ' + commit.revision });
    }
  }
  if (!component.acsAbsent) {
    for (const field of ['name', 'version', 'registration_provenance']) {
      addValue(evidence, { ...locate(component.value, [field], component.path), note: 'AgBOM ' + field });
    }
  }
  card.append(evidence);
  return card;
}

localModelEvidence = (current, component, cdxRefs) => {
  const matches = items(current.associations).filter(({record}) => record.modelId === component.value.id);
  if (!matches.length) return [];
  if (current.acsComponents.filter(({value}) => value.id === component.value.id).length > 1) {
    return [element('p', 'diagnostics', 'Insufficient evidence · The association points to an ambiguous AgBOM model ID.')];
  }
  return matches.map((association) => modelAssociationCard(current, component, association, cdxRefs));
};

function selectPersonal() {
  const current = personal.get(selector.value);
  if (!current) return;
  const artifacts = byId('personal-artifacts');
  const notes = byId('inventory-notices');
  const isAibom = current.artifact === 'aibom';
  byId('personal-filters').hidden = isAibom;
  byId('personal-evidence').hidden = isAibom;
  if (isAibom) {
    artifacts.replaceChildren(element('h3', '', 'Model AIBOM · CycloneDX ' + current.cdx.specVersion),
      element('ul', 'local-evidence', ...modelEntries(current.cdx).map(({entry}) =>
        element('li', '', dataText(entry.name), ' · Model revision ', element('code', '', dataText(entry.version))))),
      sourceDisclosure('View AIBOM JSON', current.cdxFile, current.cdxText, 'Imported AIBOM JSON contents'));
    notes.replaceChildren();
    return;
  }
  const children = [];
  if (current.cdx) {
    children.push(element('h3', '', 'CycloneDX AgBOM · ' + current.cdx.specVersion),
      sourceDisclosure('View CycloneDX JSON', current.cdxFile, current.cdxText, 'Imported CycloneDX JSON contents'));
  } else {
    children.push(element('p', 'muted explanation', [current.cdxFile, exportAvailability(current)].filter(Boolean).join(' · ')));
  }
  if (current.acs) {
    children.push(element('dl', 'inventory-summary',
      term('Agent name', dataText(current.acs.agent?.name)),
      term('Agent ID', dataText(current.acs.agent?.agent_id)),
      term('Agent version', dataText(current.acs.agent?.version)),
      term('Components', dataText(current.acs.components?.length)),
      term('AgBOM schema', dataText(current.acs.agbom_version))),
      sourceDisclosure('View ACS source inventory', current.acsFile, current.acsText, 'Imported ACS source JSON contents', 'ACS source'));
  } else {
    children.push(element('p', 'muted explanation', 'Standalone CycloneDX inventory · ' + current.label));
  }
  artifacts.replaceChildren(...children);
  const issues = inspectInventory(current);
  notes.replaceChildren(...(issues.length ? [
    element('details', 'diagnostics', element('summary', '', 'Inventory evidence notices (' + issues.length + ')'),
      element('ul', '', ...issues.map((issue) => element('li', '', issue))))] : []));
  personalMapping.show(current);
}

function populate(result) {
  const previous = selector.value;
  personal.clear();
  histories.clear();
  for (const files of result.inventories) {
    const current = snapshot(files.label ?? files.acsFile, { ...files, aiboms: result.aiboms });
    personal.set(files.id, current);
  }
  for (const {file, cdxText} of result.aiboms) {
    personal.set(file, snapshot(fileLabel(file), { id: file, artifact: 'aibom', cdxFile: file, cdxText }));
  }
  for (const history of result.series) histories.set(history.id, history);
  if (result.scenario) {
    const captures = result.scenario.captures.map((files) => snapshot(files.label, files));
    const byId = new Map(captures.map((capture) => [capture.id, capture]));
    registerUseCase('developer', {
      title: 'Developer-support assistant',
      description: [
        'The assistant registers an organization-hosted triage model at session start. An internal MCP server later exposes a code-review tool.',
        'The companion deployment record identifies the separately hosted backend model. The MCP listing supplies evidence for tool exposure.',
      ],
      captures,
      renderEvents(current, baseline) {
        const events = result.scenario.events.filter(({capture}) => capture === current.id || capture === baseline?.id);
        return [element('section', 'stage-events', element('h3', '', 'ACS event evidence'),
          ...events.map((event) => eventEvidence(event, byId)))];
      },
    });
  }
  selector.replaceChildren(...[...personal].map(([id, current]) => option(id, captureLabel(current))));
  if (personal.has(previous)) selector.value = previous;
  byId('personal-inspector').hidden = !personal.size;
  byId('local-notices').replaceChildren(...(result.notices.length ? [
    element('details', '', element('summary', '', 'Local data notices (' + result.notices.length + ')'),
      element('ul', '', ...result.notices.map((note) => element('li', '', note))))] : []),
    ...(result.scenarioIssue ? [element('p', 'muted', 'Developer-support evidence unavailable · ' + result.scenarioIssue)] : []));
  selectPersonal();
  manualComparison();
  personalHistory();
  byId('personal-events').replaceChildren(...result.events.map((event) => eventEvidence(event)));
}

async function refresh() {
  if (loading) return;
  loading = true;
  try {
    const response = await fetch('./api/agbom', { cache: 'no-store' });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    populate(await response.json());
  } catch (error) {
    byId('local-notices').textContent = 'Local inventory discovery unavailable. ' + error.message;
  } finally {
    loading = false;
  }
}

byId('refresh-inventories').addEventListener('click', refresh);
selector.addEventListener('change', () => { selectPersonal(); personalHistory(); });
refresh();
