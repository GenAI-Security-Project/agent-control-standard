const compareCycloneDx = (() => {
  const items = (value) => Array.isArray(value) ? value : [];
  const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

  const blueprintTypes = ['aggregates', 'associates', 'composes', 'contains', 'dependsOn', 'generalizes', 'realizes', 'serves'];

  function cycloneDxRelationships(bom) {
    const edges = new Map();
    function add(source, type, targets) {
      if (typeof source !== 'string' || typeof type !== 'string') return;
      for (const target of items(targets)) {
        if (typeof target !== 'string') continue;
        edges.set(JSON.stringify([source, type, target]), { source, type, target });
      }
    }
    for (const blueprint of items(bom.blueprints)) {
      for (const relationship of items(blueprint?.relationships)) {
        for (const type of blueprintTypes) add(relationship?.ref, type, relationship?.[type]);
        for (const entry of items(relationship?.custom)) add(relationship.ref, entry?.type, entry?.targets);
      }
    }
    for (const dependency of items(bom.dependencies)) {
      for (const type of ['dependsOn', 'provides']) add(dependency?.ref, type, dependency?.[type]);
    }
    return edges;
  }

  function cycloneDxComponents(bom, side, issues) {
    const entries = new Map();
    const ambiguous = new Set();
    function visit(component) {
      if (!object(component)) return;
      const { refId } = component;
      if (typeof refId !== 'string') {
        issues.push(side + ' · ' + (component.name ?? 'Component') + ' has no reference ID.');
      } else if (entries.has(refId)) {
        ambiguous.add(refId);
      } else {
        entries.set(refId, component);
      }
      for (const child of items(component.components)) visit(child);
    }
    for (const inventory of items(bom.inventories)) {
      visit(inventory?.subject);
      for (const component of items(inventory?.components)) visit(component);
    }
    for (const id of ambiguous) issues.push(side + ' · Ambiguous reference ID ' + JSON.stringify(id) + '.');
    return { entries, ambiguous };
  }

  function unorderedKey(value) {
    if (Array.isArray(value)) return '[' + value.map(unorderedKey).sort().join(',') + ']';
    if (object(value)) {
      return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + unorderedKey(value[key])).join(',') + '}';
    }
    return JSON.stringify(value);
  }

  function compareCycloneDx(baseline, selected) {
    const issues = [];
    const left = cycloneDxComponents(baseline, 'Baseline', issues);
    const right = cycloneDxComponents(selected, 'Selected stage', issues);
    const rows = [];
    for (const id of new Set([...left.entries.keys(), ...right.entries.keys()])) {
      if (left.ambiguous.has(id) || right.ambiguous.has(id)) continue;
      const before = left.entries.get(id);
      const after = right.entries.get(id);
      if (!before || !after) {
        rows.push({ kind: before ? 'Component removed' : 'Component added', id, before, after });
        continue;
      }
      for (const field of new Set([...Object.keys(before), ...Object.keys(after)])) {
        // Nested components have their own refId and are compared independently.
        if (field === 'components' || unorderedKey(before[field]) === unorderedKey(after[field])) continue;
        rows.push({ kind: 'Component field changed', id, field, before: before[field], after: after[field] });
      }
    }
    const beforeEdges = cycloneDxRelationships(baseline);
    const afterEdges = cycloneDxRelationships(selected);
    for (const [key, edge] of afterEdges) {
      if (!beforeEdges.has(key)) rows.push({ kind: 'Relationship added', after: edge });
    }
    for (const [key, edge] of beforeEdges) {
      if (!afterEdges.has(key)) rows.push({ kind: 'Relationship removed', before: edge });
    }
    return { rows, issues, beforeComponents: left.entries, afterComponents: right.entries };
  }
  return compareCycloneDx;
})();

if (typeof module === 'object') module.exports = compareCycloneDx;

function control(label, id, entries, selectedId, callback) {
  const select = element('select');
  select.id = id;
  for (const [value, text] of entries) select.append(option(value, text));
  select.value = selectedId;
  select.addEventListener('change', () => callback(select.value));
  const name = element('label', '', label);
  name.htmlFor = id;
  return element('div', 'select-field', name, select);
}

function timeline(captures, first, last, pick) {
  const start = captures.findIndex(({id}) => id === first);
  const end = captures.findIndex(({id}) => id === last);
  const list = element('ol', 'timeline');
  list.setAttribute('aria-label', 'Snapshot timeline');
  captures.forEach(({id, label}, i) => {
    const active = id === first || id === last;
    const state = last ? id === first ? ' · Baseline' : id === last ? ' · Comparison' : '' : active ? ' · Selected' : '';
    const button = element('button', '', label + state);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(active));
    button.addEventListener('click', () => {
      pick(id);
      const timeline = [...document.querySelectorAll('.timeline')].find((node) => !node.closest('[hidden]'));
      timeline?.querySelectorAll('button')[i]?.focus();
    });
    const item = element('li', '', button);
    if (last && i >= Math.min(start, end) && i <= Math.max(start, end)) item.dataset.interval = '';
    list.append(item);
  });
  return list;
}

function sourceDisclosure(title, file, source, ariaLabel, fileRole) {
  const disclosure = element('details', 'panel source-disclosure', element('summary', '', title));
  if (file) {
    const filename = element('code', 'artifact-filename', file);
    disclosure.append(fileRole ? element('dl', 'artifact-source', term(fileRole, filename)) : filename);
  }
  const pre = element('pre');
  pre.tabIndex = 0;
  pre.setAttribute('aria-label', ariaLabel);
  disclosure.append(pre);
  disclosure.addEventListener('toggle', () => {
    if (disclosure.open && !pre.hasChildNodes()) renderJson(pre, source);
  });
  return disclosure;
}

function stageArtifacts(current) {
  const artifact = element('section', 'stage-artifacts', element('h3', '', 'CycloneDX AgBOM'));
  if (current.cdx) {
    const filename = element('code', 'artifact-filename', current.cdxFile);
    artifact.append(element('dl', '', term(current.role === 'ledger' ? 'CycloneDX sample' : 'CycloneDX artifact', filename)),
      element('span', 'muted', 'Declared specVersion ' + current.cdx.specVersion),
      sourceDisclosure('View CycloneDX JSON', undefined, current.cdxText, 'Stage CycloneDX JSON contents'));
  } else {
    artifact.append(element('p', 'muted', 'CycloneDX artifact unavailable'));
  }
  artifact.append(element('p', 'muted explanation',
    'ACS records the agent’s components and relationships for this stage. The CycloneDX AgBOM represents that inventory in CycloneDX 2.0-dev. Open the ACS source inventory to see where the mapped values came from.'),
    sourceDisclosure('View ACS source inventory', current.acsFile, current.acsText, 'Stage ACS source JSON contents', 'ACS source'));
  return artifact;
}

function stageComparison(baseline, current) {
  const heading = element('h3', '', 'Stage comparison');
  const panel = element('section', 'stage-comparison', heading);
  if (!baseline.cdx || !current.cdx) {
    panel.append(element('p', 'muted', 'Both stages need a CycloneDX artifact for comparison.'));
    return panel;
  }
  const { rows, issues, beforeComponents, afterComponents } = compareCycloneDx(baseline.cdx, current.cdx);
  if (issues.length) panel.append(element('ul', 'local-evidence', ...issues.map((issue) => element('li', '', issue))));
  const baselineLabel = 'Baseline · ' + baseline.label;
  const currentLabel = 'Selected stage · ' + current.label;
  const headers = [
    element('th', '', 'Calculated from CycloneDX artifacts'),
    element('th', '', baselineLabel, element('code', 'artifact-filename', fileLabel(baseline.cdxFile))),
    element('th', '', currentLabel),
  ];
  for (const header of headers) header.scope = 'col';
  const stageCell = (row, stage, label, components) => {
    const cell = element('td', 'cell', element('span', 'format-mobile', label));
    const entry = row[stage];
    if (row.field) {
      addValue(cell, { value: entry, note: entry === undefined ? 'Field absent' : undefined });
    } else if (entry === undefined) {
      cell.append(element('span', 'muted', 'Absent'));
    } else if (row.id !== undefined) {
      cell.append(element('strong', '', componentLabel(entry)), technicalDetails(element('code', '', row.id)));
    } else {
      const source = componentReference(components.get(entry.source), entry.source);
      const target = componentReference(components.get(entry.target), entry.target, false);
      cell.append(element('strong', '', source + ' ' + relationshipVerb(entry.type) + ' ' + target),
        technicalDetails(element('code', '', entry.source + ' → ' + entry.type + ' → ' + entry.target)));
    }
    return cell;
  };
  const body = rows.map((row) => {
    const name = row.id === undefined ? '' : componentReference(afterComponents.get(row.id) ?? beforeComponents.get(row.id), row.id);
    const title = element('th', 'field-title', element('strong', '', row.kind),
      element('span', 'row-subject', [name, row.field].filter(Boolean).join(' · ')));
    title.scope = 'row';
    return element('tr', '', title, stageCell(row, 'before', baselineLabel, beforeComponents),
      stageCell(row, 'after', currentLabel, afterComponents));
  });
  if (!body.length) {
    const cell = element('td', 'cell', 'No component or relationship differences.');
    cell.colSpan = 3;
    body.push(element('tr', 'no-stage-changes', cell));
  }
  panel.append(element('table', 'matrix', element('caption', 'visually-hidden', 'Stage comparison'),
    element('thead', '', element('tr', '', ...headers)), element('tbody', '', ...body)));
  return panel;
}


const useCases = new Map();
const caseSelect = byId('use-case-choice');
const stageEvidence = element('div', 'stage-evidence');
const stageMapping = createMappingControls('investigation-', stageEvidence);
let useCaseId = 'ledger';
let selectedStage;
let baselineId = '';

function registerUseCase(id, useCase) {
  useCases.set(id, useCase);
  caseSelect.replaceChildren(...[...useCases].map(([key, value]) => option(key, value.title)));
  caseSelect.value = useCaseId;
  byId('use-case-picker').hidden = useCases.size < 2;
  if (!byId('use-case').hidden) renderUseCase();
}

function renderUseCase(focusId) {
  const useCase = useCases.get(useCaseId);
  if (!useCase?.captures.length) return;
  const captures = useCase.captures;
  const current = captures.find(({id}) => id === selectedStage) ?? captures[0];
  selectedStage = current.id;
  const baseline = captures.find(({id}) => id === baselineId && id !== current.id);
  baselineId = baseline?.id ?? '';
  byId('case-context').replaceChildren(element('h3', '', useCase.title),
    ...useCase.description.map((paragraph) => element('p', '', paragraph)));
  const controls = element('section', 'panel local-panel', element('h3', '', 'Inventory lifecycle'),
    timeline(captures, baseline ? baseline.id : current.id, baseline ? current.id : undefined, (id) => {
      if (baselineId === id && id !== current.id) baselineId = current.id;
      selectedStage = id;
      renderUseCase();
    }));
  if (current.intent) controls.append(element('p', '', current.intent));
  const comparisonControl = control('Compare the selected stage with', 'scenario-baseline',
    [['', 'No baseline'], ...captures.filter(({id}) => id !== current.id).map(({id, label}) => [id, label])],
    baselineId, (id) => { baselineId = id; renderUseCase('scenario-baseline'); });
  const investigation = element('section', 'stage-investigation',
    element('h3', '', 'Investigate this stage · ' + current.label), stageMapping.root, stageEvidence);
  stageMapping.show(current);
  byId('scenario-content').replaceChildren(controls, stageArtifacts(current), comparisonControl,
    ...(baseline ? [stageComparison(baseline, current)] : []), investigation,
    ...(useCase.renderEvents?.(current, baseline) ?? []));
  if (focusId) byId(focusId)?.focus();
}

registerUseCase('ledger', {
  title: 'Ledger assistant',
  description: ['This finance assistant can read an account balance at Startup. After tool discovery, the Ledger MCP server also exposes a tool for searching ledger entries.'],
  captures: [...bundled.values()].filter(({role}) => role === 'ledger'),
});
caseSelect.addEventListener('change', () => {
  useCaseId = caseSelect.value;
  selectedStage = undefined;
  baselineId = '';
  renderUseCase();
});
document.querySelector('[data-view="use-case"]').addEventListener('click', () => {
  if (!byId('scenario-content').hasChildNodes()) renderUseCase();
});
window.addEventListener('hashchange', () => {
  if (location.hash === '#use-case' && !byId('scenario-content').hasChildNodes()) renderUseCase();
});
