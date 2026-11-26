'use strict';

const data = globalThis.agbomViewerData;
const scenario = 'Which MCP server exposes this tool, and how did the tool enter the inventory?';
const kindNames = {
  model: 'Model', mcp_server: 'MCP server', a2a_peer: 'A2A peer', tool: 'Tool',
  skill: 'Skill', knowledge_source: 'Knowledge source', memory_store: 'Memory store', agent_capability: 'Agent capability',
};
const serviceKinds = ['mcp_server', 'a2a_peer', 'knowledge_source', 'memory_store'];
const byId = (id) => document.getElementById(id);
const items = (value) => Array.isArray(value) ? value : [];
const parseJson = (source) => JSON.parse(source.replace(/^\uFEFF/, ''));

function readCsv(source) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    if (char === '"' && source[i + 1] === '"' && quoted) {
      field += '"';
      i++;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (!quoted && /[\r\n,]/.test(char)) {
      row.push(field);
      field = '';
      if (char === ',') continue;
      rows.push(row);
      row = [];
      if (char === '\r' && source[i + 1] === '\n') i++;
    } else {
      field += char;
    }
  }
  if (row.length || field.length) rows.push([...row, field]);
  const headers = rows.shift();
  headers[0] = headers[0].replace(/^\uFEFF/, '');
  return rows.filter((cells) => cells.length > 1).map((cells) =>
    Object.fromEntries(headers.map((header, i) => [header, cells[i]])));
}

function toRule(row) {
  const [schema, fragment] = row['ACS schema pointer'].split('#');
  const segments = fragment.split('/properties/').slice(1);
  const profile = row['CDX type / profile key'];
  const property = profile.match(/property name (acs:[\w:*]+)/)?.[1];
  const edge = profile.match(/custom\.type=(acs:[\w-]+)/)?.[1];
  const isProvenance = schema === 'provenance.json';
  const scope = schema === 'agbom/document.json' ? (segments[0] === 'agent' ? 'agent' : 'document') : 'component';
  const kind = Object.hasOwn(kindNames, row['Applies to']) ? row['Applies to'] : null;
  return {
    ...row,
    id: row['Rule ID'],
    legacyId: 'rule-' + [scope, isProvenance ? 'registration_provenance' : '', ...segments, kind ?? '',
      segments.at(-1) === 'endpoint' ? (property ? 'property' : 'service') : '']
      .filter(Boolean).join('-').replaceAll('_', '-'),
    field: segments.at(-1), scope, kind, property, edge, isProvenance,
    path: isProvenance ? ['registration_provenance', ...segments] : scope === 'agent' ? segments.slice(1) : segments,
  };
}

const rules = readCsv(data.csv).map(toRule);
const questions = new Map(rules.map((rule) => [rule.id, rule]));

function locate(root, path, prefix = '$') {
  let value = root;
  let pointer = prefix;
  for (const key of path) {
    pointer += typeof key === 'number' || !/^[a-zA-Z_$][\w$]*$/.test(key) ? `[${JSON.stringify(key)}]` : `.${key}`;
    value = value != null && Object.hasOwn(value, key) ? value[key] : undefined;
  }
  return { value, path: pointer };
}

function missing(note, path) {
  return { note, path };
}

function exportAvailability(current) {
  return current.exportIssue ? `No paired CycloneDX export · ${current.exportIssue}` : 'No CycloneDX export supplied';
}

function draftInventories(cdx, agentId) {
  const inventories = items(cdx?.inventories).map((_, index) => locate(cdx, ['inventories', index]));
  const matches = inventories.filter(({ value }) => value?.subject?.refId === agentId);
  if (matches.length) return matches;
  if (inventories.length === 1 && inventories[0].value?.subject?.refId == null) return inventories;
  return [];
}

function snapshot(label, files) {
  const acs = files.acsText == null ? null : parseJson(files.acsText);
  const cdx = files.cdxText == null ? null : parseJson(files.cdxText);
  const inventories = files.inventoryIndex === undefined ? draftInventories(cdx, acs?.agent?.agent_id) :
    [locate(cdx, ['inventories', files.inventoryIndex])];
  return {
    ...files, label, acs, cdx, inventories,
    acsComponents: items(acs?.components).flatMap((entry, index) => entry && typeof entry === 'object' && !Array.isArray(entry) ?
      [locate(acs, ['components', index])] : []),
    cdxComponents: inventories.flatMap(({ value, path }) =>
      items(value?.components).flatMap((entry, index) => entry && typeof entry === 'object' ?
        [locate(value, ['components', index], path)] : [])),
  };
}

const bundled = new Map(data.snapshots.map((files) => [files.id, snapshot(files.label, files)]));

function properties(base, key) {
  const wildcard = key.endsWith('*');
  return items(base.value?.properties).flatMap((entry, index) => {
    const name = entry?.name;
    const match = typeof name === 'string' && (wildcard ? name.startsWith(key.slice(0, -1)) : name === key);
    return match ? [locate(base.value, wildcard ? ['properties', index] : ['properties', index, 'value'], base.path)] : [];
  });
}

function cdxEdges(cdx, ref, type) {
  const edges = [];
  for (const [b, blueprint] of items(cdx.blueprints).entries()) {
    for (const [r, relationship] of items(blueprint?.relationships).entries()) {
      if (ref !== null && relationship?.ref !== ref) continue;
      for (const [i, link] of items(relationship?.custom).entries()) {
        if (link?.type !== type) continue;
        const path = `$.blueprints[${b}].relationships[${r}]`;
        edges.push({
          ref: locate(relationship, ['ref'], path),
          targets: locate(relationship, ['custom', i, 'targets'], path),
        });
      }
    }
  }
  return edges;
}

function isJsonContainer(value) {
  if (typeof value !== 'string' || !/^[\[{]/.test(value.trimStart())) return false;
  try {
    JSON.parse(value);
    return true;
  } catch {
    return false;
  }
}

function cdxValues(rule, base) {
  if (rule.edge) {
    const markers = properties(base, rule.edge.replace('acs:', 'acs:empty:'));
    return markers.length ? markers.map((value) => ({ ...value, note: 'ACS convention for an explicit empty list' })) :
      [missing('Relationship omitted', '$.blueprints')];
  }
  if (rule.property) {
    const values = properties(base, rule.property);
    if (['args', 'derived_from', 'declared_capabilities'].includes(rule.field)) {
      for (const hit of values) {
        if (isJsonContainer(hit.value)) hit.note = 'JSON encoded as a string';
      }
    }
    return values.length ? values : [missing('Field omitted', base.path + '.properties')];
  }
  if (rule.path.includes('definition')) {
    const refs = items(base.value?.externalReferences).flatMap((entry, index) => entry?.type === 'distribution' ?
      [locate(base.value, ['externalReferences', index], base.path)] : []);
    if (!refs.length) return [missing('Distribution reference omitted', base.path + '.externalReferences')];
    return refs.flatMap((ref) => {
      if (rule.field === 'ref') return [locate(ref.value, ['url'], ref.path)];
      const field = rule.field === 'algorithm' ? 'alg' : 'content';
      const hashes = items(ref.value.hashes);
      return hashes.length ? hashes.map((_, index) => locate(ref.value, ['hashes', index, field], ref.path)) :
        [missing('Digest omitted', `${ref.path}.hashes`)];
    });
  }

  const field = { id: 'refId', agent_id: 'refId', endpoint: 'endpoints' }[rule.field] ?? rule.field;
  const primary = locate(base.value, [field], base.path);
  if (field === 'name' && primary.value !== undefined) {
    const fallback = properties(base, 'acs:name-is-id');
    if (fallback.some((marker) => marker.value === 'true')) {
      return [{ ...primary, componentRef: true, note: 'Name stored as a reference ID' }, ...fallback];
    }
  }
  return [primary];
}

function cdxEvidence(rule, current, component) {
  if (!current.cdx) return [missing(exportAvailability(current))];
  if (rule.scope === 'document') {
    if (rule.field !== 'components') return cdxValues(rule, locate(current.cdx, []));
    return current.inventories.length ? current.inventories.map(({ value, path }) => locate(value, ['components'], path)) :
      [missing('No matching CycloneDX draft inventory')];
  }
  if (rule.scope === 'agent') {
    return current.inventories.length ? current.inventories.flatMap(({ value, path }) =>
      cdxValues(rule, locate(value, ['subject'], path))) : [missing('No matching CycloneDX draft inventory')];
  }

  const id = component.value.id;
  const bases = current.cdxComponents.filter(({ value }) => value.refId === id);
  if (rule.edge) {
    const links = cdxEdges(current.cdx, id, rule.edge);
    if (links.length) return links.map(({ targets }) => targets);
  }
  if (!bases.length) return current.inventories.length ? current.inventories.map(({path}) =>
    missing('Component absent from the CycloneDX export', path + '.components')) :
    [missing('No matching CycloneDX draft inventory', '$.inventories')];
  if (bases.length > 1) return bases.flatMap((base) => cdxValues(rule, base).map((hit) =>
    ({ ...hit, note: [hit.note, 'Ambiguous CycloneDX component ID'].filter(Boolean).join(' · ') })));
  return bases.flatMap((base) => cdxValues(rule, base));
}

function appliesTo(rule, { value }) {
  if (rule.kind) return value.type === rule.kind;
  if (rule.field === 'endpoint') return serviceKinds.includes(value.type) !== Boolean(rule.property);
  return true;
}

function acsEvidence(rule, current, component) {
  if (!current.acs) return [missing('No ACS source inventory supplied')];
  const base = rule.scope === 'component' ? component : locate(current.acs, rule.scope === 'agent' ? ['agent'] : []);
  if (component?.acsAbsent) return [missing('Component absent from the AgBOM', '$.components')];
  return [locate(base.value, rule.path, base.path)];
}

function cdxTarget(rule) {
  if (rule.edge) return `Blueprint relationship ${rule.edge} · targets`;
  if (rule.property) return `Property ${rule.property}`;
  const field = rule['CDX schema pointer'].split('/properties/').at(-1);
  if (rule.scope === 'document') return `inventories[*].${field}`;
  if (rule.scope === 'agent') return `inventories[*].subject.${field}`;
  const base = 'inventories[*].components[*]';
  if (!rule.path.includes('definition')) return `${base}.${field}`;
  const reference = `${base}.externalReferences[*]`;
  return rule.field === 'ref' ? `${reference}.${field}` : `${reference}.hashes[*].${field}`;
}

function element(tag, className, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.append(...children);
  return node;
}

function option(value, label) {
  const item = element('option', '', label);
  item.value = value;
  return item;
}

function groupLabel(rule) {
  if (rule.scope !== 'component') return 'Document and agent';
  if (rule.isProvenance || rule.field === 'registration_provenance') return 'Registration provenance';
  if (rule.edge) return 'Relationships';
  if (rule.field === 'type') return 'Component kinds';
  if (rule.kind) return 'Kind-specific fields';
  return 'Component identity and endpoints';
}

const titles = {
  agbom_version: 'ACS schema version', agent_id: 'Agent ID', generated_at: 'Snapshot time', agbom_hash: 'ACS document hash',
  registration_provenance: 'Registration provenance', provenance_id: 'Provenance ID', source_id: 'Registration source',
  derived_from: 'Parent provenance', origin: 'Registration origin', ref: 'Distribution reference', type: 'Component kind',
  algorithm: 'Digest algorithm', value: 'Digest value', id: 'Component ID', tools: 'Tool references',
  mcp_servers: 'MCP server references', a2a_peers: 'A2A peer references', models: 'Bundled models',
  composed_skills: 'Permitted child skills',
};

function dataText(value) {
  return value === undefined ? 'Not supplied' : typeof value === 'string' ? value : JSON.stringify(value);
}

function componentKind(entry) {
  const declared = items(entry.properties).find((property) => property?.name === 'acs:kind')?.value;
  const kind = declared ?? (entry.type === 'machine-learning-model' ? 'model' : entry.type);
  if (typeof kind !== 'string') return 'Component';
  return Object.hasOwn(kindNames, kind) ? kindNames[kind] : kind.replace(/[-_]/g, ' ');
}

function componentName(entry) {
  return typeof entry.name === 'string' && entry.name.trim() &&
    !items(entry.properties).some((property) => property?.name === 'acs:name-is-id' && property?.value === 'true') ?
    entry.name : undefined;
}

function componentLabel(entry) {
  const name = componentName(entry);
  const kind = componentKind(entry);
  if (!name) return kind;
  const words = ' ' + name.toLowerCase().split(/\W+/).join(' ') + ' ';
  if (words.includes(' ' + kind.toLowerCase() + ' ')) return name;
  const suffix = /^[A-Z\d]{2}/.test(kind) ? kind : kind.toLowerCase();
  return name + ' ' + suffix;
}

function componentReference(entry, id, includeKind = true) {
  if (!entry) return 'Unresolved component reference · ' + dataText(id);
  return includeKind ? componentLabel(entry) : componentName(entry) ?? componentLabel(entry);
}

function relationshipVerb(type) {
  const verbs = {
    'acs:exposes-tool': 'exposes', 'acs:uses-tool': 'uses', 'acs:uses-mcp-server': 'uses',
    'acs:uses-peer': 'uses', 'acs:bundles-model': 'bundles', 'acs:may-load-skill': 'may load',
    dependsOn: 'depends on', contains: 'contains', provides: 'provides', serves: 'serves',
    aggregates: 'aggregates', associates: 'is associated with', composes: 'composes',
    generalizes: 'generalizes', realizes: 'realizes',
  };
  return Object.hasOwn(verbs, type) ? verbs[type] : 'is related to';
}

function technicalDetails(...children) {
  return element('details', 'technical-details', element('summary', '', 'Technical details'), ...children);
}

function coverageBadge(rule) {
  const label = rule.Coverage;
  const style = { Native: 'native', 'ACS convention': 'convention', 'Partial or lossy': 'partial' }[label];
  return element('span', `badge ${style}`, label);
}

function term(label, value) {
  return element('div', '', element('dt', '', label), element('dd', '', value));
}

const acsSchemaBase = 'https://github.com/GenAI-Security-Project/agent-control-standard/blob/' +
  data.config.acsCommit + '/specification/v0.1.0/';
const cdxSchemaBase = 'https://github.com/CycloneDX/specification/blob/' + data.config.targetCommit + '/schema/2.0/';

function link(href, label) {
  const anchor = element('a', '', label);
  anchor.href = href;
  return anchor;
}

function schemaLink(base, pointer) {
  return link(base + pointer.split('#')[0], element('code', '', pointer));
}

function resolution(rule) {
  if (rule.edge) return 'cdxEdges reads typed blueprint links in source-to-target direction. cdxValues reads explicit empty markers.';
  if (rule.path.includes('definition')) return 'cdxValues selects distribution references and reads their hashes.';
  if (rule.field === 'name') return 'cdxValues checks the ACS ID fallback marker.';
  if (rule.property) return 'properties resolves exact ACS property names or a provenance prefix. cdxValues retains encoded strings.';
  return 'draftInventories resolves the agent subject. cdxEvidence locates membership and matches components by refId.';
}

function referenceTable(headers, rows, caption, fieldReference = false) {
  const table = element('table', fieldReference ? 'reference-table field-reference-table' : 'reference-table', ...(caption ? [element('caption', 'visually-hidden', caption)] : []));
  const headings = headers.map((header) => {
    const head = element('th', '', header);
    head.scope = 'col';
    return head;
  });
  table.append(element('thead', '', element('tr', '', ...headings)),
    element('tbody', '', ...rows.map(([name, ...values]) => {
      const head = element('th', '', name);
      head.scope = 'row';
      return element('tr', '', head, ...values.map((value) => element('td', '', value)));
    })));
  const region = element('div', 'table-scroll', table);
  if (fieldReference) {
    region.tabIndex = 0;
    region.setAttribute('role', 'region');
    region.setAttribute('aria-label', caption);
  }
  return region;
}

function ruleLink(rule) {
  return link('#' + rule.id, 'View Rule ' + rule.id);
}

function mappingDetails(rule) {
  return referenceTable(['Rule detail', 'Description'], [
    ['Coverage', coverageBadge(rule)],
    ['Rationale', rule.Rationale],
    ['Requirement', [rule.Requirement, rule['Applies to']].filter(Boolean).join(' · ')],
    ['ACS schema pointer', schemaLink(acsSchemaBase, rule['ACS schema pointer'])],
    ['CycloneDX schema pointer', schemaLink(cdxSchemaBase, rule['CDX schema pointer'])],
    ['Proposed target', element('code', '', cdxTarget(rule))],
    ['Type or profile key', element('code', '', rule['CDX type / profile key'])],
    ['Reader logic', resolution(rule)],
    ['Rule test example', rule['Positive fixture'] + ' · ' + rule['Semantic assertion']],
  ], 'Rule details for ' + rule.id);
}

const fieldDefinitions = new Map(data.reference.acs.flatMap(({schema, fields}) =>
  fields.map((field) => [schema + '#' + field.pointer, field])));

function renderReference() {
  const referenceSection = (title, fields, schema, base, side) => {
    const rows = fields.map((field) => {
      const ruleList = rules.filter((rule) => rule[side + ' schema pointer'] === schema + '#' + field.pointer);
      const links = element('div', 'reference-links', ...ruleList.map(ruleLink));
      return [element('code', '', field.field), field.type, field.required, field.description || '—', ruleList.length ? links : '—'];
    });
    return element('details', 'panel reference-section', element('summary', '', title + ' · ' + fields.length + ' fields'),
      element('p', 'explanation', link(base + schema, 'Pinned schema · ' + schema)),
      referenceTable(['Field', 'Expected type', 'When required', 'Description', 'Mapping rules'], rows, title, true));
  };
  byId('reference-content').append(
    element('p', 'muted explanation', 'Nested requirements apply within the containing object. Registration provenance is optional in the base schema and required by ACS-Provenance.'),
    ...data.reference.acs.map(({title, fields, schema}) => referenceSection(title, fields, schema, acsSchemaBase, 'ACS')),
    referenceSection('CycloneDX document fields', data.reference.cdx, 'cyclonedx-2.0.schema.json', cdxSchemaBase, 'CDX'));
}

function renderCatalog() {
  const body = byId('rule-content');
  for (const rule of rules) {
    const card = element('details', 'panel rule-card',
      element('summary', '', rule.id + ' — ' + rule['Consumer question'], ' ', coverageBadge(rule)),
      mappingDetails(rule));
    card.id = rule.id;
    body.append(card);
  }
}

function referencedValues(hit, entries, key) {
  if (hit.value === undefined) return hit;
  const ids = Array.isArray(hit.value) ? hit.value : [hit.value];
  const names = ids.map((id) => {
    const matches = entries.filter(({value}) => value[key] === id);
    return componentReference(matches.length === 1 ? matches[0].value : undefined, id);
  });
  return { ...hit, names };
}

function addValue(cell, hit) {
  const block = element('div', 'value');
  if (hit.value === undefined) {
    block.append(element('span', 'missing', hit.note ?? 'Field omitted'));
  } else if (Array.isArray(hit.value) && !hit.value.length) {
    block.append(element('span', 'note', 'Empty list '), element('code', 'inline-code', '[]'));
  } else {
    const raw = JSON.stringify(hit.value, null, 2);
    const inline = Array.isArray(hit.value) && raw.length < 100 &&
      hit.value.every((item) => item === null || typeof item !== 'object');
    const rendered = element('code', 'literal', inline ? `[${hit.value.map((entry) => JSON.stringify(entry)).join(', ')}]` : raw);
    if (hit.names?.length) {
      const names = hit.names.length === 1 ? element('span', 'reference-name', hit.names[0]) :
        element('ul', 'reference-names', ...hit.names.map((name) => element('li', '', name)));
      const trace = technicalDetails(rendered);
      if (hit.relationship) trace.append(element('code', 'literal', hit.relationship));
      block.append(names, trace);
    } else if (raw.length > 500) {
      const label = Array.isArray(hit.value) ? `View value · ${hit.value.length} entries` : 'View full value';
      block.append(element('details', 'long-value', element('summary', '', label), rendered));
    } else {
      block.append(rendered);
    }
  }
  if (hit.note && hit.value !== undefined) block.append(element('span', 'note', hit.note));
  if (hit.path) block.append(element('code', 'path', hit.path));
  cell.append(block);
}

function cdxExpectedEncoding(rule) {
  const target = rule['CDX type / profile key'].split(';')[0];
  const source = fieldDefinitions.get(rule['ACS schema pointer'])?.type.split(' · ')[0];
  if (rule.property?.endsWith('*')) return 'properties with string values';
  if (rule.property && target === 'string') {
    if (source === 'integer') return 'string containing an integer';
    if (source === 'object') return 'string containing a JSON object';
    if (source?.startsWith('array')) return 'string containing a JSON array';
    if (source === 'boolean') return 'string containing a boolean';
  }
  return target;
}

function mappingField(cell, location, type) {
  cell.append(element('div', 'mapping-field', element('code', '', location),
    element('span', 'muted', type)));
}

function mappingValue(hit, current, rule, side) {
  const acs = side === 'acs';
  const key = acs ? 'id' : 'refId';
  const entries = acs ? current.acsComponents : current.cdxComponents;
  if (rule.field === 'components' && Array.isArray(hit.value) && hit.value.length) {
    return { ...hit, names: hit.value.map((entry) => componentReference(entry, entry?.[key])) };
  }
  if (rule.field === 'id' || (rule.edge && Array.isArray(hit.value)) || (hit.componentRef && rule.scope === 'component')) {
    return { ...referencedValues(hit, entries, key), relationship: rule.edge };
  }
  if (rule.field === 'agent_id' || (hit.componentRef && rule.scope === 'agent')) {
    const subjects = acs ? [{ value: { name: current.acs?.agent?.name, type: 'agent', id: current.acs?.agent?.agent_id } }] :
      current.inventories.filter(({value}) => value?.subject).map(({value}) => ({ value: { ...value.subject, type: 'agent' } }));
    return referencedValues(hit, subjects, key);
  }
  return hit;
}

function mappingRow(current, { rule, component, subject, title, acs, cdx, aibom, exposingServer }) {
  title ??= aibom ? 'Referenced model AIBOM' :
    titles[rule.field] ?? rule.field.replace(/^.|_/g, (match) => match === '_' ? ' ' : match.toUpperCase());
  const head = element('th', 'field-title', element('strong', '', title));
  head.scope = 'row';
  if (subject || component) head.append(element('span', 'row-subject', subject ?? componentLabel(component.display ?? component.value)));
  const acsCell = element('td', 'cell', element('span', 'format-mobile', 'ACS'));
  const cdxCell = element('td', 'cell', element('span', 'format-mobile', 'CycloneDX'));
  if (aibom) {
    head.append(element('span', 'badge native', 'CycloneDX reference'));
    acsCell.append(element('span', 'muted', 'No dedicated ACS model field'));
    renderAibomReference(cdxCell, current, component);
    return element('tr', 'field-row', head, acsCell, cdxCell);
  }
  head.append(coverageBadge(rule), element('div', 'rule-link', ruleLink(rule)));
  const definition = fieldDefinitions.get(rule['ACS schema pointer']);
  const source = rule.isProvenance ? rule.path.join('.') : definition.field;
  mappingField(acsCell, exposingServer ? 'id' : source,
    exposingServer ? 'string' : definition.type);
  const target = exposingServer ? 'blueprints[*].relationships[*].ref' : rule.edge ?
    'blueprints[*].relationships[*].custom[*].targets' : cdxTarget(rule);
  mappingField(cdxCell, target, exposingServer ? 'component reference ID' : cdxExpectedEncoding(rule));
  for (const hit of acs ?? acsEvidence(rule, current, component)) {
    addValue(acsCell, mappingValue(hit, current, rule, 'acs'));
  }
  for (const hit of cdx ?? cdxEvidence(rule, current, component)) {
    addValue(cdxCell, mappingValue(hit, current, rule, 'cdx'));
  }
  return element('tr', 'field-row', head, acsCell, cdxCell);
}

function evidenceTable(current, rows, caption) {
  const table = element('table', 'matrix', element('caption', 'visually-hidden', caption));
  const headings = ['Fact and coverage', 'ACS value', current.cdx ? 'CycloneDX actual value' : 'CycloneDX proposed mapping'].map((text) => {
    const head = element('th', '', text);
    head.scope = 'col';
    return head;
  });
  table.append(element('thead', '', element('tr', '', ...headings)), element('tbody', '',
    ...rows.map((row) => mappingRow(current, row))));
  return table;
}

function acsExposures(current) {
  return current.acsComponents.flatMap(({ value, path }) => value.type === 'mcp_server' ? [{
    ref: locate(value, ['id'], path),
    targets: locate(value, ['mcp_server_fields', 'tools'], path),
  }] : []);
}

function scenarioEvidence(current) {
  const tools = current.acsComponents.filter(({ value }) => value.type === 'tool');
  const cdxOnly = current.cdxComponents.filter(({ value }) => value.refId != null &&
    !tools.some((tool) => tool.value.id === value.refId) &&
    items(value.properties).some((prop) => prop?.name === 'acs:kind' && prop.value === 'tool'));
  if (!tools.length && !cdxOnly.length) return [element('p', 'panel empty-state', 'Tool absent from this snapshot')];

  const find = (field) => rules.find((rule) => rule.field === field && rule.scope === 'component');
  const edge = rules.find((rule) => rule.edge === 'acs:exposes-tool');
  const exposures = acsExposures(current);
  const exportExposures = current.cdx ? cdxEdges(current.cdx, null, edge.edge) : [];
  const absent = (component) => [{ ...component, note: 'Tool absent from this snapshot' }];
  const matches = [...tools.map((component) => ({ component, tool: component.value })),
    ...cdxOnly.map(({ value }) => ({
      component: missing('Tool absent from this snapshot', '$.components'),
      tool: { id: value.refId, name: value.name, type: 'tool' },
    }))];

  return matches.map(({ component, tool }) => {
    const { id } = tool;
    const label = componentReference(tool);
    const servers = exposures.filter(({ targets }) => items(targets.value).includes(id));
    const cdxServers = exportExposures.filter(({ targets }) => items(targets.value).includes(id));
    const acsMiss = missing(component.value ? 'No exposing server recorded' : 'Tool absent from this snapshot');
    const cdxMiss = missing(current.cdx ? 'No exposing server recorded' : exportAvailability(current));
    const fields = [
      { rule: edge, title: 'Exposing MCP server', exposingServer: true,
        acs: servers.length ? servers.map(({ ref }) => ({ ...ref, componentRef: true })) : [acsMiss],
        cdx: cdxServers.length ? cdxServers.map(({ ref }) => ({ ...ref, componentRef: true })) : [cdxMiss] },
      { rule: edge, title: 'Server exposure targets',
        acs: servers.length ? servers.map(({ targets }) => targets) : [acsMiss],
        cdx: cdxServers.length ? cdxServers.map(({ targets }) => targets) : [cdxMiss] },
      ...[
        ['origin', 'Registration origin'], ['source_id', 'Registration source'], ['provider', 'Tool publisher (provider)'],
        ['provenance_id', 'Provenance ID'], ['derived_from', 'Parent provenance'],
      ].map(([field, title]) => ({
        rule: find(field), title, component: { value: tool, path: component.path },
        acs: component.value ? undefined : absent(component),
      })),
    ];
    return element('section', 'tool-evidence', element('h3', '', label),
      evidenceTable(current, fields, `Mapping evidence for ${label}`));
  });
}

const modelQuestion = 'Which AIBOM file describes this model revision?';
let localModelEvidence;

function documentBomLink(value) {
  return typeof value === 'string' && /^urn:cdx:([\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12})\/([1-9]\d*)$/i.exec(value);
}

function resolveAibom(current, attachments, reference) {
  const bomLink = documentBomLink(reference);
  const parent = current.cdxFile?.slice(0, current.cdxFile.lastIndexOf('/') + 1) ?? '';
  const matches = attachments.filter(({file, doc}) => {
    if (!doc) return false;
    if (bomLink) return typeof doc.serialNumber === 'string' &&
      doc.serialNumber.toLowerCase() === 'urn:uuid:' + bomLink[1].toLowerCase() &&
      String(doc.version) === bomLink[2];
    return typeof reference === 'string' && file === parent + reference.replace(/^\.\//, '');
  });
  return matches.length === 1 ? matches[0] : undefined;
}

const aibomDialog = byId('aibom-dialog');
byId('close-aibom').addEventListener('click', () => aibomDialog.close());

function fileLabel(file) {
  return file?.split('/').at(-1);
}

function aibomAction(attachment) {
  const filename = fileLabel(attachment.file);
  const open = element('button', 'text-action', 'Open AIBOM JSON');
  open.type = 'button';
  open.addEventListener('click', () => {
    byId('aibom-title').textContent = filename;
    showJson('aibom-json', JSON.stringify(attachment.doc, null, 2));
    aibomDialog.showModal();
  });
  return element('div', 'aibom-file', element('code', '', filename), open);
}

function renderAibomReference(cell, current, component) {
  const modelId = component.value.id;
  const refs = current.cdxComponents.filter(({value}) => value.refId === modelId && value.type === 'machine-learning-model')
    .flatMap(({value, path}) => items(value.externalReferences).flatMap((entry, i) =>
      entry?.type === 'bom' ? [locate(value, ['externalReferences', i, 'url'], path)] : []));
  const associations = items(current.associations).filter(({record}) => record.modelId === modelId);
  const associated = associations.map((entry) => ({ file: entry.aibomFile, doc: entry.aibom, association: entry }));
  const attachments = new Map();
  for (const attachment of [...items(current.aiboms), ...associated]) {
    if (attachment.file && attachment.doc) attachments.set(attachment.file, attachment);
  }
  const showAssociationSource = ({file, location}) => {
    cell.append(element('p', 'muted', 'Filename from ', element('code', '', fileLabel(file))));
    if (location) cell.append(element('code', 'aibom-source path', location + '.aibom'));
  };
  for (const hit of refs) {
    const attachment = resolveAibom(current, [...attachments.values()], hit.value);
    if (attachment) cell.append(aibomAction(attachment));
    else cell.append(element('p', 'muted', 'AIBOM file unavailable'));
    if (attachment?.association) showAssociationSource(attachment.association);
    mappingField(cell, 'externalReferences[*].url', 'URI or BOM-Link (type = bom)');
    const bomLink = documentBomLink(hit.value);
    addValue(cell, { ...hit, note: bomLink ? 'BOM-Link · Document ID ' + bomLink[1] + ' · BOM revision ' + bomLink[2] : undefined });
  }
  if (!refs.length) {
    for (const attachment of associated) {
      if (attachment.doc) cell.append(aibomAction(attachment));
      else if (attachment.file) cell.append(element('p', 'muted', 'AIBOM file unavailable · ' + fileLabel(attachment.file)));
      showAssociationSource(attachment.association);
    }
    mappingField(cell, 'externalReferences[*].url', 'URI or BOM-Link (type = bom)');
    cell.append(element('p', 'muted', current.cdx ? 'No CycloneDX BOM reference recorded' : 'No CycloneDX artifact available'));
  }
  cell.append(...(localModelEvidence?.(current, component, refs) ?? []));
}

function mappingComponents(current) {
  return [...current.acsComponents, ...current.cdxComponents.flatMap(({ value }) => {
    if (typeof value.refId !== 'string' || current.acsComponents.some((entry) => entry.value.id === value.refId)) return [];
    const kind = items(value.properties).find((entry) => entry?.name === 'acs:kind')?.value ??
      (value.type === 'machine-learning-model' ? 'model' : undefined);
    return [{ value: { id: value.refId, type: kind, name: value.name }, display: value, acsAbsent: true }];
  })];
}

const evidenceGroup = 'Evidence questions';
const evidenceFields = new Set(['endpoint', 'protocol_version', 'agent_card_ref', 'source_id', 'derived_from',
  'ref', 'value', 'algorithm', 'version', 'scope', 'source_type', 'generated_at', 'agbom_hash']);
const focusAreas = [['document', 'Document and agent'], ...Object.entries(kindNames)];
const questionGroups = [...new Set(rules.map(groupLabel)), evidenceGroup];
const coverageLevels = [...new Set(rules.map((rule) => rule.Coverage))];

function rulesForFocus(kind) {
  if (!kind) return rules;
  if (kind === 'document') return rules.filter(({scope}) => scope !== 'component');
  return rules.filter((rule) => rule.scope === 'component' && appliesTo(rule, {value: {type: kind}}));
}

function ruleInGroup(rule, group) {
  if (group === evidenceGroup) return rule.edge || evidenceFields.has(rule.field);
  return !group || groupLabel(rule) === group;
}

function renderMappingInto(evidence, current, { question = '', kind = '', group = '', coverage = '', showPaths = true } = {}) {
  evidence.classList.toggle('show-paths', showPaths);
  if (question === scenario) {
    evidence.replaceChildren(...scenarioEvidence(current));
    return;
  }
  const byModel = question === modelQuestion;
  const activeRules = rulesForFocus(kind).filter((rule) => (byModel || !questions.has(question) || rule.id === question) &&
    ruleInGroup(rule, group) && (!coverage || rule.Coverage === coverage));
  const entries = mappingComponents(current).filter(({value}) => (!kind || value.type === kind) && (!byModel || value.type === 'model'));
  const documentRows = !byModel ?
    activeRules.filter(({scope}) => scope !== 'component').map((rule) => ({rule})) : [];
  const rows = [...documentRows, ...entries.flatMap((component) => {
    const fields = byModel ? [] : activeRules.filter((rule) => rule.scope === 'component' && appliesTo(rule, component))
      .map((rule) => ({rule, component}));
    if (!coverage && (!group || group === evidenceGroup) && (!questions.has(question) || byModel) && component.value.type === 'model') {
      fields.push({ aibom: true, component });
    }
    return fields;
  })];
  evidence.replaceChildren(rows.length ? evidenceTable(current, rows, 'AgBOM to CycloneDX mapping evidence') :
    element('p', 'panel empty-state', 'No applicable fields in the selected inventory.'));
}

function createMappingControls(prefix, evidence) {
  const focus = element('select');
  const group = element('select');
  const coverage = element('select');
  const question = element('select');
  const pathToggle = element('input');
  pathToggle.type = 'checkbox';
  pathToggle.checked = true;
  pathToggle.id = prefix + 'show-paths';
  const reset = element('button', 'text-action', 'All mapping rules');
  reset.id = prefix + 'all-rules';
  reset.type = 'button';
  const labeled = (select, id, text) => {
    select.id = prefix + id;
    const label = element('label', '', text);
    label.htmlFor = select.id;
    return element('div', 'select-field', label, select);
  };
  const root = element('div', 'mapping-controls',
    labeled(focus, 'focus-filter', 'Focus area'), labeled(group, 'group-filter', 'Question group'),
    labeled(question, 'question', 'Select a question'), labeled(coverage, 'coverage-filter', 'Filter coverage'),
    element('label', 'toggle', pathToggle, ' Show JSON paths'), reset);
  let current;
  const setOptions = (select, allLabel, choices, available, unavailable = '') => {
    const value = select.value;
    select.replaceChildren(option('', allLabel), ...choices.map(([key, label]) => {
      const enabled = available.has(key);
      const item = option(key, label + (!enabled ? unavailable : ''));
      item.disabled = !enabled;
      return item;
    }));
    select.value = available.has(value) ? value : '';
  };
  const render = () => renderMappingInto(evidence, current, {
    question: question.value, kind: focus.value, group: group.value, coverage: coverage.value, showPaths: pathToggle.checked,
  });
  function refresh(preferred = question.value) {
    const entries = mappingComponents(current);
    const kinds = new Set(['document', ...entries.map(({value}) => value.type)]);
    setOptions(focus, 'All focus areas', focusAreas, kinds, ' (absent)');
    const candidates = rulesForFocus(focus.value).filter((rule) => rule.scope !== 'component' ||
      entries.some((entry) => appliesTo(rule, entry)));
    const specials = [];
    if (kinds.has('model') && (!focus.value || focus.value === 'model')) specials.push(modelQuestion);
    if (kinds.has('tool') && (!focus.value || ['tool', 'mcp_server'].includes(focus.value))) specials.push(scenario);
    const groups = new Set(questionGroups.filter((name) => candidates.some((rule) => ruleInGroup(rule, name))));
    if (specials.length) groups.add(evidenceGroup);
    setOptions(group, 'All question groups', questionGroups.map((name) => [name, name]), groups);
    const grouped = candidates.filter((rule) => ruleInGroup(rule, group.value));
    setOptions(coverage, 'All coverage levels', coverageLevels.map((label) => [label, label]), new Set(grouped.map((rule) => rule.Coverage)));
    const narrow = focus.value || group.value || coverage.value;
    question.replaceChildren(option('', 'All mapping rules'));
    if (narrow) question.append(option('matching', 'All matching questions'));
    if (!coverage.value && (!group.value || group.value === evidenceGroup)) {
      question.append(...specials.map((label) => option(label, label)));
    }
    question.append(...grouped.filter((rule) => !coverage.value || rule.Coverage === coverage.value)
      .map((rule) => option(rule.id, rule.id + ' — ' + rule['Consumer question'])));
    question.value = preferred && [...question.options].some(({value}) => value === preferred) ?
      preferred : narrow ? 'matching' : '';
    render();
  }
  const resetFilters = () => {
    focus.value = group.value = coverage.value = '';
    refresh('');
  };
  for (const select of [focus, group, coverage]) select.addEventListener('change', () => refresh());
  question.addEventListener('change', () => question.value ? render() : resetFilters());
  pathToggle.addEventListener('change', () => evidence.classList.toggle('show-paths', pathToggle.checked));
  reset.addEventListener('click', resetFilters);
  return {
    root,
    show(snapshot, requestedFocus) {
      current = snapshot;
      if (requestedFocus === undefined) return refresh();
      if (!focus.options.length) {
        focus.append(option('', 'All focus areas'), ...focusAreas.map(([key, label]) => option(key, label)));
      }
      focus.value = requestedFocus;
      group.value = coverage.value = '';
      refresh('');
    },
  };
}

// Format the original tokens so the JSON panes retain exact strings and numeric literals.
const jsonTokens = /"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[Ee][+-]?\d+)?|true|false|null|[{}\[\],:]/g;

function showJson(id, source) {
  renderJson(byId(id), source);
}

function renderJson(output, source) {
  output.replaceChildren();
  output.scrollTop = 0;
  output.scrollLeft = 0;
  if (!source) return;
  const fragment = document.createDocumentFragment();
  const tokens = source.match(jsonTokens);
  let depth = 0;
  const line = () => fragment.append(`\n${'  '.repeat(depth)}`);
  for (const [index, token] of tokens.entries()) {
    const next = tokens[index + 1];
    const previous = tokens[index - 1];
    if (token === '{' || token === '[') {
      fragment.append(token);
      depth++;
      if (next !== '}' && next !== ']') line();
    } else if (token === '}' || token === ']') {
      depth--;
      if (previous !== '{' && previous !== '[') line();
      fragment.append(token);
    } else if (token === ',') {
      fragment.append(token);
      line();
    } else if (token === ':') {
      fragment.append(': ');
    } else {
      const type = token.startsWith('"') ? (next === ':' ? 'key' : 'string') :
        /^(true|false|null)$/.test(token) ? 'constant' : 'number';
      fragment.append(element('span', `json-${type}`, token));
    }
  }
  output.append(fragment);
}

const exportPanel = byId('export-panel');
const primary = [...bundled.values()].find(({role}) => role === 'primary');
const mainMapping = createMappingControls('', byId('evidence'));
byId('mapping-filters').append(mainMapping.root);

function showView(focus = false) {
  const [hash, requestedFocus] = location.hash.slice(1).split('/');
  const rule = rules.find(({id, legacyId}) => id === hash || legacyId === hash);
  const nav = [...document.querySelectorAll('[data-view]')];
  const view = rule ? 'mapping-rules' : nav.some((link) => !link.hidden && link.dataset.view === hash) ? hash : 'agbom-json';
  for (const link of nav) {
    const active = link.dataset.view === view;
    byId(link.dataset.view).hidden = !active;
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  if (view === 'cyclonedx-mapping') {
    if (requestedFocus === 'all' || focusAreas.some(([key]) => key === requestedFocus)) {
      mainMapping.show(primary, requestedFocus === 'all' ? '' : requestedFocus);
    } else if (!byId('evidence').hasChildNodes()) {
      mainMapping.show(primary);
    }
  }
  if (rule) {
    const card = byId(rule.id);
    card.open = true;
    card.scrollIntoView({block: 'start'});
    if (focus) card.querySelector('summary').focus({preventScroll:true});
  } else if (focus) {
    window.scrollTo(0, 0);
    byId(view).querySelector('h2').focus({preventScroll:true});
  }
}

function inspectInventory(current) {
  const {acs, acsFile} = current;
  if (!acs) return [];
  const requirements = data.reference.requirements;
  const notes = [];
  const check = (entry, required, path) => {
    for (const key of required) if (entry == null || !Object.hasOwn(entry, key)) notes.push(acsFile + ' · ' + path + '.' + key + ' is required and missing.');
  };
  check(acs, requirements.document, '$');
  if (acs.agent && typeof acs.agent === 'object' && !Array.isArray(acs.agent)) check(acs.agent, requirements.agent, '$.agent');
  else if (Object.hasOwn(acs, 'agent')) notes.push(acsFile + ' · $.agent must be an object.');
  if (Object.hasOwn(acs, 'components') && !Array.isArray(acs.components)) notes.push(acsFile + ' · $.components must be an array.');
  const seen = new Set();
  if (Array.isArray(acs.components)) {
    for (const [i, entry] of acs.components.entries()) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        notes.push(acsFile + ' · $.components[' + i + '] must be an object. Its recorded value is in the JSON pane.');
      }
    }
  }
  for (const {value, path} of current.acsComponents) {
    const kind = Object.hasOwn(requirements.kinds, value.type) ? requirements.kinds[value.type] : [];
    check(value, [...requirements.component, ...kind], path);
    for (const [block, fields] of Object.entries(requirements.nested)) {
      if (value[block] != null) check(value[block], fields, path + '.' + block);
    }
    if (value.skill_fields?.definition != null) {
      check(value.skill_fields.definition, ['ref','digest'], path + '.skill_fields.definition');
      if (value.skill_fields.definition.digest != null) {
        check(value.skill_fields.definition.digest, ['algorithm','value'], path + '.skill_fields.definition.digest');
      }
    }
    if (value.registration_provenance != null) check(value.registration_provenance, requirements.provenance, path + '.registration_provenance');
    if (typeof value.id === 'string' && seen.has(value.id)) notes.push(acsFile + ' · Ambiguous component ID ' + JSON.stringify(value.id) + ' at ' + path + '.id');
    seen.add(value.id);
  }
  return notes;
}

const sampleComponent = byId('sample-component');
sampleComponent.append(option('all', 'Whole AgBOM'), option('agent', 'Agent subject'),
  ...primary.acsComponents.map(({value}) => option(value.id, componentLabel(value))));
const sampleDownload = byId('sample-download');
sampleDownload.href = './' + primary.cdxFile;
sampleDownload.download = fileLabel(primary.cdxFile);
if (location.protocol === 'file:') {
  // Download the original asset bytes when the browser ignores download on a file URL.
  sampleDownload.addEventListener('click', (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
    event.preventDefault();
    const url = URL.createObjectURL(new Blob([primary.cdxText], {type: 'application/json'}));
    const download = link(url, '');
    download.download = sampleDownload.download;
    download.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}

const expectedByPath = new Map();
for (const rule of rules) {
  const entries = rule.scope === 'component' ? primary.acsComponents.filter((entry) => appliesTo(rule, entry)) : [undefined];
  for (const component of entries) {
    for (const hit of cdxEvidence(rule, primary, component)) {
      if (hit.value !== undefined && typeof hit.value !== 'object') {
        expectedByPath.set(hit.path, cdxExpectedEncoding(rule));
      }
    }
  }
}

function annotatedValue(value, path, key = '') {
  if (Array.isArray(value)) return value.map((item, i) => annotatedValue(item, path + '[' + i + ']', key));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([field, entry]) => {
      if (['specFormat', 'specVersion', 'type', 'alg'].includes(field) || (field === 'name' && Object.hasOwn(value, 'value'))) return [field, entry];
      if (field === 'url' && value.type === 'bom') return [field, '<URI for the model AIBOM>'];
      return [field, annotatedValue(entry, path + '.' + field, field)];
    }));
  }
  const expected = {ref: 'component reference ID', targets: 'component reference ID', url: 'URI', endpoints: 'URI'};
  return '<' + (expectedByPath.get(path) ?? expected[key] ?? (value === null ? 'null' : typeof value)) + '>';
}

let typedSample = false;
function showSample() {
  const id = sampleComponent.value;
  const target = primary.cdxComponents.find(({value}) => value.refId === id);
  const subject = id === 'agent' ? locate(primary.inventories[0].value, ['subject'], primary.inventories[0].path) : undefined;
  const part = target ?? subject ?? { value: primary.cdx, path: '$' };
  byId('sample-values').setAttribute('aria-pressed', String(!typedSample));
  byId('sample-placeholders').setAttribute('aria-pressed', String(typedSample));
  byId('sample-mode-note').hidden = !typedSample;
  byId('sample-format').textContent = typedSample ? 'Expected types in JSON' : 'CycloneDX 2.0-dev JSON';
  byId('sample-filename').textContent = primary.cdxFile + (part.path === '$' ? '' : ' · ' + part.path);
  showJson('sample-json', !typedSample && id === 'all' ? primary.cdxText :
    JSON.stringify(typedSample ? annotatedValue(part.value, part.path) : part.value, null, 2));
  const component = primary.acsComponents.find(({value}) => value.id === id);
  const review = byId('sample-mapping');
  review.href = '#cyclonedx-mapping/' + (component?.value.type ?? (id === 'agent' ? 'document' : 'all'));
  review.textContent = component ? 'Review this component’s mapping' :
    id === 'agent' ? 'Review the agent mapping' : 'Review full mapping';
}
sampleComponent.addEventListener('change', showSample);
for (const [id, typed] of [['sample-values', false], ['sample-placeholders', true]]) {
  byId(id).addEventListener('click', () => { typedSample = typed; showSample(); });
}

byId('mapping-files').append(
  term('ACS source', element('code', '', primary.acsFile)),
  term('CycloneDX sample', element('code', '', primary.cdxFile)));
exportPanel.addEventListener('toggle', () => {
  if (exportPanel.open) showJson('cdx-json', primary.cdxText);
});
byId('guide-link').href = data.config.guideHref;
byId('mapping-target').textContent = 'CycloneDX ' + data.config.mappingTarget;
byId('publication-label').textContent = data.config.publicationLabel;
byId('publication-label').hidden = !data.config.publicationLabel;
byId('reviewed-acs').append('Reviewed against ACS ', element('code', '', data.config.reviewedAcs));
byId('target-commit').append('CycloneDX ' + data.config.mappingTarget + ' target commit ',
  link('https://github.com/CycloneDX/specification/commit/' + data.config.targetCommit,
    element('code', '', data.config.targetCommit)));
byId('mapping-revision').append('Mapping CSV SHA-256 ', element('code', '', data.mappingRevision));
document.addEventListener('click', (event) => {
  const anchor = event.target.closest('a[href^="#"]');
  if (!anchor || (anchor.hash !== '#main' && !anchor.dataset.view && !anchor.hasAttribute('data-view-link') && !rules.some(({id, legacyId}) => anchor.hash === '#' + id || anchor.hash === '#' + legacyId)) ||
      event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  if (anchor.hash === '#main') return;
  event.preventDefault();
  if (location.hash !== anchor.hash) history.pushState(null, '', anchor.hash);
  showView(true);
});
for (const navLink of document.querySelectorAll('[data-view]')) {
  byId(navLink.dataset.view).querySelector('h2').tabIndex = -1;
}
window.addEventListener('hashchange', () => showView());

const theme = byId('theme');
theme.addEventListener('click', () => {
  const light = document.documentElement.dataset.theme === 'dark';
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
  theme.setAttribute('aria-pressed', String(light));
  theme.querySelector('.theme-symbol').textContent = light ? '☾' : '☼';
  byId('theme-label').textContent = light ? 'Dark mode' : 'Light mode';
});

renderReference();
renderCatalog();
showSample();
showView();
