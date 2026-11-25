import { lstat, readdir, readFile } from 'node:fs/promises';
import { join, posix } from 'node:path';

const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const list = (value) => Array.isArray(value) ? value : [];
const fold = (name) => name.toLowerCase();

function containsModel(components) {
  return list(components).some((component) => component?.type === 'machine-learning-model' || containsModel(component?.components));
}

function classify(value, filename) {
  if (!record(value)) throw new Error('Expected a JSON object');
  if (Object.hasOwn(value, 'agbom') || Object.hasOwn(value, 'full_snapshot') || Object.hasOwn(value, 'diff')) return 'event';
  if (value.specFormat === 'CycloneDX' || value.bomFormat === 'CycloneDX') {
    if (typeof value.specVersion !== 'string') throw new Error('CycloneDX specVersion is missing or invalid');
    if (filename.endsWith('.aibom.json') || (!Array.isArray(value.inventories) && containsModel(value.components))) return 'aibom';
    if (!['2.0', '2.0-dev'].includes(value.specVersion)) return 'unsupported';
    if (!Array.isArray(value.inventories) || !value.inventories.every((inventory) =>
      record(inventory) && (!Object.hasOwn(inventory, 'components') || Array.isArray(inventory.components)))) {
      throw new Error('CycloneDX draft inventories are missing or invalid');
    }
    return 'cdx';
  }
  if (Object.hasOwn(value, 'agbom_version') || (record(value.agent) && Object.hasOwn(value, 'components'))) return 'acs';
  throw new Error('Unrecognized AgBOM, CycloneDX, or ACS event document');
}

function normalizedBasename(path) {
  return posix.join(posix.dirname(path), fold(posix.basename(path)));
}

function pairName(path) {
  return normalizedBasename(path).replace(/(?:\.acs)?\.json$/, '.cdx.json');
}

function mismatch(acs, cdx) {
  const refs = cdx.inventories.map((inventory) => inventory.subject?.refId).filter((ref) => typeof ref === 'string');
  if (typeof acs.agent?.agent_id === 'string' && refs.length && !refs.includes(acs.agent.agent_id)) return 'agent ID';
  if (refs.filter((ref) => ref === acs.agent?.agent_id).length > 1) return 'multiple matching CycloneDX inventories';
  for (const [field, label] of [['agbom_version', 'AgBOM schema version'], ['agbom_hash', 'AgBOM hash'], ['generated_at', 'snapshot time']]) {
    const values = list(cdx.properties).filter((prop) => prop?.name === 'acs:' + field).map((prop) => prop.value);
    if (typeof acs[field] === 'string' && values.some((value) => value !== acs[field])) return label;
  }
  return null;
}

function relativeFile(index, name) {
  if (typeof name !== 'string' || name.split('/').some((part) => !part || part === '..' || part === '.') ||
      /[\\:]/.test(name)) return undefined;
  return posix.join(posix.dirname(index.path), name);
}

async function scan(dir, prefix, files, notices) {
  let entries;
  try {
    if (!(await lstat(dir)).isDirectory()) {
      notices.push(prefix + ' · Expected a regular directory.');
      return;
    }
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    if (error.code !== 'ENOENT') notices.push(prefix + ' · ' + error.code);
    return;
  }
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const file = join(dir, entry.name);
    const path = posix.join(prefix, entry.name);
    if (entry.isDirectory()) {
      await scan(file, path, files, notices);
      continue;
    }
    if (!entry.isFile() || !/\.json$/i.test(entry.name)) continue;
    try {
      const source = await readFile(file, 'utf8');
      const value = JSON.parse(source.replace(/^\uFEFF/, ''));
      const name = fold(entry.name);
      const kind = name === 'capture-index.json' ? 'index' : name === 'model-associations.json' ? 'associations' : classify(value, name);
      files.set(path, { path, source, value, kind });
    } catch (error) {
      files.set(path, { path, kind: 'invalid' });
      notices.push(path + ' · ' + (error instanceof SyntaxError ? 'Malformed JSON' : error.code ?? error.message));
    }
  }
}

export async function discover(roots) {
  const files = new Map();
  const notices = [];
  for (const [prefix, dir] of roots) await scan(dir, prefix, files, notices);
  const byKind = (kind) => [...files.values()].filter((file) => file.kind === kind);
  const acsFiles = byKind('acs');
  const paired = new Set();
  const inventories = acsFiles.map((acs) => {
    const inventory = { id: acs.path, acsFile: acs.path, acsText: acs.source, role: 'personal', associations: [] };
    const key = pairName(acs.path);
    const candidates = [...files.values()].filter((file) => normalizedBasename(file.path) === key);
    if (!candidates.length) return inventory;
    const [cdx] = candidates;
    inventory.cdxFile = cdx.path;
    if (candidates.length > 1 || acsFiles.filter((file) => pairName(file.path) === key).length > 1) {
      inventory.exportIssue = 'Ambiguous CycloneDX pair';
    } else if (cdx.kind !== 'cdx') {
      inventory.exportIssue = 'Expected a valid CycloneDX 2.0 draft export';
    } else {
      const difference = mismatch(acs.value, cdx.value);
      if (difference) inventory.exportIssue = 'Pairing mismatch (' + difference + ')';
      else {
        inventory.cdxText = cdx.source;
        paired.add(cdx.path);
      }
    }
    if (inventory.exportIssue) notices.push(acs.path + ' and ' + cdx.path + ' · ' + inventory.exportIssue);
    return inventory;
  });
  const byPath = new Map(inventories.map((inventory) => [inventory.acsFile, inventory]));
  const standalone = byKind('cdx').filter(({path}) => !paired.has(path)).flatMap(({path, source, value}) =>
    value.inventories.map((inventory, i) => ({
      id: path + '#inventory-' + i, cdxFile: path, cdxText: source, inventoryIndex: i,
      label: [inventory.subject?.name, inventory.subject?.refId].find((text) => typeof text === 'string') ?? 'Inventory ' + (i + 1),
      role: 'personal', associations: [],
    })));
  for (const {path, value} of byKind('unsupported')) notices.push(path + ' · Unsupported standalone CycloneDX ' + value.specVersion + ' document.');
  for (const {path, value} of byKind('cdx')) {
    if (!value.inventories.length && !paired.has(path)) notices.push(path + ' · CycloneDX document contains no inventories.');
  }
  for (const index of byKind('associations')) {
    if (!Array.isArray(index.value?.associations)) notices.push(index.path + ' · Expected an associations array.');
    for (const [i, association] of list(index.value?.associations).entries()) {
      const associatedPath = relativeFile(index, association?.inventory);
      const associated = [...(byPath.has(associatedPath) ? [byPath.get(associatedPath)] : []),
        ...standalone.filter(({cdxFile}) => cdxFile === associatedPath)];
      const location = '$.associations[' + i + ']';
      if (!associated.length || typeof association.modelId !== 'string') {
        notices.push(index.path + ' · ' + location + ' has an unavailable inventory or missing model ID.');
        continue;
      }
      const aibom = files.get(relativeFile(index, association.aibom));
      for (const inventory of associated) {
        inventory.associations.push({ record: association, file: index.path, location,
          aibomFile: aibom?.path ?? relativeFile(index, association.aibom),
          aibom: aibom?.kind === 'aibom' || aibom?.kind === 'cdx' ? aibom.value : undefined });
      }
    }
  }
  const series = [];
  for (const index of byKind('index')) {
    if (!Array.isArray(index.value?.series)) notices.push(index.path + ' · Expected a series array.');
    for (const [i, entry] of list(index.value?.series).entries()) {
      const location = '$.series[' + i + ']';
      const captures = list(entry?.captures).map((capture) => ({
        id: relativeFile(index, capture?.file), label: capture?.label,
      }));
      if (typeof entry?.id !== 'string' || captures.length < 2 || captures.some(({id}) => !byPath.has(id)) ||
          new Set(captures.map(({id}) => id)).size !== captures.length) {
        notices.push(index.path + ' · ' + location + ' needs a series ID and at least two distinct available captures.');
        continue;
      }
      series.push({ id: index.path + '#' + i, label: entry.label ?? entry.id, captures, file: index.path, location });
    }
  }
  const aiboms = byKind('aibom').map(({path, source, value}) =>
    ({ file: path, cdxText: source, doc: value }));
  return { inventories: [...inventories, ...standalone], aiboms, notices, series, events: byKind('event').map(({path, value}) => ({file: path, payload: value})) };
}
