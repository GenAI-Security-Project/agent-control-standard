const items = (value) => Array.isArray(value) ? value : [];
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

export function sameValue(a, b) {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((value, i) => sameValue(value, b[i]));
  if (!object(a) || !object(b)) return false;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && sameValue(a[key], b[key]));
}

function indexComponents(source, side, issues) {
  const entries = new Map();
  const ambiguous = new Set();
  if (!Array.isArray(source)) issues.push(side + ' · Component array is unavailable.');
  for (const [i, value] of items(source).entries()) {
    const path = ['components', i];
    if (typeof value?.id !== 'string') {
      issues.push(side + ' · $.components[' + i + '] has no usable stable ID.');
      continue;
    }
    if (entries.has(value.id)) {
      issues.push(side + ' · Ambiguous component ID ' + JSON.stringify(value.id) + ' at indices ' + entries.get(value.id).path[1] + ' and ' + i + '.');
      ambiguous.add(value.id);
    } else {
      entries.set(value.id, { value, path });
    }
  }
  return { entries, ambiguous };
}

function fields(before, after, path, out, relation) {
  if (sameValue(before, after)) return;
  const edge = relation(path);
  if (edge && Array.isArray(before) && Array.isArray(after) &&
      before.every((id) => typeof id === 'string') && after.every((id) => typeof id === 'string') &&
      sameValue([...before].sort(), [...after].sort())) return;
  if (!edge && object(before) && object(after)) {
    for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
      fields(Object.hasOwn(before, key) ? before[key] : undefined,
        Object.hasOwn(after, key) ? after[key] : undefined, [...path, key], out, relation);
    }
  } else {
    out.push({ path, before, after, edge });
  }
}

export function compareSnapshots(baseline, comparison, relationshipRules) {
  const issues = [];
  const left = indexComponents(baseline?.components, 'Baseline', issues);
  const right = indexComponents(comparison?.components, 'Comparison', issues);
  const result = { issues, added: [], removed: [], changed: [], relationships: [], document: [] };
  for (const id of new Set([...left.entries.keys(), ...right.entries.keys()])) {
    if (left.ambiguous.has(id) || right.ambiguous.has(id)) continue;
    const before = left.entries.get(id);
    const after = right.entries.get(id);
    if (!before || !after) {
      result[before ? 'removed' : 'added'].push(before ?? after);
      continue;
    }
    const knownRelations = relationshipRules.filter(({ kind }) => kind === before.value.type || kind === after.value.type);
    const relation = (path) => knownRelations.find((rule) => sameValue(rule.path, path))?.edge;
    const changes = [];
    fields(before.value, after.value, [], changes, relation);
    for (const change of changes) {
      const nested = knownRelations.filter((rule) => rule.path.length > change.path.length &&
        sameValue(rule.path.slice(0, change.path.length), change.path));
      if (nested.length && (object(change.before) || object(change.after))) {
        const children = [];
        fields(object(change.before) ? change.before : {}, object(change.after) ? change.after : {},
          change.path, children, relation);
        for (const child of children.filter(({edge}) => edge)) {
          result.relationships.push({ ...child, id, beforeEntry: before, afterEntry: after });
        }
      }
      result[change.edge ? 'relationships' : 'changed'].push({ ...change, id, beforeEntry: before, afterEntry: after });
    }
  }
  for (const key of new Set([...Object.keys(baseline), ...Object.keys(comparison)])) {
    if (key !== 'components') fields(Object.hasOwn(baseline,key) ? baseline[key] : undefined,
      Object.hasOwn(comparison,key) ? comparison[key] : undefined, [key], result.document, () => undefined);
  }
  if (baseline.agent?.agent_id !== comparison.agent?.agent_id) issues.push('The selected files record different agent IDs.');
  return result;
}

export function reportedEvent(payload) {
  if (object(payload?.agbom)) return { type: 'agbom/snapshot', snapshot: payload.agbom, field: 'agbom' };
  if (object(payload?.full_snapshot) && !Object.hasOwn(payload, 'diff')) {
    return { type: 'agbom/changed', snapshot: payload.full_snapshot, field: 'full_snapshot' };
  }
  if (object(payload?.diff) && !Object.hasOwn(payload, 'full_snapshot') &&
      ['added', 'removed', 'changed'].some((key) => Array.isArray(payload.diff[key]))) {
    return { type: 'agbom/changed', diff: payload.diff, field: 'diff' };
  }
  return { type: 'Unrecognized ACS event payload' };
}

export function corroborateDiff(diff, baseline, target) {
  const issues = [];
  if (!baseline || !target || baseline.agent?.agent_id === undefined || baseline.agent.agent_id !== target.agent?.agent_id) return false;
  const before = indexComponents(baseline.components, 'Baseline', issues);
  const after = indexComponents(target.components, 'Comparison', issues);
  if (issues.length) return false;
  const expected = new Map([...before.entries].map(([id, entry]) => [id, entry.value]));
  const affected = new Set();
  for (const operation of ['removed', 'changed', 'added']) {
    for (const entry of items(diff[operation])) {
      if (!object(entry) || typeof entry.id !== 'string' || affected.has(entry.id)) return false;
      affected.add(entry.id);
      if (operation === 'added') {
        if (expected.has(entry.id)) return false;
        expected.set(entry.id, entry);
      } else if (expected.get(entry.id)?.type !== entry.type) {
        return false;
      } else if (operation === 'removed') {
        expected.delete(entry.id);
      } else {
        if (!sameValue(expected.get(entry.id), entry.before) || entry.after?.id !== entry.id || entry.after?.type !== entry.type) return false;
        expected.set(entry.id, entry.after);
      }
    }
  }
  return expected.size === after.entries.size && [...expected].every(([id, value]) => sameValue(value, after.entries.get(id)?.value));
}

export function modelEntries(bom) {
  function visit(entries, prefix) {
    return items(entries).flatMap((entry, i) => {
      const path = [...prefix, i];
      return [
        ...(entry?.type === 'machine-learning-model' ? [{entry, path}] : []),
        ...visit(entry?.components, [...path, 'components']),
      ];
    });
  }
  return [
    ...visit(bom.components, ['components']),
    ...items(bom.inventories).flatMap((inventory, i) => visit(inventory?.components, ['inventories', i, 'components'])),
  ];
}

function packageIdentity(value) {
  if (typeof value !== 'string') return {};
  const match = /^pkg:huggingface\/([^@?#]+)(?:@([^?#]+))?(?:[?#].*)?$/i.exec(value);
  if (match) return { id: match[1], revision: match[2], source: 'Hugging Face' };
  const packageRef = /^(pkg:[a-z][a-z0-9.+-]*\/[^@?#]+)(?:@([^?#]+))?(?:[?#].*)?$/i.exec(value);
  return packageRef ? { id: packageRef[1], revision: packageRef[2] } : {};
}

function repositoryName(value) {
  return typeof value === 'string' && /^[\w.-]+\/[\w.-]+$/.test(value) ? value : undefined;
}

export function inspectModelIdentity(model, association) {
  const {record, aibom} = association;
  if (!record.aibom && !association.aibomFile) return { status: 'No AIBOM supplied' };
  if (!aibom) return { status: 'AIBOM reference supplied but unavailable' };
  const matches = modelEntries(aibom).filter(({entry}) => !record.aibomComponentRef ||
    [entry['bom-ref'], entry.refId].includes(record.aibomComponentRef));
  if (matches.length !== 1) {
    return { status: matches.length ? 'Insufficient evidence' : record.aibomComponentRef ? 'Mismatch' : 'Insufficient evidence',
      detail: matches.length ? 'Multiple machine-learning-model entries match.' : 'No matching machine-learning-model entry.' };
  }
  const {entry, path} = matches[0];
  const ref = packageIdentity(entry['bom-ref'] ?? entry.refId);
  const purl = packageIdentity(entry.purl);
  const declared = typeof record.identifier === 'string' ? packageIdentity(record.identifier).id ?? record.identifier : undefined;
  const acsName = repositoryName(model.name);
  const expected = declared ?? acsName;
  const revisions = [model.version, record.revision].filter((value) => typeof value === 'string' && value);
  const observed = [purl.id, ref.id].filter(Boolean);
  const upstreamCommits = items(entry.externalReferences).flatMap((reference, i) => {
    if (typeof reference?.url !== 'string') return [];
    const match = /^https:\/\/huggingface\.co\/([^/]+\/[^/]+)\/commit\/([\da-f]{40})\/?$/i.exec(reference.url);
    return match ? [{ id: match[1], revision: match[2], path: [...path, 'externalReferences', i, 'url'] }] : [];
  });
  const observedVersions = [entry.version, purl.revision, ref.revision].filter((value) => typeof value === 'string' && value);
  const facts = { entry, path, expected, identifier: purl.id ?? ref.id, source: purl.source ?? ref.source, upstreamCommits };
  if ((declared && acsName && declared !== acsName) || new Set(revisions).size > 1 ||
      new Set(observed).size > 1 || new Set(observedVersions).size > 1 ||
      (expected && observed.some((id) => id !== expected)) ||
      (revisions.length && observedVersions.some((version) => version !== revisions[0])) ||
      upstreamCommits.some(({id, revision}) => (observed.length && id !== observed[0]) ||
        (observedVersions.length && /^[\da-f]{7,40}$/i.test(observedVersions[0]) && !revision.startsWith(observedVersions[0])))) {
    return { ...facts, status: 'Mismatch', detail: 'Recorded model identifiers or revisions disagree.' };
  }
  if (!expected || !observed.length || !revisions.length || !entry.version) {
    return { ...facts, status: 'Insufficient evidence', detail: 'A comparable repository identifier and recorded model revision are needed on both sides.' };
  }
  return { ...facts, status: 'Matching recorded identifier and revision' };
}
