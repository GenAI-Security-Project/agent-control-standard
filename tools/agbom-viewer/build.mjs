import { createHash } from 'node:crypto';
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const root = fileURLToPath(new URL('.', import.meta.url));
export const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
export const publicDir = join(repoRoot, 'docs', 'spec', 'inspect', 'agbom-viewer');

const assetName = /^[a-z0-9][a-z0-9._-]*\.json$/i;
const normalizeLines = (text) => text.replaceAll('\r\n', '\n');
const read = (file) => readFile(join(root, file), 'utf8');
const json = async (file) => JSON.parse(await read(file));

export async function buildPublicData(configOverrides = {}) {
  const [mapping, reference, settings, indexBytes] = await Promise.all([
    read('data/mapping.csv'), json('data/field-reference.json'), json('viewer.config.json'),
    readFile(join(publicDir, 'examples', 'index.json')),
  ]);
  // Keep the existing mapping revision across Git line-ending settings.
  const csv = normalizeLines(mapping).replaceAll('\n', '\r\n');
  const index = JSON.parse(indexBytes.toString('utf8'));
  const config = { ...settings, ...configOverrides };
  if (index.filter(({ role }) => role === 'primary').length !== 1 ||
      new Set(index.map(({ id }) => id)).size !== index.length) {
    throw new Error('The public index requires unique IDs and exactly one primary sample.');
  }

  const examples = new Map([['examples/index.json', indexBytes]]);
  const exampleAsset = async (name) => {
    if (typeof name !== 'string' || !assetName.test(name) || name.toLowerCase() === 'index.json') {
      throw new Error('Invalid example filename.');
    }
    const file = 'examples/' + name;
    const path = join(publicDir, file);
    if (!(await lstat(path)).isFile()) throw new Error('Example assets must be regular files.');
    const bytes = await readFile(path);
    examples.set(file, bytes);
    return { file, text: normalizeLines(bytes.toString('utf8')) };
  };

  const snapshots = [];
  for (const item of index) {
    if (!['primary', 'reference', 'ledger'].includes(item.role) || !item.id || !item.label || !item.acs) {
      throw new Error('Unrecognized public example index entry.');
    }
    const acs = await exampleAsset(item.acs);
    const cdx = item.cdx && await exampleAsset(item.cdx);
    const aiboms = await Promise.all((item.aiboms ?? []).map(async (name) => {
      const { file, text } = await exampleAsset(name);
      return { file, doc: JSON.parse(text) };
    }));
    snapshots.push({ ...item, acsFile: acs.file, acsText: acs.text, cdxFile: cdx?.file, cdxText: cdx?.text, aiboms });
  }

  const mappingRevision = createHash('sha256').update(csv).digest('hex');
  const bundle = JSON.stringify({ snapshots, config, csv, reference, mappingRevision }).replaceAll('<', '\\u003c')
    .replaceAll('\u2028', '\\u2028').replaceAll('\u2029', '\\u2029');
  return { script: 'globalThis.agbomViewerData = ' + bundle + ';\n', examples };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const { script } = await buildPublicData();
  const destination = join(publicDir, 'viewer-data.js');
  if (process.argv.includes('--check')) {
    if (normalizeLines(await readFile(destination, 'utf8')) !== script) {
      throw new Error('Public viewer data is stale. Run node tools/agbom-viewer/build.mjs.');
    }
    console.log('Public viewer data is up to date.');
  } else {
    const existing = await lstat(destination).catch((error) => {
      if (error.code !== 'ENOENT') throw error;
    });
    if (existing && !existing.isFile()) throw new Error('Public viewer data must be a regular file.');
    await writeFile(destination, script);
    console.log('Built docs/spec/inspect/agbom-viewer/viewer-data.js.');
  }
}
