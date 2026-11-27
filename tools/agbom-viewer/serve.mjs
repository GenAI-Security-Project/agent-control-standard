import { once } from 'node:events';
import { createServer } from 'node:http';
import { readFile, lstat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildPublicData, publicDir, repoRoot, root } from './build.mjs';
import { discover } from './inventory.mjs';

const hostname = '127.0.0.1';
export const docsPath = '/docs/spec/inspect/agbom-viewer/';
const scenarioRoot = join(root, 'data', 'examples', 'developer-support');
const inventoryRoots = [['inventory', join(repoRoot, 'inventory')]];
const guidePath = 'guide.md';
const guide = join(repoRoot, 'docs', 'spec', 'inspect', 'agbom_viewer_local.md');
const staticFiles = [
  'index.html', 'viewer.css', 'viewer.js', 'use-cases.js', 'assets/InterVariable.woff2', 'assets/OFL.txt',
];
const contentTypes = {
  html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8',
  json: 'application/json; charset=utf-8', woff2: 'font/woff2', txt: 'text/plain; charset=utf-8', md: 'text/plain; charset=utf-8',
};

async function scenario() {
  const indexPath = 'scenario.json';
  const read = async (file) => {
    if (typeof file !== 'string' || !/^(?:aiboms\/)?[a-z0-9_.-]+\.json$/i.test(file)) throw new Error('Invalid scenario path');
    for (const directory of file.includes('/') ? [scenarioRoot, join(scenarioRoot, 'aiboms')] : [scenarioRoot]) {
      if (!(await lstat(directory)).isDirectory()) throw new Error('Scenario directory unavailable');
    }
    const path = join(scenarioRoot, file);
    if (!(await lstat(path)).isFile()) throw new Error('Scenario file unavailable');
    return readFile(path, 'utf8');
  };
  const prefix = 'data/examples/developer-support/';
  const index = JSON.parse(await read(indexPath));
  const associationFile = 'model-associations.json';
  const { associations: records } = JSON.parse(await read(associationFile));
  const captures = await Promise.all(index.captures.map(async (capture) => {
    const [acsText, cdxText] = await Promise.all([read(capture.file), read(capture.cdx)]);
    const associations = await Promise.all(records.flatMap((record, i) => record.inventory === capture.file ? [(async () => {
      const aibom = await read(record.aibom).then(JSON.parse).catch(() => undefined);
      return { record, file: prefix + associationFile, location: '$.associations[' + i + ']',
        aibomFile: prefix + record.aibom, aibom };
    })()] : []));
    return { ...capture, id: prefix + capture.file, acsFile: prefix + capture.file, acsText, cdxFile: prefix + capture.cdx, cdxText, associations, role: 'scenario' };
  }));
  const events = await Promise.all(index.events.map(async ({file, ...entry}) =>
    ({ ...entry, file: prefix + file, capture: prefix + entry.capture,
      baseline: entry.baseline && prefix + entry.baseline, payload: JSON.parse(await read(file)) })));
  return { captures, events, file: prefix + indexPath };
}

export async function createViewerServer({ mode = 'local', roots = inventoryRoots } = {}) {
  const localMode = mode === 'local';
  const { script, examples } = await buildPublicData(localMode ? { guideHref: './' + guidePath } : {});
  const files = new Map(examples);
  for (const file of staticFiles) files.set(file, await readFile(join(publicDir, file)));
  files.set('viewer-data.js', localMode ? script : await readFile(join(publicDir, 'viewer-data.js')));
  const prefix = localMode ? '/' : docsPath;
  if (localMode) {
    const html = files.get('index.html').toString('utf8')
      .replace("font-src 'self' file:", "connect-src 'self'; font-src 'self' file:")
      .replace('<!-- LOCAL_SCRIPT -->', '<script type="module" src="./local.js"></script>')
      .replace('<!-- LOCAL_NAV -->', '<a href="#your-inventories" data-view="your-inventories">Local BOMs</a>')
      .replace('<!-- LOCAL_VIEWS -->', await readFile(join(root, 'src', 'local.html'), 'utf8'))
      .replace('ACS Inspect documentation</a>', 'Local viewer guide</a>');
    files.set('index.html', html);
    for (const file of ['local.js', 'local-evidence.mjs']) files.set(file, await readFile(join(root, 'src', file)));
  }
  return createServer(async (request, response) => {
    const send = (status, type, body, headers = {}) => {
      response.writeHead(status, {
        'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
        ...headers,
      });
      response.end(request.method === 'HEAD' ? undefined : body);
    };
    const plain = contentTypes.txt;
    if (request.headers.host !== hostname + ':' + request.socket.localPort) return send(403, plain, 'Use the printed loopback URL.');
    if (!['GET', 'HEAD'].includes(request.method)) return send(405, plain, 'Read-only viewer.', { Allow: 'GET, HEAD' });
    const path = request.url.split('?')[0];
    if (path === prefix.slice(0, -1) && prefix !== '/') return send(308, plain, 'Opening viewer.', { Location: prefix });
    try {
      if (localMode && path === '/api/agbom') {
        const local = await discover(roots);
        try {
          local.scenario = await scenario();
        } catch (error) {
          local.scenarioIssue = error.code ?? error.message;
        }
        return send(200, contentTypes.json, JSON.stringify(local));
      }
      if (localMode && path === '/' + guidePath) {
        return send(200, contentTypes.md, await readFile(guide));
      }
      const key = path.startsWith(prefix) && (path.slice(prefix.length) || 'index.html');
      if (key && files.has(key)) {
        return send(200, key.endsWith('.mjs') ? contentTypes.js : contentTypes[key.split('.').at(-1)], files.get(key));
      }
      return send(404, plain, 'Page unavailable.');
    } catch (error) {
      console.error(error.message);
      return send(500, plain, 'Could not read viewer data.');
    }
  });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const mode = process.argv.includes('--public') ? 'public' : 'local';
  const port = 4173;
  const server = await createViewerServer({ mode });
  try {
    server.listen(port, hostname);
    await once(server, 'listening');
    console.log('AgBOM Viewer · http://' + hostname + ':' + port + (mode === 'public' ? docsPath : '/'));
  } catch (error) {
    if (error.code !== 'EADDRINUSE') throw error;
    console.error(`Cannot start the AgBOM Viewer. ${hostname}:${port} is already in use. Stop the process using port ${port} and rerun this command.`);
    process.exitCode = 1;
  }
}
