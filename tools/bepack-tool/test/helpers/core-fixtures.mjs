import path from 'node:path';
import {mkdtemp,mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const template = fileURLToPath(new URL('../../../../', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const json = value => JSON.stringify(value, null, 2) + '\n';
export async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'bepack-core-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const project = path.join(root, 'project');
  await mkdir(path.join(project, 'versions'), { recursive: true });
  await mkdir(path.join(project, 'licenses'));
  await mkdir(path.join(project, 'payload'));
  const manifest = JSON.parse(await readFile(path.join(template, 'bepack.json')));
  const set = { schema_version: 1, id: 'stable', dependencies: {}, targets: {} };
  // Deliberately synthetic test identities, never a distributable runtime catalog.
  const catalog = { schema_version: 1, id: 'fixture-only', provider: 'test.synthetic', retrieved_at: '2026-11-08T00:00:00Z', source: { url: 'https://example.invalid/fixture-source', sha256: 'e'.repeat(64) }, games: ['1.0.0','1.0.1'].map(version => ({ version, platform: 'windows-x86_64', runtime: 'bedrock-client', identity: 'synthetic-' + version, integrity: { kind: 'distribution-manifest', sha256: 'a'.repeat(64) }, loaders: [], clients: [] })) };
  const catalogFile = path.join(root, 'catalog.json');
  async function save() { await writeFile(path.join(project, 'bepack.json'), json(manifest)); await writeFile(path.join(project, 'versions/stable.json'), json(set)); await writeFile(catalogFile, json(catalog)); }
  await writeFile(path.join(project, 'licenses/pack-license.txt'), 'Fixture license only\n');
  await save();
  const options = () => ({ project, output: path.join(root, 'out'), frozen: true, runtimeCatalog: catalogFile, runtimeCatalogSha256: hash(Buffer.from(json(catalog))), generatedAt: '2026-11-08T00:00:00Z' });
  return { root, project, manifest, set, catalog, catalogFile, save, options };
}

