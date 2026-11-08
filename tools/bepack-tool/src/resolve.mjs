import path from 'node:path';
import { readFile, writeFile, rename, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { readStrictJSON } from './strict-json.mjs';
import { validateProject, matchesVersion } from './validate.mjs';
import { createAjv } from './json-schema.mjs';
const fail = (code, message) => { throw Object.assign(new Error(message), { diagnostic: code }); };
export async function resolveProject({ project, metadataDirectory }) {
  project = path.resolve(project);
  const before = await validateProject(project);
  const errors = before.diagnostics.filter(d => d.severity === 'error' && !(d.code === 'BEPACK_VERSION_SET_INVALID' && d.message === 'Missing exact selection or selected version does not satisfy requirement') && d.message !== 'Client must reference matching role=client dependency and exact selection');
  if (errors.length) fail('BEPACK_VALIDATION_FAILED', errors[0].message);
  const manifest = await readStrictJSON(path.join(project, 'bepack.json'));
  const file = path.join(project, 'versions', manifest.version_set + '.json');
  const original = await readFile(file);
  const combination = await readStrictJSON(file);
  const targets = new Set(Object.values(manifest.targets).filter(c => c?.enabled).flatMap(c => Object.keys(c.variants).filter(k => k !== 'extensions')));
  const validateMetadata = createAjv().compile(await readStrictJSON(new URL('../../../schemas/dependency-metadata.schema.json', import.meta.url)));
  const resolved = {};
  for (const dependency of manifest.dependencies.filter(d => d.targets.some(t => targets.has(t)))) {
    let choices;
    if (dependency.resolver === 'direct') {
      if (!dependency.version.exact) fail('BEPACK_NOT_RESOLVED', 'A direct URL requires an exact version: ' + dependency.id);
      choices = [dependency.version.exact];
    } else if (dependency.resolver === 'bepack-metadata') {
      const metadata = await readStrictJSON(path.join(metadataDirectory ?? path.join(project, '.bepack-local/metadata'), dependency.id + '.json'));
      if (!validateMetadata(metadata) || metadata.id !== dependency.id) fail('BEPACK_METADATA_INVALID', 'Invalid metadata for ' + dependency.id);
      choices = metadata.releases.map(r => r.version).filter(v => matchesVersion(v, dependency.version));
      if (new Set(choices).size !== choices.length) fail('BEPACK_METADATA_INVALID', 'Duplicate release version: ' + dependency.id);
    } else fail('BEPACK_RESOLVER_UNSUPPORTED', 'No injected resolver for ' + dependency.resolver);
    const previous = combination.dependencies[dependency.id];
    if (choices.includes(previous)) resolved[dependency.id] = previous;
    else if (choices.length === 1) resolved[dependency.id] = choices[0];
    else fail('BEPACK_NOT_RESOLVED', 'Require one exact metadata candidate or an existing selection for ' + dependency.id);
  }
  for (const collection of Object.values(manifest.targets).filter(c => c?.enabled)) {
    for (const [target, base] of Object.entries(collection.variants).filter(([id]) => id !== 'extensions')) {
      const client = combination.targets[target]?.client === undefined ? base.client : combination.targets[target].client;
      if (!client) continue;
      const dependency = manifest.dependencies.find(d => d.id === client.dependency);
      if (!dependency || dependency.role !== 'client' || !dependency.targets.includes(target) || !resolved[dependency.id] || !matchesVersion(resolved[dependency.id], client.version)) fail('BEPACK_NOT_RESOLVED', 'Client dependency exact selection does not match target ' + target);
    }
  }
  const result = { ...combination, dependencies: resolved };
  const bytes = Buffer.from(JSON.stringify(result, null, 2) + '\n');
  if (!bytes.equals(original)) {
    const temporary = file + '.' + randomUUID() + '.tmp';
    try { await writeFile(temporary, bytes, { flag: 'wx' }); await rename(temporary, file); }
    finally { await rm(temporary, { force: true }); }
  }
  return { schema_version: 1, command: 'resolve', valid: true, version_set: manifest.version_set, dependencies: resolved, source: 'explicit-local-metadata', network_checked: false };
}