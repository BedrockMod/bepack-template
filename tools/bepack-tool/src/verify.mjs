import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';

import { parseStrictJSON } from './strict-json.mjs';
import { createAjv, jsonPointer } from './json-schema.mjs';
import { validateProject } from './validate.mjs';
import { extractZip } from './zip.mjs';
import { ensureSafeDirectory } from './staging.mjs';
import { layoutDiagnostics, openPackage } from './container.mjs';
import { packageDigestOf } from './digest.mjs';
import { assertLockClosure } from './lock-closure.mjs';

const schemaDirectory = fileURLToPath(new URL('../../../schemas/', import.meta.url));

async function loadSchema(name) {
  const bytes = await readFile(path.join(schemaDirectory, name));
  return createAjv().compile(parseStrictJSON(bytes, { maxBytes: 4 * 1024 ** 2 }));
}

const unchecked = [
  'upstream-artifact-redistribution-rights',
  'adapter-target-compatibility-beyond-runtime-catalog',
  'live-instance-state-and-install-race-conditions',
];

// Verifies a .bepack container: layout, digests, lock closure, and published-project semantics.
export async function verifyPackage({ package: file, temporaryDirectory }) {
  const diagnostics = [];
  const add = (severity, code, message, extra = {}) => diagnostics.push({ severity, code, message, file: file, field: '', ...extra });
  const digest = await packageDigestOf(file).catch(error => { add('error', 'BEPACK_FILE_MISSING', error.message); return null; });
  if (!digest) return finish();
  let pkg;
  try { pkg = await openPackage(file); }
  catch (error) { add('error', error.diagnostic ?? 'BEPACK_ARCHIVE_INVALID', error.message); return finish(); }

  try {
    diagnostics.push(...layoutDiagnostics(pkg));
    if (!pkg.byPath.has('bepack.json')) add('error', 'BEPACK_FILE_MISSING', 'bepack.json is missing from the container');
    if (!pkg.byPath.has('bepack.lock.json')) add('error', 'BEPACK_FILE_MISSING', 'bepack.lock.json is missing from the container');
    if (diagnostics.some(item => item.severity === 'error')) return finish();

    const manifest = await pkg.document('bepack.json');
    const lock = await pkg.document('bepack.lock.json', pkg.limits.maxLockBytes);
    const setRelative = `versions/${manifest.value.version_set}.json`;
    const combination = await pkg.document(setRelative);
    if (!combination) add('error', 'BEPACK_FILE_MISSING', `${setRelative} is missing from the container`);

    const [manifestSchema, combinationSchema, lockSchema] = await Promise.all([
      loadSchema('bepack.schema.json'), loadSchema('version-set.schema.json'), loadSchema('lock.schema.json'),
    ]);
    for (const [value, validate, file_, label] of [
      [manifest.value, manifestSchema, 'bepack.json', 'manifest'],
      [combination?.value, combinationSchema, setRelative, 'version set'],
      [lock.value, lockSchema, 'bepack.lock.json', 'lock'],
    ]) {
      if (value === undefined) continue;
      if (validate(value)) continue;
      for (const error of validate.errors.slice(0, 20)) add('error', 'BEPACK_SCHEMA_INVALID', `${label}: ${error.message}`, { file: file_, field: error.instancePath + (error.keyword === 'required' ? '/' + jsonPointer(error.params.missingProperty) : '') });
    }
    if (diagnostics.some(item => item.severity === 'error')) return finish();

    const pack = lock.value.pack;
    const identity = [['id', manifest.value.id], ['version', manifest.value.version], ['version_set', manifest.value.version_set]];
    for (const [property, expected] of identity) if (pack[property] !== expected) add('error', 'BEPACK_LOCK_MISMATCH', `Lock ${property} does not match the manifest`, { field: '/pack/' + property });

    assertLockClosure(manifest.value, combination.value, lock.value);
    const files = new Map(lock.value.files.map(record => [record.path, record]));
    for (const entry of pkg.entries) {
      if (entry.directory || entry.path === 'bepack.lock.json') continue;
      const record = files.get(entry.path);
      if (!record) { add('error', 'BEPACK_LOCK_MISMATCH', 'Packaged file is absent from the lock file table: ' + entry.path, { field: '/files' }); continue; }
      const measured = await pkg.hash(entry);
      if (measured.size !== record.size || measured.sha256 !== record.sha256) add('error', 'BEPACK_DIGEST_MISMATCH', 'Packaged bytes differ from the locked digest: ' + entry.path, { field: '/files' });
    }
    for (const [path_] of files) if (!pkg.byPath.has(path_)) add('error', 'BEPACK_LOCK_MISMATCH', 'Locked file is absent from the container: ' + path_, { field: '/files' });

    const artifactIds = new Set(lock.value.artifacts.map(artifact => artifact.id));
    for (const [index, artifact] of lock.value.artifacts.entries()) {
      if (artifact.path && !files.has(artifact.path)) add('error', 'BEPACK_LOCK_MISMATCH', 'Bundled artifact is not registered in the file table: ' + artifact.id, { field: `/artifacts/${index}/path` });
    }
    const runtimeIds = new Set(lock.value.runtimes.map(runtime => runtime.id));
    for (const [index, configuration] of lock.value.configurations.entries()) {
      for (const dependency of configuration.dependencies) for (const asset of dependency.assets) {
        if (!artifactIds.has(asset)) add('error', 'BEPACK_LOCK_MISMATCH', `Configuration ${configuration.id} references unknown artifact ${asset}`, { field: `/configurations/${index}/dependencies` });
      }
      for (const slot of ['game', 'loader']) {
        const id = configuration.runtimes[slot];
        if (id !== null && !runtimeIds.has(id)) add('error', 'BEPACK_LOCK_MISMATCH', `Configuration ${configuration.id} references unknown ${slot} runtime ${id}`, { field: `/configurations/${index}/runtimes/${slot}` });
      }
    }

    const base = temporaryDirectory ?? tmpdir();
    await ensureSafeDirectory(base);
    const privateDirectory = await mkdtemp(path.join(path.resolve(base), 'bepack-verify-'));
    const staging = path.join(privateDirectory, 'project');
    try {
      await extractZip(pkg.zip, staging);
      const validation = await validateProject(staging);
      for (const diagnostic of validation.diagnostics) diagnostics.push({ ...diagnostic, file: diagnostic.file, field: diagnostic.field ?? '' });
    } finally {
      await rm(privateDirectory, { recursive: true, force: true });
    }
  } catch (error) {
    if (error.diagnostic) add('error', error.diagnostic, error.message);
    else throw error;
  } finally {
    await pkg.close().catch(() => {});
  }
  return finish();

  function finish() {
    const errors = diagnostics.filter(item => item.severity === 'error').length;
    return {
      schema_version: 1,
      command: 'verify',
      valid: errors === 0,
      package: { name: path.basename(file), size: digest?.size ?? 0, sha256: digest?.sha256 ?? '' },
      summary: { errors, warnings: diagnostics.filter(item => item.severity === 'warning').length },
      diagnostics,
      unchecked,
    };
  }
}
