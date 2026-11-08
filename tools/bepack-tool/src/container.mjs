import { stat } from 'node:fs/promises';

import { parseStrictJSON } from './strict-json.mjs';
import { safeRelative } from './paths.mjs';
import { DEFAULT_LIMITS, hashZipEntry, openZip, readZipEntry } from './zip.mjs';

export const manifestFile = 'bepack.json';
export const lockFile = 'bepack.lock.json';

// Opens a .bepack container and exposes its documents and integrity helpers.
export async function openPackage(file, options = {}) {
  const zip = await openZip(file, options);
  const info = await stat(file);
  const byPath = new Map(zip.entries.map(entry => [entry.path, entry]));
  const duplicates = zip.entries.length !== byPath.size;
  async function read(relative, maxBytes = DEFAULT_LIMITS.maxManifestBytes) {
    const entry = byPath.get(relative);
    if (!entry) return null;
    return { entry, bytes: await readZipEntry(zip, entry, { maxBytes }) };
  }
  async function document(relative, maxBytes = DEFAULT_LIMITS.maxManifestBytes) {
    const found = await read(relative, maxBytes);
    if (!found) return null;
    return { entry: found.entry, bytes: found.bytes, value: parseStrictJSON(found.bytes, { maxBytes }) };
  }
  return {
    file,
    zip,
    size: info.size,
    entries: zip.entries,
    byPath,
    duplicates,
    limits: zip.limits,
    read,
    document,
    hash: entry => hashZipEntry(zip, entry),
    close: () => zip.close(),
  };
}

export const packageLayout = {
  manifest: manifestFile,
  lock: lockFile,
  versionSet: versionSet => `versions/${versionSet}.json`,
};

export function isSafeArchivePath(value) {
  return safeRelative(value);
}

// Every entry path of a package must be a safe relative path without directory entries.
export function layoutDiagnostics(pkg) {
  const diagnostics = [];
  if (pkg.duplicates) diagnostics.push({ severity: 'error', code: 'BEPACK_ARCHIVE_INVALID', message: 'Archive contains duplicate entry paths', file: pkg.file, field: '' });
  for (const entry of pkg.entries) {
    if (!isSafeArchivePath(entry.directory ? entry.path.replace(/\/+$/, '') : entry.path)) diagnostics.push({ severity: 'error', code: 'BEPACK_PATH_UNSAFE', message: 'Unsafe archive path: ' + entry.path, file: pkg.file, field: entry.path });
  }
  return diagnostics;
}
