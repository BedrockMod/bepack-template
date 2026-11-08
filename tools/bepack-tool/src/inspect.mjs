import path from 'node:path';
import { mkdir } from 'node:fs/promises';

import { layoutDiagnostics, openPackage } from './container.mjs';
import { extractZip } from './zip.mjs';
import { packageDigestOf } from './digest.mjs';

// Reads a .bepack container and optionally extracts its byte-identical entries.
export async function inspectPackage({ package: file, extract }) {
  const digest = await packageDigestOf(file);
  const pkg = await openPackage(file);
  const diagnostics = [];
  try {
    diagnostics.push(...layoutDiagnostics(pkg));
    const manifest = await pkg.document('bepack.json');
    if (!manifest) throw Object.assign(new Error('bepack.json is missing from the container'), { diagnostic: 'BEPACK_FILE_MISSING' });
    const setRelative = `versions/${manifest.value.version_set}.json`;
    const versionSet = await pkg.document(setRelative);
    if (!versionSet) throw Object.assign(new Error(setRelative + ' is missing from the container'), { diagnostic: 'BEPACK_FILE_MISSING' });
    const lock = await pkg.document('bepack.lock.json', pkg.limits.maxLockBytes);
    const methods = { store: 0, deflate: 0 };
    let bytes = 0;
    for (const entry of pkg.entries) {
      if (entry.method === 0) methods.store++;
      else if (entry.method === 8) methods.deflate++;
      else diagnostics.push({ severity: 'error', code: 'BEPACK_ARCHIVE_INVALID', message: 'Unsupported compression method ' + entry.method + ' for ' + entry.path, file, field: entry.path });
      bytes += entry.size;
    }
    let extracted = null;
    if (extract) {
      const destination = path.resolve(extract);
      const written = await extractZip(pkg.zip, destination);
      extracted = { directory: destination, files: written.filter(entry => !entry.directory).length };
    }
    const errors = diagnostics.filter(item => item.severity === 'error').length;
    return {
      schema_version: 1,
      command: 'inspect',
      valid: errors === 0,
      package: { name: path.basename(file), size: digest.size, sha256: digest.sha256 },
      container: { entries: pkg.entries.length, bytes, methods },
      documents: {
        manifest: manifest.value,
        version_set: versionSet.value,
        lock: lock ? {
          generated_at: lock.value.generated_at,
          files: lock.value.files.length,
          artifacts: lock.value.artifacts.map(artifact => artifact.id),
          configurations: lock.value.configurations.map(configuration => configuration.id),
          evidence: lock.value.evidence.map(record => record.id),
          runtimes: lock.value.runtimes.map(runtime => runtime.id),
        } : null,
      },
      entries: pkg.entries.map(entry => ({ path: entry.path, size: entry.size, method: entry.method })),
      extracted,
      diagnostics,
      unchecked: ['adapter-config-whitelist-and-native-layout'],
    };
  } finally {
    await pkg.close().catch(() => {});
  }
}
