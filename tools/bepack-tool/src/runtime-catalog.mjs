// Runtime catalog: the adapter-provided, externally sourced directory of legal
// game releases and their loader/client compatibility. This module never
// invents an entry; a missing or mismatching catalog is a hard failure.
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { parseStrictJSON } from './strict-json.mjs';
import { createAjv, schemaErrors } from './json-schema.mjs';

const schemaDirectory = fileURLToPath(new URL('../schemas/', import.meta.url));
let validateCatalog;
async function validator() {
  if (!validateCatalog) {
    const schema = JSON.parse(await readFile(path.join(schemaDirectory, 'runtime-catalog.schema.json'), 'utf8'));
    validateCatalog = createAjv().compile(schema);
  }
  return validateCatalog;
}

const failure = (code, message) => Object.assign(new Error(message), { diagnostic: code });

const DIGEST = /^[0-9a-f]{64}$/;

// options.expectedSha256 is the externally trusted digest of the catalog FILE
// bytes (from a pinned release asset or the host). catalog.source.sha256 is a
// different thing: it is the digest of the upstream evidence document published
// at catalog.source.url, so it can never describe the catalog file itself.
export async function loadRuntimeCatalog(file, { expectedSha256 } = {}) {
  if (expectedSha256 !== undefined && !DIGEST.test(expectedSha256)) {
    throw failure('BEPACK_RUNTIME_CATALOG_DIGEST_INVALID', 'Runtime catalog digest must be 64 lowercase hexadecimal characters');
  }
  const bytes = await readFile(file);
  const catalog = parseStrictJSON(bytes, { maxBytes: 64 * 1024 * 1024, maxDepth: 64 });
  const validate = await validator();
  if (!validate(catalog)) throw failure('BEPACK_RUNTIME_CATALOG_INVALID', 'Runtime catalog does not match the tool schema');
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (expectedSha256 !== undefined && expectedSha256 !== sha256) {
    throw failure('BEPACK_RUNTIME_CATALOG_MISMATCH', `Runtime catalog digest mismatch: expected ${expectedSha256}, measured ${sha256}; the file is not the pinned catalog`);
  }
  const trusted = expectedSha256 !== undefined;
  const games = new Map();
  for (const game of catalog.games) {
    const key = `${game.platform}/${game.runtime}/${game.version}`;
    if (games.has(key)) throw failure('BEPACK_RUNTIME_CATALOG_INVALID', 'Duplicate game release in runtime catalog: ' + key);
    const loaders = new Map();
    for (const loader of game.loaders ?? []) {
      const loaderKey = `${loader.type}/${loader.version}`;
      if (loaders.has(loaderKey)) throw failure('BEPACK_RUNTIME_CATALOG_INVALID', 'Duplicate loader release in runtime catalog: ' + key + '/' + loaderKey);
      loaders.set(loaderKey, loader);
    }
    const clients = new Map();
    for (const client of game.clients ?? []) {
      const clientKey = `${client.id}/${client.version}`;
      if (clients.has(clientKey)) throw failure('BEPACK_RUNTIME_CATALOG_INVALID', 'Duplicate client release in runtime catalog: ' + key + '/' + clientKey);
      clients.set(clientKey, client);
    }
    games.set(key, { ...game, loaders: [...loaders.values()], clients: [...clients.values()] });
  }
  return {
    catalog, bytes, sha256, file, games, trusted,
    find: (platform, runtime, version) => games.get(`${platform}/${runtime}/${version}`),
    list: (platform, runtime) => [...games.values()].filter(game => game.platform === platform && game.runtime === runtime),
    provider: catalog.provider,
    url: catalog.source.url,
    sourceSha256: catalog.source.sha256,
    retrievedAt: catalog.retrieved_at,
  };
}

export { schemaErrors };
