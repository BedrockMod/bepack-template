// Build stage: the release pipeline never packs bytes itself. It invokes the
// frozen pack-toolchain build, then re-opens the produced .bepack and binds the
// exact bytes, manifest and tool source identity into the release staging area.

import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

import { openPackage } from './release-package.mjs';
import { parseStrictJSON } from './strict-json.mjs';
import {
  assertManifestForRelease,
  assertTagVersion,
  packageAssetName,
} from './release-assets.mjs';
import {
  copyFileExact,
  ensureDir,
  hashFile,
  jsonBytes,
  writeFileAtomic,
  writeNewFile,
} from './release-files.mjs';
import { inputError, ReleaseError, RELEASE_CODES } from './release-errors.mjs';

async function readProjectManifest(projectDir) {
  let bytes;
  try {
    bytes = await readFile(path.join(projectDir, 'bepack.json'));
  } catch (error) {
    throw inputError(RELEASE_CODES.MANIFEST_INVALID, `Cannot read project bepack.json: ${error.message}`);
  }
  let manifest;
  try {
    manifest = parseStrictJSON(bytes, { maxBytes: 4 * 1024 * 1024 });
  } catch (error) {
    throw inputError(RELEASE_CODES.MANIFEST_INVALID, `Invalid project bepack.json: ${error.message}`);
  }
  assertManifestForRelease(manifest);
  return manifest;
}

async function walkFiles(root, relative = '') {
  const directory = path.join(root, relative);
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const next = path.posix.join(relative, entry.name);
    if (entry.isDirectory()) files.push(...await walkFiles(root, next));
    else if (entry.isFile()) files.push(next);
    else throw inputError(RELEASE_CODES.BUILD_OUTPUT, `Unsupported entry in tool source tree: ${next}`);
  }
  return files;
}

export async function computeToolIdentity({ projectDir, toolCommit }) {
  if (typeof toolCommit !== 'string' || !/^[0-9a-f]{40}$/.test(toolCommit)) {
    throw inputError(RELEASE_CODES.GITHUB_CONFIG, 'A full commit SHA is required to identify the tool source');
  }
  const roots = ['scripts', 'tools/bepack-tool/src', 'tools/bepack-tool/schemas', 'schemas'];
  const extras = ['package.json', 'package-lock.json'];
  const relativeFiles = [];
  for (const root of roots) {
    const absolute = path.join(projectDir, root);
    const exists = await stat(absolute).then(info => info.isDirectory()).catch(() => false);
    if (!exists) throw inputError(RELEASE_CODES.BUILD_INPUT, `Tool source directory is missing: ${root}`);
    for (const file of await walkFiles(projectDir, root)) {
      if (root === 'tools/bepack-tool/src' && !file.endsWith('.mjs') && !file.includes('/src/data/')) continue;
      relativeFiles.push(file);
    }
  }
  for (const file of extras) {
    const exists = await stat(path.join(projectDir, file)).then(info => info.isFile()).catch(() => false);
    if (exists) relativeFiles.push(file);
  }
  const unique = [...new Set(relativeFiles)].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const lines = [];
  for (const file of unique) {
    const info = await hashFile(path.join(projectDir, file));
    lines.push(`${info.sha256}  ${file}\n`);
  }
  const digest = createHash('sha256').update(lines.join('')).digest('hex');
  return { version: `source-${toolCommit.slice(0, 12)}`, sha256: digest, files: unique };
}

export async function runToolBuild({ projectDir, buildDir, runtimeCatalog, runtimeCatalogSha256, generatedAt, metadataDir, stagingDir }) {
  if (typeof runtimeCatalog !== 'string' || runtimeCatalog === '') {
    throw inputError(RELEASE_CODES.BUILD_INPUT, 'A pinned runtime catalog is required; compatibility data is never invented');
  }
  if (typeof runtimeCatalogSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(runtimeCatalogSha256)) {
    throw inputError(RELEASE_CODES.BUILD_INPUT, 'An externally trusted runtime catalog SHA-256 is required (--runtime-catalog-sha256 or BEPACK_RUNTIME_CATALOG_SHA256)');
  }
  projectDir = path.resolve(projectDir);
  buildDir = path.resolve(buildDir);
  runtimeCatalog = path.resolve(runtimeCatalog);
  if (metadataDir !== undefined) metadataDir = path.resolve(metadataDir);
  if (stagingDir !== undefined) stagingDir = path.resolve(stagingDir);
  let actual;
  try {
    actual = await hashFile(runtimeCatalog);
  } catch (error) {
    throw inputError(RELEASE_CODES.BUILD_INPUT, `Cannot read pinned runtime catalog: ${error.message}`);
  }
  if (actual.sha256 !== runtimeCatalogSha256) {
    throw inputError(RELEASE_CODES.BUILD_INPUT, 'Runtime catalog raw bytes do not match the externally pinned SHA-256');
  }
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const cli = fileURLToPath(new URL('../../../scripts/bepack.mjs', import.meta.url));
  const args = [cli, 'build', '--project', projectDir, '--output', buildDir, '--frozen',
    '--runtime-catalog', path.resolve(runtimeCatalog), '--runtime-catalog-sha256', runtimeCatalogSha256];
  for (const [flag, value] of [['generated-at', generatedAt], ['metadata-dir', metadataDir], ['staging-dir', stagingDir]]) {
    if (value !== undefined) args.push(`--${flag}`, value);
  }
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { cwd: projectDir, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let diagnostic = '';
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { diagnostic = (diagnostic + chunk).slice(-16384); });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, diagnostic }));
  });
  if (result.code !== 0) {
    throw new ReleaseError(RELEASE_CODES.BUILD_INPUT, `Frozen pack build failed (exit=${result.code}, signal=${result.signal ?? 'none'}): ${result.diagnostic.trim()}`, {
      exitCode: [1, 2, 3].includes(result.code) ? result.code : 1,
    });
  }
}

async function onlyPackage(buildDir, expectedName) {
  let entries;
  try {
    entries = await readdir(buildDir, { withFileTypes: true });
  } catch (error) {
    throw inputError(RELEASE_CODES.BUILD_OUTPUT, `Build output is unavailable: ${error.message}`);
  }
  const packages = entries.filter(entry => entry.isFile() && entry.name.endsWith('.bepack'));
  if (entries.length !== 1 || packages.length !== 1 || packages[0].name !== expectedName) {
    const names = packages.map(entry => entry.name).join(', ');
    throw inputError(RELEASE_CODES.BUILD_OUTPUT, `Build output must contain exactly ${expectedName}, found: ${names || 'no .bepack file'}`);
  }
}

export async function runBuild({
  projectDir,
  assetsDir,
  workDir,
  runtimeCatalog,
  runtimeCatalogSha256,
  generatedAt,
  metadataDir,
  stagingDir,
  tag,
  commit,
  toolCommit = commit,
  buildCommand = runToolBuild,
  now = () => new Date().toISOString(),
}) {
  const manifest = await readProjectManifest(projectDir);
  assertTagVersion(tag, manifest.version);
  if (manifest.repository !== undefined) {
    const match = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/?$/.exec(manifest.repository);
    if (!match) throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Project repository is not an HTTPS GitHub repository URL');
  }
  await ensureDir(assetsDir);
  const buildDir = path.join(workDir, 'build');
  if (!/^[0-9a-f]{40}$/.test(commit ?? '')) throw inputError(RELEASE_CODES.GITHUB_CONFIG, 'A full lowercase commit SHA is required');
  await buildCommand({ projectDir, buildDir, runtimeCatalog, runtimeCatalogSha256, generatedAt, metadataDir, stagingDir });

  const expectedName = packageAssetName(manifest.id, manifest.version);
  await onlyPackage(buildDir, expectedName);
  const builtPackage = path.join(buildDir, expectedName);
  await copyFileExact(builtPackage, path.join(assetsDir, expectedName));

  const reader = await openPackage(builtPackage);
  let manifestBytes;
  try {
    manifestBytes = await reader.readEntry('bepack.json', { maxBytes: 4 * 1024 * 1024 });
    if (!reader.has('bepack.lock.json')) throw inputError(RELEASE_CODES.CONTAINER_INVALID, 'Built package is missing bepack.lock.json');
    let packageManifest;
    try {
      packageManifest = parseStrictJSON(manifestBytes, { maxBytes: 4 * 1024 * 1024 });
    } catch (error) {
      throw inputError(RELEASE_CODES.CONTAINER_INVALID, `Built package has an invalid bepack.json: ${error.message}`);
    }
    assertManifestForRelease(packageManifest);
    assertTagVersion(tag, packageManifest.version);
    for (const key of ['id', 'version', 'version_set', 'mode', 'schema_version']) {
      if (packageManifest[key] !== manifest[key]) {
        throw inputError(RELEASE_CODES.BUILD_OUTPUT, `Built package manifest changed ${key} during build`);
      }
    }
  } finally {
    await reader.close();
  }

  await writeNewFile(path.join(assetsDir, 'bepack.json'), manifestBytes);
  const packageInfo = await hashFile(path.join(assetsDir, expectedName));
  const manifestInfo = await hashFile(path.join(assetsDir, 'bepack.json'));
  await writeNewFile(path.join(assetsDir, `${expectedName}.sha256`), `${packageInfo.sha256}  ${expectedName}\n`);
  const tool = await computeToolIdentity({ projectDir, toolCommit });
  const context = {
    schema_version: 1,
    pack_id: manifest.id,
    version: manifest.version,
    tag,
    commit,
    package: { name: expectedName, size: packageInfo.size, sha256: packageInfo.sha256 },
    manifest: { name: 'bepack.json', size: manifestInfo.size, sha256: manifestInfo.sha256 },
    tool,
    built_at: now(),
  };
  await writeFileAtomic(path.join(workDir, 'build-context.json'), jsonBytes(context));
  return context;
}
