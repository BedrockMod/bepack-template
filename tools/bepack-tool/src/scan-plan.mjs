// Builds the deterministic set of files that must pass VirusTotal before a
// release may become public. The plan covers the final package, executable
// payload files, and executable unbundled dependency assets.

import path from 'node:path';

import { openPackage } from './release-package.mjs';
import { parseStrictJSON } from './strict-json.mjs';
import { hashFile } from './release-files.mjs';
import { HEX_SHA256, UTC_RFC3339 } from './release-files.mjs';
import { inputError, RELEASE_CODES } from './release-errors.mjs';

const MANIFEST_LIMIT = 4 * 1024 * 1024;
const LOCK_LIMIT = 64 * 1024 * 1024;

const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.node', '.jar', '.class', '.wasm', '.bin', '.elf',
  '.scr', '.com', '.msi', '.sys', '.ocx', '.cpl', '.apk', '.dex', '.sh', '.bat', '.cmd',
  '.ps1', '.py', '.js', '.mjs', '.cjs', '.lua', '.vbs', '.vb', '.wsf', '.hta', '.app',
  '.dmg', '.pkg', '.deb', '.rpm', '.appimage',
]);

const KNOWN_DATA_EXTENSIONS = new Set([
  '.json', '.txt', '.md', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico', '.svg',
  '.ogg', '.wav', '.mp3', '.mp4', '.webm', '.ttf', '.otf', '.woff', '.woff2', '.lang',
  '.mcmeta', '.properties', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.html', '.css',
  '.csv', '.tsv', '.xml', '.nbt', '.zip', '.mcpack', '.mcaddon', '.mcworld', '.mctemplate',
]);

const EXECUTABLE_MAGIC = [
  [Buffer.from([0x4d, 0x5a]), 'pe'],
  [Buffer.from([0x7f, 0x45, 0x4c, 0x46]), 'elf'],
  [Buffer.from([0xfe, 0xed, 0xfa, 0xce]), 'macho'],
  [Buffer.from([0xfe, 0xed, 0xfa, 0xcf]), 'macho'],
  [Buffer.from([0xce, 0xfa, 0xed, 0xfe]), 'macho'],
  [Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), 'macho'],
  [Buffer.from([0xca, 0xfe, 0xba, 0xbe]), 'macho-fat-or-java-class'],
  [Buffer.from([0xca, 0xfe, 0xd0, 0x0d]), 'macho-fat'],
  [Buffer.from([0x00, 0x61, 0x73, 0x6d]), 'wasm'],
  [Buffer.from([0x23, 0x21]), 'shebang'],
];

function planFail(message) {
  throw inputError(RELEASE_CODES.SCAN_PLAN_INVALID, message);
}

function assertArray(value, name) {
  if (!Array.isArray(value)) planFail(`Lock field ${name} must be an array`);
  return value;
}

function assertSha(value, name) {
  if (typeof value !== 'string' || !HEX_SHA256.test(value)) planFail(`Lock field ${name} must be a lowercase SHA-256`);
  return value;
}

function assertSize(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) planFail(`Lock field ${name} must be a non-negative integer`);
  return value;
}

function extname(name) {
  return path.posix.extname(name).toLowerCase();
}

export function validateLock(lock, manifest) {
  if (!lock || typeof lock !== 'object' || Array.isArray(lock)) planFail('bepack.lock.json must be an object');
  if (lock.schema_version !== 1) planFail('bepack.lock.json schema_version must be 1');
  if (!lock.pack || typeof lock.pack !== 'object') planFail('Lock pack is required');
  if (lock.pack.id !== manifest.id || lock.pack.version !== manifest.version || lock.pack.version_set !== manifest.version_set) {
    planFail('Lock pack identity does not match the manifest');
  }
  if (typeof lock.generated_at !== 'string' || !UTC_RFC3339.test(lock.generated_at)) planFail('Lock generated_at must be UTC RFC 3339');
  if (!Array.isArray(lock.files)) planFail('Lock files must be an array');
  const files = new Map();
  for (const file of lock.files) {
    if (!file || typeof file !== 'object') planFail('Lock file entry must be an object');
    if (typeof file.path !== 'string') planFail('Lock file path must be a string');
    if (files.has(file.path)) planFail(`Duplicate lock file path: ${file.path}`);
    files.set(file.path, { path: file.path, size: assertSize(file.size, `files[${file.path}].size`), sha256: assertSha(file.sha256, `files[${file.path}].sha256`) });
  }
  const artifacts = assertArray(lock.artifacts, 'artifacts').map(artifact => {
    if (!artifact || typeof artifact !== 'object') planFail('Lock artifact must be an object');
    if (typeof artifact.id !== 'string' || !artifact.id) planFail('Lock artifact id is required');
    if (typeof artifact.dependency !== 'string' || !artifact.dependency) planFail('Lock artifact dependency is required');
    if (artifact.format !== 'file' && artifact.format !== 'zip-tree') planFail(`Unsupported artifact format: ${artifact.format}`);
    assertSize(artifact.size, `artifacts[${artifact.id}].size`);
    assertSha(artifact.sha256, `artifacts[${artifact.id}].sha256`);
    if ((artifact.path === undefined) === (artifact.url === undefined)) planFail(`Artifact ${artifact.id} must have exactly one of path or url`);
    if (artifact.path !== undefined) {
      if (!artifact.path.startsWith('payload/') || files.get(artifact.path) === undefined) planFail(`Bundled artifact ${artifact.id} path is not a locked payload file`);
      if (files.get(artifact.path).size !== artifact.size || files.get(artifact.path).sha256 !== artifact.sha256) planFail(`Bundled artifact ${artifact.id} size/hash does not match lock files`);
    }
    if (artifact.url !== undefined && (typeof artifact.url !== 'string' || !/^https:\/\//i.test(artifact.url))) planFail(`Artifact ${artifact.id} url must be HTTPS`);
    return artifact;
  });
  const artifactIds = new Set();
  for (const artifact of artifacts) {
    if (artifactIds.has(artifact.id)) planFail(`Duplicate artifact id: ${artifact.id}`);
    artifactIds.add(artifact.id);
  }
  if (assertArray(lock.configurations, 'configurations').length === 0) planFail('Lock configurations must not be empty');
  if (assertArray(lock.runtimes, 'runtimes').length === 0) planFail('Lock runtimes must not be empty');
  assertArray(lock.evidence, 'evidence');
  assertArray(lock.compatibility, 'compatibility');
  return { files, artifacts };
}

export function dependencyRoles(manifest) {
  if (!Array.isArray(manifest.dependencies)) planFail('Manifest dependencies must be an array');
  const roles = new Map();
  for (const dependency of manifest.dependencies) {
    if (!dependency || typeof dependency.id !== 'string' || !dependency.id) planFail('Manifest dependency id is required');
    if (!['content', 'mod', 'client'].includes(dependency.role)) planFail(`Manifest dependency ${dependency.id} has an invalid role`);
    if (typeof dependency.bundled !== 'boolean') planFail(`Manifest dependency ${dependency.id} must declare bundled`);
    roles.set(dependency.id, { role: dependency.role, bundled: dependency.bundled });
  }
  return roles;
}

function executableByExtension(name) {
  return EXECUTABLE_EXTENSIONS.has(extname(name));
}

function executableByMagic(bytes) {
  for (const [signature, kind] of EXECUTABLE_MAGIC) {
    if (bytes.length >= signature.length && bytes.subarray(0, signature.length).equals(signature)) return kind;
  }
  return null;
}

function urlLooksExecutable(url) {
  try {
    return executableByExtension(new URL(url).pathname);
  } catch {
    return false;
  }
}

export async function computeScanPlan(packageFile, { packageName } = {}) {
  const reader = await openPackage(packageFile);
  try {
    return await computeScanPlanFromReader(reader, { packageFile, packageName });
  } finally {
    await reader.close();
  }
}

export async function computeScanPlanFromReader(reader, { packageFile, packageName } = {}) {
  if (!reader.has('bepack.json')) planFail('Package is missing bepack.json');
  let manifest;
  let lock;
  try {
    manifest = parseStrictJSON(await reader.readEntry('bepack.json', { maxBytes: MANIFEST_LIMIT }), { maxBytes: MANIFEST_LIMIT });
  } catch (error) {
    planFail(`Cannot read package bepack.json: ${error.message}`);
  }
  try {
    lock = parseStrictJSON(await reader.readEntry('bepack.lock.json', { maxBytes: LOCK_LIMIT }), { maxBytes: LOCK_LIMIT });
  } catch (error) {
    planFail(`Cannot read package bepack.lock.json: ${error.message}`);
  }
  const roles = dependencyRoles(manifest);
  const { files, artifacts } = validateLock(lock, manifest);
  const packageHash = packageFile ? await hashFile(packageFile) : null;
  const entries = [];

  if (packageFile) {
    if (!packageHash) planFail('Package hash is required');
    entries.push({
      subject: 'package',
      sha256: packageHash.sha256,
      size: packageHash.size,
      source: { kind: 'file', file: packageFile },
      reason: 'final-package',
    });
  }

  const artifactByPath = new Map();
  for (const artifact of artifacts) {
    if (artifact.path !== undefined) artifactByPath.set(artifact.path, artifact);
  }

  const payloadNames = reader.entries
    .filter(entry => entry.name.startsWith('payload/'))
    .map(entry => entry.name)
    .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));

  for (const name of payloadNames) {
    const artifact = artifactByPath.get(name);
    const role = artifact ? roles.get(artifact.dependency) : null;
    let reason = null;
    if (artifact && role && (role.role === 'mod' || role.role === 'client')) reason = 'dependency-bytes';
    else if (executableByExtension(name)) reason = 'extension';
    else {
      const entry = reader.entry(name);
      const prefix = await reader.readEntryPrefix(name, Math.min(8, entry.size));
      const magic = executableByMagic(prefix);
      if (magic) reason = `magic:${magic}`;
    }
    if (!reason) continue;
    const actual = await reader.hashEntry(name);
    if (artifact && (artifact.size !== actual.size || artifact.sha256 !== actual.sha256)) {
      planFail(`Bundled artifact ${artifact.id} bytes do not match the lock`);
    }
    entries.push({
      subject: name,
      sha256: actual.sha256,
      size: actual.size,
      source: { kind: 'package-entry', path: name },
      reason,
    });
  }

  for (const artifact of artifacts) {
    if (artifact.url === undefined) continue;
    const role = roles.get(artifact.dependency);
    if (!role) planFail(`Artifact ${artifact.id} references an unknown dependency`);
    if (role.role !== 'mod' && role.role !== 'client' && !urlLooksExecutable(artifact.url)) continue;
    entries.push({
      subject: `dependency/${artifact.dependency}/${artifact.id}`,
      sha256: artifact.sha256,
      size: artifact.size,
      source: { kind: 'url', url: artifact.url, artifact_id: artifact.id, dependency: artifact.dependency },
      reason: role.role === 'mod' || role.role === 'client' ? role.role : 'executable-url',
    });
  }

  const seenSubjects = new Set();
  const seenHashes = new Map();
  for (const entry of entries) {
    if (seenSubjects.has(entry.subject)) planFail(`Duplicate scan subject: ${entry.subject}`);
    seenSubjects.add(entry.subject);
    const previous = seenHashes.get(entry.sha256);
    if (previous && previous !== entry.size) planFail(`SHA-256 ${entry.sha256} has conflicting sizes`);
    seenHashes.set(entry.sha256, entry.size);
  }
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.subject), Buffer.from(b.subject)));

  const plan = {
    schema_version: 1,
    ...(packageName ? { package_name: packageName } : {}),
    entries,
  };
  return { plan, manifest, lock, files, artifacts, roles };
}

export async function writeScanPlan(plan, file) {
  const { jsonBytes, writeNewFile } = await import('./release-files.mjs');
  await writeNewFile(file, jsonBytes(plan));
}
