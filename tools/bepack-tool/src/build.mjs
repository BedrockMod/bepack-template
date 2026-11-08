import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, mkdtemp, copyFile, readdir, readFile, realpath, rm, stat } from 'node:fs/promises';

import { parseStrictJSON, readStrictJSON } from './strict-json.mjs';
import { createAjv, jsonPointer } from './json-schema.mjs';
import { createInspectionState, inspectProjectPath, safeRelative } from './paths.mjs';
import { loadRuntimeCatalog } from './runtime-catalog.mjs';
import { matchesVersion, validateProject } from './validate.mjs';
import { writeZipArchive } from './zip.mjs';
import { ensureSafeDirectory } from './staging.mjs';
import { constants } from 'node:fs';
import { assertLockClosure } from './lock-closure.mjs';

const schemaDirectory = fileURLToPath(new URL('../../../schemas/', import.meta.url));
const manifestFile = 'bepack.json';
const lockFile = 'bepack.lock.json';
const jsonLimit = 4 * 1024 ** 2;
const metadataLimit = 64 * 1024 ** 2;
const maximumConfigurations = 512;
// Generated lock identities are single safe IDs, not paths or version syntax.
const lockIdentity = (kind, ...parts) => createHash('sha256').update(JSON.stringify([kind, ...parts])).digest('hex');
const stalledPayloadFiles = 50;
const payloadRoot = 'payload';
const licenseRoot = 'licenses';

export class BuildFailure extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'BuildFailure';
    this.diagnostic = code;
    Object.assign(this, details);
  }
}

const fail = (code, message, details) => { throw new BuildFailure(code, message, details); };
const entries = value => Object.entries(value).filter(([key]) => key !== 'extensions');
const owned = (object, key) => object && Object.hasOwn(object, key) ? object[key] : undefined;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const byteOrder = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

async function hashFile(file) {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(file)) { size += chunk.length; hash.update(chunk); }
  return { size, sha256: hash.digest('hex') };
}

async function readLockValidator() {
  const bytes = await readFile(path.join(schemaDirectory, 'lock.schema.json'));
  const schema = parseStrictJSON(bytes, { maxBytes: jsonLimit });
  return createAjv().compile(schema);
}

async function readMetadataValidator() {
  const bytes = await readFile(path.join(schemaDirectory, 'dependency-metadata.schema.json'));
  const schema = parseStrictJSON(bytes, { maxBytes: jsonLimit });
  return createAjv().compile(schema);
}

// Collects every regular file of a project-relative path (file or directory) into target.
async function collectFiles(root, relative, state, target) {
  const info = await inspectProjectPath(root, relative, { state });
  if (!info.directory) { target.set(relative, info.absolute); return; }
  const walk = async (absolute, prefix) => {
    const names = (await readdir(absolute)).sort(byteOrder);
    for (const name of names) {
      const child = prefix + '/' + name;
      const location = path.join(absolute, name);
      const stat = await lstat(location);
      if (stat.isSymbolicLink() || (!stat.isDirectory() && (!stat.isFile() || stat.nlink > 1))) fail('BEPACK_PATH_UNSAFE', 'Links and special filesystem objects are forbidden: ' + child);
      if (stat.isDirectory()) await walk(location, child);
      else target.set(child, location);
    }
  };
  await walk(info.absolute, relative);
}

// Plans a package: projects the author project, resolves the runtime catalog, and builds the lock.
export async function planPackage(options) {
  if (typeof options?.project !== 'string' || !options.project) fail('BEPACK_ARGUMENT_INVALID', 'build requires --project');
  if (typeof options.output !== 'string' || !options.output) fail('BEPACK_ARGUMENT_INVALID', 'build requires --output');
  if (options.frozen !== true) fail('BEPACK_ARGUMENT_INVALID', 'build requires --frozen; resolve the version set first');
  if (typeof options.runtimeCatalog !== 'string' || !options.runtimeCatalog) fail('BEPACK_RUNTIME_CATALOG_MISSING', 'build requires --runtime-catalog; compatibility data must not be invented');
  if (typeof options.runtimeCatalogSha256 !== 'string' || !options.runtimeCatalogSha256) fail('BEPACK_RUNTIME_CATALOG_DIGEST_REQUIRED', 'build requires --runtime-catalog-sha256, the trusted digest of the catalog file bytes published by its owner');
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  if (Number.isNaN(Date.parse(generatedAt))) fail('BEPACK_ARGUMENT_INVALID', 'generated timestamp is not an RFC 3339 date-time');

  const project = await realpath(options.project).catch(error => fail('BEPACK_FILE_MISSING', error.message));
  const validation = await validateProject(project);
  const errors = validation.diagnostics.filter(diagnostic => diagnostic.severity === 'error');
  if (!validation.valid) fail('BEPACK_VALIDATION_FAILED', 'Project validation failed', { validation: { summary: validation.summary, diagnostics: errors } });
  const warnings = validation.diagnostics.filter(diagnostic => diagnostic.severity === 'warning').map(diagnostic => ({ code: diagnostic.code, message: diagnostic.message, file: diagnostic.file, field: diagnostic.field }));
  const warningsOf = (code, message, extra = {}) => warnings.push({ code, message, ...extra });

  let catalog;
  try { catalog = await loadRuntimeCatalog(options.runtimeCatalog, { expectedSha256: options.runtimeCatalogSha256 }); }
  catch (error) { fail(error.diagnostic ?? 'BEPACK_RUNTIME_CATALOG_INVALID', error.message); }

  const manifestBytes = await readFile(path.join(project, manifestFile));
  const manifest = parseStrictJSON(manifestBytes, { maxBytes: jsonLimit });
  const setRelative = `versions/${manifest.version_set}.json`;
  const combinationBytes = await readFile(path.join(project, setRelative));
  const combination = parseStrictJSON(combinationBytes, { maxBytes: jsonLimit });

  const inspection = createInspectionState();
  const published = new Map();
  const publishedTargets = new Map();
  for (const [group, collection] of entries(manifest.targets)) {
    if (collection.enabled !== true) continue;
    const variants = {};
    for (const [id, variant] of entries(collection.variants)) {
      const override = owned(combination.targets, id) ?? {};
      const effective = { ...variant, ...override, game_version: override.game_version ?? variant.game_version ?? manifest.game_version };
      published.set(id, effective);
      variants[id] = variant;
    }
    publishedTargets.set(group, { ...collection, variants });
  }
  if (!published.size) fail('BEPACK_TARGET_UNAVAILABLE', 'No enabled target collection remains after projection');

  const trimTargets = list => list.filter(id => published.has(id));
  const trimCompatibility = subject => {
    if (!subject.compatibility) return undefined;
    const targets = {};
    for (const [id, entry] of entries(subject.compatibility.targets)) if (published.has(id)) targets[id] = entry;
    return { targets };
  };
  const dependencies = manifest.dependencies.filter(dependency => trimTargets(dependency.targets).length).map(dependency => {
    const trimmed = { ...dependency, targets: trimTargets(dependency.targets) };
    const compatibility = trimCompatibility(dependency);
    if (compatibility) trimmed.compatibility = compatibility; else delete trimmed.compatibility;
    return trimmed;
  });
  let contents = manifest.contents.filter(content => trimTargets(content.targets).length).map(content => { const result = { ...content, targets: trimTargets(content.targets) }; const compatibility = trimCompatibility(content); if (compatibility) result.compatibility = compatibility; return result; });
  const replacementTargets = new Map();
  for (const content of contents) if (content.replaces) { if (!replacementTargets.has(content.replaces)) replacementTargets.set(content.replaces, new Set()); for (const target of content.targets) replacementTargets.get(content.replaces).add(target); }
  contents = contents.map(content => { const result = { ...content, targets: content.targets.filter(target => !replacementTargets.get(content.id)?.has(target)) }; delete result.replaces; if (result.compatibility) result.compatibility = { targets: Object.fromEntries(entries(result.compatibility.targets).filter(([id]) => result.targets.includes(id))) }; return result; }).filter(content => content.targets.length);
  const dependencyById = new Map(dependencies.map(dependency => [dependency.id, dependency]));
  const contentById = new Map(contents.map(content => [content.id, content]));

  for (const [id, dependency] of dependencyById) {
    const selected = owned(combination.dependencies, id);
    if (typeof selected !== 'string' || !matchesVersion(selected, dependency.version)) fail('BEPACK_NOT_RESOLVED', `Dependency ${id} has no resolved exact version in ${setRelative}`);
  }

  // Replacement targets: an item replaced for a target is not published for that target.
  const replaced = new Set();
  for (const [id, content] of contentById) if (content.replaces) for (const target of content.targets) replaced.add(target + '/' + content.replaces);

  const metadataDirectory = options.metadataDirectory ?? path.join(project, '.bepack-local', 'metadata');
  const metadataValidator = await readMetadataValidator();
  const metadataCache = new Map();
  async function metadataFor(dependency) {
    if (metadataCache.has(dependency.id)) return metadataCache.get(dependency.id);
    const file = path.join(metadataDirectory, dependency.id + '.json');
    let bytes;
    try { bytes = await readFile(file); } catch (error) { fail('BEPACK_METADATA_MISSING', `Cached metadata for ${dependency.id} is unavailable: ${error.message}`); }
    const value = parseStrictJSON(bytes, { maxBytes: metadataLimit });
    if (!metadataValidator(value)) fail('BEPACK_METADATA_INVALID', `Cached metadata for ${dependency.id} is invalid: ${metadataValidator.errors[0].message}`, { file });
    if (value.id !== dependency.id) fail('BEPACK_METADATA_INVALID', `Cached metadata identity mismatch for ${dependency.id}`, { file });
    const info = await stat(file);
    const record = { file, bytes, sha256: sha256(bytes), value, releases: value.releases, retrievedAt: value.retrieved_at ?? info.mtime.toISOString() };
    metadataCache.set(dependency.id, record);
    return record;
  }

  const payloadFiles = new Map();
  const licenseFiles = new Map();
  const claimed = new Set();
  async function claimFile(relative, kind) {
    const target = kind === 'licenses' ? licenseFiles : payloadFiles;
    await collectFiles(project, relative, inspection, target);
    for (const file of target.keys()) claimed.add(file);
  }

  if (manifest.license_file) await claimFile(manifest.license_file, licenseRoot);
  for (const dependency of dependencies) if (dependency.license_file) await claimFile(dependency.license_file, licenseRoot);
  for (const content of contents) await claimFile(content.path, payloadRoot);

  const contentOwned = new Set(contents.filter(content => content.source === 'dependency').map(content => content.dependency));
  const artifacts = [];
  const artifactIds = new Set();
  const assetsByDependencyTarget = new Map();
  const addArtifact = artifact => {
    if (artifactIds.has(artifact.id)) { const previous = artifacts.find(item => item.id === artifact.id); if (JSON.stringify(previous) !== JSON.stringify(artifact)) fail('BEPACK_ARTIFACT_AMBIGUOUS', 'Conflicting artifact identity: ' + artifact.id); return artifact.id; }
    artifactIds.add(artifact.id);
    artifacts.push(artifact);
    return artifact.id;
  };
  const declareAsset = (dependency, target, id) => {
    const key = dependency + '|' + target;
    if (!assetsByDependencyTarget.has(key)) assetsByDependencyTarget.set(key, []);
    assetsByDependencyTarget.get(key).push(id);
  };
  async function bundledAsset(relative, declared, dependency) {
    if (!safeRelative(relative)) fail('BEPACK_PATH_UNSAFE', 'Unsafe dependency artifact path: ' + relative);
    const info = await inspectProjectPath(project, relative, { state: inspection });
    if (info.directory) fail('BEPACK_DEPENDENCY_PAYLOAD_MISSING', `Bundled dependency ${dependency.id} must be a regular file at ${relative}`);
    const measured = await hashFile(path.join(project, relative));
    if (declared && (declared.size !== measured.size || declared.sha256 !== measured.sha256)) fail('BEPACK_DEPENDENCY_PAYLOAD_MISMATCH', `Bundled bytes of ${dependency.id} do not match the declared size or digest`, { path: relative });
    payloadFiles.set(relative, path.join(project, relative));
    claimed.add(relative);
    return measured;
  }

  for (const [id, dependency] of dependencyById) {
    const version = owned(combination.dependencies, id);
    const targets = dependency.targets.filter(target => published.has(target));
    if (dependency.resolver === 'direct') {
      const declared = dependency.direct;
      if (dependency.bundled) {
        if (contentOwned.has(id)) continue;
        const relative = `${payloadRoot}/dependencies/${id}/asset`;
        const measured = await bundledAsset(relative, declared, dependency);
        const artifactId = addArtifact({ id: lockIdentity('artifact', id, 'asset'), dependency: id, version, format: declared.format, size: measured.size, sha256: measured.sha256, path: relative, mounts: declared.mounts });
        for (const target of targets) declareAsset(id, target, artifactId);
      } else {
        const artifactId = addArtifact({ id: lockIdentity('artifact', id, 'asset'), dependency: id, version, format: declared.format, size: declared.size, sha256: declared.sha256, url: dependency.source, mounts: declared.mounts });
        for (const target of targets) declareAsset(id, target, artifactId);
      }
      continue;
    }
    if (dependency.resolver !== 'bepack-metadata') fail('BEPACK_RESOLVER_UNSUPPORTED', 'No injected resolver for ' + dependency.resolver);
    const metadata = await metadataFor(dependency);
    const release = metadata.releases.find(candidate => candidate.version === version);
    if (!release) fail('BEPACK_METADATA_RELEASE_MISSING', `Cached metadata for ${id} has no release ${version}`, { file: metadata.file });
    for (const target of targets) {
      const matches = release.artifacts.filter(candidate => candidate.targets.includes(target));
      if (matches.length !== 1) fail(matches.length ? 'BEPACK_ARTIFACT_AMBIGUOUS' : 'BEPACK_ARTIFACT_MISSING', `Release ${id}@${version} must expose exactly one artifact for ${target}`, { dependency: id, target });
      if (dependency.bundled && contentOwned.has(id)) continue;
      const artifact = matches[0];
      if (!safeRelative(artifact.id) || artifact.id.includes('/')) fail('BEPACK_PATH_UNSAFE', 'Unsafe metadata artifact id: ' + artifact.id);
      for (const mount of artifact.mounts) if (!(mount.source === '.' || safeRelative(mount.source)) || !safeRelative(mount.destination)) fail('BEPACK_PATH_UNSAFE', 'Unsafe artifact mount');
      const artifactId = lockIdentity('artifact', id, artifact.id);
      if (dependency.bundled) {
        const relative = `${payloadRoot}/dependencies/${id}/${artifact.id}`;
        const measured = await bundledAsset(relative, artifact, dependency);
        addArtifact({ id: artifactId, dependency: id, version, format: artifact.format, size: measured.size, sha256: measured.sha256, path: relative, mounts: artifact.mounts });
      } else {
        addArtifact({ id: artifactId, dependency: id, version, format: artifact.format, size: artifact.size, sha256: artifact.sha256, url: artifact.url, mounts: artifact.mounts });
      }
      declareAsset(id, target, artifactId);
    }
  }

  const evidence = [{ id: 'runtime-catalog', kind: 'runtime-catalog', url: catalog.url, sha256: catalog.sourceSha256, retrieved_at: catalog.retrievedAt }];
  if (Number.isNaN(Date.parse(evidence[0].retrieved_at))) fail('BEPACK_RUNTIME_CATALOG_INVALID', 'Runtime catalog retrieved_at is not an RFC 3339 date-time');
  for (const [id, metadata] of metadataCache) {
    if (evidence.some(record => record.id === lockIdentity('dependency-metadata', id))) continue;
    if (Number.isNaN(Date.parse(metadata.retrievedAt))) fail('BEPACK_METADATA_INVALID', `Cached metadata for ${id} has no RFC 3339 retrieval time`, { file: metadata.file });
    evidence.push({ id: lockIdentity('dependency-metadata', id), kind: 'dependency-metadata', url: dependencyById.get(id).source, sha256: metadata.sha256, retrieved_at: metadata.retrievedAt });
  }

  const constraintsFor = target => {
    const constraints = [];
    for (const dependency of dependencies) if (dependency.targets.includes(target)) constraints.push({ type: 'dependency', subject: dependency, entry: dependency.compatibility?.targets?.[target], upstream: dependency.resolver === 'bepack-metadata' ? upstreamEntry(dependency, target) : undefined });
    for (const content of contents) if (content.targets.includes(target) && !replaced.has(target + '/' + content.id)) constraints.push({ type: 'content', subject: content, entry: content.compatibility?.targets?.[target] });
    for (const constraint of constraints) {
      if (constraint.type === 'dependency' && constraint.subject.resolver === 'bepack-metadata' && !constraint.upstream) fail('BEPACK_COMPATIBILITY_UNKNOWN', `Upstream metadata for ${constraint.subject.id} has no compatibility for ${target}`);
      if (!constraint.entry && !constraint.upstream) fail('BEPACK_COMPATIBILITY_UNKNOWN', `${constraint.type} ${constraint.subject.id} has no compatibility entry for ${target}`, { target });
      constraint.requirements = [constraint.entry, constraint.upstream].filter(Boolean);
      constraint.entry ??= constraint.upstream;
    }
    return constraints;
  };
  function upstreamEntry(dependency, target) {
    const metadata = metadataCache.get(dependency.id);
    if (!metadata) return undefined;
    const release = metadata.releases.find(candidate => candidate.version === owned(combination.dependencies, dependency.id));
    return release?.compatibility?.targets?.[target];
  }

  const runtimes = [];
  const runtimeIds = new Map();
  const addRuntime = record => {
    if (runtimeIds.has(record.id)) return record.id;
    runtimeIds.set(record.id, record);
    runtimes.push(record);
    return record.id;
  };

  const configurations = [];
  const compatibility = [];
  const evidenceIds = constraint => {
    const ids = [evidence[0].id];
    if (constraint.type === 'dependency' && constraint.subject.resolver === 'bepack-metadata') ids.push(lockIdentity('dependency-metadata', constraint.subject.id));
    return ids;
  };
  const intersectGames = (author, upstream) => {
    if (!upstream) return author;
    if (author.unconstrained && upstream.unconstrained) return { unconstrained: true };
    if (author.unconstrained) return { versions: [...upstream.versions] };
    if (upstream.unconstrained) return { versions: [...author.versions] };
    return { versions: author.versions.filter(version => upstream.versions.includes(version)) };
  };

  for (const [target, variant] of published) {
    const constraints = constraintsFor(target);
    const requirements = constraints.flatMap(constraint => constraint.requirements);
    const candidates = variant.game_version === null ? catalog.list(variant.platform, variant.runtime) : [catalog.find(variant.platform, variant.runtime, variant.game_version)].filter(Boolean);
    if (!candidates.length) fail('BEPACK_RUNTIME_NOT_IN_CATALOG', `Runtime catalog has no ${variant.runtime} entry for ${variant.platform}${variant.game_version ? ' ' + variant.game_version : ''}`, { target });
    let accepted = 0, rejected = null;
    for (const game of candidates) {
      const compatible = requirements.every(entry => {
        const games = entry.games;
        return games.unconstrained === true || games.versions.includes(game.version);
      });
      if (!compatible) { rejected ??= 'game version is outside a declared compatibility range'; continue; }
      const loaderConstraint = constraint => constraint.loader;
      if (variant.loader.type === 'none') {
        if (requirements.some(constraint => loaderConstraint(constraint))) { rejected ??= 'a dependency requires a loader but the target declares none'; continue; }
      } else if (requirements.some(constraint => loaderConstraint(constraint) && loaderConstraint(constraint).type !== variant.loader.type)) {
        rejected ??= 'a dependency requires a different loader type'; continue;
      }
      let loader = null;
      if (variant.loader.type !== 'none') {
        const matches = game.loaders.filter(candidate => candidate.type === variant.loader.type
          && matchesVersion(candidate.version, variant.loader.version)
          && requirements.every(constraint => !loaderConstraint(constraint) || matchesVersion(candidate.version, loaderConstraint(constraint).version)));
        if (!matches.length) { rejected ??= 'no loader release satisfies every version requirement'; continue; }
        if (matches.length > 1) {
          const recommended = matches.filter(candidate => candidate.recommended === true);
          if (recommended.length !== 1) fail('BEPACK_LOADER_AMBIGUOUS', `Loader ${variant.loader.type} for ${target} has ${matches.length} candidates and no unique recommendation`);
          loader = recommended[0];
        } else loader = matches[0];
      }
      let client = null;
      const clientConstraint = constraint => constraint.client;
      if (variant.client === null) {
        if (requirements.some(constraint => clientConstraint(constraint))) { rejected ??= 'a dependency requires an external client but the target declares none'; continue; }
      } else {
        const declared = variant.client;
        const matches = game.clients.filter(candidate => candidate.id === declared.id
          && candidate.dependency === declared.dependency
          && matchesVersion(candidate.version, declared.version)
          && requirements.every(constraint => { const required = clientConstraint(constraint); return !required || (required.id === declared.id && matchesVersion(candidate.version, required.version)); }));
        if (!matches.length) { rejected ??= 'no client release satisfies every version requirement'; continue; }
        if (matches.length > 1) fail('BEPACK_CLIENT_AMBIGUOUS', `Client ${declared.id} for ${target} has ${matches.length} candidates`);
        client = matches[0];
        if (owned(combination.dependencies, declared.dependency) !== client.version) { rejected ??= 'client catalog version differs from selected dependency'; continue; }
      }
      if (loader && loader.integrity.kind !== 'artifact') fail('BEPACK_LOADER_INTEGRITY', `Loader ${loader.type}@${loader.version} must be pinned to an artifact digest`);
      const gameRuntime = addRuntime({ id: lockIdentity('game', game.platform, game.runtime, game.version, game.identity), kind: 'game', version: game.version, platform: game.platform, runtime: game.runtime, provider: catalog.provider, identity: game.identity, integrity: game.integrity });
      const loaderRuntime = loader ? addRuntime({ id: lockIdentity('loader', game.platform, game.runtime, loader.type, loader.version, loader.identity), kind: 'loader', version: loader.version, platform: game.platform, runtime: game.runtime, provider: catalog.provider, identity: loader.identity, integrity: loader.integrity }) : null;
      const dependenciesOfTarget = dependencies.filter(dependency => dependency.targets.includes(target)).map(dependency => ({
        id: dependency.id,
        version: owned(combination.dependencies, dependency.id),
        assets: assetsByDependencyTarget.get(dependency.id + '|' + target) ?? [],
      }));
      const contentsOfTarget = contents.filter(content => content.targets.includes(target) && !replaced.has(target + '/' + content.id)).map(content => content.id);
      configurations.push({
        id: lockIdentity('configuration', target, game.version),
        target,
        game_version: game.version,
        loader: variant.loader.type === 'none' ? { type: 'none', version: null } : { type: variant.loader.type, version: loader.version },
        client: client ? { id: client.id, version: client.version, dependency: variant.client.dependency } : null,
        dependencies: dependenciesOfTarget,
        contents: contentsOfTarget,
        runtimes: { game: gameRuntime, loader: loaderRuntime },
      });
      for (const constraint of constraints) {
        const games = intersectGames(constraint.entry.games, constraint.upstream?.games);
        if (!games.unconstrained && !games.versions.length) fail('BEPACK_COMPATIBILITY_UNSATISFIED', `Author and upstream compatibility for ${constraint.subject.id} do not intersect on ${target}`, { target });
        compatibility.push({
          subject_type: constraint.type,
          subject: constraint.subject.id,
          target,
          entry: {
            games,
            loader: loader ? { type: loader.type, version: { exact: loader.version } } : null,
            client: client ? { id: client.id, version: { exact: client.version } } : null,
            evidence: constraint.entry.evidence ?? constraint.upstream?.evidence ?? { kind: 'author', reference: manifest.id },
          },
          evidence: evidenceIds(constraint),
        });
      }
      accepted++;
    }
    if (!accepted) fail('BEPACK_COMPATIBILITY_UNSATISFIED', `Target ${target} has no publishable configuration: ${rejected ?? 'no catalog candidate'}`, { target });
    if (configurations.length > maximumConfigurations) fail('BEPACK_RESOURCE_LIMIT', 'Configuration count exceeds the packaging budget');
  }

  const projectedManifest = { ...manifest, targets: Object.fromEntries(publishedTargets), dependencies, contents };
  const projectedBytes = Buffer.from(JSON.stringify(projectedManifest, null, 2) + '\n', 'utf8');
  const projectedCombination = { ...combination, targets: Object.fromEntries(entries(combination.targets).filter(([id])=>published.has(id))), dependencies: Object.fromEntries(entries(combination.dependencies).filter(([id])=>dependencyById.has(id))) };
  const setBytes = Buffer.from(JSON.stringify(projectedCombination, null, 2) + '\n', 'utf8');

  const files = new Map([
    [manifestFile, { size: projectedBytes.length, sha256: sha256(projectedBytes) }],
    [setRelative, { size: setBytes.length, sha256: sha256(setBytes) }],
  ]);
  for (const [relative, absolute] of [...payloadFiles, ...licenseFiles]) {
    const measured = await hashFile(absolute);
    files.set(relative, measured);
  }
  for (const artifact of artifacts) if (artifact.path && !files.has(artifact.path)) fail('BEPACK_DEPENDENCY_PAYLOAD_MISSING', 'Artifact is not registered in the file table: ' + artifact.path);

  // Files the author keeps for unpublished targets are reported, never packaged silently.
  for (const root of [payloadRoot, licenseRoot]) {
    const info = await inspectProjectPath(project, root, { state: inspection }).catch(error => (error.code === 'ENOENT' ? null : fail(error.diagnostic ?? 'BEPACK_PATH_UNSAFE', error.message)));
    if (!info || !info.directory) continue;
    const present = new Map();
    const names = [];
    const walk = async (absolute, prefix) => {
      for (const name of (await readdir(absolute)).sort(byteOrder)) {
        const child = prefix + '/' + name;
        const location = path.join(absolute, name);
        const item = await lstat(location);
        if (item.isDirectory()) await walk(location, child);
        else if (item.isFile()) { present.set(child, true); names.push(child); }
      }
    };
    await walk(info.absolute, root);
    const stalled = names.filter(name => !claimed.has(name));
    if (stalled.length) warningsOf('BEPACK_UNREFERENCED_PAYLOAD', `${stalled.length} file(s) below ${root}/ belong to no published content, dependency, or license and are not packaged`, { files: stalled.slice(0, stalledPayloadFiles), truncated: stalled.length > stalledPayloadFiles });
  }

  const lock = {
    schema_version: 1,
    pack: { id: manifest.id, version: manifest.version, version_set: manifest.version_set },
    generated_at: generatedAt,
    files: [...files].map(([file, value]) => ({ path: file, size: value.size, sha256: value.sha256 })).sort((a, b) => byteOrder(a.path, b.path)),
    artifacts,
    configurations,
    evidence,
    compatibility,
    runtimes,
  };
  if (manifest.tested) lock.tested = manifest.tested;

  const validateLock = await readLockValidator();
  if (!validateLock(lock)) {
    const [error] = validateLock.errors;
    fail('BEPACK_LOCK_INVALID', `Generated lock is invalid: ${error.message}`, { field: error.instancePath + (error.keyword === 'required' ? '/' + jsonPointer(error.params.missingProperty) : '') });
  }
  assertLockClosure(projectedManifest, projectedCombination, lock);
  const lockBytes = Buffer.from(JSON.stringify(lock, null, 2) + '\n', 'utf8');

  const archiveEntries = [
    { path: manifestFile, bytes: projectedBytes },
    { path: setRelative, bytes: setBytes },
    { path: lockFile, bytes: lockBytes },
    ...[...payloadFiles, ...licenseFiles].map(([relative, absolute]) => ({ path: relative, absolute })),
  ].sort((a, b) => byteOrder(a.path, b.path));

  const output = path.resolve(options.output);
  const destination = path.join(output, `${manifest.id}-${manifest.version}.bepack`);

  return {
    manifest,
    lock,
    lockBytes,
    archiveEntries,
    output,
    destination,
    report: {
      schema_version: 1,
      command: 'build',
      valid: true,
      pack: { id: manifest.id, version: manifest.version, version_set: manifest.version_set },
      projection: {
        targets: [...published.keys()].sort(byteOrder),
        dependencies: dependencies.map(dependency => ({ id: dependency.id, version: owned(combination.dependencies, dependency.id), bundled: dependency.bundled === true })),
        contents: contents.map(content => content.id),
        configurations: configurations.map(configuration => configuration.id),
        artifacts: artifacts.map(artifact => artifact.id),
        runtimes: runtimes.map(runtime => runtime.id),
        files: lock.files.length,
      },
      evidence: evidence.map(record => record.id),
      catalog: { file: catalog.file, sha256: catalog.sha256, trusted: catalog.trusted, provider: catalog.provider, source: { url: catalog.url, sha256: catalog.sourceSha256 }, retrieved_at: catalog.retrievedAt },
      compatibility: compatibility.length,
      warnings,
      unchecked: ['upstream-content-formats-and-world-references', 'adapter-config-whitelist-and-native-layout', 'race-free-filesystem-installation'],
    },
  };
}

// Packages a validated author project into a .bepack container plus a build report.
export async function buildPackage(options) {
  const plan = await planPackage(options);
  await ensureSafeDirectory(plan.output);
  if (await lstat(plan.destination).then(() => true, () => false)) fail('BEPACK_OUTPUT_EXISTS', 'Refusing to overwrite an existing package: ' + plan.destination);
  const base = options.stagingDirectory ?? plan.output;
  await ensureSafeDirectory(base);
  const privateDirectory = await mkdtemp(path.join(path.resolve(base), '.bepack-build-'));
  const staging = path.join(privateDirectory, 'package.bepack');
  let archive;
  try {
    archive = await writeZipArchive(staging, plan.archiveEntries, { stagingDirectory: privateDirectory });
    await copyFile(staging, plan.destination, constants.COPYFILE_EXCL);
  } catch (error) {
    await rm(privateDirectory, { recursive: true, force: true });
    if (error instanceof BuildFailure) throw error;
    fail(error.diagnostic ?? 'BEPACK_ARCHIVE_FAILED', 'Failed to write the package container: ' + error.message);
  }
  await rm(privateDirectory, { recursive: true, force: true });
  return { ...plan.report, package: { file: plan.destination, size: archive.size, sha256: archive.sha256, entries: archive.entries.length } };
}

export const buildExports = { manifestFile, lockFile, payloadRoot, licenseRoot };
