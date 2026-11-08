#!/usr/bin/env node
// Release pipeline CLI. Each subcommand is a separately invocable stage so the
// workflow can keep secrets in the scan job and write permission in publish.
// The script never packs a package itself: build delegates to
// `scripts/bepack.mjs build --frozen`.

import { readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  DESCRIPTOR_ASSET,
  MANIFEST_ASSET,
  SCAN_REPORT_ASSET,
  assertManifestForRelease,
  assertTagVersion,
  buildReleaseDescriptor,
  verifyAssetDirectory,
} from '../tools/bepack-tool/src/release-assets.mjs';
import { computeToolIdentity, runBuild } from '../tools/bepack-tool/src/release-build.mjs';
import {
  ensureDir,
  hashFile,
  jsonBytes,
  readJson,
  writeFileAtomic,
} from '../tools/bepack-tool/src/release-files.mjs';
import { parseStrictJSON } from '../tools/bepack-tool/src/strict-json.mjs';
import { runScan } from '../tools/bepack-tool/src/release-scan.mjs';
import { runPublish } from '../tools/bepack-tool/src/release-publish.mjs';
import { createVirusTotalClient, assertVtConfig } from '../tools/bepack-tool/src/virustotal.mjs';
import { createGitHubClient } from '../tools/bepack-tool/src/release-github.mjs';
import {
  EXIT,
  RELEASE_CODES,
  ReleaseError,
  errorPayload,
  exitCodeOf,
  inputError,
  externalError,
} from '../tools/bepack-tool/src/release-errors.mjs';

const COMMANDS = new Set(['preflight', 'build', 'scan', 'assemble', 'publish', 'verify-assets', 'notify']);
const BOOLEAN_OPTIONS = new Set(['allow-test-hosts', 'check-existing', 'require-consent', 'help']);
const VALUE_OPTIONS = new Set([
  'project', 'assets', 'work', 'tag', 'commit', 'tool-commit', 'repository', 'repository-id',
  'report', 'plan-output', 'release-id', 'delivery-id', 'generated-at', 'tool-version', 'runtime-catalog', 'runtime-catalog-sha256', 'metadata-dir', 'staging-dir',
]);

const USAGE = `Usage: node scripts/bepack-release.mjs <command> [options]

Commands:
  preflight       Verify manifest/tag/repository before building
  build           Run the frozen pack build and stage the exact assets
  scan            Build a strict VirusTotal report for the full scan plan
  assemble        Write bepack-release.json and verify the five assets
  publish         Create/resume a draft release, verify, then publish
  verify-assets   Verify a directory of the five fixed release assets
  notify          Optional registry dispatch; skipped when not configured

Common options:
  --project <dir>          Bepack project directory (default: .)
  --assets <dir>           Release staging directory (exactly five assets at the end)
  --work <dir>             Private staging directory for plans/downloads
  --tag <tag>              Release tag (default: GITHUB_REF_NAME)
  --commit <sha>           Full commit OID (default: GITHUB_SHA)
  --repository <owner/name> Repository (default: GITHUB_REPOSITORY)
  --repository-id <id>     Numeric repository id (default: GITHUB_REPOSITORY_ID)
  --runtime-catalog <file>  Pinned runtime catalog for build (or BEPACK_RUNTIME_CATALOG_PATH)
  --runtime-catalog-sha256 <hex> Externally pinned catalog bytes (or BEPACK_RUNTIME_CATALOG_SHA256)
  --metadata-dir <dir>     Dependency metadata for the frozen toolchain
  --staging-dir <dir>      Optional toolchain staging directory
  --report <file>          Write the command result as JSON
  --allow-test-hosts       Test-only: allow localhost HTTP mocks

Exit codes: 0 success, 2 invalid input/policy, 3 external service failure, 1 internal error.`;

function camel(name) {
  return name.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

export function parseArguments(argv) {
  const [command, ...rest] = argv;
  if (!command || command === '--help' || command === '-h') return { command: 'help', options: {} };
  if (!COMMANDS.has(command)) throw inputError(RELEASE_CODES.USAGE, `Unknown command: ${command}`);
  const options = {};
  for (let index = 0; index < rest.length; index++) {
    const argument = rest[index];
    if (!argument.startsWith('--')) throw inputError(RELEASE_CODES.USAGE, `Unexpected argument: ${argument}`);
    const name = argument.slice(2);
    if (!BOOLEAN_OPTIONS.has(name) && !VALUE_OPTIONS.has(name)) throw inputError(RELEASE_CODES.USAGE, `Unknown option: --${name}`);
    if (BOOLEAN_OPTIONS.has(name)) {
      options[camel(name)] = true;
      continue;
    }
    const value = rest[++index];
    if (value === undefined || value.startsWith('--')) throw inputError(RELEASE_CODES.USAGE, `Option --${name} requires a value`);
    options[camel(name)] = value;
  }
  return { command, options };
}

function requireOption(options, name, label = name) {
  const value = options[camel(name)];
  if (typeof value !== 'string' || value === '') throw inputError(RELEASE_CODES.USAGE, `--${name} is required`);
  return value;
}

function defaults(options, env) {
  return {
    project: options.project ?? '.',
    tag: options.tag ?? env.GITHUB_REF_NAME,
    commit: options.commit ?? env.GITHUB_SHA,
    repository: options.repository ?? env.GITHUB_REPOSITORY,
    repositoryId: options.repositoryId ?? env.GITHUB_REPOSITORY_ID,
    toolCommit: options.toolCommit ?? options.commit ?? env.GITHUB_SHA,
  };
}

function assertTag(tag) {
  if (typeof tag !== 'string' || !/^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/.test(tag)) {
    throw inputError(RELEASE_CODES.TAG_MISMATCH, `Release tag must be v<semver>, got ${tag ?? 'nothing'}`);
  }
  if (tag.startsWith('tool-v')) throw inputError(RELEASE_CODES.TAG_MISMATCH, 'Tool release tags must not trigger pack releases');
  return tag;
}

function assertCommit(commit) {
  if (typeof commit !== 'string' || !/^[0-9a-f]{40}$/.test(commit)) {
    throw inputError(RELEASE_CODES.GITHUB_CONFIG, 'A full lowercase 40-hex commit SHA is required');
  }
  return commit;
}

function assertRepositoryId(repositoryId) {
  if (typeof repositoryId !== 'string' || !/^[0-9]+$/.test(repositoryId)) {
    throw inputError(RELEASE_CODES.GITHUB_CONFIG, 'A numeric repository id is required (GITHUB_REPOSITORY_ID)');
  }
  return repositoryId;
}

async function readProjectManifest(projectDir) {
  const bytes = await readFile(path.join(projectDir, 'bepack.json'));
  return parseStrictJSON(bytes, { maxBytes: 4 * 1024 * 1024 });
}

function repositoryFromManifest(manifest) {
  if (typeof manifest.repository !== 'string') return null;
  const match = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(manifest.repository);
  return match ? match[1] : null;
}

async function preflight({ options, env }) {
  const settings = defaults(options, env);
  const manifest = await readProjectManifest(settings.project);
  assertManifestForRelease(manifest);
  assertTag(settings.tag);
  assertTagVersion(settings.tag, manifest.version);
  assertCommit(settings.commit);
  if (manifest.repository !== undefined) {
    const declared = repositoryFromManifest(manifest);
    if (!declared) throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Manifest repository must be an HTTPS GitHub repository URL');
    if (settings.repository && declared.toLowerCase() !== settings.repository.toLowerCase()) {
      throw inputError(RELEASE_CODES.MANIFEST_INVALID, `Manifest repository ${declared} does not match ${settings.repository}`);
    }
  }
  if (options.requireConsent && env.VT_UPLOAD_CONSENT !== 'true') {
    throw inputError(RELEASE_CODES.VT_CONFIG, 'VT_UPLOAD_CONSENT must be set to true before a release can be scanned');
  }
  const result = {
    ok: true,
    phase: 'preflight',
    pack_id: manifest.id,
    version: manifest.version,
    version_set: manifest.version_set,
    mode: manifest.mode,
    tag: settings.tag,
    commit: settings.commit,
    package_name: `${manifest.id}-${manifest.version}.bepack`,
    repository: settings.repository ?? null,
    repository_id: settings.repositoryId ?? null,
  };
  if (env.GITHUB_TOKEN) {
    const client = createGitHubClient({
      token: env.GITHUB_TOKEN,
      apiBase: env.GITHUB_API_URL ?? 'https://api.github.com',
      uploadsBase: env.GITHUB_UPLOADS_URL,
      allowInsecureTestHosts: Boolean(options.allowTestHosts),
    });
    const repository = settings.repository;
    if (!repository) throw inputError(RELEASE_CODES.GITHUB_CONFIG, 'GITHUB_REPOSITORY is required for the remote preflight');
    const repo = await client.getRepository(repository);
    if (settings.repositoryId && String(repo.id) !== settings.repositoryId) {
      throw inputError(RELEASE_CODES.GITHUB_CONFIG, 'Repository id does not match the API response');
    }
    const tagCommit = await client.resolveTagCommit(repository, settings.tag);
    if (tagCommit !== settings.commit) throw inputError(RELEASE_CODES.IMMUTABLE, `Tag ${settings.tag} points at ${tagCommit}, not ${settings.commit}`);
    const release = await client.getReleaseByTag(repository, settings.tag);
    result.existing_release = release ? { id: release.id, draft: release.draft === true } : null;
    result.repository_id = String(repo.id);
  }
  return result;
}

async function build({ options, env }) {
  const settings = defaults(options, env);
  const assetsDir = requireOption(options, 'assets');
  const workDir = requireOption(options, 'work');
  assertTag(settings.tag);
  assertCommit(settings.commit);
  const context = await runBuild({
    projectDir: path.resolve(settings.project),
    assetsDir: path.resolve(assetsDir),
    workDir: path.resolve(workDir),
    runtimeCatalog: options.runtimeCatalog ?? env.BEPACK_RUNTIME_CATALOG_PATH,
    runtimeCatalogSha256: options.runtimeCatalogSha256 ?? env.BEPACK_RUNTIME_CATALOG_SHA256,
    generatedAt: options.generatedAt,
    metadataDir: options.metadataDir,
    stagingDir: options.stagingDir,
    tag: settings.tag,
    commit: settings.commit,
    toolCommit: settings.toolCommit,
  });
  return { ok: true, phase: 'build', ...context };
}

function integerEnv(env, name, fallback, min, max) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw inputError(RELEASE_CODES.VT_CONFIG, `${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

async function scan({ options, env }) {
  const settings = defaults(options, env);
  assertTag(settings.tag);
  const assetsDir = path.resolve(requireOption(options, 'assets'));
  const workDir = path.resolve(requireOption(options, 'work'));
  const baseUrl = env.BEPACK_VT_API_URL ?? 'https://www.virustotal.com/api/v3';
  assertVtConfig({ apiKey: env.VT_API_KEY, consent: env.VT_UPLOAD_CONSENT, baseUrl });
  const vt = createVirusTotalClient({
    apiKey: env.VT_API_KEY,
    baseUrl,
    pollIntervalMs: integerEnv(env, 'BEPACK_VT_POLL_INTERVAL_MS', 15_000, 100, 60_000),
    maxWaitMs: integerEnv(env, 'BEPACK_VT_MAX_WAIT_MS', 30 * 60 * 1000, 1_000, 60 * 60 * 1000),
  });
  const scanned = await runScan({
    assetsDir,
    workDir,
    vt,
    tag: settings.tag,
    allowPrivateHosts: Boolean(options.allowTestHosts),
  });
  const count = scanned.report.entries.length;
  return {
    ok: true,
    phase: 'scan',
    package_sha256: scanned.report.package_sha256,
    entries: count,
    analyzed: new Set(scanned.report.entries.map(entry => entry.analysis_id)).size,
    report_sha256: (await hashFile(path.join(assetsDir, SCAN_REPORT_ASSET))).sha256,
    plan_output: path.join(workDir, 'scan-plan.json'),
  };
}

async function loadManifestAsset(assetsDir) {
  const bytes = await readFile(path.join(assetsDir, MANIFEST_ASSET));
  let manifest;
  try {
    manifest = parseStrictJSON(bytes, { maxBytes: 4 * 1024 * 1024 });
  } catch (error) {
    throw inputError(RELEASE_CODES.MANIFEST_INVALID, `Cannot read staged bepack.json: ${error.message}`);
  }
  assertManifestForRelease(manifest);
  return { manifest, bytes };
}

async function assemble({ options, env }) {
  const settings = defaults(options, env);
  assertTag(settings.tag);
  assertCommit(settings.commit);
  const assetsDir = path.resolve(requireOption(options, 'assets'));
  const workDir = options.work ? path.resolve(options.work) : null;
  const repositoryId = assertRepositoryId(settings.repositoryId);
  const { manifest, bytes } = await loadManifestAsset(assetsDir);
  assertTagVersion(settings.tag, manifest.version);
  const packageName = `${manifest.id}-${manifest.version}.bepack`;
  const packageFile = path.join(assetsDir, packageName);
  const packageInfo = await hashFile(packageFile);
  const manifestInfo = await hashFile(path.join(assetsDir, MANIFEST_ASSET));
  const scanReportPath = path.join(assetsDir, SCAN_REPORT_ASSET);
  const scanInfo = await hashFile(scanReportPath);

  let tool;
  const contextPath = workDir ? path.join(workDir, 'build-context.json') : null;
  if (contextPath) {
    try {
      const context = await readJson(contextPath);
      if (context.package?.sha256 !== packageInfo.sha256 || context.package?.size !== packageInfo.size) {
        throw inputError(RELEASE_CODES.ASSET_INVALID, 'Staged package does not match build-context.json');
      }
      if (context.manifest?.sha256 !== manifestInfo.sha256 || context.manifest?.size !== manifestInfo.size) {
        throw inputError(RELEASE_CODES.ASSET_INVALID, 'Staged manifest does not match build-context.json');
      }
      if (context.tag !== settings.tag || context.commit !== settings.commit) {
        throw inputError(RELEASE_CODES.ASSET_INVALID, 'build-context.json tag/commit does not match this stage');
      }
      tool = context.tool;
    } catch (error) {
      if (error instanceof ReleaseError) throw error;
      throw inputError(RELEASE_CODES.ASSET_INVALID, `Cannot read build-context.json: ${error.message}`);
    }
  } else {
    const projectDir = path.resolve(settings.project);
    tool = await computeToolIdentity({ projectDir, toolCommit: settings.toolCommit });
  }

  const descriptor = buildReleaseDescriptor({
    manifest,
    repository: { id: repositoryId, full_name: settings.repository },
    tag: settings.tag,
    commit: settings.commit,
    tool,
    packageAsset: { name: packageName, size: packageInfo.size, sha256: packageInfo.sha256 },
    manifestAsset: { name: MANIFEST_ASSET, size: manifestInfo.size, sha256: manifestInfo.sha256 },
    scanReportAsset: { name: SCAN_REPORT_ASSET, size: scanInfo.size, sha256: scanInfo.sha256 },
    generatedAt: options.generatedAt ?? new Date().toISOString(),
  });
  if (!bytes.length) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Staged manifest is empty');
  await writeFileAtomic(path.join(assetsDir, DESCRIPTOR_ASSET), jsonBytes(descriptor));
  const verified = await verifyAssetDirectory(assetsDir, {
    repositoryId,
    repositoryFullName: settings.repository,
    tag: settings.tag,
    commit: settings.commit,
  });
  return {
    ok: true,
    phase: 'assemble',
    descriptor: verified.descriptor,
    assets: [...verified.details.entries()].map(([name, info]) => ({ name, size: info.size, sha256: info.sha256 })),
  };
}

async function publish({ options, env }) {
  const settings = defaults(options, env);
  assertTag(settings.tag);
  assertCommit(settings.commit);
  const assetsDir = path.resolve(requireOption(options, 'assets'));
  const workDir = options.work
    ? path.resolve(options.work)
    : path.join(os.tmpdir(), `bepack-publish-${process.pid}`);
  await ensureDir(workDir);
  const result = await runPublish({
    assetsDir,
    workDir,
    repository: { id: assertRepositoryId(settings.repositoryId), full_name: settings.repository },
    tag: settings.tag,
    commit: settings.commit,
    token: env.GITHUB_TOKEN,
    apiBase: env.GITHUB_API_URL ?? 'https://api.github.com',
    uploadsBase: env.GITHUB_UPLOADS_URL,
    allowInsecureTestHosts: Boolean(options.allowTestHosts),
  });
  return {
    ok: true,
    phase: 'publish',
    status: result.status,
    release_id: result.release.id,
    release_url: result.release.html_url ?? null,
    tag: settings.tag,
    commit: settings.commit,
    draft: result.release.draft === true,
    assets: (await verifyAssetDirectory(assetsDir, {
      repositoryId: settings.repositoryId,
      repositoryFullName: settings.repository,
      tag: settings.tag,
      commit: settings.commit,
    })).descriptor.package,
  };
}

async function verifyAssets({ options, env }) {
  const settings = defaults(options, env);
  assertTag(settings.tag);
  assertCommit(settings.commit);
  const assetsDir = path.resolve(requireOption(options, 'assets'));
  const verified = await verifyAssetDirectory(assetsDir, {
    repositoryId: settings.repositoryId,
    repositoryFullName: settings.repository,
    tag: settings.tag,
    commit: settings.commit,
  });
  return {
    ok: true,
    phase: 'verify-assets',
    descriptor: verified.descriptor,
    assets: [...verified.details.entries()].map(([name, info]) => ({ name, size: info.size, sha256: info.sha256 })),
  };
}

async function notify({ options, env }) {
  const assetsDir = path.resolve(requireOption(options, 'assets'));
  const descriptor = await readJson(path.join(assetsDir, DESCRIPTOR_ASSET));
  const releaseId = requireOption(options, 'release-id');
  const url = env.BEPACK_REGISTRY_DISPATCH_URL;
  if (!url) {
    return {
      ok: true,
      phase: 'notify',
      status: 'skipped',
      reason: 'not-configured',
      message: 'Release published; registry indexing is pending official GitHub App/bridge configuration.',
    };
  }
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' && !(options.allowTestHosts && parsed.protocol === 'http:')) {
    throw externalError(RELEASE_CODES.NOTIFY_ERROR, 'Registry dispatch URL must use HTTPS');
  }
  const token = env.BEPACK_REGISTRY_DISPATCH_TOKEN;
  if (!token) throw externalError(RELEASE_CODES.NOTIFY_ERROR, 'BEPACK_REGISTRY_DISPATCH_TOKEN is required when a dispatch URL is configured');
  const payload = {
    event_type: 'pack-released',
    client_payload: {
      schema_version: 1,
      repository_id: descriptor.repository.id,
      release_id: String(releaseId),
      tag: descriptor.tag,
      delivery_id: options.deliveryId ?? `bepack-${descriptor.repository.id}-${descriptor.tag}-${descriptor.commit.slice(0, 12)}`,
    },
  };
  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw externalError(RELEASE_CODES.NOTIFY_ERROR, `Registry dispatch failed: ${error.message}`);
  }
  if (!response.ok) throw externalError(RELEASE_CODES.NOTIFY_ERROR, `Registry dispatch failed (${response.status})`);
  return { ok: true, phase: 'notify', status: 'dispatched', release_id: String(releaseId), tag: descriptor.tag };
}

const HANDLERS = { preflight, build, scan, assemble, publish, 'verify-assets': verifyAssets, notify };

export async function main(argv = process.argv.slice(2), { env = process.env, stdout = process.stdout, stderr = process.stderr } = {}) {
  try {
    const { command, options } = parseArguments(argv);
    if (command === 'help') {
      stdout.write(`${USAGE}\n`);
      return EXIT.OK;
    }
    if (options.help) {
      stdout.write(`${USAGE}\n`);
      return EXIT.OK;
    }
    const result = await HANDLERS[command]({ options, env });
    if (options.report) await writeFileAtomic(path.resolve(options.report), jsonBytes(result));
    stdout.write(`${JSON.stringify(result)}\n`);
    return EXIT.OK;
  } catch (error) {
    const phase = argv[0] ?? 'cli';
    stderr.write(`${JSON.stringify(errorPayload(error, phase))}\n`);
    return exitCodeOf(error);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().then(code => { process.exitCode = code; });
}
