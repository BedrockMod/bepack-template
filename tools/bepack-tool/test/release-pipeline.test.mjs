// Release pipeline tests. All services are local mocks: no GitHub or
// VirusTotal request is made, and no release/tag is created.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile, copyFile } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';

import {
  DESCRIPTOR_ASSET,
  MANIFEST_ASSET,
  SCAN_REPORT_ASSET,
  buildReleaseDescriptor,
  validateScanReport,
  verifyAssetDirectory,
} from '../src/release-assets.mjs';
import { runBuild, runToolBuild } from '../src/release-build.mjs';
import { hashFile, jsonBytes, listRegularFiles } from '../src/release-files.mjs';
import { runPublish } from '../src/release-publish.mjs';
import { runScan } from '../src/release-scan.mjs';
import { computeScanPlan } from '../src/scan-plan.mjs';
import { assertVtConfig, createVirusTotalClient, evaluateAnalysis } from '../src/virustotal.mjs';
import { writeZipArchive } from '../src/zip.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');
const COMMIT = 'b'.repeat(40);
const TAG = 'v1.2.3';

const MANIFEST = {
  schema_version: 1,
  id: 'example.test-pack',
  name: 'Test Pack',
  author: { name: 'Test Author' },
  description: 'Release fixture',
  version: '1.2.3',
  license: 'MIT',
  mode: 'mods-only',
  game_version: null,
  version_set: 'stable',
  targets: { windows: { enabled: true } },
  dependencies: [{
    id: 'sample.mod',
    source: 'github',
    resolver: 'fixture',
    version: '1.0.0',
    license: 'MIT',
    bundled: true,
    redistribution_confirmed: true,
    targets: ['windows-x86_64'],
    role: 'mod',
  }],
  contents: [],
};

const HELPER_BYTES = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(300, 0x90)]);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function utcNow() {
  return '2026-01-01T00:00:00.000Z';
}

async function temporaryDirectory(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'bepack-release-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function createPackage(destination, { externalUrl = null, manifest = MANIFEST, helper = HELPER_BYTES } = {}) {
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  const versionSet = Buffer.from(`${JSON.stringify({ schema_version: 1, id: manifest.version_set, dependencies: {}, targets: {} }, null, 2)}\n`);
  const data = Buffer.from('{"fixture":true}\n');
  const files = new Map([
    ['bepack.json', manifestBytes],
    [`versions/${manifest.version_set}.json`, versionSet],
    ['payload/tools/helper.exe', helper],
    ['payload/data/config.json', data],
  ]);
  const dependencies = manifest.dependencies ?? [];
  const bundled = dependencies.find(dependency => dependency.bundled === true);
  const artifacts = [];
  if (bundled) {
    artifacts.push({
      id: 'helper',
      dependency: bundled.id,
      version: bundled.version,
      format: 'file',
      size: helper.length,
      sha256: sha256(helper),
      path: 'payload/tools/helper.exe',
    });
  }
  if (externalUrl) {
    const external = dependencies.find(dependency => dependency.id === 'remote.mod');
    const bytes = Buffer.from('external executable fixture');
    artifacts.push({
      id: 'remote-artifact',
      dependency: external.id,
      version: external.version,
      format: 'file',
      size: bytes.length,
      sha256: sha256(bytes),
      url: externalUrl,
    });
  }
  const lock = {
    schema_version: 1,
    pack: { id: manifest.id, version: manifest.version, version_set: manifest.version_set },
    generated_at: utcNow(),
    files: [...files.entries()].map(([file, bytes]) => ({ path: file, size: bytes.length, sha256: sha256(bytes) })),
    artifacts,
    configurations: [manifest.version_set],
    evidence: [],
    compatibility: [],
    runtimes: ['bedrock-client'],
  };
  const entries = [...files.entries()].map(([file, bytes]) => ({ path: file, bytes }));
  entries.push({ path: 'bepack.lock.json', bytes: Buffer.from(`${JSON.stringify(lock, null, 2)}\n`) });
  await writeZipArchive(destination, entries);
  return { packageFile: destination, manifest, manifestBytes, packageInfo: await hashFile(destination) };
}

function fakeVt(overrides = {}) {
  return {
    async scanFile(file, { expectedSha256, expectedSize }) {
      const info = await hashFile(file);
      assert.equal(info.sha256, expectedSha256);
      assert.equal(info.size, expectedSize);
      return {
        analysis_id: `analysis-${info.sha256.slice(0, 12)}`,
        sha256: info.sha256,
        size: info.size,
        malicious: 0,
        suspicious: 0,
        harmless: 5,
        undetected: 1,
        analyzed_at: utcNow(),
        ...overrides,
      };
    },
  };
}

async function stagePackage(assetsDir, packageFile) {
  await mkdir(assetsDir, { recursive: true });
  const staged = path.join(assetsDir, path.basename(packageFile));
  await copyFile(packageFile, staged);
  return staged;
}

async function writeAssets(assetsDir, stagedPackage, manifestBytes, report) {
  await copyFile(stagedPackage, path.join(assetsDir, path.basename(stagedPackage)));
  await writeFile(path.join(assetsDir, MANIFEST_ASSET), manifestBytes);
  const scanBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
  await writeFile(path.join(assetsDir, SCAN_REPORT_ASSET), scanBytes);
  const packageInfo = await hashFile(path.join(assetsDir, path.basename(stagedPackage)));
  await writeFile(path.join(assetsDir, `${path.basename(stagedPackage)}.sha256`), `${packageInfo.sha256}  ${path.basename(stagedPackage)}\n`);
  return { packageInfo, scanInfo: { size: scanBytes.length, sha256: sha256(scanBytes) } };
}

async function makeCompleteAssets(t, { repository = { id: '123', full_name: 'owner/repo' } } = {}) {
  const root = await temporaryDirectory(t);
  const buildRoot = path.join(root, 'build');
  await mkdir(buildRoot, { recursive: true });
  const fixture = await createPackage(path.join(buildRoot, 'example.test-pack-1.2.3.bepack'));
  const assetsDir = path.join(root, 'assets');
  const workDir = path.join(root, 'work');
  const staged = await stagePackage(assetsDir, fixture.packageFile);
  const scan = await runScan({ assetsDir, workDir, vt: fakeVt(), tag: TAG });
  const { packageInfo, scanInfo } = await writeAssets(assetsDir, staged, fixture.manifestBytes, scan.report);
  const descriptor = buildReleaseDescriptor({
    manifest: fixture.manifest,
    repository,
    tag: TAG,
    commit: COMMIT,
    tool: { version: 'source-0123456789ab', sha256: sha256(Buffer.from('tool fixture')) },
    packageAsset: { name: path.basename(staged), size: packageInfo.size, sha256: packageInfo.sha256 },
    manifestAsset: { name: MANIFEST_ASSET, size: fixture.manifestBytes.length, sha256: sha256(fixture.manifestBytes) },
    scanReportAsset: { name: SCAN_REPORT_ASSET, size: scanInfo.size, sha256: scanInfo.sha256 },
    generatedAt: utcNow(),
  });
  await writeFile(path.join(assetsDir, DESCRIPTOR_ASSET), jsonBytes(descriptor));
  return { root, assetsDir, workDir, descriptor, fixture };
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

async function startGitHubMock(t, { repositoryId = 123, fullName = 'owner/repo', tag = TAG, commit = COMMIT } = {}) {
  const state = {
    release: null,
    assets: new Map(),
    nextAssetId: 1,
    uploads: 0,
  };
  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://127.0.0.1');
      const repositoryPath = `/repos/${fullName}`;
      const send = (status, body) => {
        response.writeHead(status, { 'content-type': 'application/json' });
        response.end(body === undefined ? '' : JSON.stringify(body));
      };
      if (request.method === 'GET' && url.pathname === repositoryPath) {
        return send(200, { id: repositoryId, full_name: fullName });
      }
      if (request.method === 'GET' && url.pathname === `${repositoryPath}/git/ref/tags/${tag}`) {
        return send(200, { ref: `refs/tags/${tag}`, object: { type: 'commit', sha: commit } });
      }
      if (request.method === 'GET' && url.pathname === `${repositoryPath}/commits/${commit}`) {
        return send(200, { sha: commit });
      }
      if (request.method === 'GET' && url.pathname === `${repositoryPath}/releases/tags/${tag}`) {
        return state.release ? send(200, publicRelease(state.release)) : send(404, { message: 'Not Found' });
      }
      if (request.method === 'POST' && url.pathname === `${repositoryPath}/releases`) {
        const body = JSON.parse((await readBody(request)).toString('utf8') || '{}');
        state.release = {
          id: 77,
          tag_name: body.tag_name,
          draft: true,
          html_url: 'https://example.invalid/release/77',
        };
        return send(201, publicRelease(state.release));
      }
      if (request.method === 'GET' && url.pathname === `${repositoryPath}/releases/77`) {
        return state.release ? send(200, publicRelease(state.release)) : send(404, { message: 'Not Found' });
      }
      if (request.method === 'PATCH' && url.pathname === `${repositoryPath}/releases/77`) {
        const body = JSON.parse((await readBody(request)).toString('utf8') || '{}');
        if (!state.release) return send(404, { message: 'Not Found' });
        if (body.draft !== undefined) state.release.draft = body.draft;
        return send(200, publicRelease(state.release));
      }
      if (request.method === 'GET' && url.pathname === `${repositoryPath}/releases/77/assets`) {
        return send(200, [...state.assets.values()].map(publicAsset));
      }
      if (request.method === 'POST' && url.pathname === `${repositoryPath}/releases/77/assets`) {
        const name = url.searchParams.get('name');
        const bytes = await readBody(request);
        if (state.assets.has(name)) return send(422, { message: 'Validation Failed: already_exists' });
        state.uploads += 1;
        const asset = {
          id: state.nextAssetId++,
          name,
          size: bytes.length,
          digest: `sha256:${sha256(bytes)}`,
          bytes,
        };
        state.assets.set(name, asset);
        return send(201, publicAsset(asset));
      }
      const assetMatch = /^\/repos\/[^/]+\/[^/]+\/releases\/assets\/(\d+)$/.exec(url.pathname);
      if (request.method === 'GET' && assetMatch) {
        const asset = [...state.assets.values()].find(item => item.id === Number(assetMatch[1]));
        if (!asset) return send(404, { message: 'Not Found' });
        response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(asset.bytes.length) });
        return response.end(asset.bytes);
      }
      return send(404, { message: `Unhandled mock route ${request.method} ${url.pathname}` });
    } catch (error) {
      response.writeHead(500, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ message: error.message }));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const address = server.address();
  return { server, state, apiBase: `http://127.0.0.1:${address.port}` };
}

function publicRelease(release) {
  return {
    id: release.id,
    tag_name: release.tag_name,
    draft: release.draft,
    html_url: release.html_url,
  };
}

function publicAsset(asset) {
  return {
    id: asset.id,
    name: asset.name,
    size: asset.size,
    digest: asset.digest,
    url: `/placeholder/${asset.id}`,
  };
}

test('scan plan names payload subjects once and a clean scan writes a strict report', async t => {
  const root = await temporaryDirectory(t);
  const packageFile = path.join(root, 'example.test-pack-1.2.3.bepack');
  await createPackage(packageFile);
  const { plan } = await computeScanPlan(packageFile, { packageName: path.basename(packageFile) });
  assert.deepEqual(plan.entries.map(entry => entry.subject), ['package', 'payload/tools/helper.exe']);
  assert.equal(plan.entries[1].source.path, 'payload/tools/helper.exe');

  const assetsDir = path.join(root, 'assets');
  const staged = await stagePackage(assetsDir, packageFile);
  const scanned = await runScan({ assetsDir, workDir: path.join(root, 'work'), vt: fakeVt(), tag: TAG });
  assert.equal(scanned.report.entries.length, 2);
  assert.equal(scanned.report.package_sha256, (await hashFile(staged)).sha256);
  const written = JSON.parse(await readFile(path.join(assetsDir, SCAN_REPORT_ASSET), 'utf8'));
  assert.deepEqual(written.entries.map(entry => entry.subject), ['package', 'payload/tools/helper.exe']);
  validateScanReport(written, { packageSha256: written.package_sha256 });
});

test('scan plan includes non-bundled executable dependencies that must be scanned', async t => {
  const root = await temporaryDirectory(t);
  const manifest = {
    ...MANIFEST,
    dependencies: [
      ...MANIFEST.dependencies,
      {
        id: 'remote.mod',
        source: 'github',
        resolver: 'fixture',
        version: '2.0.0',
        license: 'MIT',
        bundled: false,
        targets: ['windows-x86_64'],
        role: 'mod',
      },
    ],
  };
  const packageFile = path.join(root, 'example.test-pack-1.2.3.bepack');
  await createPackage(packageFile, { manifest, externalUrl: 'https://example.invalid/remote.zip' });
  const { plan } = await computeScanPlan(packageFile);
  assert.ok(plan.entries.some(entry => entry.subject === 'dependency/remote.mod/remote-artifact'));
});

test('VirusTotal gate fails closed without credentials, consent, or complete clean evidence', async () => {
  assert.throws(() => assertVtConfig({}), error => error.code === 'BEPACK_RELEASE_VT_CONFIG');
  assert.throws(() => assertVtConfig({ apiKey: 'x'.repeat(40), consent: 'false' }), error => error.code === 'BEPACK_RELEASE_VT_CONFIG');
  const attributes = {
    status: 'completed',
    date: 1_700_000_000,
    stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
    results: {},
  };
  assert.throws(() => evaluateAnalysis(attributes, { analysisId: 'a' }), error => error.code === 'BEPACK_RELEASE_SCAN_INCOMPLETE');
  assert.throws(
    () => evaluateAnalysis({ ...attributes, stats: { malicious: 1, suspicious: 0, harmless: 1, undetected: 0 } }, { analysisId: 'a' }),
    error => error.code === 'BEPACK_RELEASE_SCAN_DETECTED',
  );
});

test('a detected or incomplete scan never writes a successful report', async t => {
  const root = await temporaryDirectory(t);
  const packageFile = path.join(root, 'example.test-pack-1.2.3.bepack');
  await createPackage(packageFile);
  const assetsDir = path.join(root, 'assets');
  await stagePackage(assetsDir, packageFile);
  await assert.rejects(
    runScan({ assetsDir, workDir: path.join(root, 'work'), vt: fakeVt({ malicious: 1 }) }),
    error => error.code === 'BEPACK_RELEASE_SCAN_DETECTED',
  );
  const files = await listRegularFiles(assetsDir);
  assert.ok(!files.some(file => path.basename(file) === SCAN_REPORT_ASSET));
});

test('build invokes the frozen toolchain and rejects a tag/version mismatch', async t => {
  const root = await temporaryDirectory(t);
  const projectManifest = JSON.parse(await readFile(path.join(REPO_ROOT, 'bepack.json'), 'utf8'));
  const fixtureManifest = { ...projectManifest, dependencies: MANIFEST.dependencies };
  const assetsDir = path.join(root, 'assets');
  const workDir = path.join(root, 'work');
  let forwarded;
  const buildCommand = async options => {
    forwarded = options;
    const { buildDir } = options;
    await mkdir(buildDir, { recursive: true });
    await createPackage(path.join(buildDir, `${fixtureManifest.id}-${fixtureManifest.version}.bepack`), { manifest: fixtureManifest });
  };
  const context = await runBuild({
    projectDir: REPO_ROOT,
    assetsDir,
    workDir,
    tag: `v${fixtureManifest.version}`,
    commit: COMMIT,
    buildCommand,
    runtimeCatalog: 'fixture-catalog.json',
    runtimeCatalogSha256: 'a'.repeat(64),
    metadataDir: 'fixture-metadata',
    generatedAt: '2026-11-08T00:00:00Z',
  });
  assert.equal(forwarded.runtimeCatalogSha256, 'a'.repeat(64));
  assert.equal(forwarded.metadataDir, 'fixture-metadata');
  assert.equal(forwarded.generatedAt, '2026-11-08T00:00:00Z');
  assert.equal(context.tag, `v${fixtureManifest.version}`);
  const names = (await listRegularFiles(assetsDir)).map(file => path.basename(file)).sort();
  assert.deepEqual(names, [`${fixtureManifest.id}-${fixtureManifest.version}.bepack`, `${fixtureManifest.id}-${fixtureManifest.version}.bepack.sha256`, MANIFEST_ASSET].sort());

  await assert.rejects(
    runBuild({
      projectDir: REPO_ROOT,
      assetsDir: path.join(root, 'assets2'),
      workDir: path.join(root, 'work2'),
      tag: 'v9.9.9',
      commit: COMMIT,
      buildCommand,
    }),
    error => error.code === 'BEPACK_RELEASE_TAG_MISMATCH',
  );
});

test('publish creates a draft, verifies all five assets, then makes it public', async t => {
  const assets = await makeCompleteAssets(t);
  const verified = await verifyAssetDirectory(assets.assetsDir, {
    repositoryId: '123',
    repositoryFullName: 'owner/repo',
    tag: TAG,
    commit: COMMIT,
  });
  assert.equal(verified.descriptor.package.sha256, (await hashFile(path.join(assets.assetsDir, verified.descriptor.package.name))).sha256);

  const mock = await startGitHubMock(t);
  const result = await runPublish({
    assetsDir: assets.assetsDir,
    workDir: path.join(assets.root, 'publish-work'),
    repository: { id: '123', full_name: 'owner/repo' },
    tag: TAG,
    commit: COMMIT,
    token: 'test-token',
    apiBase: mock.apiBase,
    allowInsecureTestHosts: true,
  });
  assert.equal(result.status, 'published');
  assert.equal(mock.state.release.draft, false);
  assert.equal(mock.state.assets.size, 5);
  assert.equal(mock.state.uploads, 5);

  const again = await runPublish({
    assetsDir: assets.assetsDir,
    workDir: path.join(assets.root, 'publish-work-2'),
    repository: { id: '123', full_name: 'owner/repo' },
    tag: TAG,
    commit: COMMIT,
    token: 'test-token',
    apiBase: mock.apiBase,
    allowInsecureTestHosts: true,
  });
  assert.equal(again.status, 'already-published');

  mock.state.assets.get(MANIFEST_ASSET).digest = `sha256:${'0'.repeat(64)}`;
  await assert.rejects(
    runPublish({
      assetsDir: assets.assetsDir,
      workDir: path.join(assets.root, 'publish-work-3'),
      repository: { id: '123', full_name: 'owner/repo' },
      tag: TAG,
      commit: COMMIT,
      token: 'test-token',
      apiBase: mock.apiBase,
      allowInsecureTestHosts: true,
    }),
    error => error.code === 'BEPACK_RELEASE_IMMUTABLE',
  );
});

test('tampered release assets are rejected before any GitHub request', async t => {
  const assets = await makeCompleteAssets(t);
  const reportPath = path.join(assets.assetsDir, SCAN_REPORT_ASSET);
  const report = JSON.parse(await readFile(reportPath, 'utf8'));
  report.entries[0].malicious = 1;
  const reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
  await writeFile(reportPath, reportBytes);
  const descriptorPath = path.join(assets.assetsDir, DESCRIPTOR_ASSET);
  const descriptor = JSON.parse(await readFile(descriptorPath, 'utf8'));
  descriptor.scan_report.size = reportBytes.length;
  descriptor.scan_report.sha256 = sha256(reportBytes);
  await writeFile(descriptorPath, jsonBytes(descriptor));
  await assert.rejects(
    verifyAssetDirectory(assets.assetsDir, { repositoryId: '123', repositoryFullName: 'owner/repo', tag: TAG, commit: COMMIT }),
    error => error.code === 'BEPACK_RELEASE_SCAN_DETECTED',
  );
});

function runCli(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(REPO_ROOT, 'scripts/bepack-release.mjs'), ...args], {
      cwd: REPO_ROOT,
      env: { ...process.env, ...env },
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
}

test('notify reports a visible skipped state when no bridge is configured', async t => {
  const assets = await makeCompleteAssets(t);
  const result = await runCli(
    ['notify', '--assets', assets.assetsDir, '--release-id', '77'],
    { BEPACK_REGISTRY_DISPATCH_URL: '', BEPACK_REGISTRY_DISPATCH_TOKEN: '' },
  );
  assert.equal(result.code, 0, result.stderr);
  const payload = JSON.parse(result.stdout.trim());
  assert.equal(payload.status, 'skipped');
  assert.equal(payload.reason, 'not-configured');
  assert.match(payload.message, /official GitHub App\/bridge configuration/);
});


test('release adapter invokes the real frozen CLI and keeps output package-only', async t => {
  const root = await temporaryDirectory(t);
  const projectDir = path.join(root, 'project');
  for (const dir of ['versions', 'licenses', 'payload']) await mkdir(path.join(projectDir, dir), { recursive: true });
  const manifest = JSON.parse(await readFile(path.join(REPO_ROOT, 'bepack.json'), 'utf8'));
  await writeFile(path.join(projectDir, 'bepack.json'), jsonBytes(manifest));
  await writeFile(path.join(projectDir, 'versions/stable.json'), jsonBytes({ schema_version: 1, id: 'stable', dependencies: {}, targets: {} }));
  await writeFile(path.join(projectDir, 'licenses/pack-license.txt'), 'Synthetic fixture license only\n');
  // Explicitly synthetic catalog, never a production source of compatibility facts.
  const catalog = { schema_version: 1, id: 'fixture-only', provider: 'test.synthetic', retrieved_at: '2026-11-08T00:00:00Z', source: { url: 'https://example.invalid/fixture-source', sha256: 'e'.repeat(64) }, games: [{ version: '1.0.0', platform: 'windows-x86_64', runtime: 'bedrock-client', identity: 'synthetic-1.0.0', integrity: { kind: 'distribution-manifest', sha256: 'a'.repeat(64) }, loaders: [], clients: [] }] };
  const catalogBytes = jsonBytes(catalog);
  const runtimeCatalog = path.join(root, 'catalog.json');
  await writeFile(runtimeCatalog, catalogBytes);
  const buildDir = path.join(root, 'out');
  await runToolBuild({ projectDir, buildDir, runtimeCatalog, runtimeCatalogSha256: sha256(catalogBytes), generatedAt: '2026-11-08T00:00:00Z' });
  assert.deepEqual((await listRegularFiles(buildDir)).map(file => path.basename(file)), [`${manifest.id}-${manifest.version}.bepack`]);
});

test('runtime catalog requires an external raw-byte digest before any frozen build', async t => {
  const root = await temporaryDirectory(t);
  const catalog = path.join(root, 'catalog.json');
  await writeFile(catalog, '{}');
  for (const runtimeCatalogSha256 of [undefined, 'z'.repeat(64), '0'.repeat(64)]) {
    await assert.rejects(runToolBuild({ projectDir: REPO_ROOT, buildDir: path.join(root, 'build'), runtimeCatalog: catalog, runtimeCatalogSha256 }),
      error => error.code === 'BEPACK_RELEASE_BUILD_INPUT' && error.exitCode === 2);
  }
});

function vtFixtureClient({ digest, size, resultDigest = digest, itemType = 'file', status = 'completed', maxWaitMs = 10 } = {}) {
  let clock = 0;
  let calls = 0;
  const attributes = {
    status, date: 1_700_000_000,
    stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 1 },
    results: { fixture: { category: 'undetected' } },
  };
  const client = createVirusTotalClient({
    apiKey: 'fixture-key-not-real', pollIntervalMs: 5, maxWaitMs,
    now: () => clock, sleep: async ms => { clock += ms; },
    fetchImpl: async (url, init) => {
      calls++;
      if (init.method === 'POST') return Response.json({ data: { id: 'fixture-analysis', type: 'analysis' } });
      if (url.endsWith('/item')) return Response.json({ data: { type: itemType, id: resultDigest, attributes: { sha256: resultDigest, size } } });
      assert.match(url, /analyses\/fixture-analysis$/);
      return Response.json({ data: { id: 'fixture-analysis', type: 'analysis', attributes } });
    },
  });
  return { client, calls: () => calls };
}

test('VirusTotal client binds completed analysis to exact file hash and rejects replacement', async t => {
  const root = await temporaryDirectory(t);
  const file = path.join(root, 'file.bin');
  await writeFile(file, HELPER_BYTES);
  const digest = sha256(HELPER_BYTES);
  const good = vtFixtureClient({ digest, size: HELPER_BYTES.length });
  assert.equal((await good.client.scanFile(file)).sha256, digest);
  const replaced = vtFixtureClient({ digest, size: HELPER_BYTES.length, resultDigest: '0'.repeat(64) });
  await assert.rejects(replaced.client.scanFile(file), error => error.code === 'BEPACK_RELEASE_VT_ERROR');
  const missing = vtFixtureClient({ digest, size: HELPER_BYTES.length, resultDigest: null });
  await assert.rejects(missing.client.scanFile(file), error => error.code === 'BEPACK_RELEASE_VT_ERROR');
  const urlItem = vtFixtureClient({ digest, size: HELPER_BYTES.length, itemType: 'url' });
  await assert.rejects(urlItem.client.scanFile(file), error => error.code === 'BEPACK_RELEASE_VT_ERROR');
  const wrongSize = vtFixtureClient({ digest, size: HELPER_BYTES.length + 1 });
  await assert.rejects(wrongSize.client.scanFile(file), error => error.code === 'BEPACK_RELEASE_VT_ERROR');
});

test('VirusTotal queued analysis times out instead of passing empty evidence', async t => {
  const root = await temporaryDirectory(t);
  const file = path.join(root, 'file.bin');
  await writeFile(file, HELPER_BYTES);
  const fixture = vtFixtureClient({ digest: sha256(HELPER_BYTES), size: HELPER_BYTES.length, status: 'queued' });
  await assert.rejects(fixture.client.scanFile(file), error => error.code === 'BEPACK_RELEASE_SCAN_INCOMPLETE' && error.exitCode === 3);
  assert.ok(fixture.calls() >= 3);
});

test('malicious engine evidence cannot be hidden behind clean summary stats', () => {
  assert.throws(() => evaluateAnalysis({ status: 'completed', date: 1_700_000_000,
    stats: { malicious: 0, suspicious: 0, harmless: 1, undetected: 0 },
    results: { clean: { category: 'harmless' }, detected: { category: 'suspicious' } },
  }, { analysisId: 'fixture' }), error => error.code === 'BEPACK_RELEASE_SCAN_DETECTED');
});
