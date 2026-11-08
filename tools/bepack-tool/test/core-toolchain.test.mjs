import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { buildPackage } from '../src/build.mjs';
import { inspectPackage } from '../src/inspect.mjs';
import { verifyPackage } from '../src/verify.mjs';
import { resolveProject } from '../src/resolve.mjs';
import { openZip, writeZipArchive, readZipEntry } from '../src/zip.mjs';
import { computeScanPlan } from '../src/scan-plan.mjs';
import { fixture } from './helpers/core-fixtures.mjs';
test('frozen build, inspect/extract, verify, scan-plan and no-overwrite', async t => {
  const f = await fixture(t);
  const result = await buildPackage(f.options());
  assert.equal(result.valid, true);
  assert.equal(result.projection.configurations.length, 2);
  const extracted = path.join(f.root, 'extracted');
  const info = await inspectPackage({ package: result.package.file, extract: extracted });
  assert.equal(info.valid, true);
  assert.equal((await verifyPackage({ package: result.package.file })).valid, true);
  assert.equal((await computeScanPlan(result.package.file)).plan.entries[0].subject, 'package');
  await assert.rejects(buildPackage(f.options()), /overwrite/);
  await assert.rejects(inspectPackage({ package: result.package.file, extract: extracted }), /EEXIST/);
  const wrong = { ...f.options(), runtimeCatalogSha256: '0'.repeat(64) };
  await assert.rejects(buildPackage(wrong), /digest mismatch/);
});

test('content compatibility produces finite intersection and hidden executables scan', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.project, 'payload/masked.png'), Buffer.from('MZ-not-a-real-executable'));
  f.manifest.contents.push({ id: 'configuration', category: 'config', path: 'payload/masked.png', targets: ['windows-x86_64'], source: 'local', destination: 'test.cfg', compatibility: { targets: { 'windows-x86_64': { games: { versions: ['1.0.1'] }, loader: null, client: null, evidence: { kind: 'author', reference: 'bepack.json' } } } } });
  await f.save();
  const built = await buildPackage(f.options());
  assert.deepEqual(built.projection.configurations, [createHash('sha256').update(JSON.stringify(['configuration','windows-x86_64','1.0.1'])).digest('hex')]);
  const scan = await computeScanPlan(built.package.file);
  assert.ok(scan.plan.entries.some(entry => entry.subject === 'payload/masked.png' && entry.reason === 'magic:pe'));
  assert.equal((await verifyPackage({ package: built.package.file })).valid, true);
});

test('verify rejects changed payload digest without altering caller staging', async t => {
  const f = await fixture(t); const built = await buildPackage(f.options());
  const zip = await openZip(built.package.file); const entries=[];
  try { for (const entry of zip.entries) entries.push({ path: entry.path, bytes: entry.path === 'licenses/pack-license.txt' ? Buffer.from('modified') : await readZipEntry(zip,entry) }); } finally { await zip.close(); }
  const bad = path.join(f.root, 'tampered.bepack'); await writeZipArchive(bad,entries);
  const temporaryDirectory=path.join(f.root,'caller'); await mkdir(temporaryDirectory); await writeFile(path.join(temporaryDirectory,'keep'),'safe');
  const report=await verifyPackage({package:bad,temporaryDirectory}); assert.equal(report.valid,false); assert.ok(report.diagnostics.some(d=>d.code==='BEPACK_DIGEST_MISMATCH')); assert.equal(await readFile(path.join(temporaryDirectory,'keep'),'utf8'),'safe');
});

test('resolve is offline and deterministic for an empty version set', async t => {
  const f=await fixture(t); const resolved=await resolveProject({project:f.project}); assert.equal(resolved.valid,true); assert.deepEqual(resolved.dependencies,{});
  assert.deepEqual(JSON.parse(await readFile(path.join(f.project,'versions/stable.json'),'utf8')).dependencies,{});
});