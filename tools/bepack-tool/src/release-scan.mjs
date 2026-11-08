// Scan stage: turn the scan plan into a strict VirusTotal report. Every planned
// subject must be uploaded (or matched by the same bytes), every analysis must
// complete, and the report is only written after the full plan is covered.

import path from 'node:path';
import { readFile } from 'node:fs/promises';

import { openPackage } from './release-package.mjs';
import { parseStrictJSON } from './strict-json.mjs';
import { computeScanPlanFromReader } from './scan-plan.mjs';
import {
  SCAN_POLICY,
  SCAN_REPORT_ASSET,
  assertManifestForRelease,
  assertTagVersion,
  validateScanReport,
  assertScanReportCoversPlan,
} from './release-assets.mjs';
import {
  ensureDir,
  hashFile,
  listRegularFiles,
  readJson,
  writeFileAtomic,
} from './release-files.mjs';
import { downloadToFile } from './release-download.mjs';
import { inputError, RELEASE_CODES } from './release-errors.mjs';

function findPackageAsset(files) {
  const packages = files.filter(file => file.endsWith('.bepack'));
  if (packages.length !== 1) throw inputError(RELEASE_CODES.ASSET_INVALID, `Release staging must contain exactly one .bepack, found ${packages.length}`);
  return packages[0];
}

export async function runScan({
  assetsDir,
  workDir,
  vt,
  tag,
  fetchImpl = globalThis.fetch,
  allowPrivateHosts = false,
  maxDependencyBytes = 8 * 1024 ** 3,
  now = () => new Date().toISOString(),
}) {
  if (!vt || typeof vt.scanFile !== 'function') throw inputError(RELEASE_CODES.VT_CONFIG, 'VirusTotal client is required');
  const files = await listRegularFiles(assetsDir);
  const packageFile = findPackageAsset(files);
  const packageInfo = await hashFile(packageFile);
  const reader = await openPackage(packageFile);
  const scanFiles = new Map();
  let plan;
  try {
    const manifestBytes = await reader.readEntry('bepack.json', { maxBytes: 4 * 1024 * 1024 });
    const manifest = parseStrictJSON(manifestBytes, { maxBytes: 4 * 1024 * 1024 });
    assertManifestForRelease(manifest);
    if (tag !== undefined) assertTagVersion(tag, manifest.version);
    if (path.basename(packageFile) !== `${manifest.id}-${manifest.version}.bepack`) {
      throw inputError(RELEASE_CODES.ASSET_INVALID, 'Package file name does not match manifest id/version');
    }
    const computed = await computeScanPlanFromReader(reader, { packageFile, packageName: path.basename(packageFile) });
    plan = computed.plan;
    if (!plan.entries.some(entry => entry.subject === 'package')) throw inputError(RELEASE_CODES.SCAN_PLAN_INVALID, 'Scan plan does not include the final package');

    const scanDir = path.join(workDir, 'scan');
    await ensureDir(scanDir);
    for (const planned of plan.entries) {
      if (planned.source?.kind === 'file') {
        scanFiles.set(planned.subject, packageFile);
      } else if (planned.source?.kind === 'package-entry') {
        const packagePath = planned.source.path;
        const destination = path.join(scanDir, 'payload', packagePath.slice('payload/'.length));
        await ensureDir(path.dirname(destination));
        const extracted = await reader.extractEntry(packagePath, destination);
        if (extracted.size !== planned.size || extracted.sha256 !== planned.sha256) {
          throw inputError(RELEASE_CODES.SCAN_PLAN_INVALID, `Extracted payload bytes do not match the scan plan: ${planned.subject}`);
        }
        scanFiles.set(planned.subject, destination);
      } else if (planned.source?.kind === 'url') {
        // Same bytes are scanned once. The first URL is authoritative because
        // the lock has already bound every artifact instance to one SHA-256.
        if ([...scanFiles.values()].some(file => file === path.join(scanDir, 'deps', `${planned.sha256}.bin`))) {
          scanFiles.set(planned.subject, path.join(scanDir, 'deps', `${planned.sha256}.bin`));
          continue;
        }
        const destination = path.join(scanDir, 'deps', `${planned.sha256}.bin`);
        await ensureDir(path.dirname(destination));
        await downloadToFile(planned.source.url, destination, {
          expectedSha256: planned.sha256,
          expectedSize: planned.size,
          maxBytes: maxDependencyBytes,
          fetchImpl,
          allowPrivateHosts,
        });
        scanFiles.set(planned.subject, destination);
      } else {
        throw inputError(RELEASE_CODES.SCAN_PLAN_INVALID, `Unsupported scan source for ${planned.subject}`);
      }
    }
  } finally {
    await reader.close();
  }

  const analyses = new Map();
  for (const planned of plan.entries) {
    const file = scanFiles.get(planned.subject);
    if (!file) throw inputError(RELEASE_CODES.SCAN_PLAN_INVALID, `No local file for ${planned.subject}`);
    let analysis = analyses.get(planned.sha256);
    if (!analysis) {
      analysis = await vt.scanFile(file, { expectedSha256: planned.sha256, expectedSize: planned.size });
      analyses.set(planned.sha256, analysis);
    }
    if (analysis.sha256 !== planned.sha256 || analysis.size !== planned.size) {
      throw inputError(RELEASE_CODES.SCAN_PLAN_INVALID, `VirusTotal result size/hash changed for ${planned.subject}`);
    }
  }

  const entries = plan.entries.map(planned => {
    const analysis = analyses.get(planned.sha256);
    return {
      subject: planned.subject,
      sha256: planned.sha256,
      size: planned.size,
      analysis_id: analysis.analysis_id,
      status: 'completed',
      malicious: analysis.malicious,
      suspicious: analysis.suspicious,
      harmless: analysis.harmless,
      undetected: analysis.undetected,
      analyzed_at: analysis.analyzed_at,
    };
  });
  const report = {
    schema_version: 1,
    policy: SCAN_POLICY,
    package_sha256: packageInfo.sha256,
    completed_at: now(),
    entries,
  };
  validateScanReport(report, { packageSha256: packageInfo.sha256 });
  await assertScanReportCoversPlan(report, packageFile);
  await writeFileAtomic(path.join(assetsDir, SCAN_REPORT_ASSET), `${JSON.stringify(report, null, 2)}\n`);
  await writeFileAtomic(path.join(workDir, 'scan-plan.json'), `${JSON.stringify(plan, null, 2)}\n`);
  return { report, plan, packageFile, packageInfo };
}

export async function readScanReport(assetsDir) {
  return readJson(path.join(assetsDir, SCAN_REPORT_ASSET), { maxBytes: 16 * 1024 * 1024 });
}

export async function assertReportFile(assetsDir) {
  const bytes = await readFile(path.join(assetsDir, SCAN_REPORT_ASSET));
  return JSON.parse(bytes.toString('utf8'));
}
