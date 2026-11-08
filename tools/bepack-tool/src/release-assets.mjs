// Release asset contract: the five fixed assets of a published .bepack
// release and their cross-checks. Registry consumers re-download and re-hash
// every asset; this module is the author-side implementation of the same
// contract, not a signature or a trust root.

import path from 'node:path';
import { readFile } from 'node:fs/promises';

import { openPackage } from './release-package.mjs';
import { computeScanPlan } from './scan-plan.mjs';
import { parseStrictJSON } from './strict-json.mjs';
import {
  HEX_SHA256,
  UTC_RFC3339,
  assertRegularFile,
  hashFile,
  jsonBytes,
  listRegularFiles,
  readJson,
} from './release-files.mjs';
import { inputError, RELEASE_CODES } from './release-errors.mjs';

export const RELEASE_SCHEMA_VERSION = 1;
export const SCAN_POLICY = 'bepack-official-v1';
export const MANIFEST_ASSET = 'bepack.json';
export const DESCRIPTOR_ASSET = 'bepack-release.json';
export const SCAN_REPORT_ASSET = 'scan-report.json';

export const PACK_ID_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+$/;
export const PACK_VERSION_RE = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$/;
export const COMMIT_RE = /^[0-9a-f]{40}$/;
export const REPOSITORY_FULL_NAME_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function packageAssetName(packId, version) {
  return `${packId}-${version}.bepack`;
}

export function checksumAssetName(packId, version) {
  return `${packageAssetName(packId, version)}.sha256`;
}

export function isPrerelease(version) {
  return version.includes('-');
}

export function assertPackIdentity(id, version) {
  if (typeof id !== 'string' || !PACK_ID_RE.test(id) || id.length > 128) {
    throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Manifest id is not a valid pack id');
  }
  if (typeof version !== 'string' || !PACK_VERSION_RE.test(version)) {
    throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Manifest version is not a valid v1 pack version (no build metadata)');
  }
}

export function assertTagVersion(tag, version) {
  if (tag !== `v${version}`) {
    throw inputError(RELEASE_CODES.TAG_MISMATCH, `Tag ${tag} does not match manifest version ${version}`);
  }
}

export function assertManifestForRelease(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Manifest must be an object');
  }
  if (manifest.schema_version !== 1) throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Manifest schema_version must be 1');
  assertPackIdentity(manifest.id, manifest.version);
  if (typeof manifest.version_set !== 'string' || !manifest.version_set) throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Manifest version_set is required');
  if (typeof manifest.mode !== 'string' || !['full', 'modded', 'client', 'mods-only'].includes(manifest.mode)) {
    throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Manifest mode is invalid');
  }
  if (typeof manifest.name !== 'string' || !manifest.name.trim()) throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Manifest name is required');
  if (manifest.repository !== undefined) {
    if (typeof manifest.repository !== 'string' || !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(manifest.repository)) {
      throw inputError(RELEASE_CODES.MANIFEST_INVALID, 'Manifest repository must be an HTTPS GitHub repository URL');
    }
  }
}

function assertUtc(value, label) {
  if (typeof value !== 'string' || !UTC_RFC3339.test(value)) {
    throw inputError(RELEASE_CODES.ASSET_INVALID, `${label} must be a UTC RFC 3339 timestamp`);
  }
}

function assertSha(value, label) {
  if (typeof value !== 'string' || !HEX_SHA256.test(value)) throw inputError(RELEASE_CODES.ASSET_INVALID, `${label} must be a lowercase SHA-256`);
}

function assertSize(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw inputError(RELEASE_CODES.ASSET_INVALID, `${label} must be a non-negative integer`);
}

function assertAssetRef(value, name, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw inputError(RELEASE_CODES.ASSET_INVALID, `${label} must be an object`);
  if (value.name !== name) throw inputError(RELEASE_CODES.ASSET_INVALID, `${label}.name must be ${name}`);
  assertSize(value.size, `${label}.size`);
  assertSha(value.sha256, `${label}.sha256`);
}

export function buildReleaseDescriptor({
  manifest,
  repository,
  tag,
  commit,
  tool,
  packageAsset,
  manifestAsset,
  scanReportAsset,
  generatedAt,
}) {
  assertManifestForRelease(manifest);
  assertTagVersion(tag, manifest.version);
  if (!COMMIT_RE.test(commit ?? '')) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Release commit must be a full lowercase 40-hex OID');
  if (!repository || typeof repository.id !== 'string' || !/^[0-9]+$/.test(repository.id)) {
    throw inputError(RELEASE_CODES.ASSET_INVALID, 'Repository id must be a numeric string');
  }
  if (typeof repository.full_name !== 'string' || !REPOSITORY_FULL_NAME_RE.test(repository.full_name)) {
    throw inputError(RELEASE_CODES.ASSET_INVALID, 'Repository full_name must be owner/name');
  }
  if (!tool || typeof tool.version !== 'string' || !tool.version || !HEX_SHA256.test(tool.sha256 ?? '')) {
    throw inputError(RELEASE_CODES.ASSET_INVALID, 'Tool identity must contain version and sha256');
  }
  assertAssetRef(packageAsset, packageAssetName(manifest.id, manifest.version), 'package');
  assertAssetRef(manifestAsset, MANIFEST_ASSET, 'manifest');
  assertAssetRef(scanReportAsset, SCAN_REPORT_ASSET, 'scan_report');
  if (generatedAt !== undefined) assertUtc(generatedAt, 'generated_at');

  return {
    schema_version: RELEASE_SCHEMA_VERSION,
    pack_id: manifest.id,
    version: manifest.version,
    version_set: manifest.version_set,
    mode: manifest.mode,
    package_schema_version: manifest.schema_version,
    repository: { id: repository.id, full_name: repository.full_name },
    tag,
    commit,
    generated_at: generatedAt ?? new Date().toISOString(),
    tool: { version: tool.version, sha256: tool.sha256 },
    package: { name: packageAsset.name, size: packageAsset.size, sha256: packageAsset.sha256 },
    manifest: { name: manifestAsset.name, size: manifestAsset.size, sha256: manifestAsset.sha256 },
    scan_report: { name: scanReportAsset.name, size: scanReportAsset.size, sha256: scanReportAsset.sha256 },
  };
}

export function validateReleaseDescriptor(descriptor, { repositoryId, repositoryFullName, tag, commit } = {}) {
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor must be an object');
  if (descriptor.schema_version !== RELEASE_SCHEMA_VERSION) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor schema_version must be 1');
  if (typeof descriptor.pack_id !== 'string' || !PACK_ID_RE.test(descriptor.pack_id)) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor pack_id is invalid');
  if (typeof descriptor.version !== 'string' || !PACK_VERSION_RE.test(descriptor.version)) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor version is invalid');
  if (descriptor.tag !== `v${descriptor.version}`) throw inputError(RELEASE_CODES.TAG_MISMATCH, 'Descriptor tag does not match version');
  if (typeof descriptor.version_set !== 'string' || !descriptor.version_set) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor version_set is required');
  if (!['full', 'modded', 'client', 'mods-only'].includes(descriptor.mode)) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor mode is invalid');
  if (descriptor.package_schema_version !== 1) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor package_schema_version must be 1');
  if (!descriptor.repository || typeof descriptor.repository !== 'object') throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor repository is required');
  if (typeof descriptor.repository.id !== 'string' || !/^[0-9]+$/.test(descriptor.repository.id)) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor repository.id must be numeric');
  if (typeof descriptor.repository.full_name !== 'string' || !REPOSITORY_FULL_NAME_RE.test(descriptor.repository.full_name)) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor repository.full_name is invalid');
  if (!COMMIT_RE.test(descriptor.commit ?? '')) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor commit must be a full lowercase OID');
  assertUtc(descriptor.generated_at, 'Descriptor generated_at');
  if (!descriptor.tool || typeof descriptor.tool.version !== 'string' || !descriptor.tool.version) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor tool.version is required');
  assertSha(descriptor.tool.sha256, 'Descriptor tool.sha256');
  assertAssetRef(descriptor.package, packageAssetName(descriptor.pack_id, descriptor.version), 'Descriptor package');
  assertAssetRef(descriptor.manifest, MANIFEST_ASSET, 'Descriptor manifest');
  assertAssetRef(descriptor.scan_report, SCAN_REPORT_ASSET, 'Descriptor scan_report');

  if (repositoryId !== undefined && descriptor.repository.id !== repositoryId) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor repository id does not match the expected repository');
  if (repositoryFullName !== undefined && descriptor.repository.full_name !== repositoryFullName) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Descriptor repository full_name does not match the expected repository');
  if (tag !== undefined && descriptor.tag !== tag) throw inputError(RELEASE_CODES.TAG_MISMATCH, 'Descriptor tag does not match the expected tag');
  if (commit !== undefined && descriptor.commit !== commit) throw inputError(RELEASE_CODES.IMMUTABLE, 'Descriptor commit does not match the tag commit');
  return descriptor;
}

export function validateScanReport(report, { packageSha256 } = {}) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, 'Scan report must be an object');
  if (report.schema_version !== 1) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, 'Scan report schema_version must be 1');
  if (report.policy !== SCAN_POLICY) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, `Scan report policy must be ${SCAN_POLICY}`);
  assertSha(report.package_sha256, 'Scan report package_sha256');
  if (packageSha256 !== undefined && report.package_sha256 !== packageSha256) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, 'Scan report package_sha256 does not match the package');
  assertUtc(report.completed_at, 'Scan report completed_at');
  if (!Array.isArray(report.entries) || report.entries.length === 0) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, 'Scan report entries must be a non-empty array');
  const subjects = new Set();
  const hashes = new Map();
  let executableEvidence = 0;
  for (const entry of report.entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, 'Scan report entry must be an object');
    if (typeof entry.subject !== 'string' || !/^(?:package|payload\/[^/]|dependency\/[^/]+\/[^/]+)/.test(entry.subject)) {
      throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, `Invalid scan subject: ${entry.subject}`);
    }
    if (subjects.has(entry.subject)) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, `Duplicate scan subject: ${entry.subject}`);
    subjects.add(entry.subject);
    assertSha(entry.sha256, `Scan entry ${entry.subject}.sha256`);
    assertSize(entry.size, `Scan entry ${entry.subject}.size`);
    if (typeof entry.analysis_id !== 'string' || !entry.analysis_id) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, `Scan entry ${entry.subject}.analysis_id is required`);
    if (entry.status !== 'completed') throw inputError(RELEASE_CODES.SCAN_INCOMPLETE, `Scan entry ${entry.subject} is not completed`);
    if (entry.malicious !== 0 || entry.suspicious !== 0) throw inputError(RELEASE_CODES.SCAN_DETECTED, `Scan entry ${entry.subject} has malicious/suspicious detections`);
    assertSize(entry.harmless, `Scan entry ${entry.subject}.harmless`);
    assertSize(entry.undetected, `Scan entry ${entry.subject}.undetected`);
    if (entry.harmless + entry.undetected < 1) throw inputError(RELEASE_CODES.SCAN_INCOMPLETE, `Scan entry ${entry.subject} has no harmless/undetected engine evidence`);
    assertUtc(entry.analyzed_at, `Scan entry ${entry.subject}.analyzed_at`);
    executableEvidence += 1;
    const previous = hashes.get(entry.sha256);
    if (previous && previous !== entry.size) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, `Scan entry ${entry.subject} has a conflicting size for its SHA-256`);
    hashes.set(entry.sha256, entry.size);
  }
  if (!subjects.has('package')) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, 'Scan report must cover the final package');
  const packageEntry = report.entries.find(entry => entry.subject === 'package');
  if (packageEntry.sha256 !== report.package_sha256) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, 'Scan report package entry hash does not match package_sha256');
  const sorted = [...report.entries].sort((a, b) => Buffer.compare(Buffer.from(a.subject), Buffer.from(b.subject)));
  for (let index = 0; index < sorted.length; index++) {
    if (sorted[index].subject !== report.entries[index].subject) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, 'Scan report entries must be sorted by subject bytes');
  }
  return { subjects, hashes, executableEvidence };
}

export async function assertScanReportCoversPlan(report, packageFile) {
  const { plan } = await computeScanPlan(packageFile);
  const reportBySubject = new Map(report.entries.map(entry => [entry.subject, entry]));
  for (const planned of plan.entries) {
    const found = reportBySubject.get(planned.subject);
    if (!found) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, `Scan report does not cover ${planned.subject}`);
    if (found.sha256 !== planned.sha256) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, `Scan report hash mismatch for ${planned.subject}`);
    if (found.size !== planned.size) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, `Scan report size mismatch for ${planned.subject}`);
  }
  const plannedSubjects = new Set(plan.entries.map(entry => entry.subject));
  for (const entry of report.entries) {
    if (!plannedSubjects.has(entry.subject)) throw inputError(RELEASE_CODES.SCAN_REPORT_INVALID, `Scan report contains an unplanned subject: ${entry.subject}`);
  }
  return plan;
}

function exactAssetSet(descriptor) {
  return new Set([
    descriptor.package.name,
    `${descriptor.package.name}.sha256`,
    MANIFEST_ASSET,
    DESCRIPTOR_ASSET,
    SCAN_REPORT_ASSET,
  ]);
}

export async function verifyAssetDirectory(assetsDir, { repositoryId, repositoryFullName, tag, commit } = {}) {
  const descriptorPath = path.join(assetsDir, DESCRIPTOR_ASSET);
  await assertRegularFile(descriptorPath, { label: DESCRIPTOR_ASSET });
  const descriptorBytes = await readFile(descriptorPath);
  let descriptor;
  try {
    descriptor = parseStrictJSON(descriptorBytes, { maxBytes: 4 * 1024 * 1024 });
  } catch (error) {
    throw inputError(RELEASE_CODES.ASSET_INVALID, `Cannot read ${DESCRIPTOR_ASSET}: ${error.message}`);
  }
  validateReleaseDescriptor(descriptor, { repositoryId, repositoryFullName, tag, commit });
  const expected = exactAssetSet(descriptor);
  const files = await listRegularFiles(assetsDir);
  const names = files.map(file => path.basename(file));
  if (names.length !== expected.size) throw inputError(RELEASE_CODES.ASSET_INVALID, `Release must contain exactly ${expected.size} assets, found ${names.length}`);
  for (const name of names) if (!expected.has(name)) throw inputError(RELEASE_CODES.ASSET_INVALID, `Unexpected release asset: ${name}`);
  for (const name of expected) if (!names.includes(name)) throw inputError(RELEASE_CODES.ASSET_INVALID, `Missing release asset: ${name}`);

  const details = new Map();
  for (const name of names) details.set(name, await hashFile(path.join(assetsDir, name)));
  const packageInfo = details.get(descriptor.package.name);
  if (packageInfo.size !== descriptor.package.size || packageInfo.sha256 !== descriptor.package.sha256) {
    throw inputError(RELEASE_CODES.ASSET_INVALID, 'Package asset size/hash does not match the descriptor');
  }
  const manifestInfo = details.get(MANIFEST_ASSET);
  if (manifestInfo.size !== descriptor.manifest.size || manifestInfo.sha256 !== descriptor.manifest.sha256) {
    throw inputError(RELEASE_CODES.ASSET_INVALID, 'Manifest asset size/hash does not match the descriptor');
  }
  const scanInfo = details.get(SCAN_REPORT_ASSET);
  if (scanInfo.size !== descriptor.scan_report.size || scanInfo.sha256 !== descriptor.scan_report.sha256) {
    throw inputError(RELEASE_CODES.ASSET_INVALID, 'Scan report size/hash does not match the descriptor');
  }

  const checksum = await readFile(path.join(assetsDir, `${descriptor.package.name}.sha256`));
  const expectedChecksum = `${descriptor.package.sha256}  ${descriptor.package.name}\n`;
  if (checksum.toString('utf8') !== expectedChecksum) throw inputError(RELEASE_CODES.ASSET_INVALID, 'Checksum asset must be one lowercase hash, two spaces, file name, LF');

  const packageFile = path.join(assetsDir, descriptor.package.name);
  const reader = await openPackage(packageFile);
  try {
    const manifestBytes = await reader.readEntry(MANIFEST_ASSET, { maxBytes: 4 * 1024 * 1024 });
    if (!manifestBytes.equals(await readFile(path.join(assetsDir, MANIFEST_ASSET)))) {
      throw inputError(RELEASE_CODES.ASSET_INVALID, 'Manifest asset bytes differ from the package manifest');
    }
    let packageManifest;
    try {
      packageManifest = parseStrictJSON(manifestBytes, { maxBytes: 4 * 1024 * 1024 });
    } catch (error) {
      throw inputError(RELEASE_CODES.MANIFEST_INVALID, `Cannot read package manifest: ${error.message}`);
    }
    assertManifestForRelease(packageManifest);
    if (packageManifest.id !== descriptor.pack_id || packageManifest.version !== descriptor.version) {
      throw inputError(RELEASE_CODES.ASSET_INVALID, 'Package manifest identity does not match the descriptor');
    }
    if (packageManifest.mode !== descriptor.mode || packageManifest.version_set !== descriptor.version_set) {
      throw inputError(RELEASE_CODES.ASSET_INVALID, 'Package manifest mode/version_set does not match the descriptor');
    }
    assertTagVersion(descriptor.tag, packageManifest.version);
    if (!reader.has('bepack.lock.json')) throw inputError(RELEASE_CODES.CONTAINER_INVALID, 'Package is missing bepack.lock.json');
  } finally {
    await reader.close();
  }

  const report = await readJson(path.join(assetsDir, SCAN_REPORT_ASSET), { maxBytes: 16 * 1024 * 1024 });
  validateScanReport(report, { packageSha256: descriptor.package.sha256 });
  await assertScanReportCoversPlan(report, packageFile);
  return { descriptor, details, report };
}
