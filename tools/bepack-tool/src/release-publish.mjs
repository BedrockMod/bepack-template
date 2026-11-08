// Publish stage: create or resume a draft release, upload the five fixed
// assets, verify every uploaded byte, then make the release public. A release
// is only reported successful after a post-publish re-read. A draft that fails
// stays private; a release this process made public is rolled back to draft if
// final verification fails.

import { rm } from 'node:fs/promises';
import path from 'node:path';

import {
  DESCRIPTOR_ASSET,
  MANIFEST_ASSET,
  SCAN_REPORT_ASSET,
  isPrerelease,
  verifyAssetDirectory,
} from './release-assets.mjs';
import { hashFile, ensureDir } from './release-files.mjs';
import { createGitHubClient } from './release-github.mjs';
import { inputError, externalError, RELEASE_CODES } from './release-errors.mjs';

function expectedAssets(descriptor, assetsDir) {
  return new Map([
    [descriptor.package.name, path.join(assetsDir, descriptor.package.name)],
    [`${descriptor.package.name}.sha256`, path.join(assetsDir, `${descriptor.package.name}.sha256`)],
    [MANIFEST_ASSET, path.join(assetsDir, MANIFEST_ASSET)],
    [DESCRIPTOR_ASSET, path.join(assetsDir, DESCRIPTOR_ASSET)],
    [SCAN_REPORT_ASSET, path.join(assetsDir, SCAN_REPORT_ASSET)],
  ]);
}

function digestOf(asset) {
  if (typeof asset?.digest !== 'string') return null;
  const match = /^sha256:([0-9a-f]{64})$/.exec(asset.digest);
  return match ? match[1] : null;
}

async function matchesRemote(client, asset, local, workDir) {
  if (!Number.isSafeInteger(asset.size) || asset.size !== local.size) {
    throw inputError(RELEASE_CODES.IMMUTABLE, `Existing asset ${asset.name} has a different size`);
  }
  const digest = digestOf(asset);
  if (digest) {
    if (digest !== local.sha256) throw inputError(RELEASE_CODES.IMMUTABLE, `Existing asset ${asset.name} has a different SHA-256`);
    return;
  }
  const destination = path.join(workDir, `remote-${asset.id ?? asset.name}.bin`);
  await ensureDir(workDir);
  const actual = await client.downloadAsset(asset, destination);
  await rm(destination, { force: true });
  if (actual.size !== local.size || actual.sha256 !== local.sha256) {
    throw inputError(RELEASE_CODES.IMMUTABLE, `Existing asset ${asset.name} bytes differ from this build`);
  }
}

async function inspectRemote(client, fullName, releaseId, expected, workDir, { requireAll }) {
  const assets = await client.listReleaseAssets(fullName, releaseId);
  const byName = new Map();
  for (const asset of assets) {
    if (byName.has(asset.name)) throw inputError(RELEASE_CODES.IMMUTABLE, `Release contains duplicate asset name ${asset.name}`);
    byName.set(asset.name, asset);
  }
  for (const name of byName.keys()) {
    if (!expected.has(name)) throw inputError(RELEASE_CODES.IMMUTABLE, `Release contains an unexpected asset: ${name}`);
  }
  const missing = [];
  for (const [name, file] of expected) {
    const asset = byName.get(name);
    if (!asset) { missing.push(name); continue; }
    const local = await hashFile(file);
    await matchesRemote(client, asset, local, workDir);
  }
  if (requireAll && missing.length) throw inputError(RELEASE_CODES.PUBLISH_VERIFY, `Release is missing assets: ${missing.join(', ')}`);
  return { assets, byName, missing };
}

function releaseBody(descriptor) {
  return [
    `Bepack package: ${descriptor.pack_id} ${descriptor.version}`,
    `Tag: ${descriptor.tag}`,
    `Commit: ${descriptor.commit}`,
    `Scan policy: ${descriptor.scan_report.name} (VirusTotal). This report is evidence of a completed scan, not a guarantee that the package is free of malware.`,
    '',
    'Published assets are immutable for this tag. Verify the package with the Bepack verification tool before installation.',
  ].join('\n');
}

export async function runPublish({
  assetsDir,
  workDir,
  repository,
  tag,
  commit,
  token,
  apiBase = process.env.GITHUB_API_URL ?? 'https://api.github.com',
  uploadsBase = process.env.GITHUB_UPLOADS_URL,
  fetchImpl = globalThis.fetch,
  allowInsecureTestHosts = false,
}) {
  if (typeof token !== 'string' || token.trim() === '') {
    throw externalError(RELEASE_CODES.GITHUB_CONFIG, 'GITHUB_TOKEN is required for publishing');
  }
  const verified = await verifyAssetDirectory(assetsDir, {
    repositoryId: repository.id,
    repositoryFullName: repository.full_name,
    tag,
    commit,
  });
  const { descriptor } = verified;
  const expected = expectedAssets(descriptor, assetsDir);
  const client = createGitHubClient({ token, apiBase, uploadsBase, fetchImpl, allowInsecureTestHosts });

  const repo = await client.getRepository(repository.full_name);
  if (String(repo.id) !== String(repository.id)) throw inputError(RELEASE_CODES.GITHUB_CONFIG, 'Repository id does not match the API response');
  if (repo.full_name !== repository.full_name) throw inputError(RELEASE_CODES.GITHUB_CONFIG, 'Repository full_name does not match the API response');
  const tagCommit = await client.resolveTagCommit(repository.full_name, tag);
  if (tagCommit !== commit) throw inputError(RELEASE_CODES.IMMUTABLE, `Tag ${tag} points at ${tagCommit}, not ${commit}`);
  await client.getCommit(repository.full_name, commit);

  let release = await client.getReleaseByTag(repository.full_name, tag);
  let createdDraft = false;
  if (!release) {
    try {
      release = await client.createRelease(repository.full_name, {
        tag,
        commit,
        name: `${descriptor.pack_id} ${descriptor.version}`,
        body: releaseBody(descriptor),
        prerelease: isPrerelease(descriptor.version),
      });
      createdDraft = true;
    } catch (error) {
      // A concurrent run may have created the release between the lookup and
      // the POST. Re-read once; never create a second release for one tag.
      release = await client.getReleaseByTag(repository.full_name, tag);
      if (!release) throw error;
    }
    if (!release?.id) throw externalError(RELEASE_CODES.GITHUB_ERROR, 'GitHub did not return a draft release');
  }

  if (release.tag_name !== tag) throw inputError(RELEASE_CODES.IMMUTABLE, `Existing release uses tag ${release.tag_name}, not ${tag}`);
  if (release.draft === false) {
    if (createdDraft) throw externalError(RELEASE_CODES.GITHUB_ERROR, 'Newly created release is unexpectedly public');
    await inspectRemote(client, repository.full_name, release.id, expected, workDir, { requireAll: true });
    return { status: 'already-published', release, descriptor };
  }

  // Draft path: resume only when existing bytes are identical; missing assets
  // are filled in, unexpected or changed assets abort without deleting them.
  let remote = await inspectRemote(client, repository.full_name, release.id, expected, workDir, { requireAll: false });
  for (const [name, file] of expected) {
    if (remote.byName.has(name)) continue;
    const info = await hashFile(file);
    const uploaded = await client.uploadReleaseAsset(repository.full_name, release.id, file, name);
    if (uploaded.size !== undefined && uploaded.size !== info.size) {
      throw inputError(RELEASE_CODES.PUBLISH_VERIFY, `Uploaded asset ${name} reported a different size`);
    }
    const uploadedDigest = digestOf(uploaded);
    if (uploadedDigest && uploadedDigest !== info.sha256) {
      throw inputError(RELEASE_CODES.PUBLISH_VERIFY, `Uploaded asset ${name} reported a different SHA-256`);
    }
  }
  remote = await inspectRemote(client, repository.full_name, release.id, expected, workDir, { requireAll: true });
  if (remote.assets.length !== expected.size) throw inputError(RELEASE_CODES.PUBLISH_VERIFY, 'Release does not contain exactly the five fixed assets');

  let madePublic = false;
  try {
    // Re-check immediately before exposing the release: a force-pushed tag
    // between preflight and this point must never publish bytes for an older
    // commit under the new tag.
    const beforePublishCommit = await client.resolveTagCommit(repository.full_name, tag);
    if (beforePublishCommit !== commit) throw inputError(RELEASE_CODES.IMMUTABLE, `Tag ${tag} moved to ${beforePublishCommit} before publication`);
    const updated = await client.updateRelease(repository.full_name, release.id, { draft: false });
    if (!updated || updated.draft !== false) throw externalError(RELEASE_CODES.PUBLISH_VERIFY, 'GitHub did not make the release public');
    madePublic = true;
    const finalRelease = await client.getRelease(repository.full_name, release.id);
    if (!finalRelease || finalRelease.draft !== false || finalRelease.tag_name !== tag) {
      throw externalError(RELEASE_CODES.PUBLISH_VERIFY, 'Published release does not match the expected tag/state');
    }
    const afterPublishCommit = await client.resolveTagCommit(repository.full_name, tag);
    if (afterPublishCommit !== commit) throw inputError(RELEASE_CODES.IMMUTABLE, `Tag ${tag} moved to ${afterPublishCommit} during publication`);
    await inspectRemote(client, repository.full_name, release.id, expected, workDir, { requireAll: true });
    return { status: 'published', release: finalRelease, descriptor };
  } catch (error) {
    if (madePublic) {
      try {
        await client.updateRelease(repository.full_name, release.id, { draft: true });
      } catch (rollbackError) {
        throw externalError(
          RELEASE_CODES.PUBLISH_VERIFY,
          `Release ${release.id} was made public but final verification failed and rollback to draft also failed: ${rollbackError.message}`,
        );
      }
    }
    throw error;
  }
}
