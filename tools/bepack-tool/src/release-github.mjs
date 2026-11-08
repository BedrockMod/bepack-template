// Minimal GitHub REST client used by the release pipeline. It deliberately
// implements only the endpoints needed for tag verification, draft release
// management, asset upload and post-upload verification. Every operation is
// bound to a repository, tag and commit supplied by the workflow; nothing here
// guesses or derives a release identity.

import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, open, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

import { externalError, RELEASE_CODES } from './release-errors.mjs';

const API_VERSION = '2022-11-28';
const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 300_000;
const MAX_REDIRECTS = 5;

function ensureToken(token) {
  if (typeof token !== 'string' || token.trim().length === 0) {
    throw externalError(RELEASE_CODES.GITHUB_CONFIG, 'GITHUB_TOKEN is required for release publishing');
  }
  return token.trim();
}

function assertRepository(fullName) {
  if (typeof fullName !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(fullName)) {
    throw externalError(RELEASE_CODES.GITHUB_CONFIG, 'Repository must be owner/name');
  }
  return fullName;
}

function assertSha(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) {
    throw externalError(RELEASE_CODES.GITHUB_CONFIG, `${label} must be a full lowercase commit SHA`);
  }
  return value;
}

export function createGitHubClient({
  token,
  apiBase = 'https://api.github.com',
  uploadsBase,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  downloadTimeoutMs = DEFAULT_DOWNLOAD_TIMEOUT_MS,
  maxAssetBytes = 8 * 1024 ** 3,
  allowInsecureTestHosts = false,
} = {}) {
  const apiRoot = apiBase.replace(/\/+$/, '');
  const apiOrigin = new URL(apiRoot).origin;
  const uploadRoot = (uploadsBase ?? (apiOrigin === 'https://api.github.com' ? 'https://uploads.github.com' : apiOrigin)).replace(/\/+$/, '');
  const uploadOrigin = new URL(uploadRoot).origin;
  const authHeader = token ? { authorization: `Bearer ${ensureToken(token)}` } : {};

  function assertTransport(url) {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && !(allowInsecureTestHosts && parsed.protocol === 'http:')) {
      throw externalError(RELEASE_CODES.GITHUB_CONFIG, 'GitHub API URL must use HTTPS');
    }
  }

  function urlFor(pathOrUrl) {
    const url = /^https?:\/\//i.test(pathOrUrl) ? pathOrUrl : `${apiRoot}${pathOrUrl.startsWith('/') ? '' : '/'}${pathOrUrl}`;
    assertTransport(url);
    return url;
  }

  async function request(method, pathOrUrl, { body, headers = {}, allow404 = false, raw = false, timeout = timeoutMs } = {}) {
    const url = urlFor(pathOrUrl);
    let response;
    try {
      response = await fetchImpl(url, {
        method,
        headers: {
          accept: 'application/vnd.github+json',
          'x-github-api-version': API_VERSION,
          'user-agent': 'bepack-release/1',
          ...authHeader,
          ...headers,
        },
        body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
        signal: AbortSignal.timeout(timeout),
        redirect: 'follow',
        ...(raw ? { duplex: 'half' } : {}),
      });
    } catch (error) {
      throw externalError(RELEASE_CODES.GITHUB_ERROR, `GitHub request failed: ${error.message}`);
    }
    const text = await response.text().catch(() => '');
    let parsed = null;
    if (text) {
      try { parsed = JSON.parse(text); } catch { parsed = null; }
    }
    if (allow404 && response.status === 404) return null;
    if (!response.ok) {
      const detail = parsed?.message ?? response.statusText;
      throw externalError(RELEASE_CODES.GITHUB_ERROR, `GitHub ${method} ${new URL(url).pathname} failed (${response.status}): ${detail}`);
    }
    return parsed;
  }

  async function getRepository(fullName) {
    return request('GET', `/repos/${assertRepository(fullName)}`);
  }

  async function getCommit(fullName, sha) {
    return request('GET', `/repos/${assertRepository(fullName)}/commits/${assertSha(sha, 'Commit')}`);
  }

  async function resolveTagCommit(fullName, tag) {
    if (typeof tag !== 'string' || !tag.startsWith('v')) throw externalError(RELEASE_CODES.GITHUB_CONFIG, 'Release tag must start with v');
    const repo = assertRepository(fullName);
    const ref = await request('GET', `/repos/${repo}/git/ref/tags/${encodeURIComponent(tag)}`, { allow404: true });
    if (!ref) throw externalError(RELEASE_CODES.GITHUB_ERROR, `Tag ${tag} does not exist in ${repo}`);
    if (ref.ref !== `refs/tags/${tag}`) throw externalError(RELEASE_CODES.GITHUB_ERROR, `GitHub returned an unexpected ref for ${tag}`);
    let type = ref.object?.type;
    let sha = ref.object?.sha;
    for (let depth = 0; depth < 5; depth++) {
      if (type === 'commit') return sha;
      if (type !== 'tag') throw externalError(RELEASE_CODES.GITHUB_ERROR, `Tag ${tag} points at unsupported object type ${type}`);
      const tagged = await request('GET', `/repos/${repo}/git/tags/${sha}`);
      type = tagged.object?.type;
      sha = tagged.object?.sha;
    }
    throw externalError(RELEASE_CODES.GITHUB_ERROR, `Tag ${tag} has too many nested tag objects`);
  }

  async function getReleaseByTag(fullName, tag) {
    return request('GET', `/repos/${assertRepository(fullName)}/releases/tags/${encodeURIComponent(tag)}`, { allow404: true });
  }

  async function getRelease(fullName, releaseId) {
    return request('GET', `/repos/${assertRepository(fullName)}/releases/${releaseId}`, { allow404: true });
  }

  async function createRelease(fullName, { tag, commit, name, body, prerelease }) {
    assertSha(commit, 'Release commit');
    return request('POST', `/repos/${assertRepository(fullName)}/releases`, {
      body: {
        tag_name: tag,
        target_commitish: commit,
        name,
        body,
        draft: true,
        prerelease: Boolean(prerelease),
      },
    });
  }

  async function updateRelease(fullName, releaseId, changes) {
    return request('PATCH', `/repos/${assertRepository(fullName)}/releases/${releaseId}`, { body: changes });
  }

  async function listReleaseAssets(fullName, releaseId) {
    const assets = [];
    for (let page = 1; page <= 100; page++) {
      const batch = await request('GET', `/repos/${assertRepository(fullName)}/releases/${releaseId}/assets?per_page=100&page=${page}`);
      if (!Array.isArray(batch) || batch.length === 0) break;
      assets.push(...batch);
      if (batch.length < 100) break;
    }
    return assets;
  }

  async function uploadReleaseAsset(fullName, releaseId, file, name) {
    const info = await stat(file);
    if (!info.isFile() || info.size < 0) throw externalError(RELEASE_CODES.GITHUB_ERROR, `Cannot upload ${name}: not a regular file`);
    const url = `${uploadRoot}/repos/${assertRepository(fullName)}/releases/${releaseId}/assets?name=${encodeURIComponent(name)}`;
    assertTransport(url);
    let response;
    try {
      response = await fetchImpl(url, {
        method: 'POST',
        headers: {
          ...authHeader,
          accept: 'application/vnd.github+json',
          'content-type': 'application/octet-stream',
          'content-length': String(info.size),
          'user-agent': 'bepack-release/1',
        },
        body: createReadStream(file),
        signal: AbortSignal.timeout(downloadTimeoutMs),
        duplex: 'half',
      });
    } catch (error) {
      throw externalError(RELEASE_CODES.GITHUB_ERROR, `GitHub asset upload failed for ${name}: ${error.message}`);
    }
    const text = await response.text().catch(() => '');
    let parsed = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; }
    if (response.status === 422 && /already_exists/i.test(text)) {
      const existing = (await listReleaseAssets(fullName, releaseId)).find(asset => asset.name === name);
      if (existing) return existing;
    }
    if (!response.ok) throw externalError(RELEASE_CODES.GITHUB_ERROR, `GitHub asset upload failed for ${name} (${response.status}): ${parsed?.message ?? response.statusText}`);
    if (!parsed?.id) throw externalError(RELEASE_CODES.GITHUB_ERROR, `GitHub did not return an asset id for ${name}`);
    return parsed;
  }

  function assertAssetUrl(asset) {
    if (typeof asset?.url !== 'string') throw externalError(RELEASE_CODES.GITHUB_ERROR, `Release asset ${asset?.name ?? ''} has no API URL`);
    const url = new URL(asset.url);
    if (![apiOrigin, uploadOrigin].includes(url.origin) && !allowInsecureTestHosts) {
      throw externalError(RELEASE_CODES.GITHUB_ERROR, `Refusing an asset URL outside the GitHub API origin: ${url.origin}`);
    }
    assertTransport(url.toString());
    return url.toString();
  }

  async function downloadAsset(asset, destination) {
    let url = assertAssetUrl(asset);
    let response;
    let redirects = 0;
    for (;;) {
      const sameOrigin = new URL(url).origin === apiOrigin || new URL(url).origin === uploadOrigin;
      try {
        response = await fetchImpl(url, {
          headers: { ...(sameOrigin ? authHeader : {}), accept: 'application/octet-stream', 'user-agent': 'bepack-release/1' },
          signal: AbortSignal.timeout(downloadTimeoutMs),
          redirect: 'manual',
        });
      } catch (error) {
        throw externalError(RELEASE_CODES.GITHUB_ERROR, `Cannot download release asset ${asset.name}: ${error.message}`);
      }
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        if (redirects++ >= MAX_REDIRECTS) throw externalError(RELEASE_CODES.GITHUB_ERROR, `Asset download redirect loop for ${asset.name}`);
        const location = response.headers.get('location');
        if (!location) throw externalError(RELEASE_CODES.GITHUB_ERROR, `Asset download redirect has no location for ${asset.name}`);
        url = new URL(location, url).toString();
        assertTransport(url);
        continue;
      }
      break;
    }
    if (response.status !== 200) throw externalError(RELEASE_CODES.GITHUB_ERROR, `GitHub asset download failed for ${asset.name} (${response.status})`);
    if (!response.body) throw externalError(RELEASE_CODES.GITHUB_ERROR, `GitHub asset download has no body for ${asset.name}`);
    const contentLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(contentLength) && contentLength > maxAssetBytes) throw externalError(RELEASE_CODES.GITHUB_ERROR, `Asset ${asset.name} exceeds the download limit`);
    await mkdir(path.dirname(destination), { recursive: true });
    const temp = `${destination}.${process.pid}.${randomBytes(6).toString('hex')}.part`;
    const hash = createHash('sha256');
    let size = 0;
    const sink = createWriteStream(temp, { flags: 'wx', mode: 0o600 });
    const meter = new Transform({
      transform(chunk, _encoding, callback) {
        size += chunk.length;
        if (size > maxAssetBytes) return callback(new Error('asset exceeds the download limit'));
        hash.update(chunk);
        callback(null, chunk);
      },
    });
    try {
      await pipeline(Readable.fromWeb(response.body), meter, sink);
      if (Number.isFinite(contentLength) && size !== contentLength) throw new Error('asset download was truncated');
      const handle = await open(temp, 'r');
      await handle.sync().finally(() => handle.close());
      await rename(temp, destination);
      return { sha256: hash.digest('hex'), size };
    } catch (error) {
      await rm(temp, { force: true });
      throw externalError(RELEASE_CODES.GITHUB_ERROR, `Cannot download release asset ${asset.name}: ${error.message}`);
    }
  }

  return {
    apiRoot,
    uploadRoot,
    getRepository,
    getCommit,
    resolveTagCommit,
    getReleaseByTag,
    getRelease,
    createRelease,
    updateRelease,
    listReleaseAssets,
    uploadReleaseAsset,
    downloadAsset,
  };
}
