// Downloads locked unbundled dependency assets for scanning and for release
// verification. HTTPS only, no credentials in URLs, bounded redirects, and
// private/link-local/metadata destinations rejected by default.

import { createHash, randomBytes } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { lookup } from 'node:dns/promises';
import { open, rm, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';

import { externalError, inputError, RELEASE_CODES } from './release-errors.mjs';

function privateIpv4(address) {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224) return true;
  return false;
}

function embeddedIpv4(address) {
  const match = /(?:^|:)((?:\d{1,3}\.){3}\d{1,3})$/.exec(address);
  return match ? match[1] : null;
}

function privateIpv6(address) {
  const lower = address.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  const mapped = embeddedIpv4(lower);
  if (mapped) return privateIpv4(mapped);
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
  if (/^ff[0-9a-f]{2}:/.test(lower)) return true;
  if (lower.startsWith('2001:db8:')) return true;
  if (lower.startsWith('64:ff9b:')) return true;
  if (lower.startsWith('2001:0000:')) return true;
  return false;
}

export function isPrivateAddress(address) {
  const version = isIP(address);
  if (version === 4) return privateIpv4(address);
  if (version === 6) return privateIpv6(address);
  return true;
}

async function resolvePublic(hostname, { allowPrivateHosts = false } = {}) {
  if (allowPrivateHosts) return;
  if (isIP(hostname)) {
    if (isPrivateAddress(hostname)) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, `Refusing private network destination: ${hostname}`);
    return;
  }
  let addresses;
  try {
    addresses = await lookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, `Cannot resolve download host ${hostname}: ${error.message}`);
  }
  if (!addresses.length) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, `Download host has no addresses: ${hostname}`);
  for (const { address } of addresses) {
    if (isPrivateAddress(address)) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, `Download host resolves to a private address: ${hostname}`);
  }
}

function validateUrl(raw, { allowPrivateHosts = false } = {}) {
  let url;
  try { url = new URL(raw); } catch { throw inputError(RELEASE_CODES.DOWNLOAD_FAILED, `Invalid dependency URL: ${raw}`); }
  if (url.protocol !== 'https:' && !(allowPrivateHosts && url.protocol === 'http:')) {
    throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, `Dependency URL must use HTTPS: ${url.origin}`);
  }
  if (url.username || url.password) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, 'Dependency URL must not contain credentials');
  if (!url.hostname) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, 'Dependency URL has no host');
  return url;
}

export async function downloadToFile(rawUrl, destination, {
  expectedSha256,
  expectedSize,
  maxBytes = 8 * 1024 ** 3,
  timeoutMs = 300_000,
  maxRedirects = 5,
  fetchImpl = globalThis.fetch,
  allowPrivateHosts = false,
} = {}) {
  let url = validateUrl(rawUrl, { allowPrivateHosts });
  let redirects = 0;
  let response;
  for (;;) {
    await resolvePublic(url.hostname, { allowPrivateHosts });
    try {
      response = await fetchImpl(url, {
        redirect: 'manual',
        headers: { accept: 'application/octet-stream', 'user-agent': 'bepack-release/1' },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, `Dependency download failed: ${error.message}`);
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      if (redirects >= maxRedirects) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, 'Dependency download exceeded the redirect limit');
      const location = response.headers.get('location');
      if (!location) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, 'Dependency redirect has no Location header');
      redirects++;
      url = validateUrl(new URL(location, url).toString(), { allowPrivateHosts });
      continue;
    }
    break;
  }
  if (response.status !== 200) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, `Dependency download returned HTTP ${response.status}`);
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, 'Dependency exceeds the download size limit');
  if (!response.body) throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, 'Dependency response has no body');

  await stat(path.dirname(destination)).catch(async () => {
    const { mkdir } = await import('node:fs/promises');
    await mkdir(path.dirname(destination), { recursive: true });
  });
  const temp = `${destination}.${process.pid}.${randomBytes(6).toString('hex')}.part`;
  const hash = createHash('sha256');
  let size = 0;
  const sink = createWriteStream(temp, { flags: 'wx', mode: 0o600 });
  const meter = new Transform({
    transform(chunk, _encoding, callback) {
      size += chunk.length;
      if (size > maxBytes) return callback(new Error('Dependency exceeds the download size limit'));
      hash.update(chunk);
      callback(null, chunk);
    },
  });
  try {
    await pipeline(Readable.fromWeb(response.body), meter, sink);
    if (Number.isFinite(contentLength) && size !== contentLength) throw new Error('Dependency download was truncated');
    if (expectedSize !== undefined && size !== expectedSize) throw new Error(`Dependency size mismatch: expected ${expectedSize}, got ${size}`);
    const sha256 = hash.digest('hex');
    if (expectedSha256 !== undefined && sha256 !== expectedSha256) throw new Error(`Dependency SHA-256 mismatch: expected ${expectedSha256}, got ${sha256}`);
    const handle = await open(temp, 'r');
    await handle.sync().finally(() => handle.close());
    const { rename } = await import('node:fs/promises');
    await rename(temp, destination);
    return { sha256, size };
  } catch (error) {
    await rm(temp, { force: true });
    if (error instanceof Error && /mismatch|limit|truncated/.test(error.message)) {
      throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, error.message);
    }
    throw externalError(RELEASE_CODES.DOWNLOAD_FAILED, `Dependency download failed: ${error.message}`);
  }
}
