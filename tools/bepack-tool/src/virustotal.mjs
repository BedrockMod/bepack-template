// VirusTotal client for the release scan gate. It deliberately exposes only
// the operations the pipeline needs: upload one exact file, wait for the
// analysis, and evaluate the strict pass condition. Configuration and consent
// are checked by the caller before any bytes leave the machine.

import { openAsBlob } from 'node:fs';
import { basename } from 'node:path';

import { hashFile } from './release-files.mjs';
import { externalError, inputError, ReleaseError, RELEASE_CODES, EXIT } from './release-errors.mjs';

const DEFAULT_BASE_URL = 'https://www.virustotal.com/api/v3';
const DEFAULT_DIRECT_UPLOAD_BYTES = 32 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_POLL_INTERVAL_MS = 15_000;
const DEFAULT_MAX_WAIT_MS = 30 * 60 * 1000;

const sleepDefault = ms => new Promise(resolve => setTimeout(resolve, ms));

export function isVtConsent(value) {
  return value === 'true';
}

export function assertVtConfig({ apiKey, consent, baseUrl = DEFAULT_BASE_URL }) {
  if (typeof apiKey !== 'string' || apiKey.length < 10) {
    throw externalError(RELEASE_CODES.VT_CONFIG, 'VT_API_KEY is not configured; refusing to publish without a completed scan');
  }
  if (!isVtConsent(consent)) {
    throw inputError(RELEASE_CODES.VT_CONFIG, 'VT_UPLOAD_CONSENT must be exactly "true"; author content must not be uploaded without explicit consent');
  }
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw externalError(RELEASE_CODES.VT_CONFIG, 'VirusTotal API base URL is invalid');
  }
  if (parsed.protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(parsed.hostname)) {
    throw externalError(RELEASE_CODES.VT_CONFIG, 'VirusTotal API base URL must use HTTPS');
  }
}

function numericStat(stats, key) {
  const value = stats?.[key];
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function evaluateAnalysis(attributes, { analysisId } = {}) {
  if (!attributes || typeof attributes !== 'object') {
    throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal analysis has no attributes');
  }
  if (attributes.status !== 'completed') {
    throw new ReleaseError(RELEASE_CODES.SCAN_INCOMPLETE, `VirusTotal analysis is ${attributes.status ?? 'missing status'}, not completed`, { exitCode: EXIT.EXTERNAL });
  }
  const stats = attributes.stats;
  const malicious = numericStat(stats, 'malicious');
  const suspicious = numericStat(stats, 'suspicious');
  const harmless = numericStat(stats, 'harmless');
  const undetected = numericStat(stats, 'undetected');
  if ([malicious, suspicious, harmless, undetected].some(value => value === null)) {
    throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal analysis has missing or invalid stats');
  }
  if (malicious > 0 || suspicious > 0) {
    throw inputError(RELEASE_CODES.SCAN_DETECTED, `VirusTotal reported malicious=${malicious}, suspicious=${suspicious}`, {
      malicious, suspicious, harmless, undetected,
    });
  }
  if (harmless + undetected < 1) {
    throw new ReleaseError(RELEASE_CODES.SCAN_INCOMPLETE, 'VirusTotal returned no harmless/undetected engine result', { exitCode: EXIT.EXTERNAL });
  }
  const results = attributes.results;
  if (!results || typeof results !== 'object' || Object.keys(results).length === 0) {
    throw new ReleaseError(RELEASE_CODES.SCAN_INCOMPLETE, 'VirusTotal returned an empty engine result set', { exitCode: EXIT.EXTERNAL });
  }
  if (Object.values(results).some(result => result?.category === 'malicious' || result?.category === 'suspicious')) {
    throw inputError(RELEASE_CODES.SCAN_DETECTED, 'VirusTotal engine evidence contains a malicious/suspicious result');
  }
  const positiveEngines = Object.values(results).filter(result => result?.category === 'harmless' || result?.category === 'undetected');
  if (positiveEngines.length < 1) {
    throw new ReleaseError(RELEASE_CODES.SCAN_INCOMPLETE, 'VirusTotal returned no harmless/undetected engine evidence', { exitCode: EXIT.EXTERNAL });
  }
  const timestamp = attributes.date;
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal analysis has no analysis date');
  }
  const analyzedAt = new Date(timestamp * 1000).toISOString();
  return {
    analysis_id: analysisId,
    malicious,
    suspicious,
    harmless,
    undetected,
    analyzed_at: analyzedAt,
  };
}

export function createVirusTotalClient({
  apiKey,
  baseUrl = DEFAULT_BASE_URL,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  pollIntervalMs = DEFAULT_POLL_INTERVAL_MS,
  maxWaitMs = DEFAULT_MAX_WAIT_MS,
  directUploadBytes = DEFAULT_DIRECT_UPLOAD_BYTES,
  sleep = sleepDefault,
  now = Date.now,
} = {}) {
  if (typeof apiKey !== 'string' || !apiKey) throw externalError(RELEASE_CODES.VT_CONFIG, 'VirusTotal API key is required');
  if (typeof fetchImpl !== 'function') throw externalError(RELEASE_CODES.VT_ERROR, 'No fetch implementation available');
  const root = baseUrl.replace(/\/+$/, '');
  const baseHost = new URL(root).hostname;
  const allowedUploadHosts = new Set([baseHost, 'www.virustotal.com']);

  async function request(url, init = {}, { retries = 2 } = {}) {
    let attempt = 0;
    for (;;) {
      let response;
      try {
        response = await fetchImpl(url, {
          ...init,
          headers: { 'x-apikey': apiKey, accept: 'application/json', ...(init.headers ?? {}) },
          signal: AbortSignal.timeout(timeoutMs),
          redirect: 'error',
        });
      } catch (error) {
        if (attempt < retries) { attempt++; await sleep(Math.min(30_000, 1000 * 2 ** attempt)); continue; }
        throw externalError(RELEASE_CODES.VT_ERROR, `VirusTotal request failed: ${error.message}`);
      }
      if (response.status === 429 || response.status >= 500) {
        if (attempt < retries) {
          attempt++;
          const retryAfter = Number(response.headers.get('retry-after'));
          await sleep(Math.min(30_000, Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 1000 * 2 ** attempt));
          continue;
        }
      }
      return response;
    }
  }

  async function responseJson(response, operation) {
    let body;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    if (!response.ok) {
      const detail = body?.error?.message ?? body?.error?.code ?? response.statusText;
      if (response.status === 401 || response.status === 403) {
        throw externalError(RELEASE_CODES.VT_CONFIG, `VirusTotal rejected the API key (${response.status}): ${detail}`);
      }
      if (response.status === 429) throw externalError(RELEASE_CODES.VT_ERROR, `VirusTotal quota/rate limit: ${detail}`);
      throw externalError(RELEASE_CODES.VT_ERROR, `VirusTotal ${operation} failed (${response.status}): ${detail}`);
    }
    if (!body || typeof body !== 'object') throw externalError(RELEASE_CODES.VT_ERROR, `VirusTotal ${operation} returned invalid JSON`);
    return body;
  }

  async function getAnalysis(analysisId) {
    if (typeof analysisId !== 'string' || !analysisId) throw inputError(RELEASE_CODES.VT_ERROR, 'Analysis id is required');
    const response = await request(`${root}/analyses/${encodeURIComponent(analysisId)}`);
    const body = await responseJson(response, 'analysis lookup');
    if (body.data?.id !== analysisId || body.data?.type !== 'analysis') {
      throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal returned a different or invalid analysis identity');
    }
    return { id: body.data.id, attributes: body.data.attributes, fileInfo: body.meta?.file_info };
  }

  async function uploadUrl() {
    const response = await request(`${root}/files/upload_url`);
    const body = await responseJson(response, 'upload URL request');
    const url = body.data;
    if (typeof url !== 'string') throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal did not return an upload URL');
    let parsed;
    try { parsed = new URL(url); } catch { throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal returned an invalid upload URL'); }
    if (parsed.protocol !== 'https:') throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal upload URL is not HTTPS');
    if (!allowedUploadHosts.has(parsed.hostname)) throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal upload URL points at an unexpected host');
    return parsed.toString();
  }

  async function upload(file, { size, sha256 }) {
    const blob = await openAsBlob(file);
    const form = new FormData();
    form.append('file', blob, basename(file));
    let target = `${root}/files`;
    if (size > directUploadBytes) target = await uploadUrl();
    const response = await request(target, { method: 'POST', body: form });
    if (response.status === 409) {
      // The API returns AlreadySubmitted for known bytes. Resolve the existing
      // analysis by hash instead of treating an idempotent upload as success.
      const lookup = await request(`${root}/files/${encodeURIComponent(sha256)}`);
      const body = await responseJson(lookup, 'file lookup');
      const existing = body.data?.attributes?.last_analysis_id;
      if (typeof existing !== 'string' || !existing) {
        throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal reported duplicate bytes without a last analysis id');
      }
      return existing;
    }
    const body = await responseJson(response, 'file upload');
    const analysisId = body.data?.id;
    if (typeof analysisId !== 'string' || !analysisId) throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal upload returned no analysis id');
    return analysisId;
  }

  async function waitForAnalysis(analysisId) {
    const deadline = now() + maxWaitMs;
    for (;;) {
      const analysis = await getAnalysis(analysisId);
      const status = analysis.attributes?.status;
      if (status === 'completed') return analysis;
      if (status !== 'queued' && status !== 'in-progress') {
        throw new ReleaseError(RELEASE_CODES.SCAN_INCOMPLETE, `VirusTotal analysis ended as ${status ?? 'unknown'}`, { exitCode: EXIT.EXTERNAL });
      }
      const remaining = deadline - now();
      if (remaining <= 0) throw new ReleaseError(RELEASE_CODES.SCAN_INCOMPLETE, 'Timed out waiting for the VirusTotal analysis', { exitCode: EXIT.EXTERNAL });
      await sleep(Math.min(pollIntervalMs, remaining));
    }
  }

  async function scanFile(file, { expectedSha256, expectedSize } = {}) {
    const actual = await hashFile(file);
    if (expectedSha256 !== undefined && actual.sha256 !== expectedSha256) {
      throw inputError(RELEASE_CODES.SCAN_PLAN_INVALID, `File hash changed before upload: ${file}`);
    }
    if (expectedSize !== undefined && actual.size !== expectedSize) {
      throw inputError(RELEASE_CODES.SCAN_PLAN_INVALID, `File size changed before upload: ${file}`);
    }
    const analysisId = await upload(file, actual);
    const analysis = await waitForAnalysis(analysisId);
    if ((analysis.fileInfo?.sha256 !== undefined && analysis.fileInfo.sha256 !== actual.sha256) ||
      (analysis.fileInfo?.size !== undefined && analysis.fileInfo.size !== actual.size)) {
      throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal inline metadata conflicts with the uploaded file');
    }
    // Ordinary Analysis responses do not guarantee inline file metadata.
    // The documented item relationship binds this exact analysis to its File.
    const itemResponse = await request(`${root}/analyses/${encodeURIComponent(analysisId)}/item`);
    const itemBody = await responseJson(itemResponse, 'analysis item lookup');
    const item = itemBody.data;
    if (item?.type !== 'file' || item.id !== actual.sha256 ||
      (item.attributes?.sha256 !== undefined && item.attributes.sha256 !== actual.sha256) ||
      (item.attributes?.size !== undefined && item.attributes.size !== actual.size)) {
      throw externalError(RELEASE_CODES.VT_ERROR, 'VirusTotal analysis item does not match the exact uploaded file hash/size');
    }
    const after = await hashFile(file);
    if (after.sha256 !== actual.sha256 || after.size !== actual.size) {
      throw inputError(RELEASE_CODES.SCAN_PLAN_INVALID, 'File bytes changed while uploading to VirusTotal');
    }
    return { ...evaluateAnalysis(analysis.attributes, { analysisId }), size: actual.size, sha256: actual.sha256 };
  }

  return { getAnalysis, waitForAnalysis, scanFile, uploadUrl, baseUrl: root };
}
