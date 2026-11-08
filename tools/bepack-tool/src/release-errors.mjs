// Error taxonomy shared by the release CLI. Exit codes follow the public
// command contract: 0 success, 2 invalid input/policy, 3 external service,
// 1 internal/tool error.

export const EXIT = Object.freeze({ OK: 0, INTERNAL: 1, INPUT: 2, EXTERNAL: 3 });

export const RELEASE_CODES = Object.freeze({
  USAGE: 'BEPACK_RELEASE_USAGE',
  TAG_MISMATCH: 'BEPACK_RELEASE_TAG_MISMATCH',
  MANIFEST_INVALID: 'BEPACK_RELEASE_MANIFEST_INVALID',
  BUILD_INPUT: 'BEPACK_RELEASE_BUILD_INPUT',
  BUILD_OUTPUT: 'BEPACK_RELEASE_BUILD_OUTPUT',
  ASSET_INVALID: 'BEPACK_RELEASE_ASSET_INVALID',
  CONTAINER_INVALID: 'BEPACK_RELEASE_CONTAINER_INVALID',
  SCAN_REPORT_INVALID: 'BEPACK_RELEASE_SCAN_REPORT_INVALID',
  SCAN_DETECTED: 'BEPACK_RELEASE_SCAN_DETECTED',
  SCAN_INCOMPLETE: 'BEPACK_RELEASE_SCAN_INCOMPLETE',
  SCAN_PLAN_INVALID: 'BEPACK_RELEASE_SCAN_PLAN_INVALID',
  VT_CONFIG: 'BEPACK_RELEASE_VT_CONFIG',
  VT_ERROR: 'BEPACK_RELEASE_VT_ERROR',
  DOWNLOAD_FAILED: 'BEPACK_RELEASE_DOWNLOAD_FAILED',
  GITHUB_CONFIG: 'BEPACK_RELEASE_GITHUB_CONFIG',
  GITHUB_ERROR: 'BEPACK_RELEASE_GITHUB_ERROR',
  IMMUTABLE: 'BEPACK_RELEASE_IMMUTABLE',
  PUBLISH_VERIFY: 'BEPACK_RELEASE_PUBLISH_VERIFY',
  NOTIFY_NOT_CONFIGURED: 'BEPACK_RELEASE_NOTIFY_NOT_CONFIGURED',
  NOTIFY_ERROR: 'BEPACK_RELEASE_NOTIFY_ERROR',
  INTERNAL: 'BEPACK_RELEASE_INTERNAL',
});

export class ReleaseError extends Error {
  constructor(code, message, { exitCode = EXIT.INTERNAL, details, cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = 'ReleaseError';
    this.code = code;
    this.exitCode = exitCode;
    this.details = details;
  }
}

export function inputError(code, message, details) {
  return new ReleaseError(code, message, { exitCode: EXIT.INPUT, details });
}

export function externalError(code, message, details) {
  return new ReleaseError(code, message, { exitCode: EXIT.EXTERNAL, details });
}

export function internalError(code, message, details) {
  return new ReleaseError(code, message, { exitCode: EXIT.INTERNAL, details });
}

export function errorPayload(error, phase) {
  const known = error instanceof ReleaseError;
  return {
    ok: false,
    phase,
    code: known ? error.code : RELEASE_CODES.INTERNAL,
    message: error instanceof Error ? error.message : String(error),
    ...(known && error.details !== undefined ? { details: error.details } : {}),
  };
}

export function exitCodeOf(error) {
  return error instanceof ReleaseError ? error.exitCode : EXIT.INTERNAL;
}
