import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';

// Streams a file and returns its byte size and SHA-256 digest.
export async function packageDigestOf(file) {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(file)) { size += chunk.length; hash.update(chunk); }
  return { size, sha256: hash.digest('hex') };
}

export const sha256Of = bytes => createHash('sha256').update(bytes).digest('hex');
