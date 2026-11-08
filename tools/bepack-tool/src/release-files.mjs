import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, open, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';

import { readStrictJSON } from './strict-json.mjs';
import { inputError, RELEASE_CODES } from './release-errors.mjs';

export const HEX_SHA256 = /^[0-9a-f]{64}$/;
export const UTC_RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

export function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export async function hashFile(file) {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(file)) {
    hash.update(chunk);
    size += chunk.length;
  }
  return { sha256: hash.digest('hex'), size };
}

export async function readJson(file, { maxBytes = 4 * 1024 * 1024 } = {}) {
  try {
    return await readStrictJSON(file, { maxBytes });
  } catch (error) {
    throw inputError(RELEASE_CODES.MANIFEST_INVALID, `Cannot read strict JSON ${file}: ${error.message}`);
  }
}

export async function ensureDir(dir) {
  await mkdir(dir, { recursive: true });
}

export async function assertRegularFile(file, { label = file } = {}) {
  let info;
  try {
    info = await stat(file);
  } catch (error) {
    throw inputError(RELEASE_CODES.ASSET_INVALID, `${label} does not exist`, { cause: error.message });
  }
  if (!info.isFile()) throw inputError(RELEASE_CODES.ASSET_INVALID, `${label} is not a regular file`);
  return info;
}

export async function listRegularFiles(dir) {
  const { readdir } = await import('node:fs/promises');
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      throw inputError(RELEASE_CODES.ASSET_INVALID, `Symbolic links are not allowed in release assets: ${entry.name}`);
    }
    if (entry.isDirectory()) {
      throw inputError(RELEASE_CODES.ASSET_INVALID, `Subdirectories are not allowed in release assets: ${entry.name}`);
    }
    if (!entry.isFile()) {
      throw inputError(RELEASE_CODES.ASSET_INVALID, `Special file is not allowed in release assets: ${entry.name}`);
    }
    files.push(path.join(dir, entry.name));
  }
  files.sort((a, b) => Buffer.compare(Buffer.from(path.basename(a)), Buffer.from(path.basename(b))));
  return files;
}

export function jsonBytes(value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n', 'utf8');
}

// Writes a new file and refuses to replace one. Release assets are immutable:
// a rerun must compare, not silently overwrite, an existing candidate.
export async function writeNewFile(file, data, { mode = 0o644 } = {}) {
  await mkdir(path.dirname(file), { recursive: true });
  const handle = await open(file, 'wx', mode);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function writeFileAtomic(file, data, { mode = 0o644 } = {}) {
  await mkdir(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const handle = await open(temp, 'wx', mode);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temp, file);
  } catch (error) {
    await rm(temp, { force: true });
    throw error;
  }
}

export async function copyFileExact(source, destination) {
  const info = await assertRegularFile(source);
  const handle = await open(source, 'r');
  try {
    const out = await open(destination, 'wx');
    try {
      const buffer = Buffer.allocUnsafe(1024 * 1024);
      let position = 0;
      while (position < info.size) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
        if (!bytesRead) break;
        await out.write(buffer, 0, bytesRead);
        position += bytesRead;
      }
      if (position !== info.size) throw new Error(`Short read while copying ${source}`);
      await out.sync();
    } finally {
      await out.close();
    }
  } finally {
    await handle.close();
  }
}

export async function removeRecursive(target) {
  await rm(target, { recursive: true, force: true });
}
