// Minimal, defensive ZIP/ZIP64 reader for .bepack packages. The build and
// verify steps own full container validation; the release pipeline still
// re-checks the properties it relies on (root manifest, exact bytes, no
// duplicate/unsafe paths) so a compromised build cannot smuggle content into
// the scan plan or the published asset set.

import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { open } from 'node:fs/promises';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createInflateRaw } from 'node:zlib';

import { collisionKey, safeRelative } from './paths.mjs';
import { inputError, RELEASE_CODES } from './release-errors.mjs';

const EOCD_SIGNATURE = 0x06054b50;
const ZIP64_EOCD_SIGNATURE = 0x06064b50;
const ZIP64_LOCATOR_SIGNATURE = 0x07064b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;

const DEFAULT_LIMITS = Object.freeze({
  maxEntries: 100000,
  maxEntryBytes: 8 * 1024 ** 3,
  maxTotalBytes: 32 * 1024 ** 3,
  maxCentralDirectoryBytes: 256 * 1024 * 1024,
  maxCommentBytes: 65535,
});

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let value = i;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[i] = value >>> 0;
  }
  return table;
})();

function crc32Update(state, chunk) {
  let crc = state;
  for (let i = 0; i < chunk.length; i++) crc = CRC_TABLE[(crc ^ chunk[i]) & 0xff] ^ (crc >>> 8);
  return crc >>> 0;
}

function fail(message) {
  throw inputError(RELEASE_CODES.ASSET_INVALID, message);
}

async function readAt(handle, position, length) {
  if (length === 0) return Buffer.alloc(0);
  const buffer = Buffer.allocUnsafe(length);
  let read = 0;
  while (read < length) {
    const { bytesRead } = await handle.read(buffer, read, length - read, position + read);
    if (!bytesRead) fail('Unexpected end of package');
    read += bytesRead;
  }
  return buffer;
}

function findEocd(tail) {
  for (let index = tail.length - 22; index >= 0; index--) {
    if (tail.readUInt32LE(index) !== EOCD_SIGNATURE) continue;
    const commentLength = tail.readUInt16LE(index + 20);
    if (index + 22 + commentLength !== tail.length) continue;
    return index;
  }
  return -1;
}

function decodeEntryName(bytes, flags) {
  if (flags & 0x0800) {
    // UTF-8 flag: fall through to fatal decoding below.
  }
  let name;
  try {
    name = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('Package entry name is not valid UTF-8');
  }
  if (!name.isWellFormed() || name.includes('\0')) fail('Package entry name contains invalid Unicode');
  return name;
}

function parseZip64Extra(extra, entry) {
  let offset = 0;
  while (offset + 4 <= extra.length) {
    const id = extra.readUInt16LE(offset);
    const size = extra.readUInt16LE(offset + 2);
    const start = offset + 4;
    if (start + size > extra.length) fail('Malformed ZIP extra field');
    if (id === 0x0001) {
      let cursor = start;
      if (entry.size === 0xffffffff) {
        if (cursor + 8 > start + size) fail('Malformed ZIP64 size field');
        entry.size = Number(extra.readBigUInt64LE(cursor));
        cursor += 8;
      }
      if (entry.compressedSize === 0xffffffff) {
        if (cursor + 8 > start + size) fail('Malformed ZIP64 compressed size field');
        entry.compressedSize = Number(extra.readBigUInt64LE(cursor));
        cursor += 8;
      }
      if (entry.localOffset === 0xffffffff) {
        if (cursor + 8 > start + size) fail('Malformed ZIP64 local offset field');
        entry.localOffset = Number(extra.readBigUInt64LE(cursor));
        cursor += 8;
      }
    }
    offset = start + size;
  }
}

function parseCentralDirectory(buffer, limits) {
  const entries = new Map();
  const folded = new Map();
  let cursor = 0;
  let totalBytes = 0;
  while (cursor < buffer.length) {
    if (cursor + 46 > buffer.length) fail('Truncated ZIP central directory');
    if (buffer.readUInt32LE(cursor) !== CENTRAL_SIGNATURE) fail('Invalid ZIP central directory signature');
    const flags = buffer.readUInt16LE(cursor + 8);
    const method = buffer.readUInt16LE(cursor + 10);
    const crc = buffer.readUInt32LE(cursor + 16);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const size = buffer.readUInt32LE(cursor + 24);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const diskStart = buffer.readUInt16LE(cursor + 34);
    const externalAttributes = buffer.readUInt32LE(cursor + 38);
    const localOffset = buffer.readUInt32LE(cursor + 42);
    const end = cursor + 46 + nameLength + extraLength + commentLength;
    if (end > buffer.length) fail('Truncated ZIP central directory entry');
    if (flags & 0x0001) fail('Encrypted package entries are not allowed');
    if (method !== 0 && method !== 8) fail(`Unsupported ZIP compression method ${method}`);
    if (diskStart !== 0 && diskStart !== 0xffff) fail('Multi-disk packages are not allowed');
    const name = decodeEntryName(buffer.subarray(cursor + 46, cursor + 46 + nameLength), flags);
    const extra = buffer.subarray(cursor + 46 + nameLength, cursor + 46 + nameLength + extraLength);
    const entry = {
      name,
      flags,
      method,
      crc32: crc,
      compressedSize,
      size,
      localOffset,
      externalAttributes,
      directory: name.endsWith('/'),
    };
    parseZip64Extra(extra, entry);
    if (!Number.isSafeInteger(entry.size) || !Number.isSafeInteger(entry.compressedSize) || !Number.isSafeInteger(entry.localOffset)) {
      fail('ZIP64 values exceed the safe integer range');
    }
    if (entry.size > limits.maxEntryBytes) fail(`Package entry exceeds the per-file limit: ${entry.name}`);
    totalBytes += entry.size;
    if (totalBytes > limits.maxTotalBytes) fail('Package exceeds the total uncompressed limit');
    if (entries.size >= limits.maxEntries) fail('Package exceeds the entry count limit');
    if (!entry.directory) {
      // Directories are implied by file paths; an explicit directory entry is
      // harmless but never becomes a scannable subject.
      if (!safeRelative(name)) fail(`Unsafe package entry path: ${name}`);
      const key = collisionKey(name);
      const previous = folded.get(key);
      if (previous !== undefined) fail(`Case-folding package entry collision: ${previous} / ${name}`);
      folded.set(key, name);
      entries.set(name, entry);
    }
    cursor = end;
  }
  if (cursor !== buffer.length) fail('Trailing bytes in ZIP central directory');
  return entries;
}

function zip64EndOfCentralDirectory(handle, fileSize, eocdPosition) {
  if (eocdPosition < 20) fail('ZIP64 locator is missing');
  return readAt(handle, eocdPosition - 20, 20).then(locator => {
    if (locator.readUInt32LE(0) !== ZIP64_LOCATOR_SIGNATURE) fail('ZIP64 locator is missing');
    if (locator.readUInt32LE(4) !== 0 || locator.readUInt32LE(16) !== 1) fail('Multi-disk ZIP64 packages are not allowed');
    const offset = Number(locator.readBigUInt64LE(8));
    if (!Number.isSafeInteger(offset) || offset < 0 || offset + 56 > fileSize) fail('Invalid ZIP64 EOCD offset');
    return readAt(handle, offset, 56).then(record => {
      if (record.readUInt32LE(0) !== ZIP64_EOCD_SIGNATURE) fail('Invalid ZIP64 EOCD signature');
      const recordSize = Number(record.readBigUInt64LE(4));
      if (recordSize < 44 || offset + 12 + recordSize > fileSize) fail('Invalid ZIP64 EOCD size');
      if (record.readUInt32LE(16) !== 0 || record.readUInt32LE(20) !== 0) fail('Multi-disk ZIP64 packages are not allowed');
      const entriesDisk = Number(record.readBigUInt64LE(24));
      const entriesTotal = Number(record.readBigUInt64LE(32));
      const cdSize = Number(record.readBigUInt64LE(40));
      const cdOffset = Number(record.readBigUInt64LE(48));
      if (![entriesDisk, entriesTotal, cdSize, cdOffset].every(Number.isSafeInteger)) fail('ZIP64 values exceed the safe integer range');
      if (entriesDisk !== entriesTotal) fail('Multi-disk ZIP64 packages are not allowed');
      return { entriesTotal, cdSize, cdOffset };
    });
  });
}

export class BepackPackageReader {
  #handle;
  #file;
  #entries;
  #limits;
  #closed = false;

  constructor(file, handle, entries, limits) {
    this.#file = file;
    this.#handle = handle;
    this.#entries = entries;
    this.#limits = limits;
  }

  get file() { return this.#file; }
  get entries() { return [...this.#entries.values()]; }
  get size() { return this.entries.reduce((sum, entry) => sum + entry.size, 0); }

  has(name) { return this.#entries.has(name); }

  entry(name) { return this.#entries.get(name) ?? null; }

  async #localDataOffset(entry) {
    const header = await readAt(this.#handle, entry.localOffset, 30);
    if (header.readUInt32LE(0) !== LOCAL_SIGNATURE) fail(`Invalid local header for ${entry.name}`);
    const nameLength = header.readUInt16LE(26);
    const extraLength = header.readUInt16LE(28);
    if (header.readUInt16LE(8) !== entry.method) fail(`Local header method mismatch for ${entry.name}`);
    const localName = await readAt(this.#handle, entry.localOffset + 30, nameLength);
    let decoded;
    try {
      decoded = new TextDecoder('utf-8', { fatal: true }).decode(localName);
    } catch {
      fail(`Invalid local header name for ${entry.name}`);
    }
    if (decoded !== entry.name) fail(`Local header name mismatch for ${entry.name}`);
    const offset = entry.localOffset + 30 + nameLength + extraLength;
    if (offset + entry.compressedSize > (await this.#handle.stat()).size) fail(`Entry data exceeds package size: ${entry.name}`);
    return offset;
  }

  #stream(entry) {
    const size = entry.size;
    const crcEntry = entry.crc32;
    return new Transform({
      transform(chunk, _encoding, callback) {
        this.bytes = (this.bytes ?? 0) + chunk.length;
        this.crc = crc32Update(this.crc ?? 0xffffffff, chunk);
        if (this.bytes > size) return callback(new Error(`Entry exceeds declared size: ${entry.name}`));
        callback(null, chunk);
      },
      flush(callback) {
        this.crc = (this.crc ?? 0xffffffff) ^ 0xffffffff;
        if (this.bytes !== size) return callback(new Error(`Entry size mismatch: ${entry.name}`));
        if (this.crc >>> 0 !== crcEntry) return callback(new Error(`Entry CRC mismatch: ${entry.name}`));
        callback();
      },
    });
  }

  async #pipeline(entry, destination) {
    const start = await this.#localDataOffset(entry);
    const source = createReadStream(this.#file, { start, end: start + entry.compressedSize - 1 });
    const streams = [source];
    if (entry.method === 8) streams.push(createInflateRaw());
    const check = this.#stream(entry);
    streams.push(check);
    if (destination) streams.push(destination);
    await pipeline(...streams);
  }

  async readEntry(name, { maxBytes = this.#limits.maxEntryBytes } = {}) {
    const entry = this.#entries.get(name);
    if (!entry) fail(`Package entry is missing: ${name}`);
    if (entry.size > maxBytes) fail(`Package entry ${name} exceeds read limit`);
    const chunks = [];
    const sink = new Transform({
      transform(chunk, _encoding, callback) {
        chunks.push(chunk);
        callback();
      },
    });
    await this.#pipeline(entry, sink);
    return Buffer.concat(chunks, entry.size);
  }

  async readEntryPrefix(name, byteCount) {
    const entry = this.#entries.get(name);
    if (!entry) fail(`Package entry is missing: ${name}`);
    if (!Number.isSafeInteger(byteCount) || byteCount < 0 || byteCount > entry.size) fail(`Invalid prefix length for ${name}`);
    if (byteCount === 0) return Buffer.alloc(0);
    const start = await this.#localDataOffset(entry);
    if (entry.method === 0) {
      return readAt(this.#handle, start, byteCount);
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      const chunks = [];
      let total = 0;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        source.destroy();
        inflate.destroy();
        if (error) reject(error);
        else resolve(Buffer.concat(chunks).subarray(0, byteCount));
      };
      const source = createReadStream(this.#file, { start, end: start + entry.compressedSize - 1 });
      const inflate = createInflateRaw();
      source.on('error', finish);
      inflate.on('error', finish);
      inflate.on('data', chunk => {
        chunks.push(chunk);
        total += chunk.length;
        if (total >= byteCount) finish();
      });
      inflate.on('end', () => finish());
      source.pipe(inflate);
    });
  }

  async hashEntry(name) {
    const entry = this.#entries.get(name);
    if (!entry) fail(`Package entry is missing: ${name}`);
    const hash = createHash('sha256');
    const sink = new Transform({
      transform(chunk, _encoding, callback) {
        hash.update(chunk);
        callback();
      },
    });
    await this.#pipeline(entry, sink);
    return { sha256: hash.digest('hex'), size: entry.size };
  }

  async extractEntry(name, destination) {
    const entry = this.#entries.get(name);
    if (!entry) fail(`Package entry is missing: ${name}`);
    const out = createWriteStream(destination, { flags: 'wx', mode: 0o600 });
    try {
      await this.#pipeline(entry, out);
    } catch (error) {
      const { rm } = await import('node:fs/promises');
      await rm(destination, { force: true });
      throw error;
    }
    return { size: entry.size, sha256: (await hashExtracted(destination)) };
  }

  async close() {
    if (this.#closed) return;
    this.#closed = true;
    await this.#handle.close();
  }
}

async function hashExtracted(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

export async function openPackage(file, { limits = DEFAULT_LIMITS } = {}) {
  const handle = await open(file, 'r');
  try {
    const { size: fileSize } = await handle.stat();
    if (fileSize < 22) fail('Package is too small to be a ZIP container');
    const tailLength = Math.min(fileSize, 22 + limits.maxCommentBytes);
    const tail = await readAt(handle, fileSize - tailLength, tailLength);
    const eocdIndex = findEocd(tail);
    if (eocdIndex < 0) fail('ZIP end-of-central-directory record not found');
    const eocdPosition = fileSize - tailLength + eocdIndex;
    const eocd = tail.subarray(eocdIndex, eocdIndex + 22);
    const diskNumber = eocd.readUInt16LE(4);
    const cdDisk = eocd.readUInt16LE(6);
    let entriesDisk = eocd.readUInt16LE(8);
    let entriesTotal = eocd.readUInt16LE(10);
    let cdSize = eocd.readUInt32LE(12);
    let cdOffset = eocd.readUInt32LE(16);
    if (diskNumber !== 0 || cdDisk !== 0) fail('Multi-disk packages are not allowed');
    if (entriesTotal === 0xffff || entriesDisk === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      ({ entriesTotal, cdSize, cdOffset } = await zip64EndOfCentralDirectory(handle, fileSize, eocdPosition));
    }
    if (entriesDisk !== entriesTotal && entriesDisk !== 0xffff) fail('Multi-disk packages are not allowed');
    if (cdSize > limits.maxCentralDirectoryBytes) fail('ZIP central directory exceeds the read limit');
    if (cdOffset + cdSize > fileSize) fail('ZIP central directory exceeds package size');
    const central = await readAt(handle, cdOffset, cdSize);
    const entries = parseCentralDirectory(central, limits);
    if (entries.size !== entriesTotal && entriesTotal !== 0xffff) {
      // Explicit directory entries are skipped, so count them separately.
      const directoryCount = entriesTotal - entries.size;
      if (directoryCount < 0 || directoryCount > limits.maxEntries) fail('ZIP entry count mismatch');
    }
    return new BepackPackageReader(file, handle, entries, limits);
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
}
