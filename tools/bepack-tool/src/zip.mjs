// .bepack container codec: single-volume ZIP/ZIP64, Store + Deflate only.
// Writing is a two-pass spill pipeline (never data descriptors) so the local
// header and the central directory always carry identical size and CRC values.
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, mkdtemp, open, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { Readable, Transform, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createDeflateRaw, createInflateRaw } from 'node:zlib';
import { safeRelative, collisionKey } from './paths.mjs';
import { ensureSafeDirectory } from './staging.mjs';

const table = (() => {
  const values = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; values[n] = c >>> 0; }
  return values;
})();
export const CRC32_INITIAL = 0xffffffff;
export const crc32Update = (crc, chunk) => { for (const byte of chunk) crc = (crc >>> 8) ^ table[(crc ^ byte) & 0xff]; return crc >>> 0; };
export const crc32Of = bytes => (crc32Update(CRC32_INITIAL, bytes) ^ 0xffffffff) >>> 0;

export const DEFAULT_LIMITS = { maxEntries: 100000, maxFileBytes: 8 * 1024 ** 3, maxTotalBytes: 32 * 1024 ** 3, maxManifestBytes: 4 * 1024 * 1024, maxLockBytes: 64 * 1024 * 1024, maxCompressionRatio: 1000 };

const DOS_DATE = 0x0021; // 1980-01-01, fixed for reproducible archives
const DOS_TIME = 0;
const MODE_FILE = 0o100644;
const MODE_DIRECTORY = 0o40755;
const ZIP64_LIMIT = 0xffffffff;
const MEMORY_SPILL_LIMIT = 4 * 1024 * 1024;
const failure = (code, message) => Object.assign(new Error(message), { diagnostic: code });

// ---------------------------------------------------------------------------
// writing
// ---------------------------------------------------------------------------

function zip64Extra(values) {
  if (!values.length) return Buffer.alloc(0);
  const body = Buffer.alloc(4 + values.length * 8);
  body.writeUInt16LE(0x0001, 0);
  body.writeUInt16LE(values.length * 8, 2);
  values.forEach((value, index) => body.writeBigUInt64LE(BigInt(value), 4 + index * 8));
  return body;
}

export async function writeZipArchive(destination, input, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options };
  const stagingBase = options.stagingDirectory ?? path.dirname(destination);
  const compressThreshold = options.compressThreshold ?? 256;
  const names = new Map();
  const entries = [...input].sort((a, b) => Buffer.compare(Buffer.from(a.path, 'utf8'), Buffer.from(b.path, 'utf8')));
  if (entries.length > limits.maxEntries) throw failure('BEPACK_RESOURCE_LIMIT', 'Archive entry budget exceeded');
  for (const entry of entries) {
    if (!safeRelative(entry.path)) throw failure('BEPACK_PATH_UNSAFE', 'Unsafe archive path: ' + entry.path);
    if (entry.directory) throw failure('BEPACK_ARCHIVE_INVALID', 'Directory entries are not produced by the packer');
    const key = collisionKey(entry.path);
    if (names.has(key)) throw failure('BEPACK_PATH_UNSAFE', 'Duplicate or case-folding colliding archive path: ' + entry.path);
    names.set(key, entry.path);
  }
  await ensureSafeDirectory(stagingBase);
  const staging = await mkdtemp(path.join(path.resolve(stagingBase), '.bepack-zip-'));
  const prepared = [];
  let totalBytes = 0;
  try {
    for (const [index, entry] of entries.entries()) {
      const source = entry.bytes ? { kind: 'buffer', bytes: entry.bytes } : { kind: 'file', absolute: entry.absolute };
      const size = source.kind === 'buffer' ? source.bytes.length : (await stat(source.absolute)).size;
      if (size > limits.maxFileBytes) throw failure('BEPACK_RESOURCE_LIMIT', 'File exceeds the single entry budget: ' + entry.path);
      totalBytes += size;
      if (totalBytes > limits.maxTotalBytes) throw failure('BEPACK_RESOURCE_LIMIT', 'Archive exceeds the total byte budget');
      const method = size >= compressThreshold ? 8 : 0;
      const spill = source.kind === 'file' && size > MEMORY_SPILL_LIMIT ? path.join(staging, `entry-${index}.tmp`) : null;
      let crc = CRC32_INITIAL, uncompressed = 0;
      const hash = createHash('sha256');
      const meter = new Transform({ transform(chunk, _encoding, callback) { crc = crc32Update(crc, chunk); uncompressed += chunk.length; hash.update(chunk); callback(null, chunk); } });
      const chunks = [];
      let handle = spill ? await open(spill, 'wx') : null;
      let compressed = 0;
      const sink = new Writable({
        write(chunk, _encoding, callback) {
          compressed += chunk.length;
          if (!handle) { chunks.push(chunk); return callback(); }
          handle.write(chunk).then(() => callback(), callback);
        },
      });
      const stages = [source.kind === 'buffer' ? Readable.from([source.bytes]) : createReadStream(source.absolute), meter];
      if (method === 8) stages.push(createDeflateRaw({ level: 9 }));
      stages.push(sink);
      try { await pipeline(stages); } finally { if (handle) await handle.close(); }
      if (compressed > 0 && uncompressed / compressed > limits.maxCompressionRatio) throw failure('BEPACK_RESOURCE_LIMIT', 'Compression ratio limit exceeded: ' + entry.path);
      prepared.push({ path: entry.path, method, size: uncompressed, compressedSize: compressed, crc: (crc ^ 0xffffffff) >>> 0, sha256: hash.digest('hex'), buffer: handle ? null : Buffer.concat(chunks), file: spill });
    }

    const out = await open(destination, 'wx');
    const archiveHash = createHash('sha256');
    let offset = 0;
    const write = async chunk => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      archiveHash.update(buffer);
      await out.write(buffer);
      offset += buffer.length;
    };
    const copyFile = async (file, length) => {
      const handle = await open(file, 'r');
      try {
        const buffer = Buffer.alloc(Math.min(length, 1 << 20));
        let position = 0;
        while (position < length) {
          const want = Math.min(buffer.length, length - position);
          const { bytesRead } = await handle.read(buffer, 0, want, position);
          if (!bytesRead) throw failure('BEPACK_ARCHIVE_INVALID', 'Unexpected end of staged entry data');
          await write(buffer.subarray(0, bytesRead));
          position += bytesRead;
        }
      } finally { await handle.close(); }
    };
    const central = [];
    try {
      for (const entry of prepared) {
        const name = Buffer.from(entry.path, 'utf8');
        const localOffset = offset;
        const values = [];
        if (entry.size >= ZIP64_LIMIT) values.push(entry.size);
        if (entry.compressedSize >= ZIP64_LIMIT) values.push(entry.compressedSize);
        const extra = zip64Extra(values);
        const header = Buffer.alloc(30);
        header.writeUInt32LE(0x04034b50, 0);
        header.writeUInt16LE(45, 4);
        header.writeUInt16LE(0x0800, 6);
        header.writeUInt16LE(entry.method, 8);
        header.writeUInt16LE(DOS_TIME, 10);
        header.writeUInt16LE(DOS_DATE, 12);
        header.writeUInt32LE(entry.crc, 14);
        header.writeUInt32LE(entry.compressedSize >= ZIP64_LIMIT ? ZIP64_LIMIT : entry.compressedSize, 18);
        header.writeUInt32LE(entry.size >= ZIP64_LIMIT ? ZIP64_LIMIT : entry.size, 22);
        header.writeUInt16LE(name.length, 26);
        header.writeUInt16LE(extra.length, 28);
        await write(header); await write(name); await write(extra);
        if (entry.buffer) await write(entry.buffer); else await copyFile(entry.file, entry.compressedSize);
        central.push({ entry, name, localOffset });
      }
      const directoryOffset = offset;
      for (const record of central) {
        const { entry, name, localOffset } = record;
        const values = [];
        if (entry.size >= ZIP64_LIMIT) values.push(entry.size);
        if (entry.compressedSize >= ZIP64_LIMIT) values.push(entry.compressedSize);
        if (localOffset >= ZIP64_LIMIT) values.push(localOffset);
        const extra = zip64Extra(values);
        const header = Buffer.alloc(46);
        header.writeUInt32LE(0x02014b50, 0);
        header.writeUInt16LE(0x031e, 4);
        header.writeUInt16LE(45, 6);
        header.writeUInt16LE(0x0800, 8);
        header.writeUInt16LE(entry.method, 10);
        header.writeUInt16LE(DOS_TIME, 12);
        header.writeUInt16LE(DOS_DATE, 14);
        header.writeUInt32LE(entry.crc, 16);
        header.writeUInt32LE(entry.compressedSize >= ZIP64_LIMIT ? ZIP64_LIMIT : entry.compressedSize, 20);
        header.writeUInt32LE(entry.size >= ZIP64_LIMIT ? ZIP64_LIMIT : entry.size, 24);
        header.writeUInt16LE(name.length, 28);
        header.writeUInt16LE(extra.length, 30);
        header.writeUInt16LE(0, 32);
        header.writeUInt16LE(0, 34);
        header.writeUInt16LE(0, 36);
        header.writeUInt32LE((MODE_FILE << 16) >>> 0, 38);
        header.writeUInt32LE(localOffset >= ZIP64_LIMIT ? ZIP64_LIMIT : localOffset, 42);
        await write(header); await write(name); await write(extra);
      }
      const directorySize = offset - directoryOffset;
      const needsZip64 = central.length > 0xffff || directorySize >= ZIP64_LIMIT || directoryOffset >= ZIP64_LIMIT;
      if (needsZip64) {
        const recordOffset = offset;
        const record = Buffer.alloc(56);
        record.writeUInt32LE(0x06064b50, 0);
        record.writeBigUInt64LE(44n, 4);
        record.writeUInt16LE(45, 12);
        record.writeUInt16LE(45, 14);
        record.writeUInt32LE(0, 16); record.writeUInt32LE(0, 20);
        record.writeBigUInt64LE(BigInt(central.length), 24);
        record.writeBigUInt64LE(BigInt(central.length), 32);
        record.writeBigUInt64LE(BigInt(directorySize), 40);
        record.writeBigUInt64LE(BigInt(directoryOffset), 48);
        await write(record);
        const locator = Buffer.alloc(20);
        locator.writeUInt32LE(0x07064b50, 0);
        locator.writeUInt32LE(0, 4);
        locator.writeBigUInt64LE(BigInt(recordOffset), 8);
        locator.writeUInt32LE(1, 16);
        await write(locator);
      }
      const end = Buffer.alloc(22);
      end.writeUInt32LE(0x06054b50, 0);
      end.writeUInt16LE(0, 4); end.writeUInt16LE(0, 6);
      end.writeUInt16LE(needsZip64 ? 0xffff : central.length, 8);
      end.writeUInt16LE(needsZip64 ? 0xffff : central.length, 10);
      end.writeUInt32LE(needsZip64 ? ZIP64_LIMIT : directorySize, 12);
      end.writeUInt32LE(needsZip64 ? ZIP64_LIMIT : directoryOffset, 16);
      end.writeUInt16LE(0, 20);
      await write(end);
    } finally { await out.close(); }
    return { size: offset, sha256: archiveHash.digest('hex'), entries: prepared.map(({ path: name, size, sha256 }) => ({ path: name, size, sha256 })) };
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// reading
// ---------------------------------------------------------------------------

async function readRange(handle, start, length) {
  const buffer = Buffer.alloc(length);
  let position = 0;
  while (position < length) {
    const { bytesRead } = await handle.read(buffer, position, length - position, start + position);
    if (!bytesRead) throw failure('BEPACK_ARCHIVE_INVALID', 'Unexpected end of archive');
    position += bytesRead;
  }
  return buffer;
}

function parseZip64(values, flags) {
  let cursor = 0;
  const next = () => { const value = Number(values.readBigUInt64LE(cursor)); cursor += 8; return value; };
  const result = {};
  if (flags.uncompressed) result.size = next();
  if (flags.compressed) result.compressedSize = next();
  if (flags.offset) result.localOffset = next();
  return result;
}

export async function openZip(file, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options };
  const handle = await open(file, 'r');
  try {
    const info = await handle.stat();
    const head = await readRange(handle, 0, Math.min(info.size, 4));
    if (head.length < 4 || head.readUInt32LE(0) !== 0x04034b50) throw failure('BEPACK_ARCHIVE_INVALID', 'Archive must start with a local file header; prefixes are forbidden');
    const tailLength = Math.min(info.size, 65557 + 20 + 22);
    const tail = await readRange(handle, info.size - tailLength, tailLength);
    let eocd = -1;
    for (let index = tail.length - 22; index >= 0; index--) {
      if (tail.readUInt32LE(index) !== 0x06054b50) continue;
      if (index + 22 + tail.readUInt16LE(index + 20) === tail.length) { eocd = index; break; }
    }
    if (eocd < 0) throw failure('BEPACK_ARCHIVE_INVALID', 'End of central directory record not found');
    const eocdOffset = info.size - tailLength + eocd;
    if (tail.readUInt16LE(eocd + 4) !== 0 || tail.readUInt16LE(eocd + 6) !== 0) throw failure('BEPACK_ARCHIVE_INVALID', 'Multi-volume archives are forbidden');
    let count = tail.readUInt16LE(eocd + 10);
    let directorySize = tail.readUInt32LE(eocd + 12);
    let directoryOffset = tail.readUInt32LE(eocd + 16);
    let zip64 = false;
    let zip64RecordOffset = null;
    if (count === 0xffff || directorySize === ZIP64_LIMIT || directoryOffset === ZIP64_LIMIT) {
      if (eocdOffset < 20) throw failure('BEPACK_ARCHIVE_INVALID', 'ZIP64 locator missing');
      const locator = await readRange(handle, eocdOffset - 20, 20);
      if (locator.readUInt32LE(0) !== 0x07064b50) throw failure('BEPACK_ARCHIVE_INVALID', 'ZIP64 locator missing');
      if (locator.readUInt32LE(4) !== 0 || locator.readUInt32LE(16) !== 1) throw failure('BEPACK_ARCHIVE_INVALID', 'Multi-volume ZIP64 locator');
      zip64RecordOffset = Number(locator.readBigUInt64LE(8));
      if (!Number.isSafeInteger(zip64RecordOffset) || zip64RecordOffset < 0) throw failure('BEPACK_ARCHIVE_INVALID', 'Invalid ZIP64 offset');
      const record = await readRange(handle, zip64RecordOffset, 56);
      if (record.readBigUInt64LE(4) !== 44n || record.readUInt32LE(16) !== 0 || record.readUInt32LE(20) !== 0 || record.readBigUInt64LE(24) !== record.readBigUInt64LE(32) || zip64RecordOffset + 56 !== eocdOffset - 20) throw failure('BEPACK_ARCHIVE_INVALID', 'ZIP64 record bounds or volumes disagree');
      if (record.readUInt32LE(0) !== 0x06064b50) throw failure('BEPACK_ARCHIVE_INVALID', 'ZIP64 end of central directory missing');
      count = Number(record.readBigUInt64LE(32));
      directorySize = Number(record.readBigUInt64LE(40));
      directoryOffset = Number(record.readBigUInt64LE(48));
      zip64 = true;
    }
    if (tail.readUInt16LE(eocd + 8) !== tail.readUInt16LE(eocd + 10) && !zip64) throw failure('BEPACK_ARCHIVE_INVALID', 'Central directory entry counts disagree');
    if (![count,directorySize,directoryOffset].every(Number.isSafeInteger) || directoryOffset + directorySize !== (zip64 ? zip64RecordOffset : eocdOffset)) throw failure('BEPACK_ARCHIVE_INVALID', 'Trailing data or central directory overlap in archive');
    if (directoryOffset < 4 || count > limits.maxEntries || count === 0) throw failure('BEPACK_ARCHIVE_INVALID', 'Archive entry count is out of range');
    if (directorySize > 256 * 1024 ** 2) throw failure('BEPACK_RESOURCE_LIMIT', 'Central directory exceeds the byte budget');
    const directory = await readRange(handle, directoryOffset, directorySize);
    const entries = [];
    const names = new Map();
    let total = 0;
    let cursor = 0;
    for (let index = 0; index < count; index++) {
      if (cursor + 46 > directory.length || directory.readUInt32LE(cursor) !== 0x02014b50) throw failure('BEPACK_ARCHIVE_INVALID', 'Malformed central directory entry');
      const flags = directory.readUInt16LE(cursor + 8);
      const method = directory.readUInt16LE(cursor + 10);
      const crc = directory.readUInt32LE(cursor + 16);
      let compressedSize = directory.readUInt32LE(cursor + 20);
      let size = directory.readUInt32LE(cursor + 24);
      const nameLength = directory.readUInt16LE(cursor + 28);
      const extraLength = directory.readUInt16LE(cursor + 30);
      const commentLength = directory.readUInt16LE(cursor + 32);
      const disk = directory.readUInt16LE(cursor + 34);
      const attributes = directory.readUInt32LE(cursor + 38);
      let localOffset = directory.readUInt32LE(cursor + 42);
      if (cursor + 46 + nameLength + extraLength + commentLength > directory.length) throw failure('BEPACK_ARCHIVE_INVALID', 'Truncated central directory name or extras');
      const nameBytes = directory.subarray(cursor + 46, cursor + 46 + nameLength);
      const name = nameBytes.toString('utf8');
      if ((!Buffer.from(name, 'utf8').equals(nameBytes)) || (!(flags & 0x0800) && [...nameBytes].some(byte=>byte>127))) throw failure('BEPACK_PATH_UNSAFE', 'Invalid UTF-8 entry name');
      const extra = directory.subarray(cursor + 46 + nameLength, cursor + 46 + nameLength + extraLength);
      cursor += 46 + nameLength + extraLength + commentLength;
      if (disk !== 0) throw failure('BEPACK_ARCHIVE_INVALID', 'Multi-volume archive entries are forbidden');
      if (flags !== 0 && flags !== 0x0800) throw failure('BEPACK_ARCHIVE_INVALID', 'Unsupported archive flags');
      if (flags & 0x0001 || flags & 0x0040) throw failure('BEPACK_ARCHIVE_INVALID', 'Encrypted entries are forbidden');
      if (flags & 0x0020) throw failure('BEPACK_ARCHIVE_INVALID', 'Patched entries are forbidden');
      if (flags & 0x0008) throw failure('BEPACK_ARCHIVE_INVALID', 'Local headers must not defer sizes to a trailing descriptor');
      if (method !== 0 && method !== 8) throw failure('BEPACK_ARCHIVE_INVALID', 'Only Store and Deflate are permitted: ' + name);
      let extraCursor = 0;
      while (extraCursor + 4 <= extra.length) {
        const id = extra.readUInt16LE(extraCursor);
        const length = extra.readUInt16LE(extraCursor + 2);
        if (extraCursor + 4 + length > extra.length) throw failure('BEPACK_ARCHIVE_INVALID', 'Truncated ZIP extra field');
        if (id === 0x0001) {
          const resolved = parseZip64(extra.subarray(extraCursor + 4, extraCursor + 4 + length), { uncompressed: size === ZIP64_LIMIT, compressed: compressedSize === ZIP64_LIMIT, offset: localOffset === ZIP64_LIMIT });
          if (resolved.size !== undefined) size = resolved.size;
          if (resolved.compressedSize !== undefined) compressedSize = resolved.compressedSize;
          if (resolved.localOffset !== undefined) localOffset = resolved.localOffset;
        }
        extraCursor += 4 + length;
      }
      if (size === ZIP64_LIMIT || compressedSize === ZIP64_LIMIT || localOffset === ZIP64_LIMIT) throw failure('BEPACK_ARCHIVE_INVALID', 'Missing ZIP64 extended information: ' + name);
      const directoryEntry = name.endsWith('/') || (attributes >>> 16 & 0o170000) === 0o040000;
      if (directoryEntry) {
        if (size !== 0 || compressedSize !== 0) throw failure('BEPACK_ARCHIVE_INVALID', 'Directory entry carries data: ' + name);
        if (!safeRelative(name.replace(/\/+$/, ''))) throw failure('BEPACK_PATH_UNSAFE', 'Unsafe directory entry path: ' + name);
        const key = collisionKey(name.replace(/\/+$/, ''));
        if (names.has(key)) throw failure('BEPACK_PATH_UNSAFE', 'Duplicate or colliding directory entry');
        names.set(key,name);
        entries.push({ path: name, directory: true, flags, method, size: 0, compressedSize: 0, crc, localOffset, attributes });
        continue;
      }
      if (!safeRelative(name)) throw failure('BEPACK_PATH_UNSAFE', 'Unsafe or ambiguously encoded entry path: ' + name);
      if (![0,0o100000].includes(attributes >>> 16 & 0o170000)) throw failure('BEPACK_PATH_UNSAFE', 'Symlink entries are forbidden: ' + name);
      const key = collisionKey(name);
      if (names.has(key)) throw failure('BEPACK_PATH_UNSAFE', 'Duplicate or case-folding colliding entry: ' + name);
      names.set(key, name);
      if (size > limits.maxFileBytes) throw failure('BEPACK_RESOURCE_LIMIT', 'Entry exceeds the single file budget: ' + name);
      total += size;
      if (total > limits.maxTotalBytes) throw failure('BEPACK_RESOURCE_LIMIT', 'Archive exceeds the total byte budget');
      if (compressedSize > 0 && size / compressedSize > limits.maxCompressionRatio) throw failure('BEPACK_RESOURCE_LIMIT', 'Compression ratio limit exceeded: ' + name);
      entries.push({ path: name, directory: false, flags, method, size, compressedSize, crc, localOffset, attributes });
    }
    if (cursor !== directory.length) throw failure('BEPACK_ARCHIVE_INVALID', 'Unexpected central directory trailing bytes');
    const ranges = [];
    const pathAncestors = new Map();
    for (const entry of entries) {
      let ancestor = '';
      for (const part of entry.path.replace(/\/+$/, '').split('/')) { ancestor = ancestor ? ancestor + '/' + part : part; const key = collisionKey(ancestor); const prior = pathAncestors.get(key); if (prior !== undefined && prior !== ancestor) throw failure('BEPACK_PATH_UNSAFE', 'Case-folding ancestor collision'); pathAncestors.set(key, ancestor); if (ancestor !== entry.path.replace(/\/+$/, '') && names.has(key) && !names.get(key).endsWith('/')) throw failure('BEPACK_PATH_UNSAFE', 'File overlaps directory ancestor'); }
      if (!Number.isSafeInteger(entry.localOffset) || entry.localOffset < 0) throw failure('BEPACK_ARCHIVE_INVALID', 'Invalid local header offset');
      const header = await readRange(handle, entry.localOffset, 30);
      if (header.readUInt32LE(0) !== 0x04034b50) throw failure('BEPACK_ARCHIVE_INVALID', 'Bad local header for ' + entry.path);
      const localFlags = header.readUInt16LE(6);
      const localMethod = header.readUInt16LE(8);
      const localCrc = header.readUInt32LE(14);
      const localCompressed = header.readUInt32LE(18);
      const localSize = header.readUInt32LE(22);
      const nameLength = header.readUInt16LE(26);
      const extraLength = header.readUInt16LE(28);
      const localName = (await readRange(handle, entry.localOffset + 30, nameLength)).toString('utf8');
      if (localName !== entry.path || localMethod !== entry.method || localFlags !== entry.flags) throw failure('BEPACK_ARCHIVE_INVALID', 'Local header disagrees with the central directory: ' + entry.path);
      if (localCrc !== entry.crc || localCompressed !== (entry.compressedSize >= ZIP64_LIMIT ? ZIP64_LIMIT : entry.compressedSize) || localSize !== (entry.size >= ZIP64_LIMIT ? ZIP64_LIMIT : entry.size)) throw failure('BEPACK_ARCHIVE_INVALID', 'Local header sizes or CRC disagree: ' + entry.path);
      if (entry.localOffset + 30 + nameLength + extraLength + entry.compressedSize > directoryOffset) throw failure('BEPACK_ARCHIVE_INVALID', 'Entry data overlaps the central directory: ' + entry.path);
      entry.dataOffset = entry.localOffset + 30 + nameLength + extraLength;
      ranges.push([entry.localOffset, entry.dataOffset + entry.compressedSize]);
    }
    ranges.sort((a,b)=>a[0]-b[0]);
    let next = 0; for (const [start,end] of ranges) { if (start !== next) throw failure('BEPACK_ARCHIVE_INVALID', 'Overlapping, gapped, or hidden archive entries'); next = end; }
    if (next !== directoryOffset) throw failure('BEPACK_ARCHIVE_INVALID', 'Hidden bytes before central directory');
    entries.sort((a, b) => Buffer.compare(Buffer.from(a.path, 'utf8'), Buffer.from(b.path, 'utf8')));
    return { file, size: info.size, entries, handle, limits, close: () => handle.close() };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

export async function streamZipEntry(zip, entry, onChunk) {
  let crc = CRC32_INITIAL, size = 0;
  const source = async function* () {
    const remaining = entry.compressedSize;
    const chunk = Math.min(Math.max(remaining, 1), 1 << 20);
    let position = 0;
    while (position < remaining) {
      const length = Math.min(chunk, remaining - position);
      const buffer = Buffer.alloc(length);
      let filled = 0;
      while (filled < length) {
        const { bytesRead } = await zipHandleRead(zip, buffer, filled, length - filled, entry.dataOffset + position + filled);
        if (!bytesRead) throw failure('BEPACK_ARCHIVE_INVALID', 'Truncated entry data: ' + entry.path);
        filled += bytesRead;
      }
      position += length;
      yield buffer;
    }
  };
  const meter = new Writable({
    write(chunk, _encoding, callback) { size += chunk.length; if (size > entry.size || size > zip.limits.maxFileBytes) return callback(failure('BEPACK_RESOURCE_LIMIT', 'Inflated bytes exceed declared budget: ' + entry.path)); crc = crc32Update(crc, chunk); Promise.resolve().then(() => onChunk(chunk)).then(() => callback(), callback); },
  });
  const stages = [source()];
  if (entry.method === 8) stages.push(createInflateRaw());
  stages.push(meter);
  await pipeline(stages);
  crc = (crc ^ 0xffffffff) >>> 0;
  if (size !== entry.size || crc !== entry.crc) throw failure('BEPACK_ARCHIVE_INVALID', 'Entry content does not match its recorded size or CRC: ' + entry.path);
  return { size, crc };
}

async function zipHandleRead(zip, buffer, offset, length, position) {
  if (!zip?.handle) throw failure('BEPACK_ARCHIVE_INVALID', 'Archive handle is not open');
  return zip.handle.read(buffer, offset, length, position);
}

export async function readZipEntry(zip, entry, { maxBytes = DEFAULT_LIMITS.maxManifestBytes } = {}) {
  if (entry.size > maxBytes) throw failure('BEPACK_RESOURCE_LIMIT', 'Entry exceeds the read budget: ' + entry.path);
  const chunks = [];
  await streamZipEntry(zip, entry, chunk => { chunks.push(Buffer.from(chunk)); });
  return Buffer.concat(chunks);
}

export async function hashZipEntry(zip, entry, algorithm = 'sha256') {
  const hash = createHash(algorithm);
  const result = await streamZipEntry(zip, entry, chunk => { hash.update(chunk); });
  return { size: result.size, sha256: hash.digest('hex') };
}

export async function extractZip(zip, destination, { only } = {}) {
  if (!zip?.handle) throw failure('BEPACK_ARCHIVE_INVALID', 'Archive handle is not open');
  destination = path.resolve(destination);
  await ensureSafeDirectory(path.dirname(destination));
  await mkdir(destination); // Extraction requires a NEW directory, never an existing tree.
  const written = [];
  for (const entry of zip.entries) {
    if (only && !only(entry)) continue;
    if (!safeRelative(entry.path.replace(/\/+$/, ''))) throw failure('BEPACK_PATH_UNSAFE', 'Unsafe extraction path: ' + entry.path);
    const target = path.join(destination, ...entry.path.split('/'));
    if (entry.directory) { await ensureSafeDirectory(target); written.push({ path: entry.path, directory: true }); continue; }
    await ensureSafeDirectory(path.dirname(target));
    const hash = createHash('sha256');
    const handle = await open(target, 'wx');
    try {
      await streamZipEntry(zip, entry, async chunk => { hash.update(chunk); await handle.write(chunk); });
    } finally { await handle.close(); }
    written.push({ path: entry.path, directory: false, size: entry.size, sha256: hash.digest('hex') });
  }
  return written;
}
