import path from 'node:path';
import { lstat, readdir } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const foldingBytes = readFileSync(new URL('./data/CaseFolding-17.0.0.txt', import.meta.url));
if (createHash('sha256').update(foldingBytes).digest('hex') !== 'ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183') throw new Error('Unicode folding data integrity mismatch');
const folding = new Map();
for (const line of foldingBytes.toString('utf8').split('\n')) {
  const match = /^([0-9A-F]+); ([CF]); ([0-9A-F ]+);/.exec(line);
  if (match) folding.set(parseInt(match[1], 16), String.fromCodePoint(...match[3].trim().split(' ').map(x => parseInt(x, 16))));
}

export function safeRelative(value, { prefix, dot = false } = {}) {
  if (dot && value === '.') return true;
  if (typeof value !== 'string' || !value || !value.isWellFormed() || value !== value.normalize('NFC') || Buffer.byteLength(value) > 1024) return false;
  const parts = value.split('/');
  if (parts.length > 32 || (prefix && !value.startsWith(prefix + '/'))) return false;
  return parts.every(part => part && part !== '.' && part !== '..' && Buffer.byteLength(part) <= 255
    && !/[\x00-\x1f\x7f-\x9f<>:"|?*\\]/u.test(part) && !/[ .]$/.test(part)
    && !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part));
}

// Unicode 17.0 default full case folding uses C + F mappings; excludes Turkic T.
export const collisionKey = value => Array.from(value, c => folding.get(c.codePointAt(0)) ?? c).join('').normalize('NFC');

export const createInspectionState = () => ({ names: new Map(), counted: new Set(), completed: new Map(), files: 0, bytes: 0 });

export async function inspectProjectPath(root, relative, { maxFiles = 100000, maxBytes = 32 * 1024 ** 3, state = createInspectionState() } = {}) {
  if (!safeRelative(relative)) throw Object.assign(new Error('Unsafe relative path'), { diagnostic: 'BEPACK_PATH_UNSAFE' });
  function register(rel) {
    const key = collisionKey(rel), previous = state.names.get(key);
    if (previous !== undefined && previous !== rel) throw Object.assign(new Error('Case-folding path collision: ' + previous + ' / ' + rel), { diagnostic: 'BEPACK_PATH_UNSAFE' });
    state.names.set(key, rel);
    if (state.names.size > 200000) throw Object.assign(new Error('Filesystem entry budget exceeded'), { diagnostic: 'BEPACK_RESOURCE_LIMIT' });
  }
  if (state.completed.has(relative)) return state.completed.get(relative);
  let location = root, ancestor = '';
  for (const part of relative.split('/')) {
    ancestor = ancestor ? ancestor + '/' + part : part; register(ancestor);
    location = path.join(location, part);
    const stat = await lstat(location);
    if (stat.isSymbolicLink() || (!stat.isDirectory() && (!stat.isFile() || stat.nlink > 1))) {
      throw Object.assign(new Error('Links and special filesystem objects are forbidden'), { diagnostic: 'BEPACK_PATH_UNSAFE' });
    }
  }
  const initial = await lstat(location);
  let files = 0, bytes = 0;

  async function visit(absolute, rel) {
    if (!safeRelative(rel)) throw Object.assign(new Error('Unsafe content tree path'), { diagnostic: 'BEPACK_PATH_UNSAFE' });
    register(rel);
    const stat = await lstat(absolute);
    if (stat.isSymbolicLink() || (!stat.isDirectory() && (!stat.isFile() || stat.nlink > 1))) throw Object.assign(new Error('Links and special files forbidden'), { diagnostic: 'BEPACK_PATH_UNSAFE' });
    if (stat.isDirectory()) {
      for (const entry of await readdir(absolute)) await visit(path.join(absolute, entry), rel + '/' + entry);
    } else {
      files++; bytes += stat.size;
      if (!state.counted.has(rel)) { state.counted.add(rel); state.files++; state.bytes += stat.size; }
      if (stat.size > 8 * 1024 ** 3 || state.files > maxFiles || state.bytes > maxBytes) throw Object.assign(new Error('Content resource budget exceeded'), { diagnostic: 'BEPACK_RESOURCE_LIMIT' });
    }
  }
  await visit(location, relative);
  const result = { files, bytes, directory: initial.isDirectory(), absolute: location };
  state.completed.set(relative, result);
  return result;
}