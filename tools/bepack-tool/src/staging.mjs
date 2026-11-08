import path from 'node:path';
import { lstat, mkdir } from 'node:fs/promises';
const unsafe = message => Object.assign(new Error(message), { diagnostic: 'BEPACK_PATH_UNSAFE' });
// Never traverse a link/reparse-point ancestor supplied by the caller. All
// temporary consumers create a unique child; callers' existing trees are not deleted.
export async function ensureSafeDirectory(directory) {
  const absolute = path.resolve(directory);
  const root = path.parse(absolute).root;
  let current = root;
  for (const part of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    let info;
    try { info = await lstat(current); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      try { await mkdir(current); } catch (race) { if (race.code !== 'EEXIST') throw race; }
      info = await lstat(current);
    }
    if (!info.isDirectory() || info.isSymbolicLink()) throw unsafe('Unsafe directory ancestor: ' + current);
  }
  return absolute;
}