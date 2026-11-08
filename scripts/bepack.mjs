#!/usr/bin/env node
import path from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import { validateProject } from '../tools/bepack-tool/src/validate.mjs';

async function main(args) {
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) {
    console.log('Usage: node scripts/bepack.mjs validate --project <directory> [--report <new-file>]\nOffline project validation only; does not certify release or installation readiness.');
    return 0;
  }
  if (args.shift() !== 'validate') throw Object.assign(new Error('Only validate is implemented. Use --help for usage.'), { input: true });
  const options = new Map();
  while (args.length) {
    const key = args.shift();
    if (!['--project', '--report'].includes(key) || options.has(key) || !args.length || args[0].startsWith('--')) throw Object.assign(new Error('Invalid or repeated option: ' + key), { input: true });
    options.set(key, args.shift());
  }
  if (!options.has('--project')) throw Object.assign(new Error('--project is required'), { input: true });
  const report = await validateProject(path.resolve(options.get('--project')));
  const text = JSON.stringify(report, null, 2) + '\n';
  if (options.has('--report')) {
    const destination = path.resolve(options.get('--report'));
    await mkdir(path.dirname(destination), { recursive: true });
    // Reports are additive outputs; never overwrite an author file or an existing report.
    await writeFile(destination, text, { encoding: 'utf8', flag: 'wx' });
  }
  process.stdout.write(text);
  return report.valid ? 0 : 2;
}
try { process.exitCode = await main(process.argv.slice(2)); }
catch (error) {
  process.stderr.write(JSON.stringify({ code: error.input ? 'BEPACK_ARGUMENT_INVALID' : 'BEPACK_TOOL_ERROR', message: error.message }) + '\n');
  process.exitCode = error.input ? 2 : 1;
}