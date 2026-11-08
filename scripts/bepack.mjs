#!/usr/bin/env node
import path from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import { validateProject } from '../tools/bepack-tool/src/validate.mjs';
import { buildPackage } from '../tools/bepack-tool/src/build.mjs';
import { inspectPackage } from '../tools/bepack-tool/src/inspect.mjs';
import { verifyPackage } from '../tools/bepack-tool/src/verify.mjs';
import { computeScanPlan } from '../tools/bepack-tool/src/scan-plan.mjs';
import { resolveProject } from '../tools/bepack-tool/src/resolve.mjs';
const commands = {
  validate: ['project', 'report'], resolve: ['project', 'metadata-dir', 'report'],
  build: ['project', 'output', 'frozen', 'runtime-catalog', 'runtime-catalog-sha256', 'generated-at', 'metadata-dir', 'staging-dir'],
  inspect: ['package', 'extract'], verify: ['package', 'report'], 'scan-plan': ['package', 'output'],
};
const fail = message => { throw Object.assign(new Error(message), { diagnostic: 'BEPACK_ARGUMENT_INVALID' }); };
async function output(file, value) {
  const destination = path.resolve(file);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
}
async function main(args) {
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) {
    console.log('Usage: node scripts/bepack.mjs <validate|resolve|build|inspect|verify|scan-plan> [options]\nbuild: --project DIR --output DIR --frozen --runtime-catalog FILE --runtime-catalog-sha256 HEX\ninspect/verify: --package FILE; scan-plan: --package FILE --output FILE'); return 0;
  }
  const command = args.shift();
  if (!Object.hasOwn(commands, command)) fail('Unknown command; use --help');
  const options = {};
  while (args.length) {
    const key = args.shift(), name = key?.startsWith('--') ? key.slice(2) : '';
    if (!commands[command].includes(name) || Object.hasOwn(options, name)) fail('Invalid or repeated option: ' + key);
    if (name === 'frozen') options[name] = true;
    else { if (!args.length || args[0].startsWith('--')) fail('Missing value for ' + key); options[name] = args.shift(); }
  }
  const required = ['validate', 'resolve', 'build'].includes(command) ? 'project' : 'package';
  if (!options[required]) fail('--' + required + ' is required');
  if (['build', 'scan-plan'].includes(command) && !options.output) fail('--output is required');
  let report;
  if (command === 'validate') report = await validateProject(path.resolve(options.project));
  else if (command === 'resolve') report = await resolveProject({ project: options.project, metadataDirectory: options['metadata-dir'] });
  else if (command === 'build') report = await buildPackage({ project: options.project, output: options.output, frozen: options.frozen, runtimeCatalog: options['runtime-catalog'], runtimeCatalogSha256: options['runtime-catalog-sha256'], generatedAt: options['generated-at'], metadataDirectory: options['metadata-dir'], stagingDirectory: options['staging-dir'] });
  else if (command === 'inspect') report = await inspectPackage(options);
  else if (command === 'verify') report = await verifyPackage(options);
  else {
    const verification = await verifyPackage(options);
    if (!verification.valid) { process.stdout.write(JSON.stringify(verification, null, 2) + '\n'); return 2; }
    report = (await computeScanPlan(options.package)).plan;
    await output(options.output, report);
  }
  if (options.report) await output(options.report, report);
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  return report.valid === false ? 2 : 0;
}
try { process.exitCode = await main(process.argv.slice(2)); }
catch (error) {
  process.stderr.write(JSON.stringify({ code: error.diagnostic ?? error.code ?? 'BEPACK_TOOL_ERROR', message: error.message }) + '\n');
  process.exitCode = error.exitCode ?? (error.diagnostic ? 2 : ['ENOENT', 'EACCES', 'EEXIST', 'ENOSPC'].includes(error.code) ? 3 : 1);
}