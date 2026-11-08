import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { realpath } from 'node:fs/promises';
import Ajv2020 from 'ajv/dist/2020.js';
import parseLicense from 'spdx-expression-parse';
import { readStrictJSON } from './strict-json.mjs';
import { safeRelative, collisionKey, inspectProjectPath, createInspectionState } from './paths.mjs';

const schemaDirectory = fileURLToPath(new URL('../../../schemas/', import.meta.url));
let validators;
async function loadValidators() {
  if (!validators) validators = (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    ajv.addFormat('uri', value => { try { new URL(value); return !/[\s\x00-\x1f]/u.test(value); } catch { return false; } });
    return {
      manifest: ajv.compile(await readStrictJSON(path.join(schemaDirectory, 'bepack.schema.json'))),
      combination: ajv.compile(await readStrictJSON(path.join(schemaDirectory, 'version-set.schema.json'))),
    };
  })();
  return validators;
}
const entries = value => Object.entries(value).filter(([key]) => key !== 'extensions');
const owned = (object, key) => Object.hasOwn(object, key) ? object[key] : undefined;
const pointer = value => String(value).replaceAll('~', '~0').replaceAll('/', '~1');
const codes = { manifest: 'BEPACK_MANIFEST_INVALID', combination: 'BEPACK_VERSION_SET_INVALID' };
export function matchesVersion(version, requirement) {
  if (requirement.exact !== undefined) return version === requirement.exact;
  const range = requirement.range;
  const numeric = value => /^(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2,3}$/.test(value);
  if (!numeric(version) || !numeric(range.min) || !numeric(range.max)) return false;
  const parts = value => value.split('.').map(BigInt);
  const a = parts(version), min = parts(range.min), max = parts(range.max);
  if (a.length !== min.length || min.length !== max.length) return false;
  const compare = (x, y) => { for (let i = 0; i < x.length; i++) { if (x[i] < y[i]) return -1; if (x[i] > y[i]) return 1; } return 0; };
  return compare(a, min) >= (range.include_min ? 0 : 1) && compare(a, max) <= (range.include_max ? 0 : -1);
}
export async function validateProject(project) {
  const diagnostics = [];
  const inspection = createInspectionState();
  const add = (code, message, file, field = '', extra = {}) => diagnostics.push({ severity: 'error', code, message, file, field, ...extra });
  let root;
  try { root = await realpath(project); } catch (error) {
    add('BEPACK_FILE_MISSING', error.message, 'bepack.json'); return finish();
  }
  async function read(relative, kind) {
    try {
      await inspectProjectPath(root, relative, { state: inspection });
      return await readStrictJSON(path.join(root, relative));
    } catch (error) {
      add(error.diagnostic ?? (error.code === 'ENOENT' ? 'BEPACK_FILE_MISSING' : codes[kind]), error.message, relative);
      return null;
    }
  }
  function checkSchema(value, kind, file, validate) {
    if (value.schema_version !== 1) {
      add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', file, '/schema_version'); return false;
    }
    if (validate(value)) return true;
    for (const e of validate.errors) add(codes[kind], `${e.message}${e.params.additionalProperty ? ': ' + e.params.additionalProperty : ''}`, file, e.instancePath + (e.keyword === 'required' ? '/' + pointer(e.params.missingProperty) : ''));
    if (kind === 'manifest') {
      const collections = value.targets && typeof value.targets === 'object' ? entries(value.targets).map(([, v]) => v) : [];
      if (collections.length && collections.every(v => v && v.enabled === false)) add('BEPACK_TARGET_UNAVAILABLE', 'At least one target collection must be enabled', file, '/targets');
      if (Array.isArray(value.dependencies)) for (const [i, d] of value.dependencies.entries()) {
        if (d?.resolver === 'direct' && !d.compatibility) add('BEPACK_COMPATIBILITY_UNKNOWN', 'Direct dependency requires explicit compatibility', file, '/dependencies/' + i + '/compatibility');
      }
    }
    return false;
  }
  const manifest = await read('bepack.json', 'manifest');
  if (!manifest) return finish();
  const schemas = await loadValidators();
  if (!checkSchema(manifest, 'manifest', 'bepack.json', schemas.manifest)) return finish();
  const setFile = `versions/${manifest.version_set}.json`;
  const combination = await read(setFile, 'combination');
  if (!combination || !checkSchema(combination, 'combination', setFile, schemas.combination)) return finish();
  if (combination.id !== manifest.version_set) add(codes.combination, 'Combination ID does not match version_set', setFile, '/id');
  const globalCapabilities = manifest.requires ?? [];
  const allTargets = new Map(), activeTargets = new Map(), targetFields = new Map();
  function location(id, property) {
    if (property && owned(combination.targets, id) && Object.hasOwn(combination.targets[id], property)) return { file: setFile, field: '/targets/' + pointer(id) + '/' + property };
    if (property === 'game_version' && allTargets.get(id)?.game_version == null) return { file: 'bepack.json', field: '/game_version' };
    return { file: 'bepack.json', field: targetFields.get(id) + (property ? '/' + property : '') };
  }
  for (const [group, collection] of entries(manifest.targets)) {
    if (group.startsWith('x-') && !globalCapabilities.length) add(codes.manifest, 'Extension collection requires a global capability', 'bepack.json', '/requires');
    const pairs = new Set();
    for (const [id, variant] of entries(collection.variants)) {
      const field = `/targets/${pointer(group)}/variants/${pointer(id)}`;
      if (allTargets.has(id)) add(codes.manifest, 'Target IDs must be globally unique', 'bepack.json', field, { target: id });
      allTargets.set(id, variant);
      targetFields.set(id, field);
      if (variant.loader.version) requirement(variant.loader.version, 'bepack.json', field + '/loader/version');
      if (variant.client) requirement(variant.client.version, 'bepack.json', field + '/client/version');
      const pair = variant.platform + '/' + variant.runtime;
      if (pairs.has(pair)) add(codes.manifest, 'Duplicate platform/runtime within collection', 'bepack.json', field, { target: id });
      pairs.add(pair);
      if (collection.enabled) activeTargets.set(id, variant);
      const capabilities = [...globalCapabilities, ...(variant.requires ?? [])];
      if ((variant.platform.startsWith('x-') || variant.runtime.startsWith('x-')) && !capabilities.length) add(codes.manifest, 'Extended target requires an adapter capability', 'bepack.json', field, { target: id });
      if (group === 'linux' && !(variant.requires ?? []).length) add(codes.manifest, 'Linux external client requires a target-scoped adapter capability', 'bepack.json', field + '/requires', { target: id });
    }
  }
  if (!activeTargets.size) add('BEPACK_TARGET_UNAVAILABLE', 'At least one target collection must be enabled', 'bepack.json', '/targets');
  for (const [target, override] of entries(combination.targets)) {
    for (const property of ['loader', 'client']) if (override[property]?.version) requirement(override[property].version, setFile, '/targets/' + pointer(target) + '/' + property + '/version');
    if (!activeTargets.has(target)) add(codes.combination, 'Combination refers to an unknown or disabled target', setFile, '/targets/' + pointer(target), { target });
    if (manifest.mode === 'mods-only' && Object.hasOwn(override, 'game_version')) add(codes.combination, 'mods-only must not bind a game version', setFile, '/targets/' + pointer(target) + '/game_version', { target });
  }
  const effective = new Map();
  for (const [id, original] of activeTargets) {
    const override = owned(combination.targets, id) ?? {};
    const variant = { ...original, ...override, game_version: override.game_version ?? original.game_version ?? manifest.game_version };
    effective.set(id, variant);
    const mode = manifest.mode;
    const issue = (property, message) => { const p = location(id, property); add(p.file === setFile ? codes.combination : codes.manifest, message, p.file, p.field, { target: id }); };
    if ((mode === 'full' && variant.loader.type !== 'none') || (mode === 'modded' && variant.loader.type !== 'levilamina')) issue('loader', 'Effective loader contradicts the pack mode');
    if ((['full', 'modded'].includes(mode) && variant.client !== null) || (mode === 'client' && variant.client === null)) issue('client', 'Effective client contradicts the pack mode');
    if (mode !== 'mods-only' && variant.game_version === null) issue('game_version', 'Bound mode requires a concrete game version');
    if (variant.runtime === 'external-client' && !variant.client) issue('client', 'External runtime requires a declared client');
    if (variant.loader.type.startsWith('x-') && !(variant.requires ?? []).length) issue('loader', 'Custom loader requires target-scoped adapter capability');
  }

  const dependencies = new Map();
  function references(ids, file, field) {
    for (const id of ids) if (!allTargets.has(id)) add(codes.manifest, 'Unknown target reference: ' + id, file, field, { target: id });
  }
  function https(value, file, field, { fragment = false } = {}) {
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password || (!fragment && url.hash)) throw new Error();
    } catch { add(codes.manifest, 'Expected absolute HTTPS URL without credentials' + (fragment ? '' : ' or fragment'), file, field); }
  }
  async function license(subject, field, bundled) {
    if (subject.license) {
      try { parseLicense(subject.license); } catch { add('BEPACK_LICENSE_INVALID', 'Invalid SPDX expression or LicenseRef', 'bepack.json', field + '/license'); }
    }
    if (bundled && (!subject.license?.trim() || subject.redistribution_confirmed !== true)) add('BEPACK_LICENSE_INVALID', 'Bundled dependency requires a license and redistribution confirmation', 'bepack.json', field);
    if (subject.license?.includes('LicenseRef-') && (!field || bundled) && !subject.license_file) add('BEPACK_LICENSE_INVALID', 'Custom redistributed license requires a license file', 'bepack.json', field + '/license_file');
    if (subject.license_file) await filePath(subject.license_file, 'licenses', field + '/license_file', false);
    if (subject.license_url) https(subject.license_url, 'bepack.json', field + '/license_url', { fragment: true });
  }
  async function filePath(relative, prefix, field, allowDirectory) {
    if (!safeRelative(relative, { prefix })) { add('BEPACK_PATH_UNSAFE', 'Unsafe or incorrectly rooted file path', 'bepack.json', field); return null; }
    try {
      const result = await inspectProjectPath(root, relative, { state: inspection });
      if (!allowDirectory && result.directory) add('BEPACK_CONTENT_INVALID', 'Expected a regular file', 'bepack.json', field);
      return result;
    } catch (error) { add(error.diagnostic ?? (error.code === 'ENOENT' ? 'BEPACK_FILE_MISSING' : 'BEPACK_CONTENT_INVALID'), error.message, 'bepack.json', field); return null; }
  }
  function requirement(req, file, field) {
    if (req?.range) {
      const r = req.range;
      const nums = s => s.split('.').map(BigInt);
      const valid = value => /^(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2,3}$/.test(value);
      if (!valid(r.min) || !valid(r.max)) { add(codes.manifest, 'Invalid numeric version interval', file, field); return; }
      const a = nums(r.min), b = nums(r.max);
      const cmp = a.reduce((value, n, i) => value || (n < b[i] ? -1 : n > b[i] ? 1 : 0), 0);
      if (a.length !== b.length || cmp > 0 || (cmp === 0 && (!r.include_min || !r.include_max))) add(codes.manifest, 'Version interval is empty, reversed, or uses unequal component counts', file, field);
    }
  }
  function compatibility(subject, field) {
    if (!subject.compatibility) return;
    references(entries(subject.compatibility.targets).map(([id]) => id), 'bepack.json', field + '/compatibility/targets');
    for (const [target, entry] of entries(subject.compatibility.targets)) {
      const p = `${field}/compatibility/targets/${pointer(target)}`;
      if (!subject.targets.includes(target)) add(codes.manifest, 'Compatibility target is outside subject target set', 'bepack.json', p);
      for (const property of ['loader', 'client']) if (entry[property]) requirement(entry[property].version, 'bepack.json', p + '/' + property + '/version');
      if (/^https:/i.test(entry.evidence.reference)) https(entry.evidence.reference, 'bepack.json', p + '/evidence/reference', { fragment: true });
      else if (!safeRelative(entry.evidence.reference)) add('BEPACK_PATH_UNSAFE', 'Evidence reference must be HTTPS or a safe package path', 'bepack.json', p + '/evidence/reference');
    }
  }
  if (manifest.repository) https(manifest.repository, 'bepack.json', '/repository', { fragment: true });
  if (manifest.author.url) https(manifest.author.url, 'bepack.json', '/author/url', { fragment: true });
  await license(manifest, '', false);
  for (const [i, dependency] of manifest.dependencies.entries()) {
    const field = '/dependencies/' + i;
    if (dependencies.has(dependency.id)) add(codes.manifest, 'Duplicate dependency ID', 'bepack.json', field + '/id', { dependency: dependency.id });
    dependencies.set(dependency.id, dependency);
    references(dependency.targets, 'bepack.json', field + '/targets');
    https(dependency.source, 'bepack.json', field + '/source');
    requirement(dependency.version, 'bepack.json', field + '/version');
    await license(dependency, field, dependency.bundled);
    compatibility(dependency, field);
    const active = dependency.targets.some(id => activeTargets.has(id));
    const selected = owned(combination.dependencies, dependency.id);
    if (active && (!selected || !matchesVersion(selected, dependency.version))) add(codes.combination, 'Missing exact selection or selected version does not satisfy requirement', setFile, '/dependencies/' + pointer(dependency.id), { dependency: dependency.id });
    if (!['direct', 'bepack-metadata'].includes(dependency.resolver) && !globalCapabilities.length) add(codes.manifest, 'Custom resolver requires a declared capability', 'bepack.json', field + '/resolver');
    if (dependency.resolver === 'direct') {
      if (!dependency.compatibility || dependency.targets.some(id => activeTargets.has(id) && !owned(dependency.compatibility.targets, id))) add('BEPACK_COMPATIBILITY_UNKNOWN', 'Direct dependency requires explicit compatibility for every active target', 'bepack.json', field + '/compatibility', { dependency: dependency.id });
      if (dependency.bundled && manifest.contents.some(c => c.source === 'dependency' && c.dependency === dependency.id) && dependency.direct.mounts.length) add(codes.manifest, 'Content-owned bundled artifact must not mount a second time', 'bepack.json', field + '/direct/mounts');
      for (const [index, mount] of dependency.direct.mounts.entries()) {
        if (!safeRelative(mount.source, { dot: true }) || !safeRelative(mount.destination) || (dependency.direct.format === 'file' && mount.source !== '.')) add('BEPACK_PATH_UNSAFE', 'Invalid direct artifact mount', 'bepack.json', `${field}/direct/mounts/${index}`);
        checkSlot(mount.slot, dependency.targets, field + '/direct/mounts/' + index);
      }
    }
  }
  for (const id of entries(combination.dependencies).map(([id]) => id)) {
    const dependency = dependencies.get(id);
    if (!dependency || !dependency.targets.some(t => activeTargets.has(t))) add(codes.combination, 'Selection references unknown or unpublished dependency', setFile, '/dependencies/' + pointer(id), { dependency: id });
  }
  for (const [target, variant] of effective) if (variant.client) {
    const d = dependencies.get(variant.client.dependency);
    const selected = owned(combination.dependencies, variant.client.dependency);
    if (!d || d.role !== 'client' || !d.targets.includes(target) || !selected || !matchesVersion(selected, variant.client.version)) {
      const p = location(target, 'client');
      add(p.file === setFile ? codes.combination : codes.manifest, 'Client must reference matching role=client dependency and exact selection', p.file, p.field, { target });
    }
  }
  function checkSlot(slot, targets, field) {
    for (const target of targets) {
      const v = effective.get(target); if (!v) continue;
      if ((slot === 'plugins' && (v.runtime !== 'bedrock-server' || v.loader.type !== 'levilamina')) || (slot === 'native-mods' && (v.runtime === 'bedrock-server' || v.loader.type === 'none')) || (slot === 'client-components' && v.client === null)) add('BEPACK_CONTENT_INVALID', 'Content slot contradicts target loader/client/runtime', 'bepack.json', field, { target });
      if (manifest.mode === 'full' && ['plugins', 'native-mods', 'client-components'].includes(slot)) add('BEPACK_CONTENT_INVALID', 'full mode cannot install executable dependency mounts', 'bepack.json', field, { target });
    }
  }
  const contents = new Map();
  const slots = { 'resource-pack': 'resource-packs', 'behavior-pack': 'behavior-packs', world: 'worlds', config: 'configs', 'll-plugin': 'plugins', 'native-mod': 'native-mods', 'client-component': 'client-components' };
  for (const [i, content] of manifest.contents.entries()) {
    const field = '/contents/' + i;
    if (contents.has(content.id)) add(codes.manifest, 'Duplicate content ID', 'bepack.json', field + '/id', { content: content.id });
    contents.set(content.id, content);
    references(content.targets, 'bepack.json', field + '/targets');
    if (!safeRelative(content.destination)) add('BEPACK_PATH_UNSAFE', 'Unsafe destination path', 'bepack.json', field + '/destination');
    const result = await filePath(content.path, 'payload', field + '/path', content.category !== 'config');
    if (result && ['resource-pack', 'behavior-pack', 'world'].includes(content.category) && !result.directory) add('BEPACK_CONTENT_INVALID', 'Pack/world content must be a normalized directory, not an archive', 'bepack.json', field + '/path');
    if (content.source === 'dependency') {
      const d = dependencies.get(content.dependency);
      if (!d?.bundled || content.targets.some(t => !d.targets.includes(t))) add(codes.manifest, 'Dependency content must reference a bundled dependency covering its targets', 'bepack.json', field + '/dependency');
    }
    checkSlot(slots[content.category], content.targets, field);
    compatibility(content, field);
  }
  const replaced = new Set();
  for (const [id, content] of contents) {
    if (!content.replaces) continue;
    const shared = contents.get(content.replaces);
    if (!shared || shared.replaces || content.replaces === id || shared.category !== content.category || shared.destination !== content.destination || shared.targets.length <= content.targets.length || content.targets.some(t => !shared.targets.includes(t))) add(codes.manifest, 'Replacement must be a more specific item with matching category/destination and no chain', 'bepack.json', '/contents', { content: id });
    for (const target of content.targets) {
      const key = target + '/' + content.replaces;
      if (replaced.has(key)) add('BEPACK_DESTINATION_CONFLICT', 'More than one replacement for target/content', 'bepack.json', '/contents', { content: id, target });
      replaced.add(key);
    }
  }
  for (const target of activeTargets.keys()) {
    const destinations = [], destinationNames = new Map();
    function claim(slot, destination, field, extra) {
      let prefix = slot;
      for (const part of destination.split('/')) {
        prefix += '/' + part;
        const folded = collisionKey(prefix), previous = destinationNames.get(folded);
        if (previous !== undefined && previous !== prefix) add('BEPACK_DESTINATION_CONFLICT', 'Case-folding destination ancestor collision', 'bepack.json', field, { target, ...extra });
        destinationNames.set(folded, prefix);
      }
      const key = slot + '/' + collisionKey(destination);
      if (destinations.some(previous => key === previous || key.startsWith(previous + '/') || previous.startsWith(key + '/'))) add('BEPACK_DESTINATION_CONFLICT', 'Overlapping installation destinations', 'bepack.json', field, { target, ...extra });
      destinations.push(key);
    }
    for (const [i, d] of manifest.dependencies.entries()) if (d.resolver === 'direct' && d.targets.includes(target)) {
      for (const [j, mount] of d.direct.mounts.entries()) claim(mount.slot, mount.destination, '/dependencies/' + i + '/direct/mounts/' + j, { dependency: d.id });
    }
    for (const [i, content] of manifest.contents.entries()) {
      if (!content.targets.includes(target) || replaced.has(target + '/' + content.id)) continue;
      claim(slots[content.category], content.destination, '/contents/' + i, { content: content.id });
    }
  }
  return finish();

  function finish() {
    const errors = diagnostics.filter(d => d.severity === 'error').length;
    return {
      schema_version: 1, command: 'validate', scope: 'offline-project', valid: errors === 0,
      release_checked: false,
      summary: { errors, warnings: diagnostics.filter(d => d.severity === 'warning').length }, diagnostics,
      unchecked: ['network-resolution-and-ssrf', 'runtime-catalog-and-compatibility-intersection', 'upstream-content-formats-and-world-references', 'adapter-config-whitelist-and-native-layout', 'archive-and-lock-integrity', 'release-projection-and-scanning', 'race-free-filesystem-installation'],
    };
  }
}