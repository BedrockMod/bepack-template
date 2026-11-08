import { createHash } from 'node:crypto';
import { safeRelative, collisionKey } from './paths.mjs';
import { matchesVersion } from './validate.mjs';
const fail = message => { throw Object.assign(new Error(message), { diagnostic: 'BEPACK_LOCK_MISMATCH' }); };
const entries = object => Object.entries(object).filter(([key]) => key !== 'extensions');
function index(records, key, label) {
  const result = new Map();
  for (const item of records) { const id=item[key]; if (result.has(id)) fail('Duplicate ' + label + ': ' + id); result.set(id,item); }
  return result;
}
function sameSet(actual, expected, label) {
  if (new Set(actual).size !== actual.length || actual.length !== expected.length || actual.some(id=>!expected.includes(id))) fail(label + ' does not match published manifest closure');
}
function compatible(entry, configuration) {
  if (!(entry.games.unconstrained || entry.games.versions.includes(configuration.game_version))) return false;
  if (entry.loader && (entry.loader.type !== configuration.loader.type || !configuration.loader.version || !matchesVersion(configuration.loader.version,entry.loader.version))) return false;
  if (entry.client && (!configuration.client || entry.client.id !== configuration.client.id || !matchesVersion(configuration.client.version,entry.client.version))) return false;
  return true;
}
export function assertLockClosure(manifest, combination, lock) {
  const files=index(lock.files,'path','file path');
  const folded=new Set();
  for (const file of lock.files) { if (!safeRelative(file.path) || file.path==='bepack.lock.json' || folded.has(collisionKey(file.path))) fail('Unsafe or duplicate locked file: '+file.path); folded.add(collisionKey(file.path)); }
  const dependencies=index(manifest.dependencies,'id','dependency');
  const contents=index(manifest.contents,'id','content');
  const artifacts=index(lock.artifacts,'id','artifact');
  const runtimes=index(lock.runtimes,'id','runtime');
  const evidence=index(lock.evidence,'id','evidence');
  const configurations=index(lock.configurations,'id','configuration');
  if (configurations.size>512) fail('Configuration budget exceeded');
  const targets=new Map();
  for (const [,collection] of entries(manifest.targets)) {
    if (!collection.enabled) fail('Published manifest includes a disabled collection');
    for (const [id,variant] of entries(collection.variants)) { if(targets.has(id))fail('Duplicate target: '+id); const override=combination.targets[id]??{}; targets.set(id,{...variant,...override,game_version:override.game_version??variant.game_version??manifest.game_version}); }
  }
  for (const record of lock.compatibility) {
    const subject=(record.subject_type==='dependency'?dependencies:contents).get(record.subject);
    if (!subject || !subject.targets.includes(record.target) || !targets.has(record.target)) fail('Compatibility references an unknown subject or target');
    if (!record.evidence.length || record.evidence.some(id=>!evidence.has(id))) fail('Compatibility has missing evidence');
  }
  for (const artifact of artifacts.values()) {
    const dependency=dependencies.get(artifact.dependency);
    if (!dependency || artifact.version!==combination.dependencies[dependency.id] || !matchesVersion(artifact.version,dependency.version)) fail('Artifact dependency/version mismatch: '+artifact.id);
    if (Boolean(artifact.path)!==dependency.bundled) fail('Artifact bundled flag mismatch: '+artifact.id);
    if (artifact.path) { const file=files.get(artifact.path); if (!safeRelative(artifact.path,{prefix:'payload'}) || !file || file.sha256!==artifact.sha256 || file.size!==artifact.size) fail('Artifact does not match locked payload bytes: '+artifact.id); }
    for (const mount of artifact.mounts) if (!safeRelative(mount.source,{dot:true}) || !safeRelative(mount.destination) || (artifact.format==='file'&&mount.source!=='.')) fail('Unsafe artifact mount: '+artifact.id);
    if (dependency.resolver==='direct' && (dependency.direct.sha256!==artifact.sha256 || dependency.direct.size!==artifact.size || dependency.direct.format!==artifact.format || JSON.stringify(dependency.direct.mounts)!==JSON.stringify(artifact.mounts) || (!dependency.bundled&&dependency.source!==artifact.url))) fail('Direct artifact differs from manifest: '+artifact.id);
  }
  const usedArtifacts=new Set(),usedRuntimes=new Set();
  for (const cfg of configurations.values()) {
    const variant=targets.get(cfg.target);
    if (!variant || cfg.id!==createHash('sha256').update(JSON.stringify(['configuration',cfg.target,cfg.game_version])).digest('hex') || (variant.game_version!==null&&cfg.game_version!==variant.game_version)) fail('Configuration target/game mismatch: '+cfg.id);
    if (cfg.loader.type!==variant.loader.type || (cfg.loader.type==='none' ? cfg.loader.version!==null : !cfg.loader.version||!matchesVersion(cfg.loader.version,variant.loader.version))) fail('Configuration loader mismatch: '+cfg.id);
    if (variant.client===null ? cfg.client!==null : !cfg.client||cfg.client.id!==variant.client.id||cfg.client.dependency!==variant.client.dependency||!matchesVersion(cfg.client.version,variant.client.version)) fail('Configuration client mismatch: '+cfg.id);
    const requiredDependencies=manifest.dependencies.filter(d=>d.targets.includes(cfg.target));
    sameSet(cfg.dependencies.map(d=>d.id),requiredDependencies.map(d=>d.id),'Configuration dependencies');
    for (const selected of cfg.dependencies) {
      const dependency=dependencies.get(selected.id);
      if (selected.version!==combination.dependencies[selected.id]||!matchesVersion(selected.version,dependency.version)) fail('Selected dependency version mismatch');
      if (cfg.client?.dependency===selected.id && cfg.client.version!==selected.version) fail('Client dependency exact version mismatch');
      const owned=manifest.contents.some(c=>c.source==='dependency'&&c.dependency===selected.id&&c.targets.includes(cfg.target));
      if (!selected.assets.length && !(dependency.bundled&&owned)) fail('Dependency has no artifact: '+selected.id);
      if(new Set(selected.assets).size!==selected.assets.length)fail('Duplicate selected artifact');
      for (const id of selected.assets) {const artifact=artifacts.get(id);if(!artifact||artifact.dependency!==selected.id||artifact.version!==selected.version)fail('Selected artifact identity mismatch');usedArtifacts.add(id);}
    }
    const replacements=new Set(manifest.contents.filter(c=>c.targets.includes(cfg.target)&&c.replaces).map(c=>c.replaces));
    const requiredContents=manifest.contents.filter(c=>c.targets.includes(cfg.target)&&!replacements.has(c.id));
    sameSet(cfg.contents,requiredContents.map(c=>c.id),'Configuration contents');
    for (const content of requiredContents) if (![...files.keys()].some(file=>file===content.path||file.startsWith(content.path+'/'))) fail('Content has no locked files: '+content.id);
    for (const subject of [...requiredDependencies,...requiredContents]) {
      const entry=subject.compatibility?.targets?.[cfg.target];
      if(entry&&!compatible(entry,cfg))fail('Configuration contradicts author compatibility: '+subject.id);
      const kind=dependencies.has(subject.id)&&requiredDependencies.includes(subject)?'dependency':'content';
      if(!lock.compatibility.some(record=>record.subject_type===kind&&record.subject===subject.id&&record.target===cfg.target&&compatible(record.entry,cfg)))fail('Missing compatible lock evidence for '+subject.id);
    }
    for(const slot of ['game','loader']) {
      const id=cfg.runtimes[slot];
      if(slot==='loader'&&cfg.loader.type==='none'){if(id!==null)fail('Unexpected loader runtime');continue;}
      const runtime=runtimes.get(id);
      if(!runtime||runtime.kind!==slot||runtime.platform!==variant.platform||runtime.runtime!==variant.runtime||runtime.version!==(slot==='game'?cfg.game_version:cfg.loader.version))fail('Runtime identity/platform/version mismatch: '+id);
      if(slot==='loader'&&runtime.integrity.kind!=='artifact')fail('Loader must have artifact integrity');
      usedRuntimes.add(id);
    }
  }
  for (const id of targets.keys()) if(!lock.configurations.some(c=>c.target===id))fail('Target has no configuration: '+id);
  for (const id of artifacts.keys())if(!usedArtifacts.has(id))fail('Orphan artifact: '+id);
  for (const id of runtimes.keys())if(!usedRuntimes.has(id))fail('Orphan runtime: '+id);
}