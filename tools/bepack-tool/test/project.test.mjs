import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, mkdtemp, readFile, writeFile, rm, link } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { validateProject } from '../src/validate.mjs';
const repository = fileURLToPath(new URL('../../../', import.meta.url));
const seed = JSON.parse(await readFile(path.join(repository, 'bepack.json'), 'utf8'));
const target = 'windows-x86_64';
const dependency = () => ({ id: 'example-dependency', source: 'https://example.org/metadata.json', resolver: 'bepack-metadata', version: { exact: '1.0.0' }, license: '', bundled: false, targets: [target], role: 'content' });
const content = (id = 'config-a', destination = 'settings/example.txt') => ({ id, category: 'config', path: 'payload/shared/settings.txt', targets: [target], source: 'local', destination });
const entry = () => ({ games: { unconstrained: true }, loader: null, client: null, evidence: { kind: 'author', reference: 'bepack.json' } });
async function fixture(t, change = () => {}) {
  const home = path.join(repository, '.bepack-local'); await mkdir(home, { recursive: true });
  const root = await mkdtemp(path.join(home, 'validation-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const manifest = structuredClone(seed);
  const set = { schema_version: 1, id: 'stable', dependencies: {}, targets: {} };
  await change(manifest, set);
  await mkdir(path.join(root, 'versions'), { recursive: true });
  await mkdir(path.join(root, 'licenses'), { recursive: true });
  await mkdir(path.join(root, 'payload/shared'), { recursive: true });
  await writeFile(path.join(root, 'licenses/pack-license.txt'), 'Restricted example author license.');
  await writeFile(path.join(root, 'payload/shared/settings.txt'), 'example=true\n');
  await writeFile(path.join(root, 'bepack.json'), JSON.stringify(manifest));
  await writeFile(path.join(root, 'versions/stable.json'), JSON.stringify(set));
  return { root, manifest, set };
}
async function expectCode(t, change, code) {
  const { root } = await fixture(t, change);
  const report = await validateProject(root);
  assert.equal(report.valid, false, JSON.stringify(report));
  assert(report.diagnostics.some(d => d.code === code), JSON.stringify(report));
  return report;
}
test('default draft validates without claiming release readiness', async () => {
  const report = await validateProject(repository);
  assert.equal(report.valid, true, JSON.stringify(report));
  assert.equal(report.release_checked, false);
  assert.equal(report.scope, 'offline-project');
  assert(report.unchecked.includes('archive-and-lock-integrity'));
});
for (const mode of ['full', 'modded', 'mods-only', 'client']) {
  test('accept mode with effective complete overrides: ' + mode, async t => {
    const { root } = await fixture(t, (m, s) => {
      m.mode = mode;
      if (mode !== 'mods-only') m.game_version = '1.21.0.1';
      if (mode === 'modded') s.targets[target] = { loader: { type: 'levilamina', version: { exact: '1.2.3' } } };
      if (mode === 'client') {
        const d = dependency(); d.role = 'client'; m.dependencies.push(d); s.dependencies[d.id] = '1.0.0';
        s.targets[target] = { client: { id: 'example-client', dependency: d.id, version: { exact: '1.0.0' } } };
      }
    });
    const report = await validateProject(root); assert(report.valid, JSON.stringify(report));
  });
}
const cases = [
  ['unknown root key', m => { m.unrecognized = true; }, 'BEPACK_MANIFEST_INVALID'],
  ['unknown schema', m => { m.schema_version = 2; }, 'BEPACK_SCHEMA_UNSUPPORTED'],
  ['all platforms disabled', m => { m.targets.windows.enabled = false; }, 'BEPACK_TARGET_UNAVAILABLE'],
  ['mods-only binds root game', m => { m.game_version = '1.21.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['mods-only binds variant game', m => { m.targets.windows.variants[target].game_version = '1.21.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['mods-only binds combination game', (m,s) => { s.targets[target] = { game_version: '1.21.0' }; }, 'BEPACK_VERSION_SET_INVALID'],
  ['full loader contradiction', m => { m.mode = 'full'; m.game_version = '1.21.0'; m.targets.windows.variants[target].loader = { type: 'levilamina', version: { exact: '1.2.3' } }; }, 'BEPACK_MANIFEST_INVALID'],
  ['modded requires LL after merge', m => { m.mode = 'modded'; m.game_version = '1.21.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['unknown combination target', (m,s) => { s.targets.missing = {}; }, 'BEPACK_VERSION_SET_INVALID'],
  ['combination cannot change platform', (m,s) => { s.targets[target] = { platform: 'android-arm64' }; }, 'BEPACK_VERSION_SET_INVALID'],
  ['combination ID mismatch', (m,s) => { s.id = 'different'; }, 'BEPACK_VERSION_SET_INVALID'],
  ['missing dependency selection', m => { m.dependencies.push(dependency()); }, 'BEPACK_VERSION_SET_INVALID'],
  ['wrong dependency selection', (m,s) => { const d=dependency(); m.dependencies.push(d); s.dependencies[d.id]='2.0.0'; }, 'BEPACK_VERSION_SET_INVALID'],
  ['unknown dependency selection', (m,s) => { s.dependencies.missing='1.0.0'; }, 'BEPACK_VERSION_SET_INVALID'],
  ['duplicate dependency ID', (m,s) => { const d=dependency(); m.dependencies.push(d,structuredClone(d)); s.dependencies[d.id]='1.0.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['unknown dependency target', (m,s) => { const d=dependency(); d.targets=['missing']; m.dependencies.push(d); }, 'BEPACK_MANIFEST_INVALID'],
  ['HTTP dependency source', (m,s) => { const d=dependency(); d.source='http://example.org/a'; m.dependencies.push(d); s.dependencies[d.id]='1.0.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['credentialed dependency source', (m,s) => { const d=dependency(); d.source='https://u:p@example.org/a'; m.dependencies.push(d); s.dependencies[d.id]='1.0.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['dependency source fragment', (m,s) => { const d=dependency(); d.source+='\u0023fragment'; m.dependencies.push(d); s.dependencies[d.id]='1.0.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['bundled license empty', (m,s) => { const d=dependency(); d.bundled=true; d.redistribution_confirmed=true; m.dependencies.push(d); s.dependencies[d.id]='1.0.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['bundled without confirmation', (m,s) => { const d=dependency(); d.bundled=true; d.license='MIT'; m.dependencies.push(d); s.dependencies[d.id]='1.0.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['invalid SPDX', m => { m.license='This Is Not SPDX'; }, 'BEPACK_LICENSE_INVALID'],
  ['missing author license file', m => { m.license_file='licenses/missing.txt'; }, 'BEPACK_FILE_MISSING'],
  ['reversed range', (m,s) => { const d=dependency(); d.version={range:{min:'2.0.0',max:'1.0.0',include_min:true,include_max:true}}; m.dependencies.push(d); s.dependencies[d.id]='1.0.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['unequal range arity', (m,s) => { const d=dependency(); d.version={range:{min:'1.0.0',max:'2.0.0.0',include_min:true,include_max:true}}; m.dependencies.push(d); s.dependencies[d.id]='1.0.0'; }, 'BEPACK_MANIFEST_INVALID'],
  ['unsafe payload path', m => { const c=content(); c.path='payload/../secret'; m.contents.push(c); }, 'BEPACK_MANIFEST_INVALID'],
  ['unknown content target', m => { const c=content(); c.targets=['missing']; m.contents.push(c); }, 'BEPACK_MANIFEST_INVALID'],
  ['duplicate content ID', m => { m.contents.push(content(), content()); }, 'BEPACK_MANIFEST_INVALID'],
  ['folded destination collision', m => { m.contents.push(content('config-a','ß.txt'),content('config-b','ẞ.txt')); }, 'BEPACK_DESTINATION_CONFLICT'],
  ['ancestor destination collision', m => { m.contents.push(content('config-a','settings'),content('config-b','settings/x')); }, 'BEPACK_DESTINATION_CONFLICT'],
  ['replacement cycle', m => { const a=content('a'), b=content('b'); a.replaces='b'; b.replaces='a'; m.contents.push(a,b); }, 'BEPACK_MANIFEST_INVALID'],
  ['plugin incompatible target', m => { const c=content(); c.category='ll-plugin'; m.contents.push(c); }, 'BEPACK_CONTENT_INVALID'],
  ['dependency content unbundled', (m,s) => { const d=dependency(); m.dependencies.push(d); s.dependencies[d.id]='1.0.0'; const c=content(); c.source='dependency'; c.dependency=d.id; m.contents.push(c); }, 'BEPACK_MANIFEST_INVALID'],
  ['custom resolver without capability', (m,s) => { const d=dependency(); d.resolver='x-example'; m.dependencies.push(d); s.dependencies[d.id]='1.0.0'; }, 'BEPACK_MANIFEST_INVALID'],
];
for (const [name, change, code] of cases) test('reject ' + name, async t => { await expectCode(t, change, code); });
test('all map extension containers are ignored as metadata', async t => {
  const { root } = await fixture(t, (m,s) => {
    const ext = () => ({ 'org.example.note': { data: true } });
    m.extensions=ext(); m.targets.extensions=ext(); m.targets.windows.extensions=ext(); m.targets.windows.variants.extensions=ext();
    s.extensions=ext(); s.dependencies.extensions=ext(); s.targets.extensions=ext();
    const c=content(); c.compatibility={targets:{[target]:entry(),extensions:ext()},extensions:ext()}; m.contents.push(c);
  });
  const report=await validateProject(root); assert(report.valid,JSON.stringify(report));
});
test('direct resolver requires compatibility, without network', async t => {
  const { root,manifest } = await fixture(t, (m,s) => {
    const d=dependency(); d.resolver='direct'; d.source='https://example.org/config.txt';
    d.direct={size:1,sha256:'1'.repeat(64),format:'file',mounts:[{source:'.',slot:'configs',destination:'settings/example.txt'}]};
    m.dependencies.push(d); s.dependencies[d.id]='1.0.0';
  });
  let report=await validateProject(root); assert(report.diagnostics.some(d=>d.code==='BEPACK_COMPATIBILITY_UNKNOWN'));
  manifest.dependencies[0].compatibility={targets:{[target]:entry()}};
  await writeFile(path.join(root,'bepack.json'),JSON.stringify(manifest));
  report=await validateProject(root); assert(report.valid,JSON.stringify(report));
});
test('duplicate raw keys are rejected before normal JSON parsing', async t => {
  const {root}=await fixture(t); await writeFile(path.join(root,'bepack.json'),'{"schema_version":1,"schema_version":1}');
  const report=await validateProject(root); assert.equal(report.valid,false); assert.match(report.diagnostics[0].message,/Duplicate/);
});
test('hard-linked content is rejected', async t => {
  const {root}=await fixture(t,m=>m.contents.push(content()));
  await link(path.join(root,'payload/shared/settings.txt'),path.join(root,'payload/shared/hardlink.txt'));
  const report=await validateProject(root); assert(report.diagnostics.some(d=>d.code==='BEPACK_PATH_UNSAFE'));
});
test('CLI exit codes and additive reports', async t => {
  const {root}=await fixture(t);
  const cli=path.join(repository,'scripts/bepack.mjs');
  const run=(...args)=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8'});
  let result=run('validate','--project',root); assert.equal(result.status,0,result.stderr); assert.equal(JSON.parse(result.stdout).release_checked,false);
  result=run('validate'); assert.equal(result.status,2); assert.equal(JSON.parse(result.stderr).code,'BEPACK_ARGUMENT_INVALID');
  const reportFile=path.join(root,'report.json');
  result=run('validate','--project',root,'--report',reportFile); assert.equal(result.status,0,result.stderr);
  result=run('validate','--project',root,'--report',reportFile); assert.equal(result.status,1); assert.match(result.stderr,/EEXIST/);
  await writeFile(path.join(root,'bepack.json'),'{}');
  result=run('validate','--project',root); assert.equal(result.status,2); assert.equal(JSON.parse(result.stdout).valid,false);
});
const direct = (id = 'direct-a') => ({ ...dependency(), id, resolver:'direct', source:'https://example.org/config.txt', compatibility:{targets:{[target]:entry()}}, direct:{size:1,sha256:'1'.repeat(64),format:'file',mounts:[{source:'.',slot:'configs',destination:'settings/example.txt'}]} });
const reversed = () => ({range:{min:'2.0.0',max:'1.0.0',include_min:true,include_max:true}});
for (const kind of ['same-dependency', 'cross-dependency', 'direct-content']) test('reject static mount collision: ' + kind, async t => {
  await expectCode(t,(m,s)=>{
    const d=direct(); m.dependencies.push(d); s.dependencies[d.id]='1.0.0';
    if(kind==='same-dependency') d.direct.mounts.push({...d.direct.mounts[0],destination:'settings/EXAMPLE.txt'});
    else if(kind==='cross-dependency') {const other=direct('direct-b');m.dependencies.push(other);s.dependencies[other.id]='1.0.0';}
    else m.contents.push(content());
  },'BEPACK_DESTINATION_CONFLICT');
});
test('same direct destination on different targets is allowed',async t=>{
  const {root}=await fixture(t,(m,s)=>{
    m.targets.android={enabled:true,variants:{'android-arm64':{platform:'android-arm64',runtime:'bedrock-client',game_version:null,loader:{type:'none',version:null},client:null}}};
    const a=direct(),b=direct('direct-b'); b.targets=['android-arm64'];b.compatibility={targets:{'android-arm64':entry()}};
    m.dependencies.push(a,b);s.dependencies[a.id]='1.0.0';s.dependencies[b.id]='1.0.0';
  }); const report=await validateProject(root);assert(report.valid,JSON.stringify(report));
});
test('declaration range is checked even when active combination replaces it',async t=>{
  const report=await expectCode(t,(m,s)=>{
    m.targets.windows.variants[target].loader={type:'levilamina',version:reversed()};
    s.targets[target]={loader:{type:'none',version:null}};
  },'BEPACK_MANIFEST_INVALID');
  assert(report.diagnostics.some(d=>d.file==='bepack.json'&&d.field==='/targets/windows/variants/'+target+'/loader/version'));
});
test('disabled declarations still validate their version intervals',async t=>{
  await expectCode(t,(m)=>{
    m.targets.android={enabled:false,variants:{'android-arm64':{platform:'android-arm64',runtime:'bedrock-client',game_version:null,loader:{type:'levilamina',version:reversed()},client:null}}};
  },'BEPACK_MANIFEST_INVALID');
});
test('disabled collection still rejects duplicate platform/runtime pairs',async t=>{
  await expectCode(t,m=>{
    const variant={platform:'android-arm64',runtime:'bedrock-client',game_version:null,loader:{type:'none',version:null},client:null};
    m.targets.android={enabled:false,variants:{'android-a':variant,'android-b':structuredClone(variant)}};
  },'BEPACK_MANIFEST_INVALID');
});
test('base mode diagnostics point to the real manifest variant field',async t=>{
  const report=await expectCode(t,m=>{m.mode='modded';m.game_version='1.21.0';},'BEPACK_MANIFEST_INVALID');
  assert(report.diagnostics.some(d=>d.file==='bepack.json'&&d.field==='/targets/windows/variants/'+target+'/loader'));
});
test('override mode diagnostics point to the active version set',async t=>{
  const report=await expectCode(t,(m,s)=>{m.mode='full';m.game_version='1.21.0';s.targets[target]={loader:{type:'levilamina',version:{exact:'1.2.3'}}};},'BEPACK_VERSION_SET_INVALID');
  assert(report.diagnostics.some(d=>d.file==='versions/stable.json'&&d.field==='/targets/'+target+'/loader'));
});
test('override range diagnostics retain the combination file and property',async t=>{
  const report=await expectCode(t,(m,s)=>{s.targets[target]={loader:{type:'levilamina',version:reversed()}};},'BEPACK_MANIFEST_INVALID');
  assert(report.diagnostics.some(d=>d.file==='versions/stable.json'&&d.field==='/targets/'+target+'/loader/version'));
});
test('client reference diagnostics locate the override instead of a nonexistent manifest key',async t=>{
  const report=await expectCode(t,(m,s)=>{s.targets[target]={client:{id:'example-client',dependency:'missing',version:{exact:'1.0.0'}}};},'BEPACK_VERSION_SET_INVALID');
  assert(report.diagnostics.some(d=>d.file==='versions/stable.json'&&d.field==='/targets/'+target+'/client'));
});
test('referenced ancestor aliases collide across independent paths',async t=>{
  const {root}=await fixture(t,m=>{
    const a=content('a','a.txt'),b=content('b','b.txt');a.path='payload/shared/a.txt';b.path='payload/SHARED/b.txt';m.contents.push(a,b);
  });
  await writeFile(path.join(root,'payload/shared/a.txt'),'a');await writeFile(path.join(root,'payload/shared/b.txt'),'b');
  // Windows aliases SHARED to shared. On a case-sensitive filesystem, create both.
  await mkdir(path.join(root,'payload/SHARED'),{recursive:true});await writeFile(path.join(root,'payload/SHARED/b.txt'),'b');
  const report=await validateProject(root);assert(report.diagnostics.some(d=>d.code==='BEPACK_PATH_UNSAFE'),JSON.stringify(report));
});
test('shared exact payload path may be reused at distinct destinations',async t=>{
  const {root}=await fixture(t,m=>m.contents.push(content('a','a.txt'),content('b','b.txt')));
  const report=await validateProject(root);assert(report.valid,JSON.stringify(report));
});
test('path budget is global and counts exact shared references only once',async t=>{
  const {inspectProjectPath,createInspectionState}=await import('../src/paths.mjs');
  const {root}=await fixture(t);await writeFile(path.join(root,'payload/shared/second.txt'),'b');
  const state=createInspectionState();const opts={state,maxFiles:1};
  await inspectProjectPath(root,'payload/shared/settings.txt',opts);
  await inspectProjectPath(root,'payload/shared/settings.txt',opts);assert.equal(state.files,1);
  await assert.rejects(inspectProjectPath(root,'payload/shared/second.txt',opts),e=>e.diagnostic==='BEPACK_RESOURCE_LIMIT');
});

for (const kind of ['contents','direct-content']) test('destination ancestor aliases rejected: '+kind,async t=>{
  await expectCode(t,(m,s)=>{
    m.contents.push(content('a','Settings/a.txt'));
    if(kind==='contents')m.contents.push(content('b','settings/b.txt'));
    else{const d=direct();d.direct.mounts[0].destination='settings/b.txt';m.dependencies.push(d);s.dependencies[d.id]='1.0.0';}
  },'BEPACK_DESTINATION_CONFLICT');
});
test('identically spelled destination parents allow distinct children',async t=>{
  const {root}=await fixture(t,m=>m.contents.push(content('a','Settings/a.txt'),content('b','Settings/b.txt')));
  const report=await validateProject(root);assert(report.valid,JSON.stringify(report));
});
test('independent schema documents keep identical shared definitions',async()=>{
  const load=async name=>JSON.parse(await readFile(path.join(repository,'schemas',name),'utf8'));
  const a=await load('bepack.schema.json'),b=await load('version-set.schema.json');
  for (const [name, definition] of Object.entries(a.$defs)) assert.deepEqual(definition,b.$defs[name],name);
  assert.deepEqual(Object.keys(b.$defs).filter(name=>!Object.hasOwn(a.$defs,name)).sort(),['DependencySelections','TargetOverride','TargetOverrides']);
  function refs(node){if(!node||typeof node!=='object')return;for(const [key,value] of Object.entries(node)){if(key==='$ref')assert(value.startsWith('#/'),value);else refs(value);}}
  refs(a);refs(b);
});

for (const scoped of [false,true]) test('custom loader override requires target scope: '+scoped,async t=>{
  const {root}=await fixture(t,(m,s)=>{
    m.requires=['org.example.global'];
    if(scoped)m.targets.windows.variants[target].requires=['org.example.adapter'];
    s.targets[target]={loader:{type:'x-custom',version:{exact:'1.0.0'}}};
  });
  const report=await validateProject(root);assert.equal(report.valid,scoped,JSON.stringify(report));
  if(!scoped)assert(report.diagnostics.some(d=>d.file==='versions/stable.json'&&d.field==='/targets/'+target+'/loader'&&d.code==='BEPACK_VERSION_SET_INVALID'));
});
