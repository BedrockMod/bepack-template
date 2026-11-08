// Host-neutral package staging. This module never guesses a game installation
// path, executes payloads, edits an instance, or downloads without an injected
// acquisition adapter. Host transactions own locks, native path binding, atomic
// writes, rollback and config allowlists; unsupported hosts fail before writes.
import path from 'node:path';
import { mkdtemp, mkdir, copyFile, open, rm, lstat } from 'node:fs/promises';
import { createReadStream, constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { verifyPackage } from './verify.mjs';
import { openPackage } from './container.mjs';
import { openZip, extractZip } from './zip.mjs';
import { packageDigestOf } from './digest.mjs';
import { ensureSafeDirectory } from './staging.mjs';
import { safeRelative, collisionKey, inspectProjectPath, createInspectionState } from './paths.mjs';
const fail=(code,message)=>{throw Object.assign(new Error(message),{diagnostic:code});};
const slots={ 'resource-pack':'resource-packs','behavior-pack':'behavior-packs',world:'worlds',config:'configs','ll-plugin':'plugins','native-mod':'native-mods','client-component':'client-components' };
const sessions=new WeakMap();
async function measure(file){const hash=createHash('sha256');let size=0;for await(const bytes of createReadStream(file)){size+=bytes.length;hash.update(bytes);}return{size,sha256:hash.digest('hex')};}
async function checkArtifact(file,expected,root){
  const relative=path.relative(root,file).split(path.sep).join('/');
  if(!safeRelative(relative))fail('BEPACK_PATH_UNSAFE','Artifact escaped private staging');
  const info=await inspectProjectPath(root,relative,{state:createInspectionState()});
  if(info.directory)fail('BEPACK_ARTIFACT_INVALID','An acquired artifact must be a regular file');
  const actual=await measure(file);
  if(actual.sha256!==expected.sha256||actual.size!==expected.size)fail('BEPACK_DIGEST_MISMATCH','Acquired artifact does not match locked size/SHA-256: '+expected.id);
}
export async function stagePackage({ package:file, configuration:configurationId, platform, stagingDirectory=tmpdir(), fetchArtifact }){
  if(typeof platform!=='string'||!platform)fail('BEPACK_PLATFORM_REQUIRED','The host must supply its actual platform');
  if(typeof configurationId!=='string'||!configurationId)fail('BEPACK_CONFIGURATION_REQUIRED','Select one locked configuration explicitly');
  await ensureSafeDirectory(stagingDirectory);
  const root=await mkdtemp(path.join(path.resolve(stagingDirectory),'bepack-install-'));
  try{
    const snapshot=path.join(root,'source.bepack');
    await copyFile(file,snapshot,constants.COPYFILE_EXCL);
    const verification=await verifyPackage({package:snapshot,temporaryDirectory:root});
    if(!verification.valid)fail('BEPACK_PACKAGE_INVALID','Package verification failed: '+verification.diagnostics.find(d=>d.severity==='error')?.message);
    const pkg=await openPackage(snapshot);
    let manifest,lock;
    try{
      manifest=(await pkg.document('bepack.json')).value;
      lock=(await pkg.document('bepack.lock.json',pkg.limits.maxLockBytes)).value;
      await extractZip(pkg.zip,path.join(root,'project'));
    }finally{await pkg.close();}
    const actualDigest=await packageDigestOf(snapshot);
    if(actualDigest.sha256!==verification.package.sha256||actualDigest.size!==verification.package.size)fail('BEPACK_DIGEST_MISMATCH','Package changed between verification and staging');
    const cfg=lock.configurations.find(c=>c.id===configurationId);
    if(!cfg)fail('BEPACK_CONFIGURATION_UNKNOWN','Unknown locked configuration: '+configurationId);
    const variant=Object.values(manifest.targets).filter(c=>c?.enabled).map(c=>c.variants[cfg.target]).find(Boolean);
    if(!variant||variant.platform!==platform)fail('BEPACK_PLATFORM_MISMATCH','Selected configuration is not for the host platform');
    const project=path.join(root,'project');
    const operations=[];
    const destinations=[];
    function add(source,slot,destination,content){
      if(!safeRelative(destination)||!Object.values(slots).includes(slot))fail('BEPACK_PATH_UNSAFE','Invalid installation slot/destination');
      const key=slot+'/'+collisionKey(destination);
      if(destinations.some(other=>key===other||key.startsWith(other+'/')||other.startsWith(key+'/')))fail('BEPACK_DESTINATION_CONFLICT','Overlapping installation destinations');
      destinations.push(key);operations.push({source,slot,destination,...(content?{content}: {})});
    }
    const selectedAssets=new Set(cfg.dependencies.flatMap(d=>d.assets));
    for(const artifact of lock.artifacts.filter(a=>selectedAssets.has(a.id))){
      let source;
      if(artifact.path){source=path.join(project,...artifact.path.split('/'));}
      else{
        if(typeof fetchArtifact!=='function')fail('BEPACK_ADAPTER_REQUIRED','An artifact acquisition adapter is required for '+artifact.id);
        await mkdir(path.join(root,'downloads'),{recursive:true});
        source=path.join(root,'downloads',String(selectedAssets.size)+'-'+operations.length+'-'+createHash('sha256').update(artifact.id).digest('hex'));
        await fetchArtifact({artifact:structuredClone(artifact),destination:source});
      }
      await checkArtifact(source,artifact,root);
      let mountRoot=source;
      if(artifact.format==='zip-tree'){
        const zip=await openZip(source);
        mountRoot=path.join(root,'artifact-'+createHash('sha256').update(artifact.id).digest('hex'));
        try{await extractZip(zip,mountRoot);}finally{await zip.close();}
      }
      for(const mount of artifact.mounts){
        const absolute=mount.source==='.'?mountRoot:path.join(mountRoot,...mount.source.split('/'));
        const relative=path.relative(root,absolute).split(path.sep).join('/');
        await inspectProjectPath(root,relative,{state:createInspectionState()});
        add(absolute,mount.slot,mount.destination);
      }
    }
    for(const id of cfg.contents){const content=manifest.contents.find(c=>c.id===id);const source=path.join(project,...content.path.split('/'));await inspectProjectPath(root,content.path==='.'?'project':'project/'+content.path,{state:createInspectionState()});add(source,slots[content.category],content.destination,structuredClone(content));}
    for (const operation of operations.filter(o=>o.slot==='configs')) {
      const info=await lstat(operation.source); if(!info.isFile())fail('BEPACK_CONFIG_UNSUPPORTED','Config must be one regular file');
      const extension=path.extname(operation.source).toLowerCase();
      if(['.exe','.dll','.so','.dylib','.js','.mjs','.cjs','.sh','.bat','.cmd','.ps1','.py','.jar','.wasm','.apk'].includes(extension))fail('BEPACK_CONFIG_UNSUPPORTED','Executable config payload is forbidden');
      const handle=await open(operation.source,'r');const prefix=Buffer.alloc(8);let length;try{length=(await handle.read(prefix,0,8,0)).bytesRead;}finally{await handle.close();}
      const magic=prefix.subarray(0,length);if(magic.subarray(0,2).equals(Buffer.from('MZ'))||magic.subarray(0,2).equals(Buffer.from('#!'))||magic.subarray(0,4).equals(Buffer.from([0x7f,0x45,0x4c,0x46]))||magic.subarray(0,4).equals(Buffer.from([0,0x61,0x73,0x6d])))fail('BEPACK_CONFIG_UNSUPPORTED','Executable config bytes are forbidden');
    }
    const requirements=[...new Set([...(manifest.requires??[]),...(variant.requires??[])])];
    const runtimeRecords=[cfg.runtimes.game,cfg.runtimes.loader].filter(Boolean).map(id=>lock.runtimes.find(r=>r.id===id));
    const publicHandle=Object.freeze({configuration:structuredClone(cfg),platform,package:structuredClone(verification.package),operations:operations.length,async cleanup(){const state=sessions.get(publicHandle);if(state?.installing)fail('BEPACK_INSTALL_BUSY','Installation is active');await rm(root,{recursive:true,force:true});sessions.delete(publicHandle);}});
    sessions.set(publicHandle,{root,manifest,cfg,variant,requirements,runtimeRecords,operations,installing:false});
    return publicHandle;
  }catch(error){await rm(root,{recursive:true,force:true});throw error;}
}

export async function installStagedPackage(staged,{host}={}){
  const state=sessions.get(staged);
  if(!state||state.installing)fail('BEPACK_STAGE_INVALID','Stage is expired or busy');
  if(typeof host?.beginInstall!=='function')fail('BEPACK_ADAPTER_REQUIRED','An injected transactional host adapter is required');
  state.installing=true;let transaction,committed=false;
  try{
    transaction=await host.beginInstall({pack:structuredClone({id:state.manifest.id,version:state.manifest.version}),configuration:structuredClone(state.cfg)});
    for(const method of ['measureRuntime','validateOperation','write','commit','rollback'])if(typeof transaction?.[method]!=='function')fail('BEPACK_ADAPTER_REQUIRED','Host transaction is missing '+method);
    if(transaction.environment?.platform!==state.variant.platform||transaction.environment?.runtime!==state.variant.runtime)fail('BEPACK_PLATFORM_MISMATCH','Host transaction platform/runtime mismatch');
    const supported=new Set(transaction.environment.capabilities??[]);
    if(state.requirements.some(required=>!supported.has(required)))fail('BEPACK_CAPABILITY_UNSUPPORTED','Host lacks a required adapter capability');
    for(const expected of state.runtimeRecords){
      const measured=await transaction.measureRuntime(structuredClone(expected));
      if(!measured||['kind','version','platform','runtime','provider','identity'].some(key=>measured[key]!==expected[key])||measured.integrity?.kind!==expected.integrity.kind||measured.integrity?.sha256!==expected.integrity.sha256)fail('BEPACK_RUNTIME_MISMATCH','Installed runtime does not match locked identity and integrity: '+expected.id);
    }
    if(state.manifest.launcher && (typeof transaction.validateLauncher!=='function' || await transaction.validateLauncher(structuredClone(state.manifest.launcher))!==true))fail('BEPACK_CAPABILITY_UNSUPPORTED','Host did not approve launcher requirements');
    // All slot/content/layout and config checks precede destination writes.
    for(const operation of state.operations)if(await transaction.validateOperation({...operation,configuration:structuredClone(state.cfg)})!==true)fail('BEPACK_SLOT_UNSUPPORTED','Host did not validate slot content and destination');
    // Unknown config allowlists fail closed.
    for(const operation of state.operations.filter(o=>o.slot==='configs')){
      if(typeof transaction.validateConfig!=='function'||await transaction.validateConfig({...operation,configuration:structuredClone(state.cfg)})!==true)fail('BEPACK_CONFIG_UNSUPPORTED','Host did not approve a config path and value');
    }
    for(const operation of state.operations){
      await inspectProjectPath(state.root,path.relative(state.root,operation.source).split(path.sep).join('/'),{state:createInspectionState()});
      await transaction.write({...operation});
    }
    await transaction.commit();committed=true;
    return{schema_version:1,command:'install',valid:true,configuration:state.cfg.id,writes:state.operations.length,host_transaction:true};
  }catch(error){if(transaction&&typeof transaction.rollback==='function')try{await transaction.rollback();}catch(rollback){throw new AggregateError([error,rollback],'Host installation and rollback both failed');}throw error;}
  finally{state.installing=false;if(committed){await staged.cleanup();}}
}