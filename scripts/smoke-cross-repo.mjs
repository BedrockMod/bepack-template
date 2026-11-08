// Explicit sibling-repository integration smoke. Synthetic catalog and service
// adapters are test data only; this command never publishes or makes requests.
import assert from 'node:assert/strict';
import {cp,mkdir,readFile,readdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {fixture} from '../tools/bepack-tool/test/helpers/core-fixtures.mjs';
import {runBuild} from '../tools/bepack-tool/src/release-build.mjs';
import {runScan} from '../tools/bepack-tool/src/release-scan.mjs';
import {buildReleaseDescriptor,verifyAssetDirectory} from '../tools/bepack-tool/src/release-assets.mjs';
import {hashFile} from '../tools/bepack-tool/src/release-files.mjs';
import {FixtureDownloader,FixtureGitHub,NOW,makeReleaseFixture,makeVtAnalysis,makeVtPayload} from '../../bepack-registry/test/helpers/fixtures.mjs';
import {VirusTotalClient} from '../../bepack-registry/lib/virustotal.mjs';
import {verifyRelease} from '../../bepack-registry/lib/release-verify.mjs';
import {buildCatalog,writeCatalog} from '../../bepack-registry/lib/catalog.mjs';
const template=path.resolve(import.meta.dirname,'..');
const json=value=>JSON.stringify(value,null,2)+'\n';

test('offline core CLI -> five release assets -> independent registry -> immutable catalog',async t=>{
  // The fixture owns and removes its temporary root; no repository data changes.
  const f=await fixture(t);
  const commit='b'.repeat(40), tag=`v${f.manifest.version}`;
  // runBuild fingerprints the actual tool tree present in an author checkout.
  for(const name of ['scripts','tools/bepack-tool/src','tools/bepack-tool/schemas','schemas','package.json','package-lock.json']) {
    await mkdir(path.dirname(path.join(f.project,name)),{recursive:true});
    await cp(path.join(template,name),path.join(f.project,name),{recursive:true});
  }
  const assetsDir=path.join(f.root,'assets'),workDir=path.join(f.root,'release-work');
  const options=f.options();
  const context=await runBuild({projectDir:f.project,assetsDir,workDir,runtimeCatalog:f.catalogFile,
    runtimeCatalogSha256:options.runtimeCatalogSha256,generatedAt:options.generatedAt,tag,commit,now:()=>NOW.toISOString()});
  const scan=await runScan({assetsDir,workDir,tag,now:()=>NOW.toISOString(),vt:{async scanFile(file,{expectedSha256,expectedSize}){
    const info=await hashFile(file);assert.equal(info.sha256,expectedSha256);assert.equal(info.size,expectedSize);
    return {analysis_id:`analysis-${info.sha256.slice(0,12)}`,sha256:info.sha256,size:info.size,
      malicious:0,suspicious:0,harmless:1,undetected:0,analyzed_at:new Date(NOW.getTime()-3600000).toISOString()};
  }}});
  const service=makeReleaseFixture({packId:f.manifest.id,version:f.manifest.version,now:NOW});
  const scanInfo=await hashFile(path.join(assetsDir,'scan-report.json'));
  const descriptor=buildReleaseDescriptor({manifest:f.manifest,repository:service.source.repository,tag,commit,
    tool:context.tool,packageAsset:context.package,manifestAsset:context.manifest,
    scanReportAsset:{name:'scan-report.json',...scanInfo},generatedAt:NOW.toISOString()});
  await writeFile(path.join(assetsDir,'bepack-release.json'),json(descriptor),{flag:'wx'});
  await verifyAssetDirectory(assetsDir,{repositoryId:service.source.repository.id,repositoryFullName:service.source.repository.full_name,tag,commit});
  const names=(await readdir(assetsDir)).sort();assert.equal(names.length,5);
  service.descriptor=descriptor;service.contents=new Map();
  service.assets=await Promise.all(names.map(async(name,index)=>{
    const bytes=await readFile(path.join(assetsDir,name));service.contents.set(name,bytes);
    return {id:9000+index,name,size:bytes.length,state:'uploaded',content_type:'application/octet-stream',
      browser_download_url:`https://github.com/${service.source.repository.full_name}/releases/download/${tag}/${name}`};
  }));
  const downloader=new FixtureDownloader(service);
  for(const entry of scan.report.entries) {
    const bytes=value=>Buffer.from(json(value));
    downloader.add(`https://www.virustotal.com/api/v3/files/${entry.sha256}`,bytes(makeVtPayload(entry.sha256,entry.size,{now:NOW})));
    downloader.add(`https://www.virustotal.com/api/v3/analyses/${entry.analysis_id}`,bytes(makeVtAnalysis(entry.sha256,entry.analysis_id,{now:NOW})));
    downloader.add(`https://www.virustotal.com/api/v3/analyses/${entry.analysis_id}/item`,bytes(makeVtPayload(entry.sha256,entry.size,{now:NOW})));
  }
  const verifyOptions={github:new FixtureGitHub(service),downloader,source:service.source,
    releaseId:String(service.release.id),now:NOW,vt:new VirusTotalClient({downloader,apiKey:'fixture-only',clock:()=>NOW}),workRoot:f.root};
  const record=await verifyRelease(verifyOptions).catch(error=>{console.error(JSON.stringify(error.details));throw error;});
  assert.equal(record.package.sha256,context.package.sha256);
  const registryRoot=path.join(f.root,'registry');
  for(const name of ['sources','withdrawals',`releases/${record.pack_id}`])await mkdir(path.join(registryRoot,name),{recursive:true});
  await writeFile(path.join(registryRoot,'sources',record.pack_id+'.json'),json(service.source));
  await writeFile(path.join(registryRoot,'releases',record.pack_id,record.version+'.json'),json(record));
  const catalog=await buildCatalog({root:registryRoot,now:NOW});
  const outDir=path.join(f.root,'catalog');await writeCatalog({outDir,...catalog});
  assert.equal(catalog.registry.packs.length,1);assert.equal(catalog.registry.packs[0].latest,record.version);
  assert.equal(catalog.details.size,1);assert.equal(JSON.parse(await readFile(path.join(outDir,'registry.json'))).packs[0].id,record.pack_id);
  // Prove this very same pipeline refuses substituted package bytes.
  const asset=service.assets.find(item=>item.name.endsWith('.bepack'));
  const corrupted=Buffer.from(service.contents.get(asset.name));corrupted[corrupted.length-1]^=255;
  downloader.add(asset.browser_download_url,corrupted);
  await assert.rejects(verifyRelease(verifyOptions),/SHA-256 differs|checksum|hash/i);
  console.log(JSON.stringify({offline:true,synthetic_catalog:true,assets:names,scan_subjects:scan.plan.entries.length,
    package_sha256:record.package.sha256,indexed_packs:catalog.registry.packs.length,tamper_rejected:true}));
});