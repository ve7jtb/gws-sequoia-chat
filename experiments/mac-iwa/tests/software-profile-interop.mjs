// Exercise the shipped one-shot browser workers and encrypted vault store with
// new disposable keys. The output directory MUST be a new private fixture path:
// no real account, IndexedDB, native helper, authenticator or network is used.
// Per-profile exports are encrypted under the printed source-code test password
// solely so independent command-line oracles can consume these synthetic keys.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {Worker as Thread} from 'node:worker_threads';
import {spawnSync} from 'node:child_process';
import {Vault,random,b64} from '../app/vault/core.js';
import {createSoftwareClient} from '../app/software/client.js';
import {createSoftwareIdentityStore,SOFTWARE_PROFILES} from '../app/software/store.js';
import {inspectIdentity,matchRecipients} from '../app/identities/client.js';
import {createProviderSelection} from '../app/identities/providers.js';
import {runSoftwareTest} from '../app/software-test.js';
import {signAndEncrypt} from '../app/signing-session.js';
import {decryptWithHardware} from '../app/decryption-session.js';
import {composeMime,parse} from '../app/message-mime.js';

const directory=process.argv[2],variant=process.argv[3]||'baseline';
assert(directory&&['baseline','wide'].includes(variant),'New disposable output directory and baseline/wide mode required');
fs.mkdirSync(directory,{mode:0o700});
const email='iwa-profiles@example.invalid',exportPassword='synthetic-iwa-profile-export-password';
let workers=0,terminated=0;
class BrowserWorker{
 constructor(entry){workers++;this.done=false;this.thread=new Thread(new URL('./software-worker-node.mjs',import.meta.url),{type:'module',workerData:{entry,variant}});this.thread.on('message',data=>this.onmessage?.({data}));this.thread.on('error',error=>this.onerror?.(error));}
 postMessage(data){this.thread.postMessage(data);}
 terminate(){if(!this.done){this.done=true;terminated++;}return this.thread.terminate();}
}
globalThis.Worker=class extends BrowserWorker{constructor(url,options){assert.equal(url,'/identities/worker.js');assert.deepEqual(options,{type:'module'});super('identities/worker.js');}};
const software=createSoftwareClient({createWorker:()=>new BrowserWorker('software/worker.js'),timeoutMs:180000});
const secret=random(32),wrapper={id:crypto.randomUUID(),type:'prf',name:'Disposable test PRF',binding:{salt:b64(random(32)),credentialId:b64(random(32))}};
let engine=new Vault(),record,revision,epoch=1,writes=0,store;
await engine.create(wrapper,secret);record=structuredClone(engine.record);revision=record.revision;
const state=()=>({unlocked:engine.unlocked,vaultId:engine.record?.id,revision,epoch,items:engine.data?.items||[]});
const guard=expected=>{const now=state();assert(now.unlocked);for(const key of ['vaultId','revision','epoch'])assert.equal(now[key],expected[key]);assert.equal(record.revision,revision);};
const access={snapshot:state,assertCurrent:async expected=>guard(expected),replaceItems:async(items,expected,{signal})=>{
 guard(expected);assert(!signal.aborted);engine.data.items=items;await engine.save();guard(expected);assert(!signal.aborted);record=structuredClone(engine.record);revision=record.revision;writes++;
}};
const newStore=()=>createSoftwareIdentityStore({access,inspectPublic:inspectIdentity,cryptoCall:software,entropyCollector:async({guard})=>{await guard();return random(32);}});store=newStore();
const selection=createProviderSelection({hardware:{list:async()=>({choices:[],revision:0})},software:()=>store,match:matchRecipients});
const reports=[];
const save=(name,data)=>fs.writeFileSync(path.join(directory,name),data,{mode:0o600});
async function restart(){
 const serialized=JSON.stringify(record);store.cancel();epoch++;engine.lock();assert.deepEqual(await store.records(),[]);
 engine=new Vault();store=newStore();await engine.unlock(JSON.parse(serialized),wrapper.id,secret);
}
async function roundtrip(identity,label){
 let artifact;const report=await runSoftwareTest({identity,selection,request:store.native(identity),gate:async()=>assert(engine.unlocked),
  createSigningWorker:()=>new BrowserWorker('signing-worker.js'),createDecryptionWorker:()=>new BrowserWorker('decryption-worker.js'),
  sign:async(...args)=>{const result=await signAndEncrypt(...args);artifact={cipher:result.cipher,compose:args[1]};return result;}});
 assert.equal(report.status,'PASS');assert.equal(report.nativeRequests,0);assert.equal(report.cardWrites,0);
 save(label+'-message.pgp',Buffer.from(artifact.cipher,'base64'));save(label+'-public.pgp',Buffer.from(identity.certificate,'base64'));
 return {report,artifact};
}
async function independent(identity,encryptedSecret,artifact){
 if(!process.env.IWA_MESSAGE_ORACLE_BIN||identity.version===5)return undefined;
 const oracle=(op,payload)=>{const result=spawnSync(process.env.IWA_MESSAGE_ORACLE_BIN,[],{input:JSON.stringify({op,encryptedSecret,password:exportPassword,peer:identity.certificate,payload}),maxBuffer:2*1024*1024,timeout:120000});assert.equal(result.status,0,'Independent Sequoia software oracle failed');return JSON.parse(result.stdout);};
 const opened=oracle('software-open',artifact.cipher);assert.equal(opened.verified,true);const mail=await parse(Buffer.from(opened.data,'base64'));
 assert.equal(mail.subject,artifact.compose.subject);assert.equal(mail.text,artifact.compose.body);assert.equal(mail.html,artifact.compose.html);assert.equal(mail.attachments[0].content,artifact.compose.attachments[0].data);
 const reply={...artifact.compose,subject:'Independent Sequoia '+identity.profile,body:'Synthetic independent software reply.\n'},sealed=oracle('software-seal',composeMime(reply));
 const reopened=await decryptWithHardware({cipher:sealed.data,service:'Hardware test',identity:store.nativeBinding(identity),recipientKey:identity.recipientKey,
  verification:{expectedEmail:identity.email,expectedFingerprint:identity.fingerprint,recipient:identity.email,material:{certificates:[identity.certificate],bindings:[{email:identity.email,fingerprint:identity.fingerprint}],saved:[]}},
  native:store.native(identity),gate:()=>store.assert(identity),validateMaterial:material=>store.validateMaterial(material,identity,'decryption'),createWorker:()=>new BrowserWorker('decryption-worker.js')});
 assert.equal(reopened.verified,true);assert.equal(reopened.signatureStatus,'valid');assert.equal(reopened.text,reply.body);return {outgoing:true,incoming:true};
}
try{
 for(const profile of SOFTWARE_PROFILES){
  console.log('Testing '+profile+'…');const created=await store.create({name:'Synthetic '+profile,profile,entropy:process.env.IWA_TEST_MIXED_ENTROPY==='1'},email);
  assert.equal(created.profile,profile);const originalFingerprint=created.fingerprint,exported=await store.export(created,exportPassword);
  assert(!JSON.stringify(record).includes(exportPassword));assert(!JSON.stringify(record).includes(exported.encryptedSecret));
  save(profile+'-secret.'+(created.version===5?'pqidentity':'pgp'),Buffer.from(exported.encryptedSecret,'base64'));
  // Remove/import exercises portable restore rather than merely re-reading the
  // same vault item. Wrong export passwords must not mutate the vault first.
  await store.remove(created);const before=writes;
  await assert.rejects(store.import({name:'Wrong password',encryptedSecret:exported.encryptedSecret,password:'wrong'},email));assert.equal(writes,before);
  const restored=await store.import({name:'Restored '+profile,encryptedSecret:exported.encryptedSecret,password:exportPassword},email);assert.equal(restored.fingerprint,originalFingerprint);
  await restart();const selected=await store.get(restored.id,email);assert.equal(selected.fingerprint,originalFingerprint);assert.equal(selected.profile,profile);
  const {report,artifact}=await roundtrip(selected,profile);report.encryptedExportRestore=true;report.restart=true;report.independentSequoia=await independent(selected,exported.encryptedSecret,artifact);reports.push(report);
  save('results.json',JSON.stringify({variant,reports,workers,terminated,nativeHelperCalls:0},null,2)+'\n');
 }
 if(process.env.IWA_P12_FIXTURE){
  const p12=fs.readFileSync(process.env.IWA_P12_FIXTURE).toString('base64'),sourcePassword='synthetic-iwa-p12-test-password';
  // This fixture was generated explicitly for this run by PQ Mail. Its account
  // can differ from the generated-profile mailbox, and comes from public data.
  const converted=await software('import-p12',{p12,password:sourcePassword,newPassword:exportPassword});
  const account=converted.public.emails[0],expected=[converted,...converted.compatibility].map(x=>({fingerprint:x.public.fingerprint,certificate:x.public.certificate,profile:x.public.profile}));
  const before=writes;await assert.rejects(store.importP12({name:'Rejected P12',p12,password:'wrong'},account));assert.equal(writes,before);
  await store.importP12({name:'PQ Mail synthetic P12',p12,password:sourcePassword},account);await restart();
  for(const original of expected){const selected=(await store.list(account)).choices.find(x=>x.profile===original.profile&&x.certificate===original.certificate);assert(selected);assert.equal(selected.fingerprint,original.fingerprint);
   const {report}=await roundtrip(selected,'p12-'+selected.profile);report.p12CertificatesPreserved=true;report.restart=true;reports.push(report);}
 }
 assert.equal(workers,terminated,'Every real worker must be terminated');
 save('results.json',JSON.stringify({status:'PASS',variant,reports,workers,terminated,nativeHelperCalls:0,cardWrites:0,messagesSent:0},null,2)+'\n');
 console.log('PASS '+reports.length+' software profiles/PKCS12 views; encrypted export/restore and restart; '+workers+' workers terminated; zero native helper or card calls.');
}finally{store.cancel();epoch++;engine.lock();secret.fill(0);}
