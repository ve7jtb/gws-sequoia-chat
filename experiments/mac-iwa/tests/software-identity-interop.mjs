// Real-worker integration using a newly generated password-encrypted secret
// certificate. The fixture and all artifacts remain outside the repository.
// No user's vault, native helper, YubiKey, email account or network is accessed.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {Worker as Thread} from 'node:worker_threads';
import {spawnSync} from 'node:child_process';
import {Vault,random,b64} from '../app/vault/core.js';
import {createSoftwareClient} from '../app/software/client.js';
import {createSoftwareIdentityStore} from '../app/software/store.js';
import {inspectIdentity,matchRecipients} from '../app/identities/client.js';
import {createProviderSelection} from '../app/identities/providers.js';
import {runSoftwareTest} from '../app/software-test.js';
import {signAndEncrypt} from '../app/signing-session.js';
import {decryptWithHardware} from '../app/decryption-session.js';
import {composeMime,parse} from '../app/message-mime.js';

const directory=process.argv[2],variant=process.argv[3]||'baseline';
assert(directory&&['baseline','wide'].includes(variant),'Disposable fixture directory and optional baseline/wide mode required');
const fixture=JSON.parse(fs.readFileSync(path.join(directory,'fixture.json')));
const encryptedSecret=fixture.signInput.encryptedSecret,password=fixture.signInput.password,email=fixture.identity.emails[0];
let workers=0,terminated=0,privateCalls=0;
class BrowserWorker{
 constructor(entry){
  workers++;this.done=false;
  this.thread=new Thread(new URL('./software-worker-node.mjs',import.meta.url),{type:'module',workerData:{entry,variant}});
  this.thread.on('message',data=>this.onmessage?.({data}));this.thread.on('error',error=>this.onerror?.(error));
 }
 postMessage(data){this.thread.postMessage(data);}
 terminate(){if(!this.done){this.done=true;terminated++;}return this.thread.terminate();}
}
globalThis.Worker=class extends BrowserWorker{
 constructor(url,options){assert.equal(url,'/identities/worker.js');assert.deepEqual(options,{type:'module'});super('identities/worker.js');}
};
const callSoftware=createSoftwareClient({createWorker:()=>new BrowserWorker('software/worker.js')});
// Cancellation kills a real worker even while module loading or its password
// KDF is pending. No late response can resolve the cancelled caller.
const interrupted=new AbortController(),interruptedCall=callSoftware('inspect',{encryptedSecret,password},{signal:interrupted.signal});
setTimeout(()=>interrupted.abort(),5);await assert.rejects(interruptedCall,/cancelled/);assert.equal(workers,terminated);
let engine=new Vault(),epoch=1,revision,record,writes=0,store;
const secret=random(32),wrapper={id:crypto.randomUUID(),type:'prf',name:'Disposable passkey',binding:{salt:b64(random(32)),credentialId:b64(random(32))}};
await engine.create(wrapper,secret);record=structuredClone(engine.record);revision=record.revision;
const state=()=>({unlocked:engine.unlocked,vaultId:engine.record?.id,revision,epoch,items:engine.data?.items||[]});
const guard=expected=>{const now=state();assert(now.unlocked);for(const key of ['vaultId','revision','epoch'])assert.equal(now[key],expected[key]);assert.equal(record.revision,revision);};
const access={snapshot:state,assertCurrent:async expected=>guard(expected),replaceItems:async(items,expected,{signal})=>{
 guard(expected);assert(!signal.aborted);engine.data.items=items;await engine.save();guard(expected);assert(!signal.aborted);
 record=structuredClone(engine.record);revision=record.revision;writes++;
}};
const createStore=()=>createSoftwareIdentityStore({access,inspectPublic:inspectIdentity,cryptoCall:async(op,input,options)=>{
 if(op!=='inspect')privateCalls++;return callSoftware(op,input,options);
}});
store=createStore();
// The true WASM parser rejects an incorrect password before any vault write.
await assert.rejects(store.import({name:'Rejected fixture',encryptedSecret,password:password+' wrong'},email));
assert.equal(writes,0);
const imported=await store.import({name:'Disposable Level 3 software',encryptedSecret,password},email);
assert.equal(writes,1);assert.equal(imported.fingerprint,fixture.identity.fingerprint);
// Only the sealed vault record is serializable to durable storage. Neither the
// original encrypted secret nor its password appears as cleartext in that record.
const disk=JSON.stringify(record);
for(const forbidden of [password,encryptedSecret,fixture.identity.fingerprint,'Disposable Level 3 software'])assert(!disk.includes(forbidden));
assert(!('password' in imported));assert(!('encryptedSecret' in imported));
store.cancel();epoch++;engine.lock();assert.deepEqual((await store.list(email)).choices,[]);await assert.rejects(store.assert(imported));
const beforeLocked=workers;await assert.rejects(store.native(imported)('chat-selected-signing-material',{identity:store.nativeBinding(imported)}));assert.equal(workers,beforeLocked);
// Recreate both vault engine and store to model a process restart. No decrypted
// identity/password object from the first engine is reused by this restoration.
engine=new Vault();store=createStore();await engine.unlock(JSON.parse(disk),wrapper.id,secret);
const selected=(await store.list(email)).choices[0];assert.equal(selected.fingerprint,imported.fingerprint);await assert.rejects(store.assert(imported));
assert.deepEqual((await store.list('different@example.invalid')).choices,[]);
await assert.rejects(store.get(selected.id,'different@example.invalid'));
const selection=createProviderSelection({hardware:{list:async()=>({choices:[],revision:0})},software:()=>store,match:matchRecipients});
let artifact;
const report=await runSoftwareTest({identity:selected,selection,request:store.native(selected),gate:async()=>assert(engine.unlocked),
 createSigningWorker:()=>new BrowserWorker('signing-worker.js'),createDecryptionWorker:()=>new BrowserWorker('decryption-worker.js'),
 sign:async(...args)=>{const result=await signAndEncrypt(...args);artifact={cipher:result.cipher,compose:args[1]};return result;}});
assert.equal(report.status,'PASS');assert.equal(report.nativeRequests,0);assert.equal(privateCalls,2);
assert.equal(report.signatureVerified,true);assert.equal(report.decryptionVerified,true);assert.equal(report.payloadVerified,true);
// Optional independent native Sequoia oracle verifies the exact ciphertext
// produced by the browser workers, then emits a new signed/encrypted reply.
// It is an explicit disposable-fixture executable, never a production helper
// capability. Test credentials pass only through its stdin, never command args.
if(process.env.IWA_MESSAGE_ORACLE_BIN){
 const oracle=(op,payload)=>{
  const response=spawnSync(process.env.IWA_MESSAGE_ORACLE_BIN,[],{input:JSON.stringify({op,encryptedSecret,password,peer:selected.certificate,payload}),maxBuffer:2*1024*1024,timeout:120000});
  assert.equal(response.status,0,'Independent software fixture oracle failed');
  return JSON.parse(response.stdout);
 };
 // Pass the real signed/encrypted file through the Drive transport's binary
 // multipart upload and bounded download before independent Sequoia opens it.
 // HTTP is in-memory here: this is not a claim of a live Google Drive transfer.
 const {createDriveFiles,DRIVE_SCOPE}=await import('../app/drive-files.js');
 let uploaded;
 const drive=createDriveFiles({fetcher:async(url,options)=>{
  if(options.method==='POST'){
   const body=Buffer.from(await options.body.arrayBuffer());
   const boundary=options.headers['Content-Type'].split('boundary=')[1];
   const marker=Buffer.from('Content-Type: application/pgp-encrypted\r\n\r\n');
   const start=body.indexOf(marker)+marker.length;
   assert(start>=marker.length);uploaded=body.subarray(start,body.length-Buffer.byteLength('\r\n--'+boundary+'--\r\n'));
   assert.deepEqual(uploaded,Buffer.from(artifact.cipher,'base64'));
   return Response.json({id:'synthetic_file',name:'encrypted.pgp'});
  }
  if(url.endsWith('alt=media'))return new Response(uploaded);
  return Response.json({id:'synthetic_file',appProperties:{sequoiaOpenPgp:'1'},size:uploaded.length});
 }});
 drive.connect({token:'synthetic-test-token',scope:DRIVE_SCOPE,expiresIn:60});
 await drive.upload(artifact.cipher);const downloaded=await drive.download('synthetic_file');drive.clear();
 assert.equal(downloaded,artifact.cipher);
 const nativeOpened=oracle('software-open',downloaded);assert.equal(nativeOpened.verified,true);
 const raw=Buffer.from(nativeOpened.data,'base64'),mail=await parse(raw);
 assert.equal(mail.subject,artifact.compose.subject);assert.equal(mail.text,artifact.compose.body);assert.equal(mail.html,artifact.compose.html);
 assert.equal(mail.attachments.length,1);assert.equal(mail.attachments[0].filename,artifact.compose.attachments[0].name);assert.equal(mail.attachments[0].content,artifact.compose.attachments[0].data);
 const reply={...artifact.compose,subject:'Native Sequoia reply '+crypto.randomUUID(),body:'Synthetic native Sequoia reply.\n',html:'<p>Synthetic native Sequoia reply.</p>'};
 const sealed=oracle('software-seal',composeMime(reply));
 const match=await selection.match(sealed.data,email);assert(match.choices.some(x=>x.id===selected.id));
 const verification={expectedEmail:email,expectedFingerprint:selected.fingerprint,recipient:email,
  material:{certificates:[selected.certificate],bindings:[{email,fingerprint:selected.fingerprint}],saved:[]}};
 const reopened=await decryptWithHardware({cipher:sealed.data,service:'Hardware test',identity:store.nativeBinding(selected),recipientKey:selected.recipientKey,
  verification,native:store.native(selected),gate:()=>store.assert(selected),validateMaterial:material=>store.validateMaterial(material,selected,'decryption'),
  createWorker:()=>new BrowserWorker('decryption-worker.js')});
 assert.equal(reopened.verified,true);assert.equal(reopened.encrypted,true);assert.equal(reopened.signatureStatus,'valid');assert.equal(reopened.certificateTrust,'trusted');
 assert.equal(reopened.signatures[0].fingerprint,selected.fingerprint);assert.equal(reopened.subject,reply.subject);assert.equal(reopened.text,reply.body);assert.equal(reopened.html,reply.html);
 assert.equal(reopened.attachments.length,1);assert.equal(reopened.attachments[0].data,reply.attachments[0].data);
 fs.writeFileSync(path.join(directory,variant+'-native-reply.pgp'),Buffer.from(sealed.data,'base64'),{mode:0o600});
 report.independentSequoia={outgoingDecryptedAndVerified:true,incomingDecryptedAndVerified:true,driveBinaryTransport:'in-memory HTTP; exact ciphertext round trip'};
}
assert.equal(workers,terminated,'Every worker must be terminated after its operation');
// These are synthetic ciphertext, public certificate and expected MIME fields
// for an independent native Sequoia oracle. No secret key is exported here.
fs.writeFileSync(path.join(directory,variant+'-software-roundtrip.pgp'),Buffer.from(artifact.cipher,'base64'),{mode:0o600});
fs.writeFileSync(path.join(directory,variant+'-software-roundtrip.json'),JSON.stringify({report,compose:artifact.compose},null,2)+'\n',{mode:0o600});
// A reviewed removal invalidates old operation snapshots before another worker
// is created, and reopening the persisted vault does not resurrect the key.
await store.remove(selected);assert.equal(writes,2);const removedDisk=JSON.stringify(record),beforeRemoved=workers;
await assert.rejects(store.native(selected)('chat-selected-signing-material',{identity:store.nativeBinding(selected)}));assert.equal(workers,beforeRemoved);
store.cancel();epoch++;engine.lock();engine=new Vault();store=createStore();await engine.unlock(JSON.parse(removedDisk),wrapper.id,secret);
assert.deepEqual(await store.records(),[]);store.cancel();epoch++;engine.lock();secret.fill(0);
console.log('PASS '+variant+': real encrypted software import, wrong-password no-write, encrypted persistence, restart, locked/cross-account rejection, signing/decryption and exact text/HTML/attachment verification'+(report.independentSequoia?', independent native Sequoia in both directions':'')+'; '+workers+' workers terminated; zero native helper calls.');
