// Explicitly invoked physical-card harness for the shipped IWA orchestration.
// The parent Python driver supplies the normal native grants and masked PIN
// dialogs. No PIN enters this process, and this harness has no card-write API,
// network transport, user browser database or software-key fallback.
import assert from 'node:assert/strict';
import readline from 'node:readline';
import {Worker as Thread} from 'node:worker_threads';
import {createMemoryStorage} from '../app/certificates/store.js';
import {createIdentityStore} from '../app/identities/store.js';
import {createIdentitySelection} from '../app/identities/selection.js';
import {parseCardBundle,parseCardCompanion} from '../app/identities/bundle.js';
import {inspectBundle,inspectCompanion,inspectIdentity,matchRecipients} from '../app/identities/client.js';
import {runHardwareTest} from '../app/hardware-test.js';

const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity}),iterator=lines[Symbol.asyncIterator]();
async function receive(){const line=await iterator.next();assert(!line.done&&line.value.length<1000000,'Native pipe stopped');return JSON.parse(line.value);}
const emit=value=>process.stdout.write(JSON.stringify(value)+'\n');
let counter=0,active=false;
async function native(op,request){
 // runHardwareTest serializes actual operations; a concurrent request would
 // make a response ambiguous and must fail before another PIN grant is made.
 assert(!active,'Concurrent native request');active=true;const id=++counter;
 const allowed=['chat-identity-bundle-read','chat-identity-companion-read','chat-hardware-audit','chat-selected-signing-material','chat-selected-decryption-material','chat-sign-digest','chat-decapsulate-components'];
 assert(allowed.includes(op),'Unsupported harness operation');
 try{emit({type:'native',id,op,request});const response=await receive();assert.equal(response.type,'native-result');assert.equal(response.id,id);assert(!response.error,'Native operation stopped; no retry');return response.value;}
 finally{active=false;}
}
class BrowserWorker{
 constructor(entry){this.thread=new Thread(new URL('./software-worker-node.mjs',import.meta.url),{type:'module',workerData:{entry,variant:'baseline'}});this.thread.on('message',data=>this.onmessage?.({data}));this.thread.on('error',()=>this.onerror?.({}));}
 postMessage(data){this.thread.postMessage(data);}
 terminate(){return this.thread.terminate();}
}
globalThis.Worker=class extends BrowserWorker{constructor(url,options){assert.equal(url,'/identities/worker.js');assert.deepEqual(options,{type:'module'});super('identities/worker.js');}};
const reports=[];
try{
 const start=await receive();assert.equal(start.type,'start');assert.match(start.serial,/^[1-9][0-9]{0,9}$/);assert.match(start.email,/^[^\s<>@]+@[^\s<>@]+$/);
 assert.equal(typeof start.companion,'boolean');
 const supported=start.companion?['LEVEL5_COMPANION']:['level3','level3-v4-hybrid','level3-v4-classical','level3-v5-hybrid','level5-v6-classical','level5-v4-hybrid-p384','level5-v4-classical-p384'];
 assert(Array.isArray(start.profiles)&&start.profiles.length>0&&start.profiles.length<=supported.length&&new Set(start.profiles).size===start.profiles.length&&start.profiles.every(p=>supported.includes(p)));
 // Public restore uses the same WASM inspector and review/store path as the
 // IWA. No enrolled default identity or persistent user database participates.
 // Companion ciphertext is authenticated here but opened only later inside
 // disposable signing/decryption workers after their native PIN operations.
 let preview;
 if(start.companion){
  assert(!start.compatibilityCertificate);
  const snapshot=await native('chat-identity-companion-read',{serial:start.serial,...(start.companionCertificate?{certificate:start.companionCertificate}:{})});
  preview=await parseCardCompanion(snapshot,inspectCompanion);
 }else{
  assert(!start.companionCertificate);
  const snapshot=await native('chat-identity-bundle-read',{serial:start.serial});
  preview=await parseCardBundle(snapshot,inspectBundle,{compatibilityCertificate:start.compatibilityCertificate});
 }
 assert.equal(preview.serial,start.serial,'Public restore must match the explicitly selected serial');
 // Use the same public certificate parser and inventory/review code as the UI.
 // Narrow inspect_identity's public superset to the inventory's closed schema.
 const inspect=async certificate=>{const info=await inspectIdentity(certificate);return Object.fromEntries(['certificate','fingerprint','version','algorithms','emails','hybridContact','encryptionSupported','pqSigning','pqEncryption'].map(k=>[k,info[k]]));};
 const store=createIdentityStore({inspect,storage:createMemoryStorage()});await store.save(await store.previewBundle(preview),true);
 const selection=createIdentitySelection({store,inspect:inspectIdentity,match:matchRecipients});
 for(const profile of start.profiles){
  // The storage descriptor names LEVEL5_COMPANION while the actual v6 public
  // certificate inspector names its on-wire profile level5. Require both the
  // encrypted-companion custody and that profile; never substitute ordinary
  // P-384 v6 or a software identity with the same account address.
  const candidates=(await selection.list(start.email)).choices.filter(c=>c.serial===start.serial&&(profile==='LEVEL5_COMPANION'?c.profile==='level5'&&c.custody==='hardware-companion':c.profile===profile&&c.custody==='hardware'));
  assert.equal(candidates.length,1,'One matching reviewed profile required');
  emit({type:'progress',profile,message:'Starting selected profile with unchanged-key audit.'});
  const report=await runHardwareTest({identity:candidates[0],selection,native,gate:async()=>{},
   onProgress:message=>emit({type:'progress',profile,message}),
   createSigningWorker:()=>new BrowserWorker('signing-worker.js'),createDecryptionWorker:()=>new BrowserWorker('decryption-worker.js')});
  reports.push(report);emit({type:'report',report});
  assert.equal(report.status,'PASS');assert.equal(report.unchanged,true);assert.equal(report.signatureVerified,true);assert.equal(report.decryptionVerified,true);assert.equal(report.payloadVerified,true);
  assert.equal(report.messagesSent,0);assert.equal(report.cardWrites,0);assert.deepEqual(report.privateAttempts,{signing:1,decryption:1});
 }
 emit({type:'complete',reports});
}catch(_){emit({type:'failure',message:'Hardware profile test stopped; no automatic retry.',reports});process.exitCode=1;}
finally{lines.close();}
