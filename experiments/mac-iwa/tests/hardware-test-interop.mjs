// Exercise the complete shipped coordinator and its three WASM workers using
// newly generated software keys as the card-component oracle. No test key,
// native PIN prompt, saved user identity, Google account or network is touched.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {Worker as Thread} from 'node:worker_threads';
import {spawnSync} from 'node:child_process';
import {inspectIdentity,matchRecipients} from '../app/identities/client.js';
import {createIdentitySelection} from '../app/identities/selection.js';
import {runHardwareTest} from '../app/hardware-test.js';

const directory=process.argv[2],fixture=process.env.IWA_SIGNING_FIXTURE_BIN;
assert(directory&&fixture,'Disposable fixture directory and IWA_SIGNING_FIXTURE_BIN required');
const certificate=fs.readFileSync(path.join(directory,'sender-public.pgp')).toString('base64');
class BrowserWorker{
 constructor(script){this.thread=new Thread(new URL(script,import.meta.url),{type:'module'});
  this.thread.on('message',data=>this.onmessage?.({data}));this.thread.on('error',error=>this.onerror?.(error));}
 postMessage(data){this.thread.postMessage(data);}
 terminate(){return this.thread.terminate();}
}
// Identity selection normally creates its own worker by URL. Permit only its
// exact bundled entry point so an unexpected URL can never fetch remote code.
globalThis.Worker=class extends BrowserWorker{
 constructor(url,options){assert.equal(url,'/identities/worker.js');assert.deepEqual(options,{type:'module'});super('./identity-worker-node.mjs');}
};
const info=await inspectIdentity(certificate),email=info.emails[0];
const inventory={revision:1,identities:[{id:'disposable-software-fixture',serial:'123456',
 bundleSignatureVerified:true,liveKeysMatched:true,bundleHash:'c'.repeat(64),slots:[],certificates:[info]}]};
const selection=createIdentitySelection({store:{list:async()=>structuredClone(inventory)},inspect:inspectIdentity,match:matchRecipients});
const identity=(await selection.list(email)).choices[0],binding=selection.nativeBinding(identity);
const audit={format:'sequoia-iwa-hardware-audit',version:1,identity:binding,backendHash:'b'.repeat(64),pinRetries:{remaining:3,maximum:3},
 slots:['9a','9c','9d','9e',...Array.from({length:20},(_,i)=>(0x82+i).toString(16))].map(slot=>({slot,publicKeySha256:null,algorithm:null,origin:null,pinPolicy:null,touchPolicy:null}))};
// The software fixture has no real card policies. Synthetic snapshots exercise
// schema/comparison, and must never be presented as hardware-policy evidence.
for(const slot of ['9c','9d','84','85'])Object.assign(audit.slots.find(value=>value.slot===slot),{
 publicKeySha256:'a'.repeat(64),algorithm:'disposable fixture',origin:'generated',pinPolicy:'Always',touchPolicy:'Never'});
let signingCalls=0,decryptionCalls=0,audits=0;
const fixtureCall=(op,request)=>{
 const result=spawnSync(fixture,[op,path.join(directory,'sender-secret.pgp')],{input:JSON.stringify(request),maxBuffer:1024*1024});
 assert.equal(result.status,0,result.stderr.toString());return JSON.parse(result.stdout);
};
const native=async(op,request)=>{
 if(op==='chat-hardware-audit'){audits++;assert.deepEqual(request,{identity:binding});return structuredClone(audit);}
 if(op==='chat-selected-signing-material')return {identity:binding,review:'a'.repeat(48),senderEmail:email,senderCertificate:info.certificate,signingFingerprint:info.signingFingerprint};
 if(op==='chat-selected-decryption-material'){
  assert.equal(request.service,'Hardware test');return {identity:binding,review:'d'.repeat(48),recipientCertificate:info.certificate,recipientKey:info.recipientKey};
 }
 if(op==='chat-sign-digest'){
  signingCalls++;const {review,...input}=request;assert.equal(review,'a'.repeat(48));return fixtureCall('sign',input);
 }
 if(op==='chat-decapsulate-components'){
  decryptionCalls++;const {review,service,...input}=request;
  assert.equal(review,'d'.repeat(48));assert.equal(service,'Hardware test');return fixtureCall('decap',input);
 }
 assert.fail('Unexpected native operation: '+op);
};
const report=await runHardwareTest({identity,selection,native,gate:async()=>{},
 createSigningWorker:()=>new BrowserWorker('./signing-worker-node.mjs'),
 createDecryptionWorker:()=>new BrowserWorker('./decryption-worker-node.mjs')});
assert.equal(report.status,'PASS',JSON.stringify(report,null,2));
assert.equal(report.signatureVerified,true);assert.equal(report.decryptionVerified,true);assert.equal(report.payloadVerified,true);assert.equal(report.unchanged,true);
assert.deepEqual(report.privateAttempts,{signing:1,decryption:1});assert.equal(signingCalls,1);assert.equal(decryptionCalls,1);assert.equal(audits,2);
assert.equal(report.messagesSent,0);assert.equal(report.cardWrites,0);
for(const secretField of ['mlkemSecret','x25519Secret','digest','cipher','payload','signed'])assert.ok(!JSON.stringify(report).includes('"'+secretField+'"'));
console.log('PASS real hardware-test coordinator: signing, own-recipient matching, component decapsulation, hybrid combining and exact text/HTML/binary attachment verification in shipped WASM workers; one signing and one decryption callback; two synthetic public audits; no hardware/network operations.');
