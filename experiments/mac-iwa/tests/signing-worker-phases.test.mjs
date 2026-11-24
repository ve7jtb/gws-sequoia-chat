// Execute the shipped worker controller with a deliberately failing crypto seam.
// These tests classify the actual async boundaries, not reimplemented signing.
// Real crypto round trips remain in the worker/WASM interoperability suites.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {signingFailurePhase} from '../app/signing-phases.js';
const source=fs.readFileSync(new URL('../app/signing-worker.js',import.meta.url),'utf8');
const requestId='A'.repeat(64),signingFingerprint='B'.repeat(64);
const material={review:'a'.repeat(48),senderEmail:'sender@example.invalid',recipientEmail:'peer@example.invalid',subject:'Synthetic',senderCertificate:'YQ==',recipientCertificate:'YQ==',signingFingerprint};
function controller(fault){
 const messages=[];let closed=false,cancelled=false;
 const fail=phase=>{if(fault===phase)throw Error('SECRET /private/path/raw error');};
 const context={JSON,Error,Math,signingFailurePhase,
  init:async()=>{fail('signing-preparation');},composeMime:()=> 'YQ==',inspect_public:()=>JSON.stringify({version:6}),
  prepare_signing:()=>JSON.stringify({requestId,signingFingerprint}),companion_complete:()=>assert.fail('Injected companion wrapper is the crypto seam'),
  completeCompanion:async()=>{fail('companion-completion');return {requestId};},
  finalize_signing:()=>{fail('signature-finalization');return JSON.stringify({requestId,senderCertificate:'YQ==',signed:'YQ==',payload:'YQ=='});},
  encrypt_signed:()=>{fail('recipient-encryption');return JSON.stringify({cipher:'YQ=='});},cancel_signing:()=>{cancelled=true;},
  self:{postMessage:value=>messages.push(structuredClone(value)),close:()=>{closed=true;}}};
 vm.createContext(context);
 // Strip only the module imports; the entire shipped event handler runs with
 // the same operation binding, state transitions, cleanup and error handling.
 vm.runInContext(source.replace(/^import .+;\n/gm,''),context);
 return {messages,closed:()=>closed,cancelled:()=>cancelled,post:async data=>context.self.onmessage({data})};
}
for(const phase of ['signing-preparation','companion-completion','signature-finalization','recipient-encryption'])test('worker reports the fixed '+phase+' boundary without raw diagnostic data',async()=>{
 const worker=controller(phase);
 await worker.post({type:'prepare',requestId,material,compose:{sender:material.senderEmail,recipient:material.recipientEmail,subject:material.subject}});
 const signature={companion:{encoded:'public ciphertext'},companionShared:'SECRET'};
 if(phase!=='signing-preparation'){
  assert.equal(worker.messages[0].type,'sign-request');await worker.post({type:'finalize',requestId,signature});
  assert.equal(Object.hasOwn(signature,'companionShared'),false);
 }
 assert.deepEqual(worker.messages.at(-1),{type:'error',requestId,failurePhase:phase});
 assert.ok(!JSON.stringify(worker.messages).includes('SECRET'));assert.ok(worker.closed());assert.ok(worker.cancelled());
});
test('worker success still returns only the bound ciphertext and no diagnostic or component fields',async()=>{
 const worker=controller();await worker.post({type:'prepare',requestId,material,compose:{sender:material.senderEmail,recipient:material.recipientEmail,subject:material.subject}});
 await worker.post({type:'finalize',requestId,signature:{companion:{encoded:'ciphertext'},companionShared:'SECRET'}});
 assert.deepEqual(worker.messages.at(-1),{type:'complete',requestId,cipher:'YQ=='});assert.ok(worker.closed());assert.equal(worker.cancelled(),false);
});
