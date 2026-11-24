// A prepared send must not survive removal/replacement of its own identity.
// Synthetic public bytes suffice here; cryptographic checks have separate WASM
// integration tests and no private operation occurs in these review-state tests.
import test from 'node:test';import assert from 'node:assert/strict';
import {createComposeReviews} from '../app/compose-review.js';
const id='a'.repeat(48),account='me@example.invalid';
const material={review:id,senderCertificate:btoa('public sender'),senderEmail:account,signingFingerprint:'B'.repeat(64)};
const contact={email:'other@example.invalid',fingerprint:'C'.repeat(64),certificate:btoa('public recipient')};
const identity={id:'selected',revision:1,email:account,serial:'123',fingerprint:'D'.repeat(64)};
const request={account,subject:'Test',service:'Gmail',space:'Gmail',identity};
function setup(){let revision=1,checks=0;
 const selection={validateMaterial:async(m,i)=>{assert.deepEqual(i,identity);assert.equal(m,material);if(i.revision!==revision)throw Error('Identity changed');},assert:async i=>{checks++;if(i.revision!==revision)throw Error('Identity changed');}};
 return {reviews:createComposeReviews({certificateStore:{assertContact:async()=>{}},identitySelection:selection}),replace:()=>revision++,checks:()=>checks};
}
test('selected own identity is shown in completion and rechecked at export',async()=>{
 const s=setup();await s.reviews.prepare(material,contact,request);const ready=await s.reviews.complete(id,btoa('cipher'));
 assert.equal(ready.serial,'123');assert.equal(ready.sender,account);assert.equal(ready.senderFingerprint,identity.fingerprint);
 await s.reviews.exportEmail(id,account,true);assert.equal(s.checks(),2);
});
test('replaced own identity invalidates completion, sending and offline export',async()=>{
 for(const step of ['complete','send','export']){
  const s=setup();await s.reviews.prepare(material,contact,request);
  if(step!=='complete')await s.reviews.complete(id,btoa('cipher'));
  s.replace();await assert.rejects(step==='complete'?s.reviews.complete(id,btoa('cipher')):step==='send'?s.reviews.take(id,'Gmail',true,account):s.reviews.exportEmail(id,account,true),/Identity changed/);
  await assert.rejects(s.reviews.take(id,'Gmail',true,account),/consumed/);
 }
});
