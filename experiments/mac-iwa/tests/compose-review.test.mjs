// Send reviews are entirely browser-owned. These tests use synthetic public
// certificate placeholders and ciphertext; no account or hardware is accessed.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createComposeReviews,gmailEnvelope} from '../app/compose-review.js';
import {b64,bytes64,envelope,LIMIT} from '../app/message-mime.js';
const account='sender@example.invalid',recipient='recipient@example.invalid';
const cipher=b64(Uint8Array.from({length:1024},(_,i)=>i%256));
const id='a'.repeat(48);
const native={review:id,senderCertificate:btoa('public sender'),senderEmail:account,signingFingerprint:'B'.repeat(64)};
const contact={id:'contact',email:recipient,fingerprint:'C'.repeat(64),certificate:btoa('public recipient'),certificateHash:'D'.repeat(64),revision:1};
const request={account,subject:'Secret synthetic subject',service:'Gmail',space:'Gmail'};
function fixture(){
 let time=1000,valid=true,locked=false,checks=0;
 const certificateStore={assertContact:async c=>{checks++;assert.deepEqual(c,contact);if(!valid)throw Error('Trust changed');}};
 const reviews=createComposeReviews({certificateStore,now:()=>time,gate:()=>{if(locked)throw Error('Vault locked');}});
 return {reviews,certificateStore,prepare:()=>reviews.prepare(native,contact,request),setTime:n=>time=n,revoke:()=>valid=false,lock:()=>{locked=true;reviews.clear();},checks:()=>checks};
}

test('PGP/MIME wrapper preserves exact ciphertext and hides protected subject/body',()=>{
 const raw=bytes64(gmailEnvelope(account,recipient,cipher)),s=new TextDecoder().decode(raw);
 assert.equal(envelope(raw).kind,'encrypted');assert.deepEqual(envelope(raw).cipher,bytes64(cipher));
 assert.match(s,/^From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nSubject: Encrypted OpenPGP message\r\n/);
 assert.ok(!s.includes(request.subject));assert.ok(!s.includes('public sender'));assert.ok(!s.replaceAll('\r\n','').includes('\n'));
 for(const address of ['victim@example.invalid\r\nBcc: other@example.invalid','a@example.invalid,other@example.invalid','Name <a@example.invalid>'])assert.throws(()=>gmailEnvelope(address,recipient,cipher));
 assert.throws(()=>gmailEnvelope(account,recipient,b64(new Uint8Array(LIMIT))),/preview limit/);
});

test('prepared review keeps fixed recipient metadata and is used once after independent completion',async()=>{
 const f=fixture();const material=await f.prepare();
 assert.equal(material.recipientEmail,recipient);assert.equal(material.recipientCertificate,contact.certificate);assert.equal(material.senderEmail,account);
 // Caller-visible mutable output must never change the internal review.
 material.subject='replacement';material.recipientEmail='other@example.invalid';
 const ready=await f.reviews.complete(id,cipher);assert.equal(ready.subject,request.subject);assert.equal(ready.recipient,recipient);
 const output=await f.reviews.take(id,'Gmail',true,account);assert.deepEqual(envelope(bytes64(output.raw)).cipher,bytes64(cipher));assert.equal(f.checks(),3);
 await assert.rejects(f.reviews.take(id,'Gmail',true,account),/consumed/);
});

test('Chat review preserves space, ciphertext and sender public certificate',async()=>{
 const f=fixture();await f.reviews.prepare(native,contact,{...request,service:'Chat',space:'spaces/test'});
 assert.equal((await f.reviews.complete(id,cipher)).space,'spaces/test');
 assert.deepEqual(await f.reviews.take(id,'Chat',true,account),{space:'spaces/test',cipher,certificate:native.senderCertificate});
});

test('trust removal after preparation stops completion and permanently consumes that review',async()=>{
 const f=fixture();await f.prepare();f.revoke();await assert.rejects(f.reviews.complete(id,cipher),/Trust changed/);
 await assert.rejects(f.reviews.complete(id,cipher),/consumed/);
});

test('trust removal after signing stops send; destination and account substitutions fail closed',async()=>{
 const f=fixture();await f.prepare();await f.reviews.complete(id,cipher);f.revoke();await assert.rejects(f.reviews.take(id,'Gmail',true,account),/Trust changed/);
 for(const [service,confirmed,sender] of [['Chat',true,account],['Gmail',false,account],['Gmail',true,'other@example.invalid']]){
  const t=fixture();await t.prepare();await t.reviews.complete(id,cipher);
  await assert.rejects(t.reviews.take(id,service,confirmed,sender),/changed/);
  await assert.rejects(t.reviews.take(id,'Gmail',true,account),/consumed/);
 }
});

test('expiration, clock reversal, cancellation and malformed completion cannot create a sendable draft',async()=>{
 for(const time of [1000+600001,0]){const f=fixture();await f.prepare();f.setTime(time);await assert.rejects(f.reviews.complete(id,cipher),/expired/);}
 const f=fixture();await f.prepare();f.reviews.cancel(id);await assert.rejects(f.reviews.complete(id,cipher),/consumed/);
 const bad=fixture();await bad.prepare();await assert.rejects(bad.reviews.complete(id,'not base64'),/Invalid/);await assert.rejects(bad.reviews.complete(id,cipher),/consumed/);
 const late=fixture();await late.prepare();await late.reviews.complete(id,cipher);late.setTime(602000);await assert.rejects(late.reviews.take(id,'Gmail',true,account),/expired/);
});

test('send attempts consume synchronously so two clicks cannot release the same ciphertext',async()=>{
 const f=fixture();await f.prepare();await f.reviews.complete(id,cipher);
 const [a,b]=await Promise.allSettled([f.reviews.take(id,'Gmail',true,account),f.reviews.take(id,'Gmail',true,account)]);
 assert.equal(a.status,'fulfilled');assert.equal(b.status,'rejected');
});

test('lock or page clear invalidates asynchronous preparation, completion and take results',async()=>{
 for(const stage of ['prepare','complete','take']){
  const f=fixture();if(stage!=='prepare')await f.prepare();if(stage==='take')await f.reviews.complete(id,cipher);
  let release;f.certificateStore.assertContact=()=>new Promise(r=>release=r);
  const operation=stage==='prepare'?f.prepare():stage==='complete'?f.reviews.complete(id,cipher):f.reviews.take(id,'Gmail',true,account);
  await Promise.resolve();f.reviews.clear();release();await assert.rejects(operation,/cleared/);
  await assert.rejects(f.reviews.take(id,'Gmail',true,account),/consumed/);
 }
});

test('invalid identity and recipient metadata stop before a review is retained',async()=>{
 const f=fixture();
 await assert.rejects(f.reviews.prepare({...native,senderEmail:'other@example.invalid'},contact,request),/identity mismatch/);
 await assert.rejects(f.reviews.prepare(native,{...contact,email:'evil@example.invalid\r\nBcc: x@y'},request),/mailbox/);
 await assert.rejects(f.reviews.prepare(native,contact,{...request,subject:'line\nbreak'}),/subject/);
 await assert.rejects(f.reviews.prepare(native,contact,{...request,service:'Chat',space:'spaces/../other'}),/destination/);
 await assert.rejects(f.reviews.prepare({...native,senderCertificate:'c2VjcmV0='},contact,request),/certificate/);
 await f.prepare();await assert.rejects(f.prepare(),/already exists/);
 f.lock();await assert.rejects(f.prepare(),/locked/);
});

test('explicit encrypted-email export preserves ciphertext and consumes the send review',async()=>{
 const f=fixture();await f.prepare();await f.reviews.complete(id,cipher);
 const saved=await f.reviews.exportEmail(id,account,true);
 assert.equal(saved.name,'encrypted-message.eml');assert.equal(saved.type,'message/rfc822');
 assert.deepEqual(envelope(bytes64(saved.raw)).cipher,bytes64(cipher));
 assert.ok(!new TextDecoder().decode(bytes64(saved.raw)).includes(request.subject));
 await assert.rejects(f.reviews.take(id,'Gmail',true,account),/consumed/);
 await assert.rejects(f.reviews.exportEmail(id,account,true),/consumed/);
});

test('ciphertext export rejects stale trust, vault lock, expiry and changed account or service',async()=>{
 for(const failure of ['trust','lock','expiry','account','confirmation','service']){
  const f=fixture();await f.reviews.prepare(native,contact,failure==='service'?{...request,service:'Chat',space:'spaces/test'}:request);
  await f.reviews.complete(id,cipher);
  if(failure==='trust')f.revoke();if(failure==='lock')f.lock();if(failure==='expiry')f.setTime(602000);
  await assert.rejects(f.reviews.exportEmail(id,failure==='account'?'other@example.invalid':account,failure!=='confirmation'),/changed|locked|expired|consumed/);
 }
 const f=fixture();await f.prepare();await f.reviews.complete(id,cipher);
 let release;f.certificateStore.assertContact=()=>new Promise(r=>release=r);
 const saving=f.reviews.exportEmail(id,account,true);await Promise.resolve();f.reviews.clear();release();
 await assert.rejects(saving,/cleared/);
});

test('classical signing or encryption requires explicit compatibility confirmation',async()=>{
 for(const [pqSigning,pqEncryption] of [[false,true],[true,false],[false,false]]){
  const selected={provider:'software',profile:'level3-v4-classical',pqSigning};
  const peer={...contact,pqEncryption};
  const reviews=createComposeReviews({certificateStore:{assertContact:async()=>true},identitySelection:{assert:async()=>true,validateMaterial:async()=>true}});
  await assert.rejects(reviews.prepare(native,peer,{...request,identity:selected}),/classical compatibility/);
  const material=await reviews.prepare(native,peer,{...request,identity:selected,compatibilityConfirmed:true});
  assert.equal(material.compatibilityWarnings.length,Number(!pqSigning)+Number(!pqEncryption));
 }
});
test('hybrid signature and encryption never warn solely for classical component presence',async()=>{
 const reviews=createComposeReviews({certificateStore:{assertContact:async()=>true},identitySelection:{assert:async()=>true,validateMaterial:async()=>true}});
 const value=await reviews.prepare(native,{...contact,pqEncryption:true},{...request,identity:{provider:'software',profile:'level5',pqSigning:true}});
 assert.equal(value.compatibilityWarnings,undefined);assert.equal(value.softwareProfile,'level5');
});

// Reject incompatible packet dialects before invoking any private provider.
test('v5 cannot silently mix with RFC v4/v6 sender or recipient certificates',async()=>{
 for(const [own,peer] of [[5,6],[6,5],[4,5],[5,4]]){
  const f=fixture();await assert.rejects(f.reviews.prepare(native,{...contact,version:peer},{...request,identity:{version:own},compatibilityConfirmed:true}),/requires v5 certificates/);
 }
});
