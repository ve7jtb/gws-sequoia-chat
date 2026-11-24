// Exercise the browser coordinator's authorization and cleanup behavior. These
// fakes are only the hardware/worker seam; real worker cryptography is covered
// separately by hardware-test-interop.mjs with disposable software keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import {runHardwareTest,validateHardwareAudit,hardwareTestFixture} from '../app/hardware-test.js';
import {nativeIdentity} from '../app/identities/selection.js';
const clone=value=>structuredClone(value),runId='11111111-1111-4111-8111-111111111111';
const identity={id:'saved',serial:'123456',bundleHash:'a'.repeat(64),certificateHash:'b'.repeat(64),fingerprint:'C'.repeat(64),recipientKey:'D'.repeat(64),signingFingerprint:'E'.repeat(64),email:'test@example.invalid',certificate:btoa('synthetic public certificate')};
const slots=['9a','9c','9d','9e',...Array.from({length:20},(_,i)=>(0x82+i).toString(16))];
function snapshot(){return {format:'sequoia-iwa-hardware-audit',version:1,identity:nativeIdentity(identity),backendHash:'f'.repeat(64),pinRetries:{remaining:3,maximum:3},slots:slots.map(slot=>({slot,publicKeySha256:slot==='9c'?'a'.repeat(64):null,algorithm:slot==='9c'?'MLDSA65':null,origin:slot==='9c'?'GENERATED':null,pinPolicy:slot==='9c'?'ALWAYS':null,touchPolicy:slot==='9c'?'ALWAYS':null}))};}
function harness(change={}){
 const calls=[],phases=[];let audits=0,compose,valid=true,finishSign;
 const material={review:'a'.repeat(48),identity:nativeIdentity(identity),senderCertificate:identity.certificate,senderEmail:identity.email,signingFingerprint:identity.signingFingerprint};
 const expected=()=>({encrypted:true,verified:true,signatureStatus:'valid',certificateTrust:'trusted',sender:identity.email,subject:compose.subject,text:compose.body,html:compose.html,signatures:[{status:'valid',fingerprint:identity.fingerprint,trusted:true}],attachments:[{name:'hardware-test.bin',size:64,data:compose.attachments[0].data}],omittedAttachments:0});
 const selection={assert:async value=>{assert.deepEqual(value,identity);if(!valid)throw Error('Identity changed');},validateMaterial:async(value,selected,kind)=>{assert.equal(kind==='signing'?value.signingFingerprint:value.recipientKey,kind==='signing'?selected.signingFingerprint:selected.recipientKey);if(change.materialFailure)throw Error('Bad selected material');},match:async()=>change.match??{choices:[identity],recipientKey:identity.recipientKey}};
 const native=async(op,value)=>{
  calls.push(op);
  if(op==='chat-hardware-audit'){
   assert.deepEqual(value,{identity:nativeIdentity(identity)});audits++;
   if(change.auditFailure===audits)throw Error('Read failed');
   const audit=snapshot();if(change.audit)change.audit(audit,audits);
   if(change.changeDuringFinalAudit&&audits===2)valid=false;
   return audit;
  }
  if(op==='chat-selected-signing-material')return clone(material);
  if(op==='chat-sign-digest'){
   if(change.signFailure)throw Error('PIN or private transport failed, sensitive detail');
   if(change.waitSign)await new Promise(resolve=>{finishSign=resolve;});
   return {signature:'not a key'};
  }
  if(op==='chat-selected-decryption-material')return {identity:nativeIdentity(identity),review:'b'.repeat(48),recipientCertificate:identity.certificate,recipientKey:identity.recipientKey};
  if(op==='chat-decapsulate-components'){
   if(change.decryptFailure)throw Error('PIN rejected');
   return {mlkemSecret:'transient',x25519Secret:'transient'};
  }
  assert.fail('Unexpected operation '+op);
 };
 const sign=async(m,c,privateCall)=>{
  compose=c;assert.equal(m.recipientCertificate,identity.certificate);assert.equal(m.recipientFingerprint,identity.fingerprint);
  await privateCall({review:m.review,requestId:'A'.repeat(64),signingFingerprint:identity.signingFingerprint,hashAlgorithm:10,digest:btoa('digest')});
  if(change.duplicateSign)await privateCall({});
  change.afterSign?.();return {cipher:btoa('ciphertext')};
 };
 const decrypt=async options=>{
  assert.equal(options.service,'Hardware test');assert.equal(options.verification.material.saved.length,0);
  await options.gate();const m=await options.native('chat-selected-decryption-material',{identity:options.identity,service:options.service});await options.validateMaterial(m);
  await options.native('chat-decapsulate-components',{service:options.service});
  const result=expected();change.opened?.(result);return result;
 };
 return {calls,phases,release:()=>finishSign(),invalidate:()=>{valid=false;},
  run:extra=>runHardwareTest({identity,selection,native,gate:async()=>{},sign,decrypt,newId:()=>runId,onProgress:text=>phases.push(text),...extra})};
}

test('one browser test signs once, decrypts once, compares exact content and complete public audits',async()=>{
 const h=harness(),r=await h.run();
 assert.equal(r.status,'PASS');assert.equal(r.unchanged,true);assert.equal(r.signatureVerified,true);assert.equal(r.decryptionVerified,true);assert.equal(r.payloadVerified,true);
 assert.deepEqual(r.privateAttempts,{signing:1,decryption:1});
 assert.deepEqual(h.calls,['chat-hardware-audit','chat-selected-signing-material','chat-sign-digest','chat-selected-decryption-material','chat-decapsulate-components','chat-hardware-audit']);
 assert.equal(r.audit.before.slots.length,24);assert.equal(r.messagesSent,0);assert.equal(r.cardWrites,0);
 const json=JSON.stringify(r);for(const disallowed of ['mlkemSecret','x25519Secret','transient','ciphertext','synthetic public certificate','private transport'])assert.ok(!json.includes(disallowed));
});
test('audit rejects omitted, duplicate, incomplete or private metadata before any private operation',async()=>{
 for(const mutate of [a=>a.slots.pop(),a=>a.slots[0]=a.slots[1],a=>a.slots[0].algorithm='empty?',a=>a.pinRetries.remaining=4,a=>a.identity.serial='999999',a=>a.pin='secret',a=>a.backendHash='']){
  const h=harness({audit:(a,n)=>{if(n===1)mutate(a);}}),r=await h.run();
  assert.equal(r.status,'STOPPED');assert.equal(r.unchanged,null);assert.deepEqual(h.calls,['chat-hardware-audit']);
 }
});
test('PIN or signing failure never retries and still collects the public final audit',async()=>{
 const h=harness({signFailure:true}),r=await h.run();
 assert.equal(r.status,'STOPPED');assert.equal(r.failureStage,'signing');assert.equal(r.unchanged,true);
 assert.deepEqual(r.privateAttempts,{signing:1,decryption:0});assert.equal(h.calls.at(-1),'chat-hardware-audit');
 assert.ok(!JSON.stringify(r).includes('sensitive detail'));
});
test('decryption failure never retries or reports plaintext/signature success',async()=>{
 const h=harness({decryptFailure:true}),r=await h.run();
 assert.equal(r.status,'STOPPED');assert.equal(r.signatureVerified,true);assert.equal(r.decryptionVerified,false);assert.equal(r.unchanged,true);
 assert.deepEqual(r.privateAttempts,{signing:1,decryption:1});
});
test('duplicate signing request is stopped before a second native private call',async()=>{
 const h=harness({duplicateSign:true}),r=await h.run();
 assert.equal(r.status,'STOPPED');assert.equal(h.calls.filter(x=>x==='chat-sign-digest').length,1);assert.equal(r.decryptionVerified,false);
});
test('wrong native material or recipient match stops before the corresponding private operation',async()=>{
 for(const change of [{materialFailure:true},{match:{choices:[],recipientKey:identity.recipientKey}},{match:{choices:[{...identity,serial:'654321'}],recipientKey:identity.recipientKey}},{match:{choices:[identity],recipientKey:'F'.repeat(64)}}]){
  const h=harness(change),r=await h.run();assert.equal(r.status,'STOPPED');assert.equal(r.privateAttempts.decryption,0);assert.equal(r.unchanged,true);
  if(change.materialFailure)assert.equal(r.privateAttempts.signing,0);
 }
});
test('wrong text, HTML, signature, sender or binary attachment cannot pass',async()=>{
 for(const opened of [r=>r.text+='changed',r=>r.html='',r=>r.subject='stale',r=>r.sender='wrong@example.invalid',r=>r.signatures[0].fingerprint='F'.repeat(64),r=>r.signatures[0].trusted=false,r=>r.attachments[0].data=btoa('changed'),r=>r.attachments.push(r.attachments[0]),r=>r.omittedAttachments=1]){
  const h=harness({opened}),r=await h.run();assert.equal(r.status,'STOPPED');assert.equal(r.payloadVerified,false);assert.equal(r.unchanged,true);
 }
});
test('changed policies, public keys, PIN retries or backend are never reported unchanged',async()=>{
 for(const mutate of [a=>a.slots[1].touchPolicy='NEVER',a=>a.slots[1].publicKeySha256='b'.repeat(64),a=>a.pinRetries.remaining=2,a=>a.backendHash='e'.repeat(64)]){
  const h=harness({audit:(a,n)=>{if(n===2)mutate(a);}}),r=await h.run();assert.equal(r.status,'STOPPED');assert.equal(r.unchanged,false);assert.equal(r.failureStage,'after-audit');
 }
 const h=harness({auditFailure:2}),r=await h.run();assert.equal(r.status,'STOPPED');assert.equal(r.unchanged,null);
});
test('pre-abort and invalidated context cannot start hardware',async()=>{
 const control=new AbortController();control.abort();let h=harness(),r=await h.run({signal:control.signal});assert.equal(r.status,'CANCELLED');assert.deepEqual(h.calls,[]);
 h=harness();h.invalidate();r=await h.run();assert.equal(r.status,'STOPPED');assert.deepEqual(h.calls,[]);
});
test('cancel during PIN/touch waits for the native attempt, then only audits and never decrypts',async()=>{
 const control=new AbortController(),h=harness({waitSign:true});let finished=false;
 const running=h.run({signal:control.signal}).then(r=>{finished=true;return r;});
 await new Promise(resolve=>setImmediate(resolve));control.abort();await new Promise(resolve=>setImmediate(resolve));assert.equal(finished,false);
 h.release();const r=await running;assert.equal(r.status,'CANCELLED');assert.equal(r.unchanged,true);assert.equal(r.privateAttempts.decryption,0);assert.equal(h.calls.at(-1),'chat-hardware-audit');
});
test('context change before decryption or during final audit suppresses stale success',async()=>{
 let h=harness({afterSign:()=>h.invalidate()}),r=await h.run();assert.equal(r.status,'STOPPED');assert.equal(r.privateAttempts.decryption,0);assert.equal(r.unchanged,true);
 h=harness({changeDuringFinalAudit:true});r=await h.run();assert.equal(r.status,'STOPPED');assert.equal(r.failureStage,'final-context');assert.equal(r.unchanged,true);
});
test('fixture is isolated from drafts and has binary octets and a fresh run binding',()=>{
 const fixture=hardwareTestFixture(identity.email,runId);assert.match(fixture.body,new RegExp(runId));assert.equal(Buffer.from(fixture.attachments[0].data,'base64').length,64);
 assert.equal(fixture.sender,fixture.recipient);assert.equal(validateHardwareAudit(snapshot(),identity).slots.length,24);
});
