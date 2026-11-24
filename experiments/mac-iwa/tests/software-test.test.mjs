// Exercise the offline software test coordinator at its worker/provider seam.
// Private operations are counted but contain only placeholders. Cryptographic
// correctness is covered by the separate real WASM software interoperability
// suite; here failures must not silently retry, cross providers or report PASS.
import test from 'node:test';
import assert from 'node:assert/strict';
import {runSoftwareTest} from '../app/software-test.js';
const identity={provider:'software',id:'software:123',identityId:'123',vaultId:'vault',revision:7,
 email:'me@example.invalid',fingerprint:'A'.repeat(64),recipientKey:'B'.repeat(64),
 signingFingerprint:'C'.repeat(64),certificate:btoa('public certificate'),certificateHash:'d'.repeat(64)};
function harness(change={}){
 const calls=[],progress=[];let compose,valid=true;
 const binding={provider:'software',identityId:identity.identityId,vaultId:identity.vaultId};
 const own={identity:binding,review:'a'.repeat(48),senderCertificate:identity.certificate,
 senderEmail:identity.email,signingFingerprint:identity.signingFingerprint};
 const selection={nativeBinding:value=>{assert.deepEqual(value,identity);return binding;},
 assert:async value=>{assert.deepEqual(value,identity);if(!valid)throw Error('Vault identity changed');},
 validateMaterial:async(m,s,kind)=>{assert.deepEqual(s,identity);if(change.materialFailure)throw Error('Wrong material');assert.equal(kind==='signing'?m.signingFingerprint:m.recipientKey,kind==='signing'?s.signingFingerprint:s.recipientKey);},
 match:async()=>change.match??{choices:[identity],recipientKey:identity.recipientKey}};
 const request=async(op,data)=>{
  calls.push(op);if(change.fail===op)throw Error('Provider refused');
  if(op==='chat-selected-signing-material')return structuredClone(own);
  if(op==='chat-sign-digest'){change.duringSign?.();return {signature:'synthetic'};}
  if(op==='chat-selected-decryption-material')return {identity:binding,review:'b'.repeat(48),recipientCertificate:identity.certificate,recipientKey:identity.recipientKey};
  if(op==='chat-decapsulate-components')return {mlkemSecret:'synthetic',x25519Secret:'synthetic'};
  assert.fail('Unexpected provider operation '+op);
 };
 const sign=async(m,c,privateCall)=>{
  compose=c;assert.equal(c.sender,identity.email);assert.equal(c.recipient,identity.email);
  assert.equal(m.recipientCertificate,identity.certificate);assert.equal(m.recipientFingerprint,identity.fingerprint);
  await privateCall({review:m.review});if(change.duplicateSign)await privateCall({});
  change.afterSign?.();return {cipher:btoa('encrypted synthetic packet')};
 };
 const decrypt=async options=>{
  assert.equal(options.service,'Hardware test');assert.deepEqual(options.identity,binding);
  assert.deepEqual(options.verification.material,{certificates:[identity.certificate],bindings:[{email:identity.email,fingerprint:identity.fingerprint}],saved:[]});
  await options.gate();const material=await options.native('chat-selected-decryption-material',{identity:binding,service:options.service});await options.validateMaterial(material);
  if(change.unexpected)await options.native(change.unexpected,{});
  await options.native('chat-decapsulate-components',{});if(change.duplicateDecrypt)await options.native('chat-decapsulate-components',{});
  const result={encrypted:true,verified:true,signatureStatus:'valid',certificateTrust:'trusted',sender:identity.email,
   subject:compose.subject,text:compose.body,html:compose.html,signatures:[{status:'valid',fingerprint:identity.fingerprint,trusted:true}],
   attachments:[{name:compose.attachments[0].name,size:64,data:compose.attachments[0].data}],omittedAttachments:0};
  change.opened?.(result);return result;
 };
 return {calls,progress,invalidate:()=>{valid=false;},run:extra=>runSoftwareTest({identity,selection,request,gate:async()=>{},sign,decrypt,onProgress:p=>progress.push(p),...extra})};
}
test('software test signs and decrypts once with exact MIME bytes and transient self-trust',async()=>{
 const h=harness(),r=await h.run();assert.equal(r.status,'PASS');assert.equal(r.signatureVerified,true);assert.equal(r.decryptionVerified,true);assert.equal(r.payloadVerified,true);
 assert.deepEqual(r.privateOperations,{signing:1,decapsulation:1});assert.equal(r.nativeRequests,0);assert.equal(r.cardWrites,0);assert.equal(r.messagesSent,0);
 assert.deepEqual(h.calls,['chat-selected-signing-material','chat-sign-digest','chat-selected-decryption-material','chat-decapsulate-components']);
 assert.equal(h.progress.length,2);for(const secret of ['synthetic','mlkemSecret','x25519Secret','vault'])assert.ok(!JSON.stringify(r).includes(secret));
});
test('wrong custody, cancellation and lock stop before software private calls',async()=>{
 const h=harness();await assert.rejects(h.run({identity:{...identity,provider:'hardware'}}),/software identity/);assert.deepEqual(h.calls,[]);
 const control=new AbortController();control.abort();await assert.rejects(h.run({signal:control.signal}),/cancelled/);assert.deepEqual(h.calls,[]);
 h.invalidate();await assert.rejects(h.run(),/changed/);assert.deepEqual(h.calls,[]);
});
test('duplicate component requests never make a second private call',async()=>{
 for(const setting of ['duplicateSign','duplicateDecrypt']){const h=harness({[setting]:true});await assert.rejects(h.run(),/Repeated/);
 assert.equal(h.calls.filter(x=>x==='chat-sign-digest').length,1);assert.ok(h.calls.filter(x=>x==='chat-decapsulate-components').length<=1);}
});
test('provider errors stop without retry or hardware fallback',async()=>{
 for(const fail of ['chat-selected-signing-material','chat-sign-digest','chat-selected-decryption-material','chat-decapsulate-components']){
  const h=harness({fail});await assert.rejects(h.run(),/Provider refused/);assert.equal(h.calls.filter(op=>op===fail).length,1);assert.equal(h.calls.at(-1),fail);
 }
 const h=harness({unexpected:'chat-hardware-audit'});await assert.rejects(h.run(),/Unexpected/);assert.ok(!h.calls.includes('chat-hardware-audit'));
});
test('wrong signing material or recipient cannot start software decryption',async()=>{
 for(const change of [{materialFailure:true},{match:{choices:[],recipientKey:identity.recipientKey}},{match:{choices:[identity],recipientKey:'E'.repeat(64)}}]){
  const h=harness(change);await assert.rejects(h.run());assert.ok(!h.calls.includes('chat-decapsulate-components'));if(change.materialFailure)assert.ok(!h.calls.includes('chat-sign-digest'));
 }
});
test('changed vault state or cancellation after signing suppresses stale decryption',async()=>{
 let h=harness({afterSign:()=>h.invalidate()});await assert.rejects(h.run(),/changed/);assert.ok(!h.calls.includes('chat-selected-decryption-material'));
 const control=new AbortController();h=harness({duringSign:()=>control.abort()});await assert.rejects(h.run({signal:control.signal}),/cancelled/);assert.ok(!h.calls.includes('chat-selected-decryption-material'));
});
test('every payload, signature and attachment mismatch rejects a passing report',async()=>{
 for(const opened of [r=>r.sender='other@example.invalid',r=>r.subject='stale',r=>r.text+='bad',r=>r.html='',r=>r.signatureStatus='invalid',
 r=>r.certificateTrust='untrusted',r=>r.signatures[0].fingerprint='F'.repeat(64),r=>r.signatures.push(r.signatures[0]),r=>r.attachments[0].size=63,
 r=>r.attachments[0].data=btoa('bad'),r=>r.attachments[0].name='other',r=>r.attachments=[],r=>r.omittedAttachments=1]){
  await assert.rejects(harness({opened}).run());
 }
});
test('success requires literal verified/encrypted true and a trusted individual signature',async()=>{
 for(const opened of [r=>r.verified='true',r=>r.encrypted=1,r=>r.signatures[0].trusted=false,r=>delete r.signatures[0].trusted])await assert.rejects(harness({opened}).run());
});
