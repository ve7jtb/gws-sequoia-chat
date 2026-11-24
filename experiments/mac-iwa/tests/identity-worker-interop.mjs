// Verify the browser client and actual WASM worker together with a disposable
// Sequoia fixture. It contains no user key or credential and never calls native.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {Worker as Thread} from 'node:worker_threads';
import {createHash} from 'node:crypto';
import {inspectIdentity,matchRecipients} from '../app/identities/client.js';
import {createIdentitySelection} from '../app/identities/selection.js';

const path=process.env.IWA_SPLIT_DECAP_FIXTURE;
assert(path,'Set IWA_SPLIT_DECAP_FIXTURE to the disposable Sequoia software fixture');
const fixture=JSON.parse(fs.readFileSync(path));
class BrowserWorker{
 constructor(url,options){
  assert.equal(url,'/identities/worker.js');assert.deepEqual(options,{type:'module'});
  this.thread=new Thread(new URL('./identity-worker-node.mjs',import.meta.url),{type:'module'});
  this.thread.on('message',data=>this.onmessage?.({data}));this.thread.on('error',error=>this.onerror?.(error));
 }
 postMessage(data){this.thread.postMessage(data);}
 terminate(){return this.thread.terminate();}
}
globalThis.Worker=BrowserWorker;

test('shipped identity inspector binds canonical public certificate and operational subkeys',async()=>{
 const info=await inspectIdentity(fixture.certificate);
 assert.equal(info.supported,true);assert.equal(info.version,6);
 assert.equal(info.recipientKey,fixture.request.recipientKey);
 assert.match(info.signingFingerprint,/^[A-F0-9]{64}$/);
 assert.equal(info.certificateHash,createHash('sha256').update(Buffer.from(info.certificate,'base64')).digest('hex'));
 assert.deepEqual(info.emails,['fixture@example.invalid']);
 await assert.rejects(inspectIdentity(Buffer.from('not a public certificate').toString('base64')),/rejected/);
});

test('shipped matcher chooses only an exact recipient and preserves ambiguity for UI choice',async()=>{
 const request={cipher:fixture.request.cipher,candidates:[
  {id:'different-card',certificate:fixture.vault.request.recipientCertificate},
  {id:'selected-card',certificate:fixture.certificate}]};
 const result=await matchRecipients(request);
 assert.equal(result.cipherHash,fixture.reply.cipherHash);assert.equal(result.recipientKey,fixture.request.recipientKey);
 assert.deepEqual(result.matches.map(x=>x.id),['selected-card']);
 const info=await inspectIdentity(fixture.certificate);
 assert.equal(result.matches[0].fingerprint,info.fingerprint);assert.equal(result.matches[0].certificateHash,info.certificateHash);
 assert.equal(result.matches[0].signingFingerprint,info.signingFingerprint);
 const ambiguous=await matchRecipients({...request,candidates:[{id:'first',certificate:fixture.certificate},{id:'second',certificate:fixture.certificate}]});
 assert.deepEqual(ambiguous.matches.map(x=>x.id),['first','second']);
 assert.deepEqual((await matchRecipients({...request,candidates:[]})).matches,[]);
});

test('matching rejects malformed packets, duplicate candidates and extra authority fields',async()=>{
 const good={cipher:fixture.request.cipher,candidates:[{id:'one',certificate:fixture.certificate}]};
 for(const value of [{...good,cipher:Buffer.from('plaintext').toString('base64')},
  {...good,cipher:good.cipher+'AAAA'},
  {...good,candidates:[good.candidates[0],good.candidates[0]]},
  {...good,candidates:[{...good.candidates[0],slot:'9d'}]}])await assert.rejects(matchRecipients(value),/rejected/);
});

test('an aborted public review cannot return a late recipient selection',async()=>{
 const controller=new AbortController();controller.abort();
 await assert.rejects(matchRecipients({cipher:fixture.request.cipher,candidates:[]},{signal:controller.signal}),/cancelled/);
 const pending=new AbortController(),operation=inspectIdentity(fixture.certificate,{signal:pending.signal});
 pending.abort();await assert.rejects(operation,/cancelled/);
});

test('actual WASM outputs satisfy saved-identity matching and selected native material bindings',async()=>{
 // Use the same inspector and matcher as the shipped IWA. Only the public
 // inventory and native response are synthetic: this catches API field/case/
 // canonical-hash drift that isolated tests with mocked inspectors cannot.
 const inspected=await inspectIdentity(fixture.certificate),email=inspected.emails[0];
 const inventory={revision:1,identities:[{
  id:'test-yubikey:123',serial:'123',bundleSignatureVerified:true,liveKeysMatched:true,
  bundleHash:'c'.repeat(64),slots:[],certificates:[inspected]
 }]};
 const selection=createIdentitySelection({store:{list:async()=>structuredClone(inventory)},
  inspect:inspectIdentity,match:matchRecipients});
 const candidates=await selection.list(email);assert.equal(candidates.choices.length,1);
 assert.deepEqual((await selection.list('other@example.invalid')).choices,[]);
 const matched=await selection.match(fixture.request.cipher,email);
 assert.equal(matched.cipherHash,fixture.reply.cipherHash);
 assert.equal(matched.recipientKey,fixture.request.recipientKey);
 assert.equal(matched.choices[0].id,candidates.choices[0].id);
 const chosen=matched.choices[0],binding=selection.nativeBinding(chosen);
 assert.deepEqual(Object.keys(binding).sort(),['bundleHash','certificateHash','email','fingerprint','serial']);
 const material={identity:binding,recipientCertificate:fixture.certificate,
  recipientKey:fixture.request.recipientKey};
 assert.equal(await selection.validateMaterial(material,chosen,'decryption'),material);
 const substituted={...material,recipientCertificate:fixture.vault.request.recipientCertificate};
 await assert.rejects(selection.validateMaterial(substituted,chosen,'decryption'),/differs/);
 // A saved-identity edit invalidates the reviewed match before it could be
 // used to obtain/redeem a native private-operation grant.
 inventory.revision++;
 await assert.rejects(selection.validateMaterial(material,chosen,'decryption'),/changed/);
});
